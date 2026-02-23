"""Simplified Nova KMS demo client using enclaver's /v1/kms integration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Any, Deque, Dict, Optional

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

import config
from odyn import Odyn, OdynRequestError, OdynTransportError


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("nova-kms-demo-enclaver")

MAX_LOGS = 50
request_logs: Deque[Dict[str, Any]] = deque(maxlen=MAX_LOGS)
REGISTRATION_PENDING_MARKERS = (
    "not zk-verified on registry",
    "is not active on registry",
    "instance not found",
    "registry discovery returned no active kms nodes",
    "registry-based authz requires kms_app_id/nova_app_registry",
    "kms_integration requires registry discovery configuration",
    "has no anchored appwallet on registry",
)
TRANSIENT_REQUEST_MARKERS = (
    # Discovery may briefly fail while local Helios RPC is initializing/reconnecting.
    "registry discovery failed",
    "error sending request for url",
    "127.0.0.1:18545",
    "connection refused",
    "connection reset",
    "temporarily unavailable",
    "timed out",
    "timeout",
)


def _fmt_ts(ts_ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_ms / 1000))


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    return bool(value)


def _render_log(entry: Dict[str, Any]) -> str:
    details = entry.get("details") or {}
    lines = [f"Run @ {_fmt_ts(entry['timestamp_ms'])} | status={entry.get('status')}"]

    if entry.get("error"):
        lines.append(f"Error: {entry['error']}")
    if "retryable" in details:
        lines.append(f"Retryable: {details.get('retryable')}")
    if "http_status" in details:
        lines.append(f"HTTP status: {details.get('http_status')}")
    if "path" in details:
        lines.append(f"Path: {details.get('path')}")
    if "transport_error" in details:
        lines.append(f"Transport error: {details.get('transport_error')}")

    lines.extend(
        [
            "",
            f"1) Derive path: {details.get('derive_path', '-')}",
            f"   key: {details.get('derived_key', '-')}",
            f"   matches_previous: {details.get('derive_matches_previous')}",
            "",
            f"2) Read key: {details.get('data_key', '-')}",
            f"   found: {details.get('read_found')}",
            f"   value: {details.get('read_value')}",
            f"   expected_previous_value: {details.get('expected_previous_value')}",
            f"   matches_previous_write: {details.get('read_matches_previous_write')}",
            "",
            f"3) Write key: {details.get('data_key', '-')}",
            f"   written_value: {details.get('written_value')}",
            f"   write_success: {details.get('write_success')}",
            f"   duration_ms: {details.get('duration_ms')}",
        ]
    )

    return "\n".join(lines)


def _is_registration_pending_error(exc: Exception) -> bool:
    message = str(exc).lower()
    if isinstance(exc, OdynRequestError):
        status = exc.status_code
        if status not in (400, 401, 403, 404, 409, 503):
            return False
        message = exc.response_body.lower()
    return any(marker in message for marker in REGISTRATION_PENDING_MARKERS)


def _is_transient_error(exc: Exception) -> bool:
    if isinstance(exc, OdynTransportError):
        return True
    if isinstance(exc, OdynRequestError):
        if exc.status_code in (408, 429, 500, 502, 503, 504):
            return True
        body = exc.response_body.lower()
        message = str(exc).lower()
        return any(
            (marker in body) or (marker in message) for marker in TRANSIENT_REQUEST_MARKERS
        )
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "timed out",
            "timeout",
            "temporary",
            "temporarily unavailable",
            "connection refused",
            "connection reset",
            "incompletemessage",
        )
    )


class KMSDemoClient:
    def __init__(self):
        self.odyn = Odyn()
        self.interval_seconds = int(config.TEST_CYCLE_INTERVAL_SECONDS)
        self.derive_path = config.FIXED_DERIVE_PATH
        self.data_key = config.KV_DATA_KEY

        self._expected_derive_key: Optional[str] = None
        self._last_written_value: Optional[str] = None
        self._tee_address_logged = False
        self._stop_event = asyncio.Event()
        self._cycle_lock = asyncio.Lock()

    async def run_loop(self) -> None:
        while not self._stop_event.is_set():
            if not self._tee_address_logged:
                await self._try_log_tee_address()
            await self.run_once()
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop_event.set()

    async def run_once(self) -> None:
        async with self._cycle_lock:
            started_ms = int(time.time() * 1000)
            try:
                details = await asyncio.to_thread(self._run_once_sync)
                status = "Success"
                if (
                    details.get("derive_matches_previous") is False
                    or details.get("read_matches_previous_write") is False
                ):
                    status = "Partial"

                self._log(status=status, details=details)
            except Exception as exc:
                registration_pending = _is_registration_pending_error(exc)
                transient_error = _is_transient_error(exc)
                status = (
                    "PendingRegistration"
                    if registration_pending
                    else ("TransientFailure" if transient_error else "Failed")
                )
                details: Dict[str, Any] = {
                    "duration_ms": int(time.time() * 1000) - started_ms,
                    "retryable": (registration_pending or transient_error),
                }
                if isinstance(exc, OdynRequestError):
                    details["http_status"] = exc.status_code
                    details["path"] = exc.path
                elif isinstance(exc, OdynTransportError):
                    details["path"] = exc.path
                    details["transport_error"] = type(exc.cause).__name__
                self._log(
                    status=status,
                    details=details,
                    error=str(exc),
                )
                if registration_pending:
                    logger.warning(
                        "KMS is not ready yet (likely pending app-registry registration): %s",
                        exc,
                    )
                elif transient_error:
                    logger.warning("KMS API transient failure; will retry: %s", exc)
                else:
                    logger.exception("KMS cycle failed")

    async def _try_log_tee_address(self) -> None:
        try:
            addr = await asyncio.to_thread(self.odyn.eth_address)
            self._tee_address_logged = True
            logger.info("Connected to Odyn. TEE address=%s", addr)
        except Exception as exc:
            logger.info("Odyn identity is not available yet: %s", exc)

    def _run_once_sync(self) -> Dict[str, Any]:
        started = time.time()
        now_value = str(int(started))
        previous_written = self._last_written_value
        previous_derive = self._expected_derive_key

        derive_res = self.odyn.kms_derive(path=self.derive_path)
        derived_key = derive_res.get("key")
        if not isinstance(derived_key, str) or not derived_key.strip():
            raise RuntimeError("kms/derive returned an empty key")

        if previous_derive is None:
            derive_matches_previous = None
            self._expected_derive_key = derived_key
        else:
            derive_matches_previous = derived_key == previous_derive

        read_res = self.odyn.kms_kv_get(self.data_key)
        read_found = _parse_bool(read_res.get("found"))
        read_value_raw = read_res.get("value")
        read_value = None if read_value_raw is None else str(read_value_raw)

        write_res = self.odyn.kms_kv_put(self.data_key, now_value, ttl_ms=0)
        write_success = _parse_bool(write_res.get("success"))
        if not write_success:
            raise RuntimeError("kms/kv/put returned success=false")

        # Only advance local expectation when write has succeeded.
        self._last_written_value = now_value

        return {
            "derive_path": self.derive_path,
            "derived_key": derived_key,
            "derive_matches_previous": derive_matches_previous,
            "data_key": self.data_key,
            "read_found": read_found,
            "read_value": read_value,
            "expected_previous_value": previous_written,
            "read_matches_previous_write": (
                None
                if previous_written is None
                else (read_found and read_value == previous_written)
            ),
            "written_value": now_value,
            "write_success": write_success,
            "duration_ms": int((time.time() - started) * 1000),
        }

    def _log(self, status: str, details: Dict[str, Any], error: Optional[str] = None) -> None:
        entry: Dict[str, Any] = {
            "timestamp_ms": int(time.time() * 1000),
            "action": "ScanSummary",
            "status": status,
            "details": details,
            "error": error,
        }
        entry["text"] = _render_log(entry)
        request_logs.appendleft(entry)
        logger.info("[%s] run complete", status)


kms_demo = KMSDemoClient()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Startup is non-blocking: KMS availability and registry registration are handled in background cycles.
    task = asyncio.create_task(kms_demo.run_loop())
    yield
    kms_demo.stop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    kms_demo.odyn.close()


app = FastAPI(title="Nova KMS Demo Client (Enclaver KMS API)", lifespan=lifespan)


@app.get("/", include_in_schema=False)
def root() -> Dict[str, Any]:
    return {
        "service": "Nova KMS Demo Client (Enclaver KMS API)",
        "endpoints": ["/health", "/logs"],
        "interval_seconds": kms_demo.interval_seconds,
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "healthy"}


@app.get("/logs", response_class=PlainTextResponse)
def logs() -> str:
    if not request_logs:
        return "(no logs yet)"
    separator = "\n\n" + "=" * 120 + "\n\n"
    return separator.join(str(item.get("text", "")) for item in request_logs)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
