"""Simplified Nova KMS demo client using enclaver's /v1/kms integration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Any, Deque, Dict, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

import config
from odyn import Odyn


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("nova-kms-demo-enclaver")

MAX_LOGS = 50
request_logs: Deque[Dict[str, Any]] = deque(maxlen=MAX_LOGS)


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


class KMSDemoClient:
    def __init__(self):
        self.odyn = Odyn()
        self.interval_seconds = int(config.TEST_CYCLE_INTERVAL_SECONDS)
        self.derive_path = config.FIXED_DERIVE_PATH
        self.data_key = config.KV_DATA_KEY

        self._expected_derive_key: Optional[str] = None
        self._last_written_value: Optional[str] = None
        self._stop_event = asyncio.Event()
        self._cycle_lock = asyncio.Lock()

    async def run_loop(self) -> None:
        while not self._stop_event.is_set():
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
                self._log(
                    status="Failed",
                    details={"duration_ms": int(time.time() * 1000) - started_ms},
                    error=str(exc),
                )
                logger.exception("KMS cycle failed")

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
    try:
        addr = await asyncio.to_thread(kms_demo.odyn.eth_address)
        logger.info("Connected to Odyn. TEE address=%s", addr)
    except Exception as exc:
        logger.warning("Could not query Odyn eth address at startup: %s", exc)

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
    uvicorn.run(app, host="0.0.0.0", port=8000)
