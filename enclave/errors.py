"""
Shared API error formatting utilities.

All HTTP errors should use a consistent response shape:
    {"code": "<machine_readable_code>", "message": "<human_readable_message>"}
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse

_STATUS_CODE_MAP: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


def default_error_code(status_code: int) -> str:
    return _STATUS_CODE_MAP.get(status_code, f"http_{status_code}")


def extract_message(detail: Any) -> str:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        message = detail.get("message")
        if isinstance(message, str) and message:
            return message

        reason = detail.get("reason")
        error = detail.get("error")
        if isinstance(error, str) and isinstance(reason, str):
            return f"{error}: {reason}"
        if isinstance(reason, str):
            return reason
        if isinstance(error, str):
            return error
    return str(detail)


def extract_code(status_code: int, detail: Any) -> str:
    if isinstance(detail, dict):
        code = detail.get("code")
        if isinstance(code, str) and code:
            return code
    return default_error_code(status_code)


def error_response(status_code: int, detail: Any) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "code": extract_code(status_code, detail),
            "message": extract_message(detail),
        },
    )
