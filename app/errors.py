# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

from enum import StrEnum
from typing import Any

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class ErrorCode(StrEnum):
    MISSING_DEVICE_TOKEN = "missing_device_token"
    INVALID_DEVICE_TOKEN = "invalid_device_token"

    REQUEST_VALIDATION_FAILED = "request_validation_failed"
    NAME_TOO_SHORT = "name_too_short"
    NAME_TOO_LONG = "name_too_long"
    NAME_CONTAINS_CONTROL_CHARACTERS = "name_contains_control_characters"
    NAME_REQUIRES_ALPHANUMERIC_CHARACTER = "name_requires_alphanumeric_character"
    INVALID_LINK = "invalid_link"
    UNSUPPORTED_LINK_SCHEME = "unsupported_link_scheme"


def api_error(
    *,
    status_code: int,
    code: ErrorCode | str,
    message: str,
    headers: dict[str, str] | None = None,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "code": str(code),
            "message": message,
        },
        headers=headers,
    )


def _validation_error_code(
    error: dict[str, Any],
) -> str:
    error_type = str(error.get("type", ""))

    if error_type == "string_too_short":
        return ErrorCode.NAME_TOO_SHORT

    if error_type == "string_too_long":
        return ErrorCode.NAME_TOO_LONG

    return ErrorCode.REQUEST_VALIDATION_FAILED


async def request_validation_exception_handler(
    request: Request,
    exception: RequestValidationError,
) -> JSONResponse:
    errors = []

    for error in exception.errors():
        location = [
            str(part)
            for part in error.get("loc", ())
            if part
            not in {
                "body",
                "query",
                "path",
                "header",
                "cookie",
            }
        ]

        errors.append(
            {
                "code": str(_validation_error_code(error)),
                "field": ".".join(location) or None,
                "message": str(
                    error.get(
                        "msg",
                        "Invalid request data.",
                    )
                ),
            }
        )

    return JSONResponse(
        status_code=422,
        content={
            "detail": {
                "code": str(ErrorCode.REQUEST_VALIDATION_FAILED),
                "message": "Request validation failed.",
                "errors": errors,
            }
        },
    )
