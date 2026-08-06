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
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

    ACCOUNT_CODE_GENERATION_FAILED = "account_code_generation_failed"
    PROFILE_CONFLICT = "profile_conflict"
    ACCOUNT_CREATION_FAILED = "account_creation_failed"
    INVALID_RECOVERY_CREDENTIALS = "invalid_recovery_credentials"
    ACTIVE_DEVICE_LIMIT_REACHED = "active_device_limit_reached"
    PROFILE_RECOVERY_FAILED = "profile_recovery_failed"
    PROFILE_NOT_FOUND = "profile_not_found"
    PROFILE_ALREADY_DELETED = "profile_already_deleted"
    PROFILE_UPDATE_FAILED = "profile_update_failed"
    ACCOUNT_NOT_FOUND = "account_not_found"
    ACCOUNT_ALREADY_DELETED = "account_already_deleted"
    ACCOUNT_DELETE_CONFLICT = "account_delete_conflict"
    ACCOUNT_DELETE_FAILED = "account_delete_failed"

    GROUP_NAME_TOO_SHORT = "group_name_too_short"
    OPEN_GROUP_LIMIT_REACHED = "open_group_limit_reached"
    INVITE_CODE_GENERATION_FAILED = "invite_code_generation_failed"
    GROUP_NOT_FOUND_OR_NOT_MEMBER = "group_not_found_or_not_member"
    INVITE_CODE_NOT_FOUND = "invite_code_not_found"
    GROUP_ALREADY_DRAWN = "group_already_drawn"
    GROUP_NOT_FOUND = "group_not_found"
    GROUP_UPDATE_FORBIDDEN = "group_update_forbidden"
    GROUP_UPDATE_AFTER_DRAW_FORBIDDEN = "group_update_after_draw_forbidden"
    GROUP_UPDATE_FAILED = "group_update_failed"
    GROUP_OWNER_CANNOT_LEAVE = "group_owner_cannot_leave"
    GROUP_LEAVE_AFTER_DRAW_FORBIDDEN = "group_leave_after_draw_forbidden"
    GROUP_MEMBERSHIP_NOT_FOUND = "group_membership_not_found"
    GROUP_LEAVE_FAILED = "group_leave_failed"
    MEMBER_REMOVAL_FORBIDDEN = "member_removal_forbidden"
    MEMBER_REMOVAL_AFTER_DRAW_FORBIDDEN = "member_removal_after_draw_forbidden"
    GROUP_OWNER_REMOVAL_FORBIDDEN = "group_owner_removal_forbidden"
    GROUP_MEMBER_NOT_FOUND = "group_member_not_found"
    GROUP_MEMBER_REMOVAL_FAILED = "group_member_removal_failed"
    GROUP_DELETE_FORBIDDEN = "group_delete_forbidden"
    GROUP_DELETE_FAILED = "group_delete_failed"
    GROUP_MEMBER_LIMIT_REACHED = "group_member_limit_reached"

    WISHLIST_TITLE_REQUIRED = "wishlist_title_required"
    WISHLIST_CREATE_AFTER_DRAW_FORBIDDEN = "wishlist_create_after_draw_forbidden"
    WISHLIST_ITEM_LIMIT_REACHED = "wishlist_item_limit_reached"
    WISHLIST_ITEM_NOT_FOUND = "wishlist_item_not_found"
    WISHLIST_UPDATE_AFTER_DRAW_FORBIDDEN = "wishlist_update_after_draw_forbidden"
    WISHLIST_DELETE_AFTER_DRAW_FORBIDDEN = "wishlist_delete_after_draw_forbidden"
    WISHLIST_DELETE_AMBIGUOUS = "wishlist_delete_ambiguous"


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
