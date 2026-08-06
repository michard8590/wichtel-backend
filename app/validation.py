# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import unicodedata
from urllib.parse import urlparse

from fastapi import status

from app.errors import ErrorCode, api_error


def validate_display_name(
    display_name: str,
) -> str:
    normalized_name = unicodedata.normalize(
        "NFC",
        display_name.strip(),
    )

    if len(normalized_name) < 2:
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.NAME_TOO_SHORT,
            message="The name must contain at least two characters.",
        )

    if len(normalized_name) > 50:
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.NAME_TOO_LONG,
            message="The name must not exceed 50 characters.",
        )

    if any(
        unicodedata.category(character).startswith("C") for character in normalized_name
    ):
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.NAME_CONTAINS_CONTROL_CHARACTERS,
            message="The name contains unsupported control characters.",
        )

    if not any(character.isalnum() for character in normalized_name):
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.NAME_REQUIRES_ALPHANUMERIC_CHARACTER,
            message="The name must contain at least one letter or number.",
        )

    return normalized_name


def validate_optional_http_url(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    normalized_value = value.strip()

    if not normalized_value:
        return None

    try:
        parsed = urlparse(normalized_value)
    except ValueError as exception:
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.INVALID_LINK,
            message="The link is invalid.",
        ) from exception

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.UNSUPPORTED_LINK_SCHEME,
            message="Links must start with http:// or https://.",
        )

    if not parsed.netloc:
        raise api_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.INVALID_LINK,
            message="The link is invalid.",
        )

    return normalized_value
