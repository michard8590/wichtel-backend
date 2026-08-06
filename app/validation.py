# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import unicodedata
from urllib.parse import urlsplit

from fastapi import HTTPException, status

__all__ = [
    "validate_display_name",
    "validate_optional_http_url",
]


def validate_display_name(
    value: str,
) -> str:
    display_name = value.strip()

    if len(display_name) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=("The name must contain at least two characters."),
        )

    if len(display_name) > 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=("The name must not exceed 50 characters."),
        )

    if any(
        unicodedata.category(character).startswith("C") for character in display_name
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=("The name contains unsupported control characters."),
        )

    if not any(character.isalnum() for character in display_name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=("The name must contain at least one letter or number."),
        )

    return display_name


def validate_optional_http_url(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    link = value.strip()

    if not link:
        return None

    try:
        parsed = urlsplit(link)
    except ValueError as exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The link is invalid.",
        ) from exception

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=("Links must start with http:// or https://."),
        )

    return link
