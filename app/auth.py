# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

from fastapi import HTTPException, status

from app.database import open_database
from app.security import hash_secret

__all__ = [
    "get_authenticated_user_id",
]


def get_authenticated_user_id(
    authorization: str | None,
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Device token is missing."
        )

    token = authorization.removeprefix("Bearer ").strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Device token is missing."
        )

    with open_database() as connection:
        device = connection.execute(
            """
            SELECT user_id
            FROM devices
            WHERE token_hash = ?
              AND revoked_at IS NULL
            """,
            (hash_secret(token),),
        ).fetchone()

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Device token is invalid."
        )

    return device[0]
