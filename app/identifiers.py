# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import secrets


__all__ = [
    "create_account_code",
]


def create_account_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    first = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )

    second = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )

    return f"{first}-{second}"
