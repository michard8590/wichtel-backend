# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import secrets

__all__ = [
    "create_account_code",
    "create_invite_code",
    "create_recovery_key",
]


def create_account_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    first = "".join(secrets.choice(alphabet) for _ in range(4))

    second = "".join(secrets.choice(alphabet) for _ in range(4))

    return f"{first}-{second}"


def create_recovery_key() -> str:
    raw = secrets.token_hex(8).upper()

    return f"WICHTEL-{raw[0:4]}-{raw[4:8]}-" f"{raw[8:12]}-{raw[12:16]}"


def create_invite_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(6))
