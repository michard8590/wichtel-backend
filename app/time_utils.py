# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

from datetime import datetime, timezone


__all__ = [
    "utc_now",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
