# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import ipaddress
import os
from pathlib import Path


DATABASE_PATH = Path(
    os.getenv(
        "DATABASE_PATH",
        "/app/data/wichtel.db",
    )
)

MAX_ACTIVE_DEVICES_PER_USER = 10
MAX_OPEN_GROUPS_PER_OWNER = 25
MAX_GROUP_MEMBERS = 50
MAX_WISHLIST_ITEMS_PER_USER_GROUP = 30

RATE_LIMIT_ENABLED = (
    os.getenv(
        "RATE_LIMIT_ENABLED",
        "true",
    ).strip().lower()
    not in {
        "0",
        "false",
        "no",
        "off",
    }
)

TRUSTED_PROXY_NETWORKS = tuple(
    ipaddress.ip_network(
        value.strip(),
        strict=False,
    )
    for value in os.getenv(
        "TRUSTED_PROXY_NETWORKS",
        "",
    ).split(",")
    if value.strip()
)

RATE_LIMIT_RULES = {
    "register_ip": (5, 3600),
    "recover_ip": (20, 900),
    "recover_account": (8, 900),
    "join_ip": (30, 900),
    "join_user": (10, 900),
}
