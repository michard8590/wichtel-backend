# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import ipaddress
import threading
import time
from collections import defaultdict, deque

from fastapi import Request, status

from app.errors import ErrorCode, api_error

from app.config import (
    RATE_LIMIT_ENABLED,
    RATE_LIMIT_RULES,
    TRUSTED_PROXY_NETWORKS,
)

__all__ = [
    "RATE_LIMIT_ENABLED",
    "RATE_LIMIT_RULES",
    "_rate_limit_buckets",
    "_rate_limit_lock",
    "check_rate_limit",
    "get_client_ip",
    "is_trusted_proxy",
]


_rate_limit_buckets = defaultdict(deque)
_rate_limit_lock = threading.Lock()


def is_trusted_proxy(
    host: str,
) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False

    return any(address in network for network in TRUSTED_PROXY_NETWORKS)


def get_client_ip(
    request: Request,
) -> str:
    peer_host = request.client.host if request.client is not None else ""

    if is_trusted_proxy(peer_host):
        forwarded_ip = request.headers.get("x-real-ip")

        if not forwarded_ip:
            forwarded_for = request.headers.get(
                "x-forwarded-for",
                "",
            )

            if forwarded_for:
                # For a single trusted NPM proxy
                # the rightmost entry represents the direct
                # peer of the proxy.
                forwarded_ip = forwarded_for.split(",")[-1].strip()

        if forwarded_ip:
            try:
                return str(ipaddress.ip_address(forwarded_ip))
            except ValueError:
                pass

    try:
        return str(ipaddress.ip_address(peer_host))
    except ValueError:
        return peer_host or "unknown"


def check_rate_limit(
    rule_name: str,
    identity: str,
) -> None:
    if not RATE_LIMIT_ENABLED:
        return

    limit, window_seconds = RATE_LIMIT_RULES[rule_name]

    now = time.monotonic()
    oldest_allowed = now - window_seconds
    bucket_key = (
        rule_name,
        identity,
    )

    with _rate_limit_lock:
        bucket = _rate_limit_buckets[bucket_key]

        while bucket and bucket[0] <= oldest_allowed:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = max(
                1,
                int(window_seconds - (now - bucket[0])) + 1,
            )

            raise api_error(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                code=ErrorCode.RATE_LIMIT_EXCEEDED,
                message="Too many requests. Please try again later.",
                headers={
                    "Retry-After": str(retry_after),
                },
            )

        bucket.append(now)

        # Periodically clean up fully
        # expired keys.
        if len(_rate_limit_buckets) > 10_000:
            empty_keys = []

            for key, values in _rate_limit_buckets.items():
                rule = RATE_LIMIT_RULES[key[0]]
                key_oldest_allowed = now - rule[1]

                while values and values[0] <= key_oldest_allowed:
                    values.popleft()

                if not values:
                    empty_keys.append(key)

            for key in empty_keys:
                _rate_limit_buckets.pop(
                    key,
                    None,
                )
