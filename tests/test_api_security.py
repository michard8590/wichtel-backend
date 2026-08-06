import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "wichtel-test.db"

    monkeypatch.setenv(
        "DATABASE_PATH",
        str(database_path),
    )
    monkeypatch.setenv(
        "RATE_LIMIT_ENABLED",
        "false",
    )

    for module_name in [
        "app.main",
        "app.routers.groups",
        "app.routers.users",
        "app.auth",
        "app.rate_limit",
        "app.database",
        "app.config",
        "app",
    ]:
        sys.modules.pop(module_name, None)

    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        yield client, database_path


def register(
    client: TestClient,
    name: str,
) -> dict:
    response = client.post(
        "/api/users/register",
        json={
            "display_name": name,
        },
    )

    assert response.status_code == 201, response.text
    return response.json()


def auth_headers(user: dict) -> dict[str, str]:
    return {
        "Authorization":
            f"Bearer {user['device_token']}",
    }


def create_group(
    client: TestClient,
    user: dict,
    name: str = "Testgruppe",
) -> dict:
    response = client.post(
        "/api/groups",
        headers=auth_headers(user),
        json={
            "name": name,
            "budget_cents": 5000,
        },
    )

    assert response.status_code == 201, response.text
    return response.json()


def join_group(
    client: TestClient,
    user: dict,
    invite_code: str,
):
    return client.post(
        "/api/groups/join",
        headers=auth_headers(user),
        json={
            "invite_code": invite_code,
        },
    )


def test_database_is_temporary(api):
    _, database_path = api

    assert database_path.exists()
    assert str(database_path).startswith("/tmp/")
    assert (
        database_path
        != Path("/opt/wichtel/backend/data/wichtel.db")
    )


def test_request_without_token_is_rejected(api):
    client, _ = api

    response = client.get("/api/groups")

    assert response.status_code == 401


def test_invalid_token_is_rejected(api):
    client, _ = api

    response = client.get(
        "/api/groups",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_non_member_cannot_read_group(api):
    client, _ = api

    owner = register(client, "Owner")
    stranger = register(client, "Stranger")
    group = create_group(client, owner)

    response = client.get(
        f"/api/groups/{group['id']}",
        headers=auth_headers(stranger),
    )

    assert response.status_code == 404


def test_non_owner_cannot_update_group(api):
    client, _ = api

    owner = register(client, "Owner")
    member = register(client, "Member")
    group = create_group(client, owner)

    joined = join_group(
        client,
        member,
        group["invite_code"],
    )
    assert joined.status_code == 200

    response = client.patch(
        f"/api/groups/{group['id']}",
        headers=auth_headers(member),
        json={
            "name": "Manipuliert",
            "budget_cents": 1,
        },
    )

    assert response.status_code == 403


def test_non_owner_cannot_remove_member(api):
    client, _ = api

    owner = register(client, "Owner")
    member = register(client, "Member")
    second_member = register(client, "Member Two")
    group = create_group(client, owner)

    assert join_group(
        client,
        member,
        group["invite_code"],
    ).status_code == 200

    assert join_group(
        client,
        second_member,
        group["invite_code"],
    ).status_code == 200

    response = client.delete(
        (
            f"/api/groups/{group['id']}/members/"
            f"{second_member['user_id']}"
        ),
        headers=auth_headers(member),
    )

    assert response.status_code == 403


def test_user_cannot_edit_another_users_wish(api):
    client, _ = api

    owner = register(client, "Owner")
    member = register(client, "Member")
    group = create_group(client, owner)

    assert join_group(
        client,
        member,
        group["invite_code"],
    ).status_code == 200

    created = client.post(
        f"/api/groups/{group['id']}/wishlist",
        headers=auth_headers(owner),
        json={
            "title": "Mein Wunsch",
            "description": None,
            "link": None,
        },
    )

    assert created.status_code == 201
    item_id = created.json()["id"]

    response = client.put(
        (
            f"/api/groups/{group['id']}/wishlist/"
            f"{item_id}"
        ),
        headers=auth_headers(member),
        json={
            "title": "Manipuliert",
            "description": None,
            "link": None,
        },
    )

    assert response.status_code == 404


def test_only_owner_can_draw(api):
    client, _ = api

    owner = register(client, "Owner")
    member_one = register(client, "Member One")
    member_two = register(client, "Member Two")
    group = create_group(client, owner)

    assert join_group(
        client,
        member_one,
        group["invite_code"],
    ).status_code == 200

    assert join_group(
        client,
        member_two,
        group["invite_code"],
    ).status_code == 200

    response = client.post(
        f"/api/groups/{group['id']}/draw",
        headers=auth_headers(member_one),
    )

    assert response.status_code == 403


def test_draw_has_no_self_assignments(api):
    client, database_path = api

    users = [
        register(client, "Owner"),
        register(client, "Member One"),
        register(client, "Member Two"),
        register(client, "Member Three"),
    ]

    group = create_group(client, users[0])

    for user in users[1:]:
        assert join_group(
            client,
            user,
            group["invite_code"],
        ).status_code == 200

    response = client.post(
        f"/api/groups/{group['id']}/draw",
        headers=auth_headers(users[0]),
    )

    assert response.status_code == 200

    import sqlite3

    with sqlite3.connect(database_path) as connection:
        assignments = connection.execute(
            """
            SELECT giver_user_id, receiver_user_id
            FROM draw_assignments
            WHERE group_id = ?
            """,
            (group["id"],),
        ).fetchall()

    assert len(assignments) == len(users)
    assert all(
        giver != receiver
        for giver, receiver in assignments
    )

    assert len({
        receiver
        for _, receiver in assignments
    }) == len(users)


def test_member_only_sees_own_assignment(api):
    client, _ = api

    users = [
        register(client, "Owner"),
        register(client, "Member One"),
        register(client, "Member Two"),
    ]

    group = create_group(client, users[0])

    for user in users[1:]:
        assert join_group(
            client,
            user,
            group["invite_code"],
        ).status_code == 200

    assert client.post(
        f"/api/groups/{group['id']}/draw",
        headers=auth_headers(users[0]),
    ).status_code == 200

    assignments = []

    for user in users:
        response = client.get(
            f"/api/groups/{group['id']}/assignment",
            headers=auth_headers(user),
        )

        assert response.status_code == 200
        result = response.json()

        assert (
            result["receiver_user_id"]
            != user["user_id"]
        )

        assignments.append(
            result["receiver_user_id"]
        )

    assert len(set(assignments)) == len(users)


def test_recovery_creates_new_device_token(api):
    client, _ = api

    user = register(client, "Recovery User")

    response = client.post(
        "/api/users/recover",
        json={
            "account_code": user["account_code"],
            "recovery_key": user["recovery_key"],
        },
    )

    assert response.status_code == 201
    recovered = response.json()

    assert (
        recovered["device_token"]
        != user["device_token"]
    )

    groups_response = client.get(
        "/api/groups",
        headers=auth_headers(recovered),
    )

    assert groups_response.status_code == 200


def test_recovery_does_not_reveal_existing_account_codes(api):
    client, _ = api

    user = register(client, "Recovery Privacy")

    unknown_response = client.post(
        "/api/users/recover",
        json={
            "account_code": "AAAA-BBBB",
            "recovery_key":
                "WICHTEL-0000-0000-0000-0000",
        },
    )

    wrong_key_response = client.post(
        "/api/users/recover",
        json={
            "account_code": user["account_code"],
            "recovery_key":
                "WICHTEL-0000-0000-0000-0000",
        },
    )

    assert (
        unknown_response.status_code
        == wrong_key_response.status_code
    )

    assert (
        unknown_response.json()
        == wrong_key_response.json()
    )


@pytest.mark.parametrize(
    "link",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.org/file",
        "data:text/html,test",
        "//example.org/path",
    ],
)
def test_wishlist_rejects_unsafe_links(api, link):
    client, _ = api

    owner = register(client, "Link Owner")
    group = create_group(client, owner)

    response = client.post(
        f"/api/groups/{group['id']}/wishlist",
        headers=auth_headers(owner),
        json={
            "title": "Unsicherer Link",
            "description": None,
            "link": link,
        },
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "link",
    [
        "https://example.org",
        "http://example.org/path",
        "https://example.org/a?b=c",
    ],
)
def test_wishlist_accepts_http_links(api, link):
    client, _ = api

    owner = register(client, "Link Owner")
    group = create_group(client, owner)

    response = client.post(
        f"/api/groups/{group['id']}/wishlist",
        headers=auth_headers(owner),
        json={
            "title": "Sicherer Link",
            "description": None,
            "link": link,
        },
    )

    assert response.status_code == 201


def test_deleted_account_cannot_be_recovered(api):
    client, _ = api

    user = register(client, "Delete Recovery")

    deleted = client.delete(
        "/api/users/me",
        headers=auth_headers(user),
    )

    assert deleted.status_code == 204

    recovered = client.post(
        "/api/users/recover",
        json={
            "account_code": user["account_code"],
            "recovery_key": user["recovery_key"],
        },
    )

    assert recovered.status_code in {
        401,
        404,
    }


def test_drawn_group_cannot_be_updated(api):
    client, _ = api

    users = [
        register(client, "Owner"),
        register(client, "Member One"),
        register(client, "Member Two"),
    ]

    group = create_group(client, users[0])

    for user in users[1:]:
        assert join_group(
            client,
            user,
            group["invite_code"],
        ).status_code == 200

    assert client.post(
        f"/api/groups/{group['id']}/draw",
        headers=auth_headers(users[0]),
    ).status_code == 200

    response = client.patch(
        f"/api/groups/{group['id']}",
        headers=auth_headers(users[0]),
        json={
            "name": "Nachträglich geändert",
            "budget_cents": 100,
        },
    )

    assert response.status_code == 409


def test_drawn_group_wishlist_cannot_be_changed(api):
    client, _ = api

    users = [
        register(client, "Owner"),
        register(client, "Member One"),
        register(client, "Member Two"),
    ]

    group = create_group(client, users[0])

    for user in users[1:]:
        assert join_group(
            client,
            user,
            group["invite_code"],
        ).status_code == 200

    assert client.post(
        f"/api/groups/{group['id']}/draw",
        headers=auth_headers(users[0]),
    ).status_code == 200

    response = client.post(
        f"/api/groups/{group['id']}/wishlist",
        headers=auth_headers(users[0]),
        json={
            "title": "Zu spät",
            "description": None,
            "link": None,
        },
    )

    assert response.status_code == 409


def test_recovery_limits_active_devices(api):
    client, database_path = api

    user = register(client, "Device Limit")

    for _ in range(9):
        response = client.post(
            "/api/users/recover",
            json={
                "account_code": user["account_code"],
                "recovery_key": user["recovery_key"],
            },
        )
        assert response.status_code == 201

    response = client.post(
        "/api/users/recover",
        json={
            "account_code": user["account_code"],
            "recovery_key": user["recovery_key"],
        },
    )

    assert response.status_code == 409

    import sqlite3

    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM devices
            WHERE user_id = ?
              AND revoked_at IS NULL
            """,
            (user["user_id"],),
        ).fetchone()[0]

    assert count == 10


def test_user_cannot_create_more_than_25_open_groups(api):
    client, _ = api

    owner = register(client, "Group Limit")

    for index in range(25):
        response = client.post(
            "/api/groups",
            headers=auth_headers(owner),
            json={
                "name": f"Gruppe {index + 1}",
                "budget_cents": None,
            },
        )
        assert response.status_code == 201

    response = client.post(
        "/api/groups",
        headers=auth_headers(owner),
        json={
            "name": "Gruppe 26",
            "budget_cents": None,
        },
    )

    assert response.status_code == 409


def test_group_cannot_have_more_than_50_members(api):
    client, _ = api

    owner = register(client, "Member Limit Owner")
    group = create_group(client, owner)

    for index in range(49):
        member = register(
            client,
            f"Member {index + 1}",
        )

        response = join_group(
            client,
            member,
            group["invite_code"],
        )

        assert response.status_code == 200

    extra_member = register(
        client,
        "Member Too Many",
    )

    response = join_group(
        client,
        extra_member,
        group["invite_code"],
    )

    assert response.status_code == 409


def test_user_cannot_create_more_than_30_wishes(api):
    client, _ = api

    owner = register(client, "Wishlist Limit")
    group = create_group(client, owner)

    for index in range(30):
        response = client.post(
            f"/api/groups/{group['id']}/wishlist",
            headers=auth_headers(owner),
            json={
                "title": f"Wunsch {index + 1}",
                "description": None,
                "link": None,
            },
        )

        assert response.status_code == 201

    response = client.post(
        f"/api/groups/{group['id']}/wishlist",
        headers=auth_headers(owner),
        json={
            "title": "Wunsch 31",
            "description": None,
            "link": None,
        },
    )

    assert response.status_code == 409


def test_registration_rate_limit_returns_429(
    api,
):
    client, _ = api

    import sys

    rate_limit = sys.modules["app.rate_limit"]

    original_enabled = (
        rate_limit.RATE_LIMIT_ENABLED
    )
    original_rule = (
        rate_limit.RATE_LIMIT_RULES[
            "register_ip"
        ]
    )

    try:
        rate_limit.RATE_LIMIT_ENABLED = True
        rate_limit.RATE_LIMIT_RULES[
            "register_ip"
        ] = (2, 3600)

        with rate_limit._rate_limit_lock:
            rate_limit._rate_limit_buckets.clear()

        first = client.post(
            "/api/users/register",
            json={
                "display_name":
                    "Rate Limit One",
            },
        )
        second = client.post(
            "/api/users/register",
            json={
                "display_name":
                    "Rate Limit Two",
            },
        )
        blocked = client.post(
            "/api/users/register",
            json={
                "display_name":
                    "Rate Limit Three",
            },
        )

        assert first.status_code == 201
        assert second.status_code == 201
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers

    finally:
        rate_limit.RATE_LIMIT_ENABLED = (
            original_enabled
        )
        rate_limit.RATE_LIMIT_RULES[
            "register_ip"
        ] = original_rule

        with rate_limit._rate_limit_lock:
            rate_limit._rate_limit_buckets.clear()
