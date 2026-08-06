# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request, status

from app.config import (
    MAX_ACTIVE_DEVICES_PER_USER,
    MAX_GROUP_MEMBERS,
    MAX_OPEN_GROUPS_PER_OWNER,
    MAX_WISHLIST_ITEMS_PER_USER_GROUP,
)
from app.database import (
    delete_groups_without_active_members,
    initialise_database,
    open_database,
)
from app.identifiers import (
    create_account_code,
    create_invite_code,
    create_recovery_key,
)
from app.security import hash_secret
from app.time_utils import utc_now
from app.rate_limit import (
    check_rate_limit,
    get_client_ip,
)
from app.validation import (
    validate_display_name,
    validate_optional_http_url,
)
from app.schemas import (
    CreateGroupRequest,
    CreateWishlistItemRequest,
    DrawAssignmentResponse,
    DrawGroupResponse,
    GroupDetailResponse,
    GroupMemberResponse,
    GroupResponse,
    JoinGroupRequest,
    ProfileResponse,
    RecoverRequest,
    RecoverResponse,
    RegisterRequest,
    RegisterResponse,
    UpdateGroupRequest,
    UpdateProfileRequest,
    UpdateWishlistItemRequest,
    WishlistItemResponse,
)


def get_authenticated_user_id(
    authorization: str | None,
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geräte-Token fehlt.",
        )

    token = authorization.removeprefix("Bearer ").strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geräte-Token fehlt.",
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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geräte-Token ist ungültig.",
        )

    return device[0]


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialise_database()
    yield


app = FastAPI(
    title="Wichtel API",
    version="1.5.0",
    lifespan=lifespan,
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "wichtel-backend",
    }


@app.post(
    "/api/users/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    request: RegisterRequest,
    http_request: Request,
) -> RegisterResponse:
    check_rate_limit(
        "register_ip",
        get_client_ip(http_request),
    )

    display_name = validate_display_name(
        request.display_name
    )

    user_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    device_token = secrets.token_urlsafe(32)
    recovery_key = create_recovery_key()
    created_at = utc_now()

    with open_database() as connection:
        for _ in range(100):
            account_code = create_account_code()

            already_exists = connection.execute(
                """
                SELECT 1
                FROM users
                WHERE account_code = ? COLLATE NOCASE
                """,
                (account_code,),
            ).fetchone()

            if already_exists is None:
                break
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Es konnte kein Account-Code erzeugt werden.",
            )

    try:
        with open_database() as connection:
            connection.execute("PRAGMA foreign_keys = ON")

            connection.execute(
                """
                INSERT INTO users (
                    id,
                    display_name,
                    account_code,
                    recovery_key_hash,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    display_name,
                    account_code,
                    hash_secret(recovery_key),
                    created_at,
                ),
            )

            connection.execute(
                """
                INSERT INTO devices (
                    id,
                    user_id,
                    token_hash,
                    created_at,
                    last_seen_at,
                    revoked_at
                )
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    device_id,
                    user_id,
                    hash_secret(device_token),
                    created_at,
                    created_at,
                ),
            )

            connection.commit()

    except sqlite3.IntegrityError as exception:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Das Profil konnte wegen eines "
                "eindeutigen Datenkonflikts nicht erstellt werden."
            ),
        ) from exception

    except sqlite3.Error as exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Das Benutzerkonto konnte nicht erstellt werden.",
        ) from exception

    return RegisterResponse(
        user_id=user_id,
        display_name=display_name,
        account_code=account_code,
        device_token=device_token,
        recovery_key=recovery_key,
    )

@app.post(
    "/api/users/recover",
    response_model=RecoverResponse,
    status_code=status.HTTP_201_CREATED,
)
def recover_user(
    request: RecoverRequest,
    http_request: Request,
) -> RecoverResponse:
    account_code = (
        request.account_code
        .strip()
        .upper()
    )
    recovery_key = (
        request.recovery_key
        .strip()
        .upper()
    )

    check_rate_limit(
        "recover_ip",
        get_client_ip(http_request),
    )
    check_rate_limit(
        "recover_account",
        account_code,
    )

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        user = connection.execute(
            """
            SELECT
                id,
                display_name,
                account_code,
                recovery_key_hash,
                COALESCE(is_deleted, 0)
            FROM users
            WHERE account_code = ? COLLATE NOCASE
            """,
            (account_code,),
        ).fetchone()

        supplied_recovery_hash = hash_secret(
            recovery_key
        )

        if user is None:
            secrets.compare_digest(
                hash_secret(
                    "INVALID-RECOVERY-KEY"
                ),
                supplied_recovery_hash,
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "Account-Code oder "
                    "Wiederherstellungsschlüssel ist ungültig."
                ),
            )

        (
            user_id,
            stored_display_name,
            stored_account_code,
            recovery_key_hash,
            is_deleted_value,
        ) = user

        recovery_matches = secrets.compare_digest(
            recovery_key_hash,
            supplied_recovery_hash,
        )

        if (
            not recovery_matches
            or bool(is_deleted_value)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "Account-Code oder "
                    "Wiederherstellungsschlüssel ist ungültig."
                ),
            )

        active_device_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM devices
            WHERE user_id = ?
              AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchone()[0]

        if (
            active_device_count
            >= MAX_ACTIVE_DEVICES_PER_USER
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Für dieses Profil sind bereits zu viele "
                    "aktive Geräte registriert."
                ),
            )

        device_id = str(uuid.uuid4())
        device_token = secrets.token_urlsafe(32)
        created_at = utc_now()

        try:
            connection.execute(
                """
                INSERT INTO devices (
                    id,
                    user_id,
                    token_hash,
                    created_at,
                    last_seen_at,
                    revoked_at
                )
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    device_id,
                    user_id,
                    hash_secret(device_token),
                    created_at,
                    created_at,
                ),
            )

            connection.commit()

        except sqlite3.Error as exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Das Profil konnte nicht wiederhergestellt werden.",
            ) from exception

    return RecoverResponse(
        user_id=user_id,
        display_name=stored_display_name,
        account_code=stored_account_code,
        device_token=device_token,
    )


@app.patch(
    "/api/users/me",
    response_model=ProfileResponse,
)
def update_own_profile(
    request: UpdateProfileRequest,
    authorization: str | None = Header(default=None),
) -> ProfileResponse:
    user_id = get_authenticated_user_id(
        authorization
    )

    display_name = validate_display_name(
        request.display_name
    )

    with open_database() as connection:
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        try:
            user = connection.execute(
                """
                SELECT
                    account_code,
                    COALESCE(is_deleted, 0)
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

            if user is None:
                raise HTTPException(
                    status_code=
                        status.HTTP_404_NOT_FOUND,
                    detail=(
                        "Das Profil wurde nicht gefunden."
                    ),
                )

            (
                account_code,
                is_deleted_value,
            ) = user

            if bool(is_deleted_value):
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail=(
                        "Das Profil wurde bereits gelöscht."
                    ),
                )

            connection.execute(
                """
                UPDATE users
                SET display_name = ?
                WHERE id = ?
                """,
                (
                    display_name,
                    user_id,
                ),
            )

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Das Profil konnte nicht "
                    "aktualisiert werden."
                ),
            ) from exception

    return ProfileResponse(
        user_id=user_id,
        display_name=display_name,
        account_code=account_code,
    )


@app.get(
    "/api/groups",
    response_model=list[GroupResponse],
)
def list_groups(
    authorization: str | None = Header(default=None),
) -> list[GroupResponse]:
    user_id = get_authenticated_user_id(authorization)

    with open_database() as connection:
        groups = connection.execute(
            """
            SELECT
                g.id,
                g.name,
                g.invite_code,
                g.status,
                g.budget_cents,
                g.budget_currency,
                g.created_at,
                COUNT(gm_all.user_id) AS member_count
            FROM groups g
            INNER JOIN group_members gm_user
                ON gm_user.group_id = g.id
               AND gm_user.user_id = ?
            LEFT JOIN group_members gm_all
                ON gm_all.group_id = g.id
            GROUP BY
                g.id,
                g.name,
                g.invite_code,
                g.status,
                g.budget_cents,
                g.budget_currency,
                g.created_at
            ORDER BY g.created_at DESC
            """,
            (user_id,),
        ).fetchall()

    return [
        GroupResponse(
            id=group_id,
            name=group_name,
            invite_code=invite_code,
            member_count=member_count,
            status=group_status,
            budget_cents=budget_cents,
            budget_currency=budget_currency,
            created_at=created_at,
        )
        for (
            group_id,
            group_name,
            invite_code,
            group_status,
            budget_cents,
            budget_currency,
            created_at,
            member_count,
        ) in groups
    ]


@app.delete(
    "/api/users/me",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_own_account(
    authorization: str | None = Header(default=None),
) -> None:
    user_id = get_authenticated_user_id(
        authorization
    )

    deleted_at = utc_now()

    anonymous_name = (
        "Gelöschter Benutzer "
        + secrets.token_hex(2).upper()
    )

    # Technisch eindeutiger interner Wert.
    # Dieser wird nicht mehr an die App ausgeliefert.
    anonymous_account_code = (
        "DEL-"
        + secrets.token_hex(8).upper()
    )

    invalid_recovery_hash = hash_secret(
        "DELETED-"
        + secrets.token_urlsafe(48)
    )

    with open_database() as connection:
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        try:
            user = connection.execute(
                """
                SELECT is_deleted
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

            if user is None:
                raise HTTPException(
                    status_code=
                        status.HTTP_404_NOT_FOUND,
                    detail=(
                        "Das Konto wurde nicht gefunden."
                    ),
                )

            if bool(user[0]):
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail=(
                        "Das Konto wurde bereits gelöscht."
                    ),
                )

            # Offene Gruppen des Benutzers löschen.
            # Zugehörige Mitglieder, Wünsche und Zuteilungen
            # werden durch ON DELETE CASCADE entfernt.
            connection.execute(
                """
                DELETE FROM groups
                WHERE owner_user_id = ?
                  AND status = 'OPEN'
                """,
                (user_id,),
            )

            # Eigene Wünsche in anderen offenen Gruppen löschen.
            connection.execute(
                """
                DELETE FROM wishlist_items
                WHERE user_id = ?
                  AND group_id IN (
                      SELECT id
                      FROM groups
                      WHERE status = 'OPEN'
                  )
                """,
                (user_id,),
            )

            # Aus anderen offenen Gruppen austreten.
            connection.execute(
                """
                DELETE FROM group_members
                WHERE user_id = ?
                  AND group_id IN (
                      SELECT id
                      FROM groups
                      WHERE status = 'OPEN'
                  )
                """,
                (user_id,),
            )

            # Alle Geräte und damit alle Sitzungen ungültig machen.
            connection.execute(
                """
                DELETE FROM devices
                WHERE user_id = ?
                """,
                (user_id,),
            )

            # In ausgelosten Gruppen bleibt der Benutzer als
            # anonymisierter Platzhalter bestehen.
            connection.execute(
                """
                UPDATE users
                SET
                    display_name = ?,
                    account_code = ?,
                    recovery_key_hash = ?,
                    is_deleted = 1,
                    deleted_at = ?
                WHERE id = ?
                """,
                (
                    anonymous_name,
                    anonymous_account_code,
                    invalid_recovery_hash,
                    deleted_at,
                    user_id,
                ),
            )

            delete_groups_without_active_members(
                connection
            )

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.IntegrityError as exception:
            connection.rollback()

            raise HTTPException(
                status_code=
                    status.HTTP_409_CONFLICT,
                detail=(
                    "Das Konto konnte wegen bestehender "
                    "Datenbeziehungen nicht gelöscht werden."
                ),
            ) from exception

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Das Konto konnte nicht gelöscht werden."
                ),
            ) from exception


@app.post(
    "/api/groups",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_group(
    request: CreateGroupRequest,
    authorization: str | None = Header(default=None),
) -> GroupResponse:
    owner_user_id = get_authenticated_user_id(authorization)
    group_name = request.name.strip()

    if len(group_name) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Der Gruppenname muss mindestens zwei Zeichen enthalten.",
        )

    group_id = str(uuid.uuid4())
    created_at = utc_now()
    budget_cents = request.budget_cents
    budget_currency = "CHF"

    with open_database() as connection:
        open_group_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM groups
            WHERE owner_user_id = ?
              AND status = 'OPEN'
            """,
            (owner_user_id,),
        ).fetchone()[0]

        if (
            open_group_count
            >= MAX_OPEN_GROUPS_PER_OWNER
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Du hast bereits die maximal erlaubte "
                    "Anzahl offener Gruppen erstellt."
                ),
            )
        connection.execute("PRAGMA foreign_keys = ON")

        for _ in range(20):
            invite_code = create_invite_code()

            try:
                connection.execute(
                    """
                    INSERT INTO groups (
                        id,
                        name,
                        invite_code,
                        owner_user_id,
                        status,
                        budget_cents,
                        budget_currency,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?)
                    """,
                    (
                        group_id,
                        group_name,
                        invite_code,
                        owner_user_id,
                        budget_cents,
                        budget_currency,
                        created_at,
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO group_members (
                        group_id,
                        user_id,
                        joined_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        group_id,
                        owner_user_id,
                        created_at,
                    ),
                )

                connection.commit()
                break

            except sqlite3.IntegrityError:
                connection.rollback()
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Es konnte kein Einladungscode erzeugt werden.",
            )

    return GroupResponse(
        id=group_id,
        name=group_name,
        invite_code=invite_code,
        member_count=1,
        status="OPEN",
        budget_cents=budget_cents,
        budget_currency=budget_currency,
        created_at=created_at,
    )


@app.patch(
    "/api/groups/{group_id}",
    response_model=GroupResponse,
)
def update_group(
    group_id: str,
    request: UpdateGroupRequest,
    authorization: str | None = Header(default=None),
) -> GroupResponse:
    user_id = get_authenticated_user_id(authorization)
    group_name = request.name.strip()

    if len(group_name) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "Der Gruppenname muss mindestens "
                "zwei Zeichen enthalten."
            ),
        )

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        try:
            group = connection.execute(
                """
                SELECT
                    owner_user_id,
                    invite_code,
                    status,
                    budget_currency,
                    created_at
                FROM groups
                WHERE id = ?
                """,
                (group_id,),
            ).fetchone()

            if group is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Die Gruppe wurde nicht gefunden.",
                )

            (
                owner_user_id,
                invite_code,
                group_status,
                budget_currency,
                created_at,
            ) = group

            if owner_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Nur der Ersteller darf "
                        "diese Gruppe bearbeiten."
                    ),
                )

            if group_status != "OPEN":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Nach der Auslosung kann die "
                        "Gruppe nicht mehr bearbeitet werden."
                    ),
                )

            connection.execute(
                """
                UPDATE groups
                SET
                    name = ?,
                    budget_cents = ?
                WHERE id = ?
                  AND owner_user_id = ?
                """,
                (
                    group_name,
                    request.budget_cents,
                    group_id,
                    user_id,
                ),
            )

            member_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM group_members
                WHERE group_id = ?
                """,
                (group_id,),
            ).fetchone()[0]

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Die Gruppe konnte nicht "
                    "aktualisiert werden."
                ),
            ) from exception

    return GroupResponse(
        id=group_id,
        name=group_name,
        invite_code=invite_code,
        member_count=member_count,
        status=group_status,
        budget_cents=request.budget_cents,
        budget_currency=budget_currency,
        created_at=created_at,
    )


@app.delete(
    "/api/groups/{group_id}/membership",
    status_code=status.HTTP_204_NO_CONTENT,
)
def leave_group(
    group_id: str,
    authorization: str | None = Header(default=None),
) -> None:
    user_id = get_authenticated_user_id(authorization)

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        try:
            group = connection.execute(
                """
                SELECT
                    owner_user_id,
                    status
                FROM groups
                WHERE id = ?
                """,
                (group_id,),
            ).fetchone()

            if group is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Die Gruppe wurde nicht gefunden.",
                )

            owner_user_id, group_status = group

            if owner_user_id == user_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Der Ersteller kann die Gruppe nicht verlassen. "
                        "Er kann sie nur löschen."
                    ),
                )

            if group_status != "OPEN":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Nach der Auslosung kann die Gruppe "
                        "nicht mehr verlassen werden."
                    ),
                )

            membership = connection.execute(
                """
                SELECT 1
                FROM group_members
                WHERE group_id = ?
                  AND user_id = ?
                """,
                (
                    group_id,
                    user_id,
                ),
            ).fetchone()

            if membership is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        "Du bist kein Mitglied dieser Gruppe."
                    ),
                )

            connection.execute(
                """
                DELETE FROM wishlist_items
                WHERE group_id = ?
                  AND user_id = ?
                """,
                (
                    group_id,
                    user_id,
                ),
            )

            connection.execute(
                """
                DELETE FROM group_members
                WHERE group_id = ?
                  AND user_id = ?
                """,
                (
                    group_id,
                    user_id,
                ),
            )

            delete_groups_without_active_members(
                connection
            )

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Die Gruppe konnte nicht verlassen werden."
                ),
            ) from exception


@app.delete(
    "/api/groups/{group_id}/members/{member_user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_group_member(
    group_id: str,
    member_user_id: str,
    authorization: str | None = Header(default=None),
) -> None:
    user_id = get_authenticated_user_id(authorization)

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        try:
            group = connection.execute(
                """
                SELECT
                    owner_user_id,
                    status
                FROM groups
                WHERE id = ?
                """,
                (group_id,),
            ).fetchone()

            if group is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Die Gruppe wurde nicht gefunden.",
                )

            owner_user_id, group_status = group

            if owner_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Nur der Ersteller darf Mitglieder entfernen."
                    ),
                )

            if group_status != "OPEN":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Nach der Auslosung können keine Mitglieder "
                        "mehr entfernt werden."
                    ),
                )

            if member_user_id == owner_user_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Der Ersteller kann nicht aus der eigenen "
                        "Gruppe entfernt werden."
                    ),
                )

            membership = connection.execute(
                """
                SELECT 1
                FROM group_members
                WHERE group_id = ?
                  AND user_id = ?
                """,
                (
                    group_id,
                    member_user_id,
                ),
            ).fetchone()

            if membership is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        "Das Mitglied wurde in dieser Gruppe "
                        "nicht gefunden."
                    ),
                )

            connection.execute(
                """
                DELETE FROM wishlist_items
                WHERE group_id = ?
                  AND user_id = ?
                """,
                (
                    group_id,
                    member_user_id,
                ),
            )

            connection.execute(
                """
                DELETE FROM group_members
                WHERE group_id = ?
                  AND user_id = ?
                """,
                (
                    group_id,
                    member_user_id,
                ),
            )

            delete_groups_without_active_members(
                connection
            )

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Das Mitglied konnte nicht entfernt werden."
                ),
            ) from exception


@app.delete(
    "/api/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_group(
    group_id: str,
    authorization: str | None = Header(default=None),
) -> None:
    user_id = get_authenticated_user_id(
        authorization
    )

    with open_database() as connection:
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        try:
            group = connection.execute(
                """
                SELECT
                    g.owner_user_id,
                    COALESCE(
                        owner.is_deleted,
                        0
                    )
                FROM groups g
                INNER JOIN users owner
                    ON owner.id =
                        g.owner_user_id
                WHERE g.id = ?
                """,
                (group_id,),
            ).fetchone()

            if group is None:
                raise HTTPException(
                    status_code=
                        status.HTTP_404_NOT_FOUND,
                    detail=(
                        "Die Gruppe wurde nicht gefunden."
                    ),
                )

            (
                owner_user_id,
                owner_deleted_value,
            ) = group

            owner_deleted = bool(
                owner_deleted_value
            )

            membership = connection.execute(
                """
                SELECT 1
                FROM group_members gm
                INNER JOIN users u
                    ON u.id = gm.user_id
                WHERE gm.group_id = ?
                  AND gm.user_id = ?
                  AND COALESCE(
                      u.is_deleted,
                      0
                  ) = 0
                """,
                (
                    group_id,
                    user_id,
                ),
            ).fetchone()

            user_may_delete = (
                owner_user_id == user_id
                or (
                    owner_deleted
                    and membership is not None
                )
            )

            if not user_may_delete:
                raise HTTPException(
                    status_code=
                        status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Du darfst diese Gruppe "
                        "nicht löschen."
                    ),
                )

            connection.execute(
                """
                DELETE FROM groups
                WHERE id = ?
                """,
                (group_id,),
            )

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Die Gruppe konnte nicht "
                    "gelöscht werden."
                ),
            ) from exception

@app.get(
    "/api/groups/{group_id}",
    response_model=GroupDetailResponse,
)
def get_group_detail(
    group_id: str,
    authorization: str | None = Header(default=None),
) -> GroupDetailResponse:
    user_id = get_authenticated_user_id(
        authorization
    )

    with open_database() as connection:
        group = connection.execute(
            """
            SELECT
                g.id,
                g.name,
                g.invite_code,
                g.status,
                g.owner_user_id,
                owner.display_name,
                COALESCE(owner.is_deleted, 0),
                g.budget_cents,
                g.budget_currency,
                g.created_at
            FROM groups g
            INNER JOIN users owner
                ON owner.id = g.owner_user_id
            INNER JOIN group_members gm
                ON gm.group_id = g.id
               AND gm.user_id = ?
            WHERE g.id = ?
            """,
            (
                user_id,
                group_id,
            ),
        ).fetchone()

        if group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "Gruppe wurde nicht gefunden "
                    "oder du bist kein Mitglied."
                ),
            )

        (
            stored_group_id,
            group_name,
            invite_code,
            group_status,
            owner_user_id,
            owner_display_name,
            owner_deleted_value,
            budget_cents,
            budget_currency,
            created_at,
        ) = group

        owner_deleted = bool(
            owner_deleted_value
        )

        member_rows = connection.execute(
            """
            SELECT
                u.id,
                u.display_name,
                CASE
                    WHEN COALESCE(
                        u.is_deleted,
                        0
                    ) = 1
                    THEN ''
                    ELSE u.account_code
                END
            FROM group_members gm
            INNER JOIN users u
                ON u.id = gm.user_id
            WHERE gm.group_id = ?
            ORDER BY
                CASE
                    WHEN u.id = ?
                    THEN 0
                    ELSE 1
                END,
                u.display_name COLLATE NOCASE
            """,
            (
                stored_group_id,
                owner_user_id,
            ),
        ).fetchall()

    members = [
        GroupMemberResponse(
            user_id=member_user_id,
            display_name=display_name,
            account_code=account_code or "",
            is_owner=(
                member_user_id
                == owner_user_id
            ),
        )
        for (
            member_user_id,
            display_name,
            account_code,
        ) in member_rows
    ]

    is_owner = (
        user_id == owner_user_id
        and not owner_deleted
    )

    can_delete_group = (
        is_owner
        or owner_deleted
    )

    return GroupDetailResponse(
        id=stored_group_id,
        name=group_name,
        invite_code=invite_code,
        status=group_status,
        member_count=len(members),
        is_owner=is_owner,
        owner_display_name=owner_display_name,
        owner_deleted=owner_deleted,
        can_delete_group=can_delete_group,
        budget_cents=budget_cents,
        budget_currency=budget_currency,
        created_at=created_at,
        members=members,
    )

@app.post(
    "/api/groups/{group_id}/wishlist",
    response_model=WishlistItemResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_wishlist_item(
    group_id: str,
    request: CreateWishlistItemRequest,
    authorization: str | None = Header(default=None),
) -> WishlistItemResponse:
    user_id = get_authenticated_user_id(authorization)

    title = request.title.strip()
    description = (
        request.description.strip()
        if request.description and request.description.strip()
        else None
    )
    link = validate_optional_http_url(
        request.link
    )

    if not title:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Der Wunsch benötigt einen Titel.",
        )

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        membership = connection.execute(
            """
            SELECT g.status
            FROM group_members gm
            INNER JOIN groups g
                ON g.id = gm.group_id
            WHERE gm.group_id = ?
              AND gm.user_id = ?
            """,
            (
                group_id,
                user_id,
            ),
        ).fetchone()

        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "Gruppe wurde nicht gefunden "
                    "oder du bist kein Mitglied."
                ),
            )

        if membership[0] != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Nach der Auslosung können Wünsche "
                    "nicht mehr hinzugefügt werden."
                ),
            )

        wishlist_item_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM wishlist_items
            WHERE group_id = ?
              AND user_id = ?
            """,
            (
                group_id,
                user_id,
            ),
        ).fetchone()[0]

        if (
            wishlist_item_count
            >= MAX_WISHLIST_ITEMS_PER_USER_GROUP
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Für diese Gruppe ist die maximal erlaubte "
                    "Anzahl Wünsche erreicht."
                ),
            )

        item_id = str(uuid.uuid4())
        timestamp = utc_now()

        connection.execute(
            """
            INSERT INTO wishlist_items (
                id,
                group_id,
                user_id,
                title,
                description,
                link,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                group_id,
                user_id,
                title,
                description,
                link,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

    return WishlistItemResponse(
        id=item_id,
        title=title,
        description=description,
        link=link,
    )


@app.put(
    "/api/groups/{group_id}/wishlist/{item_id}",
    response_model=WishlistItemResponse,
)
def update_wishlist_item(
    group_id: str,
    item_id: str,
    request: UpdateWishlistItemRequest,
    authorization: str | None = Header(default=None),
) -> WishlistItemResponse:
    user_id = get_authenticated_user_id(authorization)

    title = request.title.strip()
    description = (
        request.description.strip()
        if request.description and request.description.strip()
        else None
    )
    link = validate_optional_http_url(
        request.link
    )

    if not title:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Der Wunsch benötigt einen Titel.",
        )

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        item = connection.execute(
            """
            SELECT
                wi.id,
                g.status
            FROM wishlist_items wi
            INNER JOIN groups g
                ON g.id = wi.group_id
            WHERE wi.id = ?
              AND wi.group_id = ?
              AND wi.user_id = ?
            """,
            (
                item_id,
                group_id,
                user_id,
            ),
        ).fetchone()

        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Der Wunsch wurde nicht gefunden.",
            )

        if item[1] != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Nach der Auslosung können Wünsche "
                    "nicht mehr bearbeitet werden."
                ),
            )

        connection.execute(
            """
            UPDATE wishlist_items
            SET
                title = ?,
                description = ?,
                link = ?,
                updated_at = ?
            WHERE id = ?
              AND group_id = ?
              AND user_id = ?
            """,
            (
                title,
                description,
                link,
                utc_now(),
                item_id,
                group_id,
                user_id,
            ),
        )

        connection.commit()

    return WishlistItemResponse(
        id=item_id,
        title=title,
        description=description,
        link=link,
    )


@app.delete(
    "/api/groups/{group_id}/wishlist/{item_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_wishlist_item(
    group_id: str,
    item_id: str,
    authorization: str | None = Header(default=None),
) -> None:
    user_id = get_authenticated_user_id(authorization)

    with open_database() as connection:
        item = connection.execute(
            """
            SELECT
                wi.id,
                g.status
            FROM wishlist_items wi
            INNER JOIN groups g
                ON g.id = wi.group_id
            WHERE wi.id = ?
              AND wi.group_id = ?
              AND wi.user_id = ?
            """,
            (
                item_id,
                group_id,
                user_id,
            ),
        ).fetchone()

        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Der Wunsch wurde nicht gefunden.",
            )

        if item[1] != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Nach der Auslosung können Wünsche "
                    "nicht mehr gelöscht werden."
                ),
            )

        cursor = connection.execute(
            """
            DELETE FROM wishlist_items
            WHERE id = ?
              AND group_id = ?
              AND user_id = ?
            """,
            (
                item_id,
                group_id,
                user_id,
            ),
        )

        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Der Wunsch konnte nicht "
                    "eindeutig gelöscht werden."
                ),
            )

        connection.commit()


@app.get(
    "/api/groups/{group_id}/assignment",
    response_model=DrawAssignmentResponse,
)
def get_own_draw_assignment(
    group_id: str,
    authorization: str | None = Header(default=None),
) -> DrawAssignmentResponse:
    user_id = get_authenticated_user_id(authorization)

    with open_database() as connection:
        assignment = connection.execute(
            """
            SELECT
                g.status,
                da.receiver_user_id,
                receiver.display_name,
                CASE
                    WHEN COALESCE(receiver.is_deleted, 0) = 1
                    THEN ''
                    ELSE receiver.account_code
                END AS receiver_account_code
            FROM groups g
            INNER JOIN group_members gm
                ON gm.group_id = g.id
               AND gm.user_id = ?
            LEFT JOIN draw_assignments da
                ON da.group_id = g.id
               AND da.giver_user_id = ?
            LEFT JOIN users receiver
                ON receiver.id = da.receiver_user_id
            WHERE g.id = ?
            """,
            (
                user_id,
                user_id,
                group_id,
            ),
        ).fetchone()

        if assignment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "Die Gruppe wurde nicht gefunden "
                    "oder du bist kein Mitglied."
                ),
            )

        (
            group_status,
            receiver_user_id,
            receiver_display_name,
            receiver_account_code,
        ) = assignment

        if group_status != "DRAWN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Die Gruppe wurde noch nicht ausgelost.",
            )

        if receiver_user_id is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Für dich wurde keine Zuteilung gefunden.",
            )

        wishlist_rows = connection.execute(
            """
            SELECT
                id,
                title,
                description,
                link
            FROM wishlist_items
            WHERE group_id = ?
              AND user_id = ?
            ORDER BY created_at ASC
            """,
            (
                group_id,
                receiver_user_id,
            ),
        ).fetchall()

    wishlist = [
        WishlistItemResponse(
            id=item_id,
            title=title,
            description=description,
            link=link,
        )
        for item_id, title, description, link
        in wishlist_rows
    ]

    return DrawAssignmentResponse(
        group_id=group_id,
        receiver_user_id=receiver_user_id,
        receiver_display_name=receiver_display_name,
        receiver_account_code=receiver_account_code,
        wishlist=wishlist,
    )


@app.post(
    "/api/groups/{group_id}/draw",
    response_model=DrawGroupResponse,
)
def draw_group(
    group_id: str,
    authorization: str | None = Header(default=None),
) -> DrawGroupResponse:
    user_id = get_authenticated_user_id(authorization)
    random_source = secrets.SystemRandom()

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        try:
            group = connection.execute(
                """
                SELECT
                    owner_user_id,
                    status
                FROM groups
                WHERE id = ?
                """,
                (group_id,),
            ).fetchone()

            if group is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Die Gruppe wurde nicht gefunden.",
                )

            owner_user_id, group_status = group

            if owner_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Nur der Ersteller der Gruppe "
                        "darf die Auslosung starten."
                    ),
                )

            if group_status != "OPEN":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Diese Gruppe wurde bereits ausgelost.",
                )

            member_rows = connection.execute(
                """
                SELECT user_id
                FROM group_members
                WHERE group_id = ?
                ORDER BY joined_at, user_id
                """,
                (group_id,),
            ).fetchall()

            member_ids = [
                row[0]
                for row in member_rows
            ]

            if len(member_ids) < 3:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=(
                        "Für die Auslosung werden "
                        "mindestens 3 Mitglieder benötigt."
                    ),
                )

            receivers = member_ids.copy()

            for _ in range(1000):
                random_source.shuffle(receivers)

                if all(
                    giver_id != receiver_id
                    for giver_id, receiver_id
                    in zip(member_ids, receivers)
                ):
                    break
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=(
                        "Es konnte keine gültige "
                        "Zuteilung erzeugt werden."
                    ),
                )

            created_at = utc_now()

            connection.executemany(
                """
                INSERT INTO draw_assignments (
                    group_id,
                    giver_user_id,
                    receiver_user_id,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        group_id,
                        giver_id,
                        receiver_id,
                        created_at,
                    )
                    for giver_id, receiver_id
                    in zip(member_ids, receivers)
                ],
            )

            cursor = connection.execute(
                """
                UPDATE groups
                SET status = 'DRAWN'
                WHERE id = ?
                  AND status = 'OPEN'
                """,
                (group_id,),
            )

            if cursor.rowcount != 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Diese Gruppe wurde bereits ausgelost.",
                )

            connection.commit()

        except HTTPException:
            connection.rollback()
            raise

        except sqlite3.IntegrityError as exception:
            connection.rollback()

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Die Gruppe wurde möglicherweise "
                    "bereits ausgelost."
                ),
            ) from exception

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Die Auslosung konnte nicht gespeichert werden.",
            ) from exception

    return DrawGroupResponse(
        group_id=group_id,
        status="DRAWN",
        assignment_count=len(member_ids),
    )


@app.get(
    "/api/groups/{group_id}/wishlist",
    response_model=list[WishlistItemResponse],
)
def get_own_wishlist(
    group_id: str,
    authorization: str | None = Header(default=None),
) -> list[WishlistItemResponse]:
    user_id = get_authenticated_user_id(authorization)

    with open_database() as connection:
        membership = connection.execute(
            """
            SELECT 1
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
            """,
            (
                group_id,
                user_id,
            ),
        ).fetchone()

        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Gruppe wurde nicht gefunden oder du bist kein Mitglied.",
            )

        rows = connection.execute(
            """
            SELECT
                id,
                title,
                description,
                link
            FROM wishlist_items
            WHERE group_id = ?
              AND user_id = ?
            ORDER BY created_at ASC
            """,
            (
                group_id,
                user_id,
            ),
        ).fetchall()

    return [
        WishlistItemResponse(
            id=item_id,
            title=title,
            description=description,
            link=link,
        )
        for item_id, title, description, link in rows
    ]


@app.post(
    "/api/groups/join",
    response_model=GroupResponse,
    status_code=status.HTTP_200_OK,
)
def join_group(
    request: JoinGroupRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
) -> GroupResponse:
    user_id = get_authenticated_user_id(
        authorization
    )
    invite_code = (
        request.invite_code
        .strip()
        .upper()
    )

    check_rate_limit(
        "join_ip",
        get_client_ip(http_request),
    )
    check_rate_limit(
        "join_user",
        user_id,
    )

    with open_database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        group = connection.execute(
            """
            SELECT
                id,
                name,
                invite_code,
                status,
                budget_cents,
                budget_currency,
                created_at
            FROM groups
            WHERE invite_code = ?
            """,
            (invite_code,),
        ).fetchone()

        if group is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Es wurde keine Gruppe mit diesem Einladungscode gefunden.",
            )

        (
            group_id,
            group_name,
            stored_invite_code,
            group_status,
            budget_cents,
            budget_currency,
            created_at,
        ) = group

        existing_member = connection.execute(
            """
            SELECT 1
            FROM group_members
            WHERE group_id = ?
              AND user_id = ?
            """,
            (group_id, user_id),
        ).fetchone()

        joined_now = existing_member is None

        if joined_now and group_status != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Bereits ausgelosten Gruppen kann "
                    "nicht beigetreten werden."
                ),
            )

        if joined_now:
            member_count_before_join = connection.execute(
                """
                SELECT COUNT(*)
                FROM group_members
                WHERE group_id = ?
                """,
                (group_id,),
            ).fetchone()[0]

            if (
                member_count_before_join
                >= MAX_GROUP_MEMBERS
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Diese Gruppe hat bereits die maximal "
                        "erlaubte Anzahl Mitglieder."
                    ),
                )

            connection.execute(
                """
                INSERT INTO group_members (
                    group_id,
                    user_id,
                    joined_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    group_id,
                    user_id,
                    utc_now(),
                ),
            )
            connection.commit()

        member_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM group_members
            WHERE group_id = ?
            """,
            (group_id,),
        ).fetchone()[0]

    return GroupResponse(
        id=group_id,
        name=group_name,
        invite_code=stored_invite_code,
        member_count=member_count,
        status=group_status,
        budget_cents=budget_cents,
        budget_currency=budget_currency,
        created_at=created_at,
        joined_now=joined_now,
    )

