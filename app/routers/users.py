# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import secrets
import sqlite3
import uuid

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    Request,
    status,
)

from app.auth import get_authenticated_user_id
from app.config import MAX_ACTIVE_DEVICES_PER_USER
from app.database import (
    delete_groups_without_active_members,
    open_database,
)
from app.identifiers import (
    create_account_code,
    create_recovery_key,
)
from app.rate_limit import (
    check_rate_limit,
    get_client_ip,
)
from app.schemas import (
    ProfileResponse,
    RecoverRequest,
    RecoverResponse,
    RegisterRequest,
    RegisterResponse,
    UpdateProfileRequest,
)
from app.security import hash_secret
from app.time_utils import utc_now
from app.validation import validate_display_name


router = APIRouter()


@router.post(
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


@router.post(
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


@router.patch(
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


@router.delete(
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
