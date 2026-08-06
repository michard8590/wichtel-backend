# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

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
from app.config import (
    MAX_GROUP_MEMBERS,
    MAX_OPEN_GROUPS_PER_OWNER,
)
from app.database import (
    delete_groups_without_active_members,
    open_database,
)
from app.identifiers import create_invite_code
from app.rate_limit import (
    check_rate_limit,
    get_client_ip,
)
from app.schemas import (
    CreateGroupRequest,
    GroupDetailResponse,
    GroupMemberResponse,
    GroupResponse,
    JoinGroupRequest,
    UpdateGroupRequest,
)
from app.time_utils import utc_now


router = APIRouter()


@router.get(
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


@router.post(
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


@router.patch(
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


@router.delete(
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


@router.delete(
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


@router.delete(
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


@router.get(
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


@router.post(
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
