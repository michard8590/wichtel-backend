# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request, status

from app.auth import get_authenticated_user_id
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
from app.routers.health import router as health_router
from app.routers.groups import router as groups_router
from app.routers.users import router as users_router
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialise_database()
    yield


app = FastAPI(
    title="Wichtel API",
    version="1.5.0",
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(groups_router)
app.include_router(users_router)


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
