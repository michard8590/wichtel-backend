# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import secrets
import sqlite3

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    status,
)

from app.auth import get_authenticated_user_id
from app.database import open_database
from app.schemas import (
    DrawAssignmentResponse,
    DrawGroupResponse,
    WishlistItemResponse,
)
from app.time_utils import utc_now


router = APIRouter()


@router.get(
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
                    'The group was not found or you are not a member.'
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
                detail='The group has not been drawn yet.',
            )

        if receiver_user_id is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail='No assignment was found for you.'
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


@router.post(
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
                    detail='The group was not found.',
                )

            owner_user_id, group_status = group

            if owner_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        'Only the group owner may start the draw.'
                    ),
                )

            if group_status != "OPEN":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail='This group has already been drawn.',
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
                        'At least three members are required for the draw.'                    ),
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
                        'A valid assignment could not be generated.'
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
                    detail='This group has already been drawn.',
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
                    'The group may already have been drawn.'
                ),
            ) from exception

        except sqlite3.Error as exception:
            connection.rollback()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='The draw could not be saved.',
            ) from exception

    return DrawGroupResponse(
        group_id=group_id,
        status="DRAWN",
        assignment_count=len(member_ids),
    )
