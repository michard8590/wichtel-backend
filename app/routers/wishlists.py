# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import uuid

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    status,
)

from app.auth import get_authenticated_user_id
from app.config import MAX_WISHLIST_ITEMS_PER_USER_GROUP
from app.database import open_database
from app.schemas import (
    CreateWishlistItemRequest,
    UpdateWishlistItemRequest,
    WishlistItemResponse,
)
from app.time_utils import utc_now
from app.validation import validate_optional_http_url

router = APIRouter()


@router.post(
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
    link = validate_optional_http_url(request.link)

    if not title:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The wishlist item requires a title.",
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
                detail=("The group was not found or you are not a member."),
            )

        if membership[0] != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=("Wishlist items cannot be added after the draw."),
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

        if wishlist_item_count >= MAX_WISHLIST_ITEMS_PER_USER_GROUP:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "The maximum number of wishlist items has been reached for this group."
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


@router.put(
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
    link = validate_optional_http_url(request.link)

    if not title:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The wishlist item requires a title.",
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
                detail="The wishlist item was not found.",
            )

        if item[1] != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=("Wishlist items cannot be updated after the draw."),
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


@router.delete(
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
                detail="The wishlist item was not found.",
            )

        if item[1] != "OPEN":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=("Wishlist items cannot be deleted after the draw."),
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
                detail=("The wishlist item could not be deleted unambiguously."),
            )

        connection.commit()


@router.get(
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
                detail="The group was not found or you are not a member.",
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
