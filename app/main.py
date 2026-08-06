# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

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
from app.routers.draw import router as draw_router
from app.routers.groups import router as groups_router
from app.routers.users import router as users_router
from app.routers.wishlists import router as wishlists_router
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
app.include_router(draw_router)
app.include_router(groups_router)
app.include_router(users_router)
app.include_router(wishlists_router)
