# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

from pydantic import BaseModel, Field


__all__ = [
    "RegisterRequest",
    "RegisterResponse",
    "RecoverRequest",
    "RecoverResponse",
    "UpdateProfileRequest",
    "ProfileResponse",
    "CreateGroupRequest",
    "GroupResponse",
    "JoinGroupRequest",
    "UpdateGroupRequest",
    "GroupMemberResponse",
    "GroupDetailResponse",
    "CreateWishlistItemRequest",
    "WishlistItemResponse",
    "UpdateWishlistItemRequest",
    "DrawGroupResponse",
    "DrawAssignmentResponse",
]


class RegisterRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=50)


class RegisterResponse(BaseModel):
    user_id: str
    display_name: str
    account_code: str
    device_token: str
    recovery_key: str


class RecoverRequest(BaseModel):
    account_code: str = Field(min_length=4, max_length=20)
    recovery_key: str = Field(min_length=10, max_length=100)


class RecoverResponse(BaseModel):
    user_id: str
    display_name: str
    account_code: str
    device_token: str


class UpdateProfileRequest(BaseModel):
    display_name: str = Field(
        min_length=2,
        max_length=50,
    )


class ProfileResponse(BaseModel):
    user_id: str
    display_name: str
    account_code: str


class CreateGroupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    budget_cents: int | None = Field(
        default=None,
        ge=0,
        le=100_000_000,
    )


class GroupResponse(BaseModel):
    id: str
    name: str
    invite_code: str
    member_count: int
    status: str
    budget_cents: int | None
    budget_currency: str
    created_at: str
    joined_now: bool | None = None


class JoinGroupRequest(BaseModel):
    invite_code: str = Field(min_length=5, max_length=6)


class UpdateGroupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    budget_cents: int | None = Field(
        default=None,
        ge=0,
        le=100_000_000,
    )


class GroupMemberResponse(BaseModel):
    user_id: str
    display_name: str
    account_code: str
    is_owner: bool


class GroupDetailResponse(BaseModel):
    id: str
    name: str
    invite_code: str
    status: str
    member_count: int
    is_owner: bool
    owner_display_name: str
    owner_deleted: bool
    can_delete_group: bool
    budget_cents: int | None
    budget_currency: str
    created_at: str
    members: list[GroupMemberResponse]


class CreateWishlistItemRequest(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    link: str | None = Field(default=None, max_length=1000)


class WishlistItemResponse(BaseModel):
    id: str
    title: str
    description: str | None
    link: str | None


class UpdateWishlistItemRequest(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    link: str | None = Field(default=None, max_length=1000)


class DrawGroupResponse(BaseModel):
    group_id: str
    status: str
    assignment_count: int


class DrawAssignmentResponse(BaseModel):
    group_id: str
    receiver_user_id: str
    receiver_display_name: str
    receiver_account_code: str
    wishlist: list[WishlistItemResponse]
