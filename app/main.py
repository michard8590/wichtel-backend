# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from app.database import initialise_database
from app.errors import request_validation_exception_handler
from app.routers.draw import router as draw_router
from app.routers.groups import router as groups_router
from app.routers.health import router as health_router
from app.routers.users import router as users_router
from app.routers.wishlists import router as wishlists_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialise_database()
    yield


app = FastAPI(
    title="Wichtel API",
    version="1.5.0",
    lifespan=lifespan,
)

app.add_exception_handler(
    RequestValidationError,
    request_validation_exception_handler,
)

app.include_router(health_router)
app.include_router(draw_router)
app.include_router(groups_router)
app.include_router(users_router)
app.include_router(wishlists_router)
