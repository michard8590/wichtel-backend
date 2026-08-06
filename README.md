# Wichtel Backend

Free REST backend for the Android application **Wichtel**.

The backend is built with FastAPI and SQLite. It provides account registration without Google services, Secret Santa groups, group-specific wishlists, and random assignments without assigning users to themselves.

## Features

- User accounts without email addresses or external authentication
- Account recovery using an account code and recovery key
- Device-based authentication with bearer tokens
- Create, update, leave, and delete Secret Santa groups
- Join groups using invite codes
- Manage group members
- Random Secret Santa assignments without self-assignment
- Group-specific wishlists
- Protection against changes after a group has been drawn
- Rate limiting for sensitive endpoints
- Automatically generated OpenAPI documentation
- Persistent SQLite storage
- Docker Compose deployment behind a reverse proxy

## Technology

- Python 3.13
- FastAPI
- Pydantic
- SQLite
- Uvicorn
- Docker and Docker Compose
- Pytest

## Project structure

```text
app/
├── main.py
├── auth.py
├── config.py
├── database.py
├── identifiers.py
├── rate_limit.py
├── schemas.py
├── security.py
├── time_utils.py
├── validation.py
└── routers/
    ├── health.py
    ├── users.py
    ├── groups.py
    ├── wishlists.py
    └── draw.py

tests/
└── test_api_security.py
```

## Requirements

- Docker
- Docker Compose
- An external Docker network named `docker_web`
- Optionally, a reverse proxy such as Nginx Proxy Manager

## Installation

Clone the repository:

```bash
git clone https://github.com/michard8590/wichtel-backend.git
cd wichtel-backend
```

Copy the example configuration:

```bash
cp .env.example .env
```

Create the external Docker network if it does not already exist:

```bash
docker network create docker_web
```

Build and start the backend:

```bash
docker compose up -d --build
```

Display the container status and logs:

```bash
docker compose ps
docker compose logs -f
```

Stop the backend:

```bash
docker compose down
```

The service is available on port `8000` inside the Docker network. The SQLite database is stored persistently under `/app/data`.

## Configuration

Configuration is provided through environment variables, typically using the `.env` file.

| Variable | Description | Default |
|---|---|---|
| `DATABASE_PATH` | Path to the SQLite database | `/app/data/wichtel.db` |
| `RATE_LIMIT_ENABLED` | Enable application-level rate limiting | `true` |
| `TRUSTED_PROXY_NETWORKS` | Trusted reverse proxy IP addresses or networks | empty |
| `MAX_ACTIVE_DEVICES_PER_USER` | Maximum active devices per user | see `app/config.py` |
| `MAX_OPEN_GROUPS_PER_OWNER` | Maximum open groups per owner | see `app/config.py` |
| `MAX_GROUP_MEMBERS` | Maximum members per group | see `app/config.py` |
| `MAX_WISHLIST_ITEMS_PER_USER_GROUP` | Maximum wishlist items per user and group | see `app/config.py` |

`X-Forwarded-For` and `X-Real-IP` are only evaluated when the direct peer belongs to `TRUSTED_PROXY_NETWORKS`.

## Local development

Create a virtual environment and install the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --requirement requirements.txt
```

Set a writable database path for local development:

```bash
export DATABASE_PATH=/tmp/wichtel-development.db
```

Start the application:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

## Authentication

Protected endpoints require a device token in the HTTP header:

```http
Authorization: Bearer DEVICE_TOKEN
```

The device token is returned during registration or account recovery. Device tokens and recovery keys are stored only as hashes in the database.

## API endpoints

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Return the backend status |

### Users

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/users/register` | Register a user |
| `POST` | `/api/users/recover` | Recover a user account |
| `PATCH` | `/api/users/me` | Update the current user profile |
| `DELETE` | `/api/users/me` | Delete the current user account |

### Groups

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/groups` | List the current user's groups |
| `POST` | `/api/groups` | Create a group |
| `POST` | `/api/groups/join` | Join a group |
| `GET` | `/api/groups/{group_id}` | Return group details |
| `PATCH` | `/api/groups/{group_id}` | Update a group |
| `DELETE` | `/api/groups/{group_id}` | Delete a group |
| `DELETE` | `/api/groups/{group_id}/membership` | Leave a group |
| `DELETE` | `/api/groups/{group_id}/members/{member_user_id}` | Remove a member |

### Wishlists

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/groups/{group_id}/wishlist` | Return the current user's wishlist |
| `POST` | `/api/groups/{group_id}/wishlist` | Add a wishlist item |
| `PUT` | `/api/groups/{group_id}/wishlist/{item_id}` | Update a wishlist item |
| `DELETE` | `/api/groups/{group_id}/wishlist/{item_id}` | Delete a wishlist item |

### Draw

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/groups/{group_id}/draw` | Draw the group assignments |
| `GET` | `/api/groups/{group_id}/assignment` | Return the current user's assignment |

The backend provides 19 API operations across 13 distinct paths.

## API documentation

FastAPI automatically generates documentation at:

- `/docs`
- `/redoc`
- `/openapi.json`

## Tests

Run the tests and compile all Python modules:

```bash
python -m pytest -q
python -m compileall -q app tests
```

Validate the Docker Compose configuration and build the image:

```bash
docker compose config
docker compose build
```

## Database backup

Create a consistent SQLite backup before copying the database:

```bash
docker exec -i wichtel-backend python3 - <<'PY'
import sqlite3

source = sqlite3.connect("/app/data/wichtel.db")
target = sqlite3.connect("/app/data/wichtel-backup.db")

with target:
    source.backup(target)

source.close()
target.close()
PY
```

Copy the generated backup file from the persistent data directory and store it outside the repository.

## Security

The container and application use several security measures:

- Runs as a non-root user
- Read-only root filesystem
- All Linux capabilities removed
- `no-new-privileges` enabled
- Write access limited to `/app/data` and `/tmp`
- Device tokens and recovery keys stored only as hashes
- Authorization checks for users, groups, and wishlists
- Limits for devices, groups, members, and wishlist items
- Rate limiting for registration, recovery, and group joining
- Forwarded client IP addresses accepted only from trusted proxies

## License

This project is licensed under the GNU Affero General Public License, version 3 or later (`AGPL-3.0-or-later`).

See the `LICENSE` file for the complete license text.
