# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Michael Gsell

import sqlite3

from app.config import DATABASE_PATH
from app.identifiers import create_account_code


__all__ = [
    "delete_groups_without_active_members",
    "initialise_database",
    "open_database",
]


def open_database() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=5.0,
    )

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )
    connection.execute(
        "PRAGMA busy_timeout = 5000"
    )

    return connection


def initialise_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open_database() as connection:
        connection.execute(
            "PRAGMA journal_mode = WAL"
        )
        connection.execute(
            "PRAGMA synchronous = NORMAL"
        )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                account_code TEXT,
                recovery_key_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        connection.execute(
            "DROP INDEX IF EXISTS idx_users_display_name_nocase"
        )

        user_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "account_code" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN account_code TEXT"
            )

        users_without_account_code = connection.execute(
            """
            SELECT id
            FROM users
            WHERE account_code IS NULL
               OR TRIM(account_code) = ''
            """
        ).fetchall()

        for (existing_user_id,) in users_without_account_code:
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
                    connection.execute(
                        """
                        UPDATE users
                        SET account_code = ?
                        WHERE id = ?
                        """,
                        (
                            account_code,
                            existing_user_id,
                        ),
                    )
                    break
            else:
                raise RuntimeError(
                    "Es konnte kein eindeutiger Account-Code erzeugt werden."
                )

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_users_account_code_nocase
            ON users(account_code COLLATE NOCASE)
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)


        connection.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                invite_code TEXT NOT NULL UNIQUE,
                owner_user_id TEXT NOT NULL,
                status TEXT NOT NULL,
                budget_cents INTEGER,
                budget_currency TEXT NOT NULL DEFAULT 'CHF',
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_user_id) REFERENCES users(id)
            )
        """)

        group_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(groups)"
            ).fetchall()
        }

        if "budget_cents" not in group_columns:
            connection.execute(
                "ALTER TABLE groups ADD COLUMN budget_cents INTEGER"
            )

        if "budget_currency" not in group_columns:
            connection.execute(
                """
                ALTER TABLE groups
                ADD COLUMN budget_currency TEXT NOT NULL DEFAULT 'CHF'
                """
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES groups(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS wishlist_items (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                link TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES groups(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_wishlist_items_group_user
            ON wishlist_items(group_id, user_id)
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS draw_assignments (
                group_id TEXT NOT NULL,
                giver_user_id TEXT NOT NULL,
                receiver_user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (group_id, giver_user_id),
                UNIQUE (group_id, receiver_user_id),
                CHECK (giver_user_id <> receiver_user_id),
                FOREIGN KEY (group_id) REFERENCES groups(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (giver_user_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (receiver_user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        user_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "is_deleted" not in user_columns:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN is_deleted INTEGER
                NOT NULL DEFAULT 0
                """
            )

        if "deleted_at" not in user_columns:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN deleted_at TEXT
                """
            )

        connection.commit()


def delete_groups_without_active_members(
    connection: sqlite3.Connection,
) -> int:
    cursor = connection.execute(
        """
        DELETE FROM groups
        WHERE NOT EXISTS (
            SELECT 1
            FROM group_members gm
            INNER JOIN users u
                ON u.id = gm.user_id
            WHERE gm.group_id = groups.id
              AND COALESCE(u.is_deleted, 0) = 0
        )
        """
    )

    return cursor.rowcount
