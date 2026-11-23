import json
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database_path = current_app.config["DATABASE"]

        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        g.db = connection

    return g.db


def close_db(error: BaseException | None = None) -> None:
    connection = g.pop("db", None)

    if connection is not None:
        connection.close()


def init_db() -> None:
    connection = get_db()
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS local_user (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            project_name TEXT NOT NULL,
            project_directory TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_address TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS login_failures_remote_time
            ON login_failures (remote_address, attempted_at);
        CREATE INDEX IF NOT EXISTS scan_history_created_at
            ON scan_history (created_at DESC, id DESC);
        """
    )
    connection.execute(
        "INSERT OR IGNORE INTO app_settings (name, value) VALUES (?, ?)",
        ("session_secret", secrets.token_urlsafe(48)),
    )
    connection.execute("PRAGMA user_version = 3")
    connection.commit()


def get_session_secret() -> str:
    row = get_db().execute(
        "SELECT value FROM app_settings WHERE name = ?",
        ("session_secret",),
    ).fetchone()
    if row is None:
        raise RuntimeError("session secret was not initialized")
    return str(row["value"])


def has_local_user() -> bool:
    row = get_db().execute("SELECT 1 FROM local_user WHERE id = 1").fetchone()
    return row is not None


def create_local_user(username: str, password_hash: str) -> bool:
    connection = get_db()
    try:
        connection.execute(
            """
            INSERT INTO local_user (id, username, password_hash, created_at)
            VALUES (1, ?, ?, ?)
            """,
            (
                username,
                password_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    except sqlite3.IntegrityError:
        connection.rollback()
        return False
    connection.commit()
    return True


def verify_local_user(username: str) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT username, password_hash FROM local_user WHERE id = 1 AND username = ?",
        (username,),
    ).fetchone()


def register_login_attempt(
    remote_address: str,
    *,
    max_attempts: int,
    window_seconds: int,
) -> int | None:
    connection = get_db()
    now = int(time.time())
    cutoff = now - window_seconds
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "DELETE FROM login_failures WHERE attempted_at <= ?",
        (cutoff,),
    )
    row = connection.execute(
        """
        SELECT COUNT(*) AS attempt_count, MIN(attempted_at) AS oldest_attempt
        FROM login_failures
        WHERE remote_address = ? AND attempted_at > ?
        """,
        (remote_address, cutoff),
    ).fetchone()
    if int(row["attempt_count"]) >= max_attempts:
        connection.commit()
        return max(1, int(row["oldest_attempt"]) + window_seconds - now)

    connection.execute(
        "INSERT INTO login_failures (remote_address, attempted_at) VALUES (?, ?)",
        (remote_address, now),
    )
    connection.commit()
    return None


def clear_login_failures(remote_address: str) -> None:
    connection = get_db()
    connection.execute(
        "DELETE FROM login_failures WHERE remote_address = ?",
        (remote_address,),
    )
    connection.commit()


def save_scan_history(payload: dict[str, Any]) -> int:
    project = payload.get("project")
    summary = payload.get("summary")
    if not isinstance(project, dict) or not isinstance(summary, dict):
        raise ValueError("scan history requires project and summary objects")

    stored_payload = {
        key: value
        for key, value in payload.items()
        if key != "report_html"
    }
    serialized = json.dumps(stored_payload, ensure_ascii=False, allow_nan=False)
    connection = get_db()
    cursor = connection.execute(
        """
        INSERT INTO scan_history (
            created_at, project_name, project_directory, status, payload_json
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            str(project.get("name") or ""),
            str(project.get("directory") or ""),
            str(payload.get("status") or "unknown"),
            serialized,
        ),
    )
    connection.execute(
        """
        DELETE FROM scan_history
        WHERE id NOT IN (
            SELECT id FROM scan_history ORDER BY id DESC LIMIT ?
        )
        """,
        (int(current_app.config["HISTORY_RETENTION"]),),
    )
    connection.commit()
    return int(cursor.lastrowid)


def list_scan_history() -> list[dict[str, Any]]:
    rows = get_db().execute(
        """
        SELECT id, created_at, project_name, project_directory, status, payload_json
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(current_app.config["HISTORY_RETENTION"]),),
    ).fetchall()
    history = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        summary = payload.get("summary")
        history.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "project_name": row["project_name"],
                "project_directory": row["project_directory"],
                "status": row["status"],
                "summary": summary if isinstance(summary, dict) else {},
            }
        )
    return history


def get_scan_history(scan_id: int) -> dict[str, Any] | None:
    row = get_db().execute(
        "SELECT created_at, payload_json FROM scan_history WHERE id = ?",
        (scan_id,),
    ).fetchone()
    if row is None:
        return None
    payload = json.loads(row["payload_json"])
    payload["history_id"] = scan_id
    payload["history_created_at"] = row["created_at"]
    return payload


def delete_scan_history(scan_id: int) -> bool:
    cursor = get_db().execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    get_db().commit()
    return cursor.rowcount > 0


def clear_scan_history() -> int:
    connection = get_db()
    cursor = connection.execute("DELETE FROM scan_history")
    connection.commit()
    return cursor.rowcount


def init_app(app) -> None:
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()
        app.secret_key = get_session_secret()
