"""SQLite storage for clients (single source of truth; unique client_id for delete/get_config)."""
import os
import sqlite3
import logging
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Unix epoch seconds (UTC). NULL means "no expiry".
    expires_at INTEGER,
    -- Stored so we can re-enable Xray/Hysteria without changing credentials.
    xray_uuid TEXT,
    hysteria_password TEXT,
    -- Unix epoch seconds (UTC). NULL means "enabled".
    disabled_at INTEGER,
    -- Unix epoch seconds (UTC) when "expires in 24h" notice was sent to admins.
    expiry_notice_sent_at INTEGER
);
"""


def _ensure_migration(conn: sqlite3.Connection) -> None:
    """Migrate existing DB to current schema (non-destructive)."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(clients)").fetchall()}
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN expires_at INTEGER")
        conn.commit()
    if "xray_uuid" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN xray_uuid TEXT")
        conn.commit()
    if "hysteria_password" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN hysteria_password TEXT")
        conn.commit()
    if "disabled_at" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN disabled_at INTEGER")
        conn.commit()
    if "expiry_notice_sent_at" not in cols:
        conn.execute("ALTER TABLE clients ADD COLUMN expiry_notice_sent_at INTEGER")
        conn.commit()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_clients_expires_at ON clients(expires_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_clients_disabled_at ON clients(disabled_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_clients_notice_sent ON clients(expiry_notice_sent_at)"
    )
    conn.commit()


def init_db(db_path: str) -> None:
    """Create DB file and clients table if not exists."""
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        _ensure_migration(conn)
        conn.commit()
    finally:
        conn.close()
    logger.info(f"DB initialized: {db_path}")


def add_client(
    client_id: str,
    name: str,
    db_path: str,
    expires_at: Optional[int] = None,
    xray_uuid: Optional[str] = None,
    hysteria_password: Optional[str] = None,
    disabled_at: Optional[int] = None,
    expiry_notice_sent_at: Optional[int] = None,
) -> None:
    """Insert client (id, name, optional expiry)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO clients (id, name, expires_at, xray_uuid, hysteria_password, disabled_at, expiry_notice_sent_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                name,
                expires_at,
                xray_uuid,
                hysteria_password,
                disabled_at,
                expiry_notice_sent_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_name_by_id(client_id: str, db_path: str) -> Optional[str]:
    """Return name by client_id; None if not found."""
    row = get_client_by_id(client_id, db_path)
    return row[0] if row else None


def get_client_by_id(
    client_id: str,
    db_path: str,
) -> Optional[Tuple[str, Optional[int]]]:
    """Return (name, expires_at) by client_id; None if not found."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT name, expires_at FROM clients WHERE id = ?",
            (client_id,),
        ).fetchone()
        if not row:
            return None
        return row[0], row[1]
    finally:
        conn.close()


def get_client_details_by_id(
    client_id: str,
    db_path: str,
) -> Optional[Tuple[str, Optional[int], Optional[int], Optional[str], Optional[str]]]:
    """
    Return (name, expires_at, disabled_at, xray_uuid, hysteria_password) or None.
    """
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT name, expires_at, disabled_at, xray_uuid, hysteria_password
            FROM clients
            WHERE id = ?
            """,
            (client_id,),
        ).fetchone()
        if not row:
            return None
        return row[0], row[1], row[2], row[3], row[4]
    finally:
        conn.close()


def get_id_by_name(name: str, db_path: str) -> Optional[str]:
    """Return client_id by name; None if not found."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT id FROM clients WHERE name = ?",
            (name,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def list_clients(db_path: str) -> List[Tuple[str, str, Optional[int]]]:
    """Return list of (client_id, name, expires_at) for display."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, name, expires_at FROM clients ORDER BY created_at"
        ).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]
    finally:
        conn.close()


def get_expired_clients(now_ts: int, db_path: str) -> List[Tuple[str, str]]:
    """Return list of (client_id, name) that must be disabled now."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, name
            FROM clients
            WHERE expires_at IS NOT NULL
              AND expires_at <= ?
              AND disabled_at IS NULL
            ORDER BY expires_at
            """,
            (now_ts,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]
    finally:
        conn.close()


def set_expires_at(
    client_id: str,
    expires_at: Optional[int],
    db_path: str,
) -> bool:
    """Update expiry for an existing client; returns True if updated."""
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute(
            "UPDATE clients SET expires_at = ?, expiry_notice_sent_at = NULL WHERE id = ?",
            (expires_at, client_id),
        )
        conn.commit()
        return r.rowcount > 0
    finally:
        conn.close()


def set_disabled_at(
    client_id: str,
    disabled_at: Optional[int],
    db_path: str,
) -> bool:
    """Set disabled_at (NULL means enabled)."""
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute(
            "UPDATE clients SET disabled_at = ? WHERE id = ?",
            (disabled_at, client_id),
        )
        conn.commit()
        return r.rowcount > 0
    finally:
        conn.close()


def set_expires_at_and_disabled_at(
    client_id: str,
    expires_at: Optional[int],
    disabled_at: Optional[int],
    db_path: str,
) -> bool:
    """Atomic update of expiry + disabled_at."""
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute(
            "UPDATE clients SET expires_at = ?, disabled_at = ?, expiry_notice_sent_at = NULL WHERE id = ?",
            (expires_at, disabled_at, client_id),
        )
        conn.commit()
        return r.rowcount > 0
    finally:
        conn.close()


def get_clients_expiring_within_window(
    now_ts: int,
    until_ts: int,
    db_path: str,
) -> List[Tuple[str, str, int]]:
    """
    Return clients that expire in (now_ts, until_ts] and are not disabled,
    and haven't been notified yet for current expiry.
    """
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, name, expires_at
            FROM clients
            WHERE expires_at IS NOT NULL
              AND expires_at > ?
              AND expires_at <= ?
              AND disabled_at IS NULL
              AND (expiry_notice_sent_at IS NULL OR expiry_notice_sent_at < expires_at)
            ORDER BY expires_at
            """,
            (now_ts, until_ts),
        ).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]
    finally:
        conn.close()


def set_expiry_notice_sent_at(
    client_id: str,
    sent_at_ts: int,
    db_path: str,
) -> bool:
    """Mark that expiry warning has been sent."""
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute(
            "UPDATE clients SET expiry_notice_sent_at = ? WHERE id = ?",
            (sent_at_ts, client_id),
        )
        conn.commit()
        return r.rowcount > 0
    finally:
        conn.close()


def set_xray_uuid(
    client_id: str,
    xray_uuid: Optional[str],
    db_path: str,
) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute(
            "UPDATE clients SET xray_uuid = ? WHERE id = ?",
            (xray_uuid, client_id),
        )
        conn.commit()
        return r.rowcount > 0
    finally:
        conn.close()


def set_hysteria_password(
    client_id: str,
    hysteria_password: Optional[str],
    db_path: str,
) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        r = conn.execute(
            "UPDATE clients SET hysteria_password = ? WHERE id = ?",
            (hysteria_password, client_id),
        )
        conn.commit()
        return r.rowcount > 0
    finally:
        conn.close()


def delete_client(client_id: str, db_path: str) -> Optional[str]:
    """Delete client by id; return name if found, else None."""
    name = get_name_by_id(client_id, db_path)
    if name is None:
        return None
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        conn.commit()
    finally:
        conn.close()
    return name
