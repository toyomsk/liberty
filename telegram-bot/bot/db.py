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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def init_db(db_path: str) -> None:
    """Create DB file and clients table if not exists."""
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()
    logger.info(f"DB initialized: {db_path}")


def add_client(client_id: str, name: str, db_path: str) -> None:
    """Insert client (id, name)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO clients (id, name) VALUES (?, ?)",
            (client_id, name)
        )
        conn.commit()
    finally:
        conn.close()


def get_name_by_id(client_id: str, db_path: str) -> Optional[str]:
    """Return name by client_id; None if not found."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT name FROM clients WHERE id = ?",
            (client_id,)
        ).fetchone()
        return row[0] if row else None
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


def list_clients(db_path: str) -> List[Tuple[str, str]]:
    """Return list of (client_id, name) for display."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, name FROM clients ORDER BY created_at"
        ).fetchall()
        return [(r[0], r[1]) for r in rows]
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
