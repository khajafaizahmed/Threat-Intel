# threat_intel/storage.py
import os
import sqlite3
from typing import Optional, Dict, Any, List
import pandas as pd

from .utils import ensure_dir, hash_key

DEFAULT_DB = "data/threats.db"


def get_connection(path: Optional[str] = None) -> sqlite3.Connection:
    db = path or DEFAULT_DB
    ensure_dir(os.path.dirname(db) or ".")
    conn = sqlite3.connect(db, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def migrate(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            url_hash TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            title TEXT,
            published_at TEXT,
            text TEXT,
            summary TEXT,
            severity INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ioc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        );
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_unique ON ioc(item_id, type, value);
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS labels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        );
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_label_unique ON labels(item_id, label);
        """
    )
    conn.commit()


def upsert_item(conn: sqlite3.Connection, item: Dict[str, Any]) -> int:
    """Insert or update by URL hash. Return row id."""
    url = item["url"]
    url_hash = hash_key(url)
    row = (
        item.get("url"),
        url_hash,
        item.get("source"),
        item.get("title"),
        item.get("published_at"),
        item.get("text"),
        item.get("summary"),
        int(item.get("severity") or 1),
    )
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO items (url, url_hash, source, title, published_at, text, summary, severity)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(url_hash) DO UPDATE SET
            source=excluded.source,
            title=excluded.title,
            published_at=excluded.published_at,
            text=excluded.text,
            summary=excluded.summary,
            severity=excluded.severity
        ;
        """,
        row,
    )
    conn.commit()
    cur.execute("SELECT id FROM items WHERE url_hash=?", (url_hash,))
    rid = cur.fetchone()[0]
    return int(rid)


def insert_iocs(conn: sqlite3.Connection, item_id: int, iocs: Dict[str, List[str]]):
    if not iocs:
        return
    cur = conn.cursor()
    for t, vals in iocs.items():
        for v in (vals or []):
            try:
                cur.execute(
                    "INSERT OR IGNORE INTO ioc(item_id, type, value) VALUES (?,?,?)",
                    (item_id, t, v),
                )
            except Exception:
                pass
    conn.commit()


def insert_labels(conn: sqlite3.Connection, item_id: int, labels: List[str]):
    cur = conn.cursor()
    for lbl in labels or []:
        try:
            cur.execute(
                "INSERT OR IGNORE INTO labels(item_id, label) VALUES (?,?)",
                (item_id, lbl),
            )
        except Exception:
            pass
    conn.commit()


def query_items(
    conn: sqlite3.Connection,
    sources: Optional[List[str]] = None,
    date_from=None,
    date_to=None,
    categories: Optional[List[str]] = None,
    severity_min: int = 1,
    text_query: str = "",
    limit: int = 2000,
) -> pd.DataFrame:
    q = """
        SELECT i.id, i.title, i.url, i.source, i.published_at, i.severity, i.summary
        FROM items i
        LEFT JOIN labels l ON l.item_id = i.id
        WHERE 1=1
    """
    params: List[Any] = []

    if sources:
        q += f" AND i.source IN ({','.join(['?']*len(sources))})"
        params += sources

    if date_from:
        q += " AND (i.published_at IS NULL OR i.published_at >= ?)"
        params.append(date_from.isoformat())
    if date_to:
        q += " AND (i.published_at IS NULL OR i.published_at <= ?)"
        params.append(date_to.isoformat())

    if categories:
        q += f" AND l.label IN ({','.join(['?']*len(categories))})"
        params += categories

    if severity_min:
        q += " AND i.severity >= ?"
        params.append(int(severity_min))

    if text_query:
        like = f"%{text_query}%"
        q += " AND (i.title LIKE ? OR i.summary LIKE ? OR i.text LIKE ?)"
        params += [like, like, like]

    q += " GROUP BY i.id ORDER BY COALESCE(i.published_at, i.created_at) DESC LIMIT ?"
    params.append(int(limit))

    df = pd.read_sql_query(q, conn, params=params)
    if not df.empty:
        df["published_at"] = df["published_at"].fillna("")
    return df


def get_iocs_for_item_ids(conn: sqlite3.Connection, ids: List[int]) -> pd.DataFrame:
    if not ids:
        return pd.DataFrame(columns=["item_id", "type", "value"])
    q = f"SELECT item_id, type, value FROM ioc WHERE item_id IN ({','.join(['?']*len(ids))})"
    df = pd.read_sql_query(q, conn, params=ids)
    return df


def export_items_dataframe(conn: sqlite3.Connection, **filters) -> pd.DataFrame:
    return query_items(conn, **filters)
