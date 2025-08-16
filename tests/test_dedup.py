import os
import tempfile
from threat_intel.storage import get_connection, migrate, upsert_item
from threat_intel.utils import normalize_date

def test_upsert_dedup():
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "t.db")
        conn = get_connection(db)
        migrate(conn)

        item = {
            "title": "Sample",
            "url": "https://example.com/a",
            "source": "test",
            "published_at": normalize_date("2025-01-01T00:00:00Z"),
            "text": "hello world",
            "summary": "sum",
            "severity": 3,
        }
        id1 = upsert_item(conn, item)
        id2 = upsert_item(conn, item)  # same URL -> update same row
        assert id1 == id2

        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM items")
        count = cur.fetchone()[0]
        assert count == 1
