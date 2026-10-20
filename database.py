import sqlite3
from contextlib import closing
from pathlib import Path

from config import DB_PATH


def migration_1_create_tables(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            actor_hash TEXT,
            auth_masked TEXT,
            method TEXT,
            raw_path TEXT,
            normalized_path TEXT,
            status_code INTEGER,
            payload_size INTEGER,
            latency_ms REAL,
            is_shadow INTEGER DEFAULT 0,
            anomaly_score REAL DEFAULT 0.0,
            autoencoder_mse REAL DEFAULT 0.0,
            is_anomaly INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            severity TEXT DEFAULT 'Low',
            explanation TEXT DEFAULT 'Normal baseline activity',
            ground_truth INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS gateway_policies (
            actor_hash TEXT PRIMARY KEY,
            action TEXT,
            reason TEXT,
            created_at TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS semantic_test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            test_type TEXT,
            endpoint TEXT,
            method TEXT,
            actor_used TEXT,
            target_resource TEXT,
            status_code INTEGER,
            vulnerable INTEGER,
            evidence TEXT
        )
    """)


def migration_2_add_autoencoder_mse(
    conn: sqlite3.Connection,
) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(api_logs)")}

    if "autoencoder_mse" not in columns:
        conn.execute("""
            ALTER TABLE api_logs
            ADD COLUMN autoencoder_mse REAL DEFAULT 0.0
        """)


def migration_3_add_traffic_source(
    conn: sqlite3.Connection,
) -> None:
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(api_logs)")
    }

    if "traffic_source" not in columns:
        conn.execute("""
            ALTER TABLE api_logs
            ADD COLUMN traffic_source TEXT NOT NULL DEFAULT 'legacy'
        """)


def migration_4_add_request_id(
    conn: sqlite3.Connection,
) -> None:
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(api_logs)")
    }

    if "request_id" not in columns:
        conn.execute("""
            ALTER TABLE api_logs
            ADD COLUMN request_id TEXT
        """)

    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_api_logs_request_id
        ON api_logs(request_id)
        WHERE request_id IS NOT NULL
    """)


MIGRATIONS = [
    (1, migration_1_create_tables),
    (2, migration_2_add_autoencoder_mse),
    (3, migration_3_add_traffic_source),
    (4, migration_4_add_request_id),
]


def init_db(db_path: str | Path | None = None) -> None:
    path = Path(db_path) if db_path is not None else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(path, timeout=10)) as conn:
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

        for version, migration in MIGRATIONS:
            conn.execute("BEGIN IMMEDIATE")

            try:
                already_applied = conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?",
                    (version,),
                ).fetchone()

                if already_applied:
                    conn.commit()
                    continue

                migration(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?)",
                    (version,),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
