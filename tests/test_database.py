import sqlite3

import pytest

from database import init_db


def test_migration_preserves_legacy_telemetry(tmp_path):
    db_path = tmp_path / "legacy.db"

    # Simulate the previous schema without autoencoder_mse.
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE api_logs (
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
                is_anomaly INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'Low',
                explanation TEXT DEFAULT 'Normal baseline activity',
                ground_truth INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            INSERT INTO api_logs (
                timestamp, actor_hash, method, raw_path,
                normalized_path, status_code
            )
            VALUES (
                '2026-01-01T00:00:00+00:00',
                'actor123', 'GET', '/api/v1/users',
                '/api/v1/users', 200
            )
        """)

    init_db(db_path)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("""
            SELECT actor_hash, status_code, autoencoder_mse
            FROM api_logs
        """).fetchone()

        assert row == ("actor123", 200, 0.0)

        versions = conn.execute("""
            SELECT version FROM schema_migrations ORDER BY version
        """).fetchall()

        assert versions == [(1,), (2,), (3,), (4,)]


def test_init_db_is_idempotent(tmp_path):
    db_path = tmp_path / "fresh.db"

    init_db(db_path)
    init_db(db_path)

    with sqlite3.connect(db_path) as conn:
        versions = conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()

        tables = {
            row[0]
            for row in conn.execute("""
                SELECT name FROM sqlite_master WHERE type = 'table'
            """)
        }

    assert versions == [(1,), (2,), (3,), (4,)]
    assert {
        "api_logs",
        "gateway_policies",
        "semantic_test_results",
    }.issubset(tables)


def test_failed_migration_rolls_back_and_does_not_record_version(tmp_path, monkeypatch):
    import database

    db_path = tmp_path / "failed_migration.db"

    def failing_migration(conn):
        conn.execute("CREATE TABLE temporary_migration_table (id INTEGER)")
        raise RuntimeError("Simulated migration failure")

    monkeypatch.setattr(
        database,
        "MIGRATIONS",
        [(1, failing_migration)],
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated migration failure",
    ):
        database.init_db(db_path)

    with sqlite3.connect(db_path) as conn:
        table = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'temporary_migration_table'
        """).fetchone()

        versions = conn.execute("SELECT version FROM schema_migrations").fetchall()

    assert table is None
    assert versions == []
