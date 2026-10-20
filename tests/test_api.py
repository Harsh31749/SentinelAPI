import sqlite3

from fastapi.testclient import TestClient

import main
from database import init_db


def test_list_users_records_telemetry(tmp_path, monkeypatch):
    db_path = tmp_path / "api-test.db"

    # Route startup initialization and middleware logging to the test DB.
    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    with TestClient(main.app) as client:
        response = client.get("/api/v1/users")

    assert response.status_code == 200
    assert response.json() == [
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"},
    ]

    with sqlite3.connect(db_path) as conn:
        event = conn.execute("""
            SELECT method, raw_path, status_code
            FROM api_logs
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

    assert event == ("GET", "/api/v1/users", 200)


def test_blocked_actor_receives_403_and_is_logged(tmp_path, monkeypatch):
    import hashlib

    db_path = tmp_path / "blocked-api-test.db"
    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    actor_id = "blocked-test-actor"
    actor_hash = hashlib.sha256(actor_id.encode()).hexdigest()[:12]

    # Startup creates the schema; seed the policy before making a request.
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO gateway_policies (actor_hash, action, reason, created_at)
            VALUES (?, 'BLOCK', 'Test policy', '2026-01-01T00:00:00+00:00')
            """,
            (actor_hash,),
        )

    with TestClient(main.app) as client:
        response = client.get(
            "/api/v1/users",
            headers={"X-Actor-ID": actor_id},
        )

    assert response.status_code == 403
    assert "Blocked by AI API Security Analyzer" in response.json()["detail"]

    with sqlite3.connect(db_path) as conn:
        event = conn.execute(
            """
            SELECT actor_hash, method, raw_path, status_code
            FROM api_logs
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    assert event == (actor_hash, "GET", "/api/v1/users", 403)


def test_policy_lookup_failure_returns_503(tmp_path, monkeypatch, caplog):
    db_path = tmp_path / "policy-failure.db"

    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    def fail_policy_lookup(actor_hash):
        raise sqlite3.OperationalError("Simulated database failure")

    monkeypatch.setattr(main, "get_policy_action", fail_policy_lookup)

    with TestClient(main.app) as client:
        response = client.get("/api/v1/users")

    assert response.status_code == 503
    assert response.json() == {"detail": "Security policy service unavailable"}
    assert "Policy lookup failed" in caplog.text

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM api_logs").fetchone()[0]

    assert count == 0


def test_telemetry_failure_preserves_endpoint_response(tmp_path, monkeypatch, caplog):
    db_path = tmp_path / "telemetry-failure.db"

    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    def fail_telemetry_write(**kwargs):
        raise sqlite3.OperationalError("Simulated write failure")

    monkeypatch.setattr(main, "write_telemetry", fail_telemetry_write)

    with TestClient(main.app) as client:
        response = client.get("/api/v1/users")

    assert response.status_code == 200
    assert response.json()[0]["name"] == "Alice"
    assert "Failed to persist API telemetry" in caplog.text
