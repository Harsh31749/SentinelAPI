import hashlib
import sqlite3
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import main
from database import init_db

TEST_JWT_SECRET = "test-only-secret-for-sentinelapi-32-bytes-minimum"


@pytest.fixture(autouse=True)
def configure_test_jwt(monkeypatch):
    """Provide a deterministic signing secret for API tests."""
    monkeypatch.setenv("SENTINEL_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setenv("SENTINEL_JWT_ISSUER", "sentinelapi-local")
    monkeypatch.setenv("SENTINEL_JWT_AUDIENCE", "sentinelapi")


def make_token(
    subject: str = "test-actor",
    *,
    secret: str = TEST_JWT_SECRET,
    expires_in: int = 300,
    issuer: str = "sentinelapi-local",
    audience: str = "sentinelapi",
) -> str:
    now = int(time.time())
    claims = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a test client backed by an isolated temporary database."""
    db_path = tmp_path / "jwt-api-test.db"

    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    with TestClient(main.app) as test_client:
        yield test_client


def auth_headers(subject: str = "test-actor") -> dict[str, str]:
    return {"Authorization": f"Bearer {make_token(subject)}"}


def hash_actor(subject: str) -> str:
    """Match the actor hash used by SentinelAPI policies and telemetry."""
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()[:12]


def test_list_users_records_telemetry(tmp_path, monkeypatch):
    db_path = tmp_path / "api-test.db"

    # Route startup initialization and middleware logging to the test DB.
    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    with TestClient(main.app) as client:
        response = client.get(
            "/api/v1/users",
            headers=auth_headers("student-demo"),
        )

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
    db_path = tmp_path / "blocked-api-test.db"
    monkeypatch.setattr(main, "init_db", lambda: init_db(db_path))
    monkeypatch.setattr(main, "DB_FILE", str(db_path))

    subject = "blocked-test-actor"
    actor_hash = hash_actor(subject)

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
            headers={
                "Authorization": f"Bearer {make_token(subject)}",
                "X-Actor-ID": "spoofed-different-actor",
            },
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
        response = client.get(
            "/api/v1/users",
            headers=auth_headers("student-demo"),
        )

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
        response = client.get(
            "/api/v1/users",
            headers=auth_headers("student-demo"),
        )

    assert response.status_code == 200
    assert response.json()[0]["name"] == "Alice"
    assert "Failed to persist API telemetry" in caplog.text


def test_missing_bearer_token_is_rejected(client):
    response = client.get("/api/v1/users")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_bearer_token_is_rejected(client):
    response = client.get(
        "/api/v1/users",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )

    assert response.status_code == 401


def test_expired_jwt_is_rejected(client):
    token = make_token("test-actor", expires_in=-60)

    response = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_wrong_issuer_is_rejected(client):
    token = make_token("test-actor", issuer="untrusted-issuer")

    response = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_missing_jwt_secret_fails_closed(client, monkeypatch):
    monkeypatch.delenv("SENTINEL_JWT_SECRET")

    response = client.get(
        "/api/v1/users",
        headers=auth_headers(),
    )

    assert response.status_code == 503
