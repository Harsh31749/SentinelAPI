
import json
import os
import sqlite3
import time
from datetime import UTC, datetime

import jwt
import requests

from config import DB_PATH, SPEC_PATH
from database import init_db

DB_FILE = str(DB_PATH)
SPEC_FILE = str(SPEC_PATH)
BASE_URL = "http://127.0.0.1:8000"

JWT_SECRET = os.getenv("SENTINEL_JWT_SECRET", "")
JWT_ISSUER = os.getenv("SENTINEL_JWT_ISSUER", "sentinelapi-local")
JWT_AUDIENCE = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinelapi")

def init_semantic_db() -> None:
    """Initialize the database tables used by the semantic tester and dashboard."""
    init_db()

def make_token(subject: str) -> str:
    """Create a short-lived JWT for a local security demonstration."""
    if len(JWT_SECRET.encode("utf-8")) < 32:
        raise RuntimeError(
            "SENTINEL_JWT_SECRET must be set to a secret of at least "
            "32 bytes. Configure it in PowerShell before running this script."
        )

    now = int(time.time())
    claims = {
        "sub": subject,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def send_test_request(
    method: str,
    path: str,
    subject: str,
    extra_headers: dict | None = None,
) -> requests.Response:
    """Send a semantic security test using a valid JWT."""
    headers = {
        "Authorization": f"Bearer {make_token(subject)}",
        "X-Actor-ID": subject,
    }
    if extra_headers:
        headers.update(extra_headers)

    return requests.request(
        method,
        f"{BASE_URL}{path}",
        headers=headers,
        timeout=5,
    )


def run_semantic_tests():
    init_db()

    with open(SPEC_FILE, encoding="utf-8") as spec_file:
        spec = json.load(spec_file)

    results = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if "{user_id}" in path and "get" in methods:
            target_path = path.replace("{user_id}", "2")
            resp = send_test_request(
                "GET",
                target_path,
                "semantic_fuzzer_user_1",
                {
                    "X-User-Role": "standard",
                    "X-Authenticated-User-ID": "1",
                },
            )

            is_vuln = int(resp.status_code == 200)
            evidence = (
                f"Potential BOLA: User 1 received User 2's resource "
                f"(HTTP {resp.status_code}); verify response contents."
                if is_vuln
                else f"Request did not return HTTP 200 "
                f"(HTTP {resp.status_code}); review response to confirm security."
            )

            results.append(
                (
                    datetime.now(UTC).isoformat(),
                    "BOLA (Broken Object Level Auth)",
                    path,
                    "GET",
                    "User_1 (Standard)",
                    "User_2 Resource (ID=2)",
                    resp.status_code,
                    is_vuln,
                    evidence,
                )
            )

    bfla_targets = [
        ("DELETE", "/api/v1/debug/reset-cache", "Admin Cache Purge"),
        ("GET", "/api/v1/legacy-admin-export", "Admin Database Export"),
    ]

    for method, path, desc in bfla_targets:
        resp = send_test_request(
            method,
            path,
            "semantic_fuzzer_low_priv",
            {"X-User-Role": "guest"},
        )

        is_vuln = int(resp.status_code == 200)
        evidence = (
            f"Potential BFLA: Low-privilege test identity received HTTP 200 "
            f"for '{desc}'; verify the response and side effects."
            if is_vuln
            else f"Request did not return HTTP 200 for '{desc}' "
            f"(HTTP {resp.status_code}); review response to confirm security."
        )

        results.append(
            (
                datetime.now(UTC).isoformat(),
                "BFLA (Broken Function Level Auth)",
                path,
                method,
                "Guest (Low-Privilege)",
                desc,
                resp.status_code,
                is_vuln,
                evidence,
            )
        )

    with sqlite3.connect(DB_FILE) as conn:
        conn.executemany(
            """
            INSERT INTO semantic_test_results (
                timestamp, test_type, endpoint, method, actor_used,
                target_resource, status_code, vulnerable, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            results,
        )

    return len(results)


if __name__ == "__main__":
    try:
        count = run_semantic_tests()
        print(f"Executed {count} schema-aware semantic security tests.")
    except (requests.RequestException, RuntimeError, OSError, ValueError) as exc:
        print(f"Semantic tests could not complete: {exc}")
        raise SystemExit(1) from exc
