
import os
import random
import sqlite3
import time

import jwt
import requests

from config import DB_PATH

BASE_URL = "http://127.0.0.1:8000"
JWT_SECRET = os.getenv("SENTINEL_JWT_SECRET", "")
JWT_ISSUER = os.getenv("SENTINEL_JWT_ISSUER", "sentinelapi-local")
JWT_AUDIENCE = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinelapi")


def make_token(subject: str) -> str:
    """Create a short-lived JWT for a local security demonstration."""
    if len(JWT_SECRET.encode("utf-8")) < 32:
        raise RuntimeError(
            "SENTINEL_JWT_SECRET must contain at least 32 bytes."
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



def label_request_event(request_id: str, label: int) -> None:
    """Label the telemetry event identified by the API response request ID."""
    if not request_id:
        raise RuntimeError("API response did not include X-Request-ID.")

    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("PRAGMA busy_timeout = 10000")
        cursor = conn.execute(
            """
            UPDATE api_logs
            SET ground_truth = ?
            WHERE request_id = ?
            """,
            (label, request_id),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "Expected exactly one telemetry event for request ID "
                f"{request_id}; updated {cursor.rowcount} rows. "
                "The event was not labeled as expected."
            )




def send_request(
    method: str,
    path: str,
    subject: str,
    is_attack: bool,
) -> None:
    headers = {
        "Authorization": f"Bearer {make_token(subject)}",
        "X-Actor-ID": subject,
    }

    try:
        response = requests.request(
            method,
            f"{BASE_URL}{path}",
            headers=headers,
            timeout=5,
        )
        print(f"{method} {path} -> HTTP {response.status_code}")

        request_id = response.headers.get("X-Request-ID")
        if not request_id:
            print(
                f"Warning: no X-Request-ID for {method} {path}; "
                "this request was not labeled."
            )
            return

        label_request_event(request_id, label=int(is_attack))

    except requests.RequestException as exc:
        print(f"Request failed for {method} {path}: {exc}")



def simulate_traffic():
    print("1. Generating 120 baseline normal requests...")
    normal_endpoints = [
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/products"),
        ("GET", "/api/v1/orders"),
        ("POST", "/api/v1/orders"),
        ("GET", "/api/v1/users/5"),
        ("GET", "/api/v1/users/12"),
    ]

    for i in range(120):
        method, path = random.choice(normal_endpoints)
        send_request(
            method,
            path,
            f"normal_user_{i % 5}",
            is_attack=False,
        )
        time.sleep(0.01)

    print("2. Simulating Shadow API discovery and exploitation...")
    shadow_targets = [
        ("GET", "/api/v1/legacy-admin-export"),
        ("DELETE", "/api/v1/debug/reset-cache"),
    ]

    for _ in range(8):
        method, path = random.choice(shadow_targets)
        send_request(
            method,
            path,
            "attacker_shadow_scanner",
            is_attack=True,
        )

    print("3. Simulating rapid BOLA ID enumeration and scraping burst...")
    for user_id in range(45, 75):
        send_request(
            "GET",
            f"/api/v1/users/{user_id}",
            "attacker_bola_scraper",
            is_attack=True,
        )

    print("Traffic simulation complete!")


if __name__ == "__main__":
    simulate_traffic()
