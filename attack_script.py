import os
import random
import time

import jwt
import requests

BASE_URL = "http://127.0.0.1:8000"
JWT_SECRET = os.getenv("SENTINEL_JWT_SECRET", "")
JWT_ISSUER = os.getenv("SENTINEL_JWT_ISSUER", "sentinelapi-local")
JWT_AUDIENCE = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinelapi")


def make_token(subject: str) -> str:
    """Create a short-lived JWT for a local security demonstration."""
    if len(JWT_SECRET.encode("utf-8")) < 32:
        raise RuntimeError(
            "SENTINEL_JWT_SECRET must be set to a secret of at least 32 bytes. "
            "Configure it in PowerShell before running this script."
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


def send_request(method: str, path: str, subject: str, is_attack: bool) -> None:
    """Send one request with a valid JWT and simulation metadata."""
    headers = {
        "Authorization": f"Bearer {make_token(subject)}",
        "X-Actor-ID": subject,
        "X-Sim-Attack": "1" if is_attack else "0",
    }

    try:
        response = requests.request(
            method,
            f"{BASE_URL}{path}",
            headers=headers,
            timeout=5,
        )
        print(f"{method} {path} -> HTTP {response.status_code}")
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
        subject = f"normal_user_{i % 5}"
        send_request(method, path, subject, is_attack=False)
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
