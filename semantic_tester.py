import json
import sqlite3
from datetime import datetime, timezone
import requests

DB_FILE = "telemetry.db"
SPEC_FILE = "openapi.json"
BASE_URL = "http://127.0.0.1:8000"

def init_semantic_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
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
    conn.commit()
    conn.close()

def run_semantic_tests():
    init_semantic_db()
    with open(SPEC_FILE, "r") as f:
        spec = json.load(f)

    results = []
    paths = spec.get("paths", {})

    # 1. Automated BOLA Test: Authenticate as User 1, attempt to access User 2's private object
    for path, methods in paths.items():
        if "{user_id}" in path and "get" in methods:
            target_url = f"{BASE_URL}{path.replace('{user_id}', '2')}"
            headers = {
                "Authorization": "Bearer token_user_1",
                "X-Actor-ID": "semantic_fuzzer_user_1",
                "X-User-Role": "standard",
                "X-Authenticated-User-ID": "1"
            }
            resp = requests.get(target_url, headers=headers)
            # If User 1 gets a 200 OK when requesting User 2's resource, BOLA is confirmed!
            is_vuln = 1 if resp.status_code == 200 else 0
            evidence = (
                f"CRITICAL BOLA: User 1 accessed User 2's private record (HTTP {resp.status_code})"
                if is_vuln else f"Secure: Access denied with HTTP {resp.status_code}"
            )
            results.append((
                datetime.now(timezone.utc).isoformat(),
                "BOLA (Broken Object Level Auth)",
                path,
                "GET",
                "User_1 (Standard)",
                "User_2 Resource (ID=2)",
                resp.status_code,
                is_vuln,
                evidence
            ))

    # 2. Automated BFLA Test: Use a standard consumer token to invoke sensitive DELETE/Admin functions
    bfla_targets = [
        ("DELETE", "/api/v1/debug/reset-cache", "Admin Cache Purge"),
        ("GET", "/api/v1/legacy-admin-export", "Admin Database Export")
    ]
    for method, path, desc in bfla_targets:
        headers = {
            "Authorization": "Bearer token_low_priv_user",
            "X-Actor-ID": "semantic_fuzzer_low_priv",
            "X-User-Role": "guest"
        }
        resp = requests.request(method, f"{BASE_URL}{path}", headers=headers)
        is_vuln = 1 if resp.status_code == 200 else 0
        evidence = (
            f"CRITICAL BFLA: Low-privilege 'guest' role executed '{desc}' (HTTP {resp.status_code})"
            if is_vuln else f"Secure: Function blocked with HTTP {resp.status_code}"
        )
        results.append((
            datetime.now(timezone.utc).isoformat(),
            "BFLA (Broken Function Level Auth)",
            path,
            method,
            "Guest (Low-Privilege)",
            desc,
            resp.status_code,
            is_vuln,
            evidence
        ))

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO semantic_test_results (
            timestamp, test_type, endpoint, method, actor_used,
            target_resource, status_code, vulnerable, evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, results)
    conn.commit()
    conn.close()
    return len(results)

if __name__ == "__main__":
    count = run_semantic_tests()
    print(f"Executed {count} schema-aware semantic security tests.")