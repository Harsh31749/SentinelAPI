import random
import time
import requests

BASE_URL = "http://127.0.0.1:8000"

def simulate_traffic():
    print("1. Generating 120 baseline normal requests...")
    normal_endpoints = [
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/products"),
        ("GET", "/api/v1/orders"),
        ("POST", "/api/v1/orders"),
        ("GET", "/api/v1/users/5"),
        ("GET", "/api/v1/users/12")
    ]

    for i in range(120):
        method, path = random.choice(normal_endpoints)
        headers = {
            "Authorization": f"Bearer valid_jwt_token_user_{i % 5}",
            "X-Actor-ID": f"normal_user_{i % 5}",
            "X-Sim-Attack": "0"
        }
        requests.request(method, f"{BASE_URL}{path}", headers=headers)
        time.sleep(0.01)

    print("2. Simulating Shadow API discovery & exploitation...")
    shadow_targets = [
        ("GET", "/api/v1/legacy-admin-export"),
        ("DELETE", "/api/v1/debug/reset-cache")
    ]
    for _ in range(8):
        method, path = random.choice(shadow_targets)
        headers = {
            "Authorization": "Bearer compromised_token_99",
            "X-Actor-ID": "attacker_shadow_scanner",
            "X-Sim-Attack": "1"
        }
        requests.request(method, f"{BASE_URL}{path}", headers=headers)

    print("3. Simulating rapid BOLA ID enumeration & scraping burst...")
    for user_id in range(45, 75):
        headers = {
            "Authorization": "Bearer attacker_jwt_token",
            "X-Actor-ID": "attacker_bola_scraper",
            "X-Sim-Attack": "1"
        }
        requests.get(f"{BASE_URL}/api/v1/users/{user_id}", headers=headers)

    print("Traffic simulation complete!")

if __name__ == "__main__":
    simulate_traffic()