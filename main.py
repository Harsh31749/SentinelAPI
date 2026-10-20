import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

DB_FILE = "telemetry.db"
SPEC_FILE = "openapi.json"

with open(SPEC_FILE, "r") as f:
    OPENAPI_SPEC = json.load(f)

DOCUMENTED_PATHS = {
    path: [method.upper() for method in methods.keys()]
    for path, methods in OPENAPI_SPEC.get("paths", {}).items()
}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Ensure api_logs has the autoencoder_mse column for the final project
    cursor.execute("PRAGMA table_info(api_logs)")
    columns = [col[1] for col in cursor.fetchall()]
    if columns and "autoencoder_mse" not in columns:
        cursor.execute("DROP TABLE api_logs")

    cursor.execute("""
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

    # Gateway policy table for active blocking / rate-limiting
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gateway_policies (
            actor_hash TEXT PRIMARY KEY,
            action TEXT,
            reason TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def normalize_path(path: str) -> str:
    return re.sub(r"/users/\d+", "/users/{user_id}", path)

def redact_and_hash_actor(request: Request) -> tuple[str, str]:
    auth_header = request.headers.get("Authorization", "")
    client_host = request.client.host if request.client else "127.0.0.1"
    actor_id = request.headers.get("X-Actor-ID", client_host)
    actor_hash = hashlib.sha256(actor_id.encode()).hexdigest()[:12]

    if auth_header.startswith("Bearer "):
        auth_masked = "Bearer [REDACTED]"
    elif auth_header:
        auth_masked = "[REDACTED_SECRET]"
    else:
        auth_masked = "None"
    return actor_hash, auth_masked

class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in ["/docs", "/openapi.json", "/redoc", "/favicon.ico"]:
            return await call_next(request)

        actor_hash, auth_masked = redact_and_hash_actor(request)

        # Check Active Gateway Mitigation Policies
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT action FROM gateway_policies WHERE actor_hash = ?", (actor_hash,))
        policy = cursor.fetchone()

        start_perf = time.perf_counter()
        if policy and policy[0] == "BLOCK":
            response = JSONResponse(
                status_code=403,
                content={"detail": "Blocked by AI API Security Analyzer Active Gateway Policy"}
            )
        else:
            response = await call_next(request)
        latency_ms = round((time.perf_counter() - start_perf) * 1000, 2)

        method = request.method.upper()
        norm_path = normalize_path(path)
        allowed_methods = DOCUMENTED_PATHS.get(norm_path, [])
        is_shadow = 0 if method in allowed_methods else 1

        content_length = response.headers.get("content-length")
        payload_size = int(content_length) if content_length else 0
        sim_label = 1 if request.headers.get("X-Sim-Attack") == "1" or is_shadow == 1 else 0

        cursor.execute("""
            INSERT INTO api_logs (
                timestamp, actor_hash, auth_masked, method, raw_path,
                normalized_path, status_code, payload_size, latency_ms,
                is_shadow, ground_truth
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(),
            actor_hash,
            auth_masked,
            method,
            path,
            norm_path,
            response.status_code,
            payload_size,
            latency_ms,
            is_shadow,
            sim_label
        ))
        conn.commit()
        conn.close()
        return response

app = FastAPI(title="SentinelAPI — Protected Core Service & Gateway")
app.add_middleware(TelemetryMiddleware)

@app.get("/api/v1/users")
def list_users():
    return [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]

@app.post("/api/v1/users")
def create_user():
    return {"status": "created", "id": 3}

@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int, request: Request):
    if user_id > 50:
        raise HTTPException(status_code=404, detail="User record not found")
    # Intentional BOLA flaw for semantic testing demonstration:
    # Does not verify if X-Authenticated-User-ID matches user_id!
    return {"id": user_id, "name": f"User_{user_id}", "email": f"user{user_id}@corp.internal", "role": "standard"}

@app.get("/api/v1/products")
def list_products():
    return [{"sku": "P100", "item": "Router"}, {"sku": "P200", "item": "Switch"}]

@app.get("/api/v1/orders")
def list_orders():
    return [{"order_id": 9001, "total": 2500}]

@app.post("/api/v1/orders")
def create_order():
    return {"status": "order_placed", "order_id": 9002}

@app.get("/api/v1/legacy-admin-export")
def legacy_export():
    return {"dump": "UNENCRYPTED_CUSTOMER_RECORDS_BACKUP_2025", "records": 14200}

@app.delete("/api/v1/debug/reset-cache")
def debug_reset():
    return {"status": "internal_cache_purged"}