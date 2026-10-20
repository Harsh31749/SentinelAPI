import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import DB_PATH, SPEC_PATH
from database import init_db

DB_FILE = str(DB_PATH)
SPEC_FILE = str(SPEC_PATH)
logger = logging.getLogger(__name__)


class InvalidBearerToken(Exception):
    """Raised when a request has missing or invalid Bearer credentials."""


class JWTConfigurationError(Exception):
    """Raised when the JWT signing secret is missing or too weak."""


with open(SPEC_FILE, encoding="utf-8") as f:
    OPENAPI_SPEC = json.load(f)

DOCUMENTED_PATHS = {
    path: [method.upper() for method in methods.keys()]
    for path, methods in OPENAPI_SPEC.get("paths", {}).items()
}


def normalize_path(path: str) -> str:
    return re.sub(r"/users/\d+", "/users/{user_id}", path)


def authenticate_and_hash_actor(request: Request) -> tuple[str, str]:
    """Validate a JWT and return its hashed subject and a redacted auth label.

    Actor identity comes only from the verified JWT subject. X-Actor-ID is
    intentionally ignored because clients can freely modify that header.
    """
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise InvalidBearerToken

    token = parts[1]
    secret = os.getenv("SENTINEL_JWT_SECRET", "")

    # HS256 uses a 256-bit (32-byte) minimum secret for this application.
    if len(secret.encode("utf-8")) < 32:
        raise JWTConfigurationError

    issuer = os.getenv("SENTINEL_JWT_ISSUER", "sentinelapi-local")
    audience = os.getenv("SENTINEL_JWT_AUDIENCE", "sentinelapi")

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
            options={
                "require": ["sub", "iss", "aud", "iat", "exp"],
            },
        )
    except jwt.InvalidTokenError as exc:
        raise InvalidBearerToken from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise InvalidBearerToken

    # Preserve the existing gateway policy and telemetry hash format.
    actor_id = subject.strip()
    actor_hash = hashlib.sha256(actor_id.encode("utf-8")).hexdigest()[:12]

    return actor_hash, "Bearer [REDACTED]"


def get_policy_action(actor_hash: str) -> str | None:
    """Return the actor's configured policy action."""
    with closing(sqlite3.connect(DB_FILE, timeout=10)) as conn:
        conn.execute("PRAGMA busy_timeout = 10000")
        policy = conn.execute(
            "SELECT action FROM gateway_policies WHERE actor_hash = ?",
            (actor_hash,),
        ).fetchone()

    return policy[0] if policy else None


def write_telemetry(
    *,
    timestamp: str,
    actor_hash: str,
    auth_masked: str,
    method: str,
    path: str,
    normalized_path: str,
    status_code: int,
    payload_size: int,
    latency_ms: float,
    is_shadow: int,
    ground_truth: int,
) -> None:
    """Persist one request event to the telemetry database."""
    with closing(sqlite3.connect(DB_FILE, timeout=10)) as conn:
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute(
            """
            INSERT INTO api_logs (
                timestamp, actor_hash, auth_masked, method, raw_path,
                normalized_path, status_code, payload_size, latency_ms,
                is_shadow, ground_truth
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                actor_hash,
                auth_masked,
                method,
                path,
                normalized_path,
                status_code,
                payload_size,
                latency_ms,
                is_shadow,
                ground_truth,
            ),
        )
        conn.commit()


class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in ["/docs", "/openapi.json", "/redoc", "/favicon.ico"]:
            return await call_next(request)

        try:
            actor_hash, auth_masked = authenticate_and_hash_actor(request)
        except InvalidBearerToken:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing Bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        except JWTConfigurationError:
            logger.error(
                "JWT authentication is unavailable: "
                "SENTINEL_JWT_SECRET must be at least 32 bytes"
            )
            return JSONResponse(
                status_code=503,
                content={"detail": "Authentication service unavailable"},
            )

        start_perf = time.perf_counter()

        # Fail closed if the policy database cannot be checked.
        try:
            policy_action = get_policy_action(actor_hash)
        except sqlite3.Error:
            logger.exception("Policy lookup failed; rejecting request with 503")
            return JSONResponse(
                status_code=503,
                content={"detail": "Security policy service unavailable"},
            )

        if policy_action == "BLOCK":
            response = JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        "Blocked by AI API Security Analyzer Active Gateway Policy"
                    )
                },
            )
        else:
            response = await call_next(request)

        latency_ms = round((time.perf_counter() - start_perf) * 1000, 2)
        method = request.method.upper()
        normalized_path = normalize_path(path)
        allowed_methods = DOCUMENTED_PATHS.get(normalized_path, [])
        is_shadow = 0 if method in allowed_methods else 1

        content_length = response.headers.get("content-length")
        payload_size = int(content_length) if content_length else 0
        ground_truth = int(request.headers.get("X-Sim-Attack") == "1" or is_shadow == 1)

        # Log persistence failures without replacing the endpoint response.
        try:
            write_telemetry(
                timestamp=datetime.now(UTC).isoformat(),
                actor_hash=actor_hash,
                auth_masked=auth_masked,
                method=method,
                path=path,
                normalized_path=normalized_path,
                status_code=response.status_code,
                payload_size=payload_size,
                latency_ms=latency_ms,
                is_shadow=is_shadow,
                ground_truth=ground_truth,
            )
        except sqlite3.Error:
            logger.exception("Failed to persist API telemetry")

        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SentinelAPI",
    lifespan=lifespan,
)

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

    # Intentional BOLA flaw for isolated security-testing demonstrations.
    # This endpoint does not authorize access to the requested user.
    return {
        "id": user_id,
        "name": f"User_{user_id}",
        "email": f"user{user_id}@corp.internal",
        "role": "standard",
    }


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
