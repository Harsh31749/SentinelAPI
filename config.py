import os
from pathlib import Path

# Resolve defaults relative to the repository, not the shell's working directory.
ROOT_DIR = Path(__file__).resolve().parent


def configured_path(variable: str, default: str) -> Path:
    value = os.getenv(variable)
    path = Path(value).expanduser() if value else ROOT_DIR / default
    return path.resolve()


DB_PATH = configured_path("SENTINEL_DB_PATH", "telemetry.db")
SPEC_PATH = configured_path("SENTINEL_OPENAPI_PATH", "openapi.json")
