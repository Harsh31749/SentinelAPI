# SentinelAPI

**AI-Assisted API Security Monitoring and Anomaly Detection**

SentinelAPI is a Python-based API security project combining request telemetry, gateway policy enforcement, anomaly scoring, and security testing. It provides a foundation for exploring how API traffic can be monitored and assessed for suspicious behavior.

## Features

- **API gateway:** FastAPI-based service with request middleware.
- **Telemetry collection:** Records request metadata and response status in SQLite.
- **Policy enforcement:** Supports actor-based blocking policies.
- **Database migrations:** Uses versioned migrations to evolve the database schema while preserving existing telemetry.
- **Anomaly analysis:** Includes a machine-learning component for analyzing API activity.
- **Security testing:** Includes scripts for API security testing and semantic checks.
- **Dashboard:** Provides a Streamlit interface for inspecting security telemetry.
- **Automated tests:** Includes pytest tests for database migrations and API behavior.

## Technology Stack

- Python
- FastAPI and Uvicorn
- SQLite
- Streamlit
- NumPy, pandas, scikit-learn, and PyTorch
- pytest and Ruff

## Project Structure

| File or directory | Purpose |
|---|---|
| `main.py` | FastAPI application and gateway middleware |
| `config.py` | Centralized paths and environment configuration |
| `database.py` | SQLite schema and versioned migrations |
| `model.py` | Machine-learning and anomaly-analysis logic |
| `dashboard.py` | Streamlit monitoring dashboard |
| `semantic_tester.py` | API semantic security testing |
| `attack_script.py` | Security testing script |
| `openapi.json` | OpenAPI specification |
| `tests/` | Automated tests |
| `requirements.txt` | Python dependencies |
| `pyproject.toml` | Ruff and pytest configuration |

## Requirements

- Python 3.11 or compatible version
- pip
- PowerShell on Windows, or an equivalent terminal
- The dependencies listed in `requirements.txt`

## Installation

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration

SentinelAPI supports these environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `SENTINEL_DB_PATH` | SQLite database location | `telemetry.db` in the project directory |
| `SENTINEL_OPENAPI_PATH` | OpenAPI specification location | `openapi.json` in the project directory |

For a PowerShell session, for example:

```powershell
$env:SENTINEL_DB_PATH = "D:\SentinelData\telemetry.db"
```

Set custom paths before launching the application. Ensure the process has permission to access the configured files.

## Running the API

Start the FastAPI service:

```powershell
uvicorn main:app --reload
```

When the application starts, its lifespan handler initializes the database and applies pending migrations.

Open the interactive API documentation at:

`http://127.0.0.1:8000/docs`

## Running the Dashboard

In a separate terminal with the virtual environment activated:

```powershell
streamlit run dashboard.py
```

## Running the Tests

Run the automated test suite:

```powershell
python -m pytest -q
```

Check code style and lint rules:

```powershell
python -m ruff format --check .
python -m ruff check .
```

Measure database-module test coverage:

```powershell
python -m pytest -q --cov=database --cov-report=term-missing
```

## Database Safety

Database schema changes are managed through versioned migrations. The migration tests check that existing telemetry is preserved when `autoencoder_mse` is added, repeated initialization is safe, and failed migrations roll back.

Back up important databases before upgrading or experimenting with schema changes.

## Security and Limitations

This project is intended for development, testing, and demonstration unless it has undergone a separate production security review.

- Run security tests only against systems you own or are explicitly authorized to assess.
- Do not expose the development server directly to the public internet.
- Review authentication, authorization, secrets management, logging privacy, and deployment configuration before production use.
- Machine-learning anomaly scores should be treated as signals for investigation, not proof of malicious activity.

## Current Test Status

The database migration tests and core API tests have passed in the development environment. The database module has achieved 100% statement coverage in the reported test run. A dependency deprecation warning remains in the test environment.

Re-run the test suite in your own environment before relying on these results.

## License

Add the project's chosen license before distributing or publishing it. Until a license is included, do not assume others have permission to reuse the code.
