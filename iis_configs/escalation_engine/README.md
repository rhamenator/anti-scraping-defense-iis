# README for Escalation Engine web.config (IIS Hosting)

This document explains the `web.config` file used to host the Python FastAPI Escalation Engine service under IIS using the `HttpPlatformHandler` module and the `uvicorn` ASGI server.

## Purpose

This configuration file instructs IIS to:

1. Launch a Python process using the specified executable.
2. Run the `uvicorn` ASGI server (with 2 workers by default) to serve the FastAPI application defined in `escalation.escalation_engine:app`.
3. Manage the lifecycle of the Python/Uvicorn process.
4. Proxy incoming HTTP requests routed to this IIS Application to the `uvicorn` process.
5. Set necessary environment variables required by the `escalation_engine.py` script, including paths, service endpoints, API keys/flags, and Redis details.

## Placement

This `web.config` file should be placed in the **root physical directory** mapped to the IIS Application created specifically for the Escalation Engine service.

## Configuration Placeholders

You **MUST** replace the following placeholders in the `web.config` file with values specific to your Windows server environment:

* **`C:\path\to\your\python\env\Scripts\python.exe`**: Replace with the absolute path to the `python.exe` executable within the Python virtual environment (or system installation) where the application's dependencies (`requirements.txt`) are installed.
* **`C:\inetpub\wwwroot\anti_scraping_defense_iis`**: Replace this value in the `PYTHONPATH` and `APP_BASE_DIRECTORY` environment variables with the absolute path to the root directory of your deployed `anti-scraping-defense-iis` application code.
* **`C:\secrets`**: Replace this value in the `APP_SECRETS_DIRECTORY` environment variable with the absolute path to the directory where your secret files (e.g., `redis_password.txt`, `external_api_key.txt`, `ip_reputation_api_key.txt`) are stored. Ensure the IIS Application Pool identity has read access to this directory and its files.

## Environment Variables

The `<environmentVariables>` section sets configuration values needed by `escalation_engine.py`:

* `PYTHONPATH`: Tells Python where to find the project modules.
* `APP_BASE_DIRECTORY`: Informs the script of its own base location for constructing other paths (models, config).
* `APP_SECRETS_DIRECTORY`: Defines the base location for secret files.
* `ESCALATION_WEBHOOK_URL`: URL of the AI Service webhook endpoint (defaults to localhost:8000).
* `RF_MODEL_FILENAME`, `ROBOTS_TXT_FILENAME`: Specifies the names of the ML model and robots.txt files within the `models` and `config` subdirectories (derived from `APP_BASE_DIRECTORY`).
* `REDIS_*`: Configures connection to Redis for frequency tracking.
* `LOCAL_LLM_*`, `EXTERNAL_*`, `IP_REPUTATION_*`, `ENABLE_*`, `CAPTCHA_*`: Configure optional integrations with external APIs, LLMs, IP reputation services, and CAPTCHA triggers. Filenames for API keys (`*_FILENAME`) are relative to `APP_SECRETS_DIRECTORY`.
* `KNOWN_BAD_UAS`, `KNOWN_BENIGN_CRAWLERS_UAS`: Comma-separated lists used for heuristic checks.
* `TRAINING_FREQ_WINDOW_SEC`: Time window (seconds) used for frequency analysis.
* `LOG_LEVEL`: Sets the logging verbosity.

## Dependencies

* IIS with `HttpPlatformHandler` module installed.
* Python environment with all packages from `requirements.txt` installed (including `fastapi`, `uvicorn`, `scikit-learn`, `joblib`, `redis`, `httpx`, etc.).
* The Random Forest model file (e.g., `bot_detection_rf_model.joblib`) must exist in the `models` directory (relative to `APP_BASE_DIRECTORY`).
* The `robots.txt` file must exist in the `config` directory.
* Accessible Redis instance.
* Accessible AI Service (at `ESCALATION_WEBHOOK_URL`).
* Accessible external APIs/LLMs if configured and enabled.
* Necessary secret files must exist in the `APP_SECRETS_DIRECTORY`.

## Logging

* The `stdoutLogFile` attribute in `<httpPlatform>` captures the console output from the `uvicorn` process. Check this file (`.\logs\python_escalation_stdout.log` relative to the app root) for startup errors or tracebacks.
* The Python application itself writes logs based on the `LOGS_DIR` derived from `APP_BASE_DIRECTORY`.
