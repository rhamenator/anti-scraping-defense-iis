# README for AI Service web.config (IIS Hosting)

This document explains the `web.config` file used to host the Python FastAPI AI Service (`ai_webhook.py`) under IIS using the `HttpPlatformHandler` module and the `uvicorn` ASGI server. This service receives escalations, manages the Redis blocklist, reports IPs, and sends alerts.

## Purpose

This configuration file instructs IIS to:

1. Launch a Python process using the specified executable.
2. Run the `uvicorn` ASGI server (with 2 workers by default) to serve the FastAPI application defined in `ai_service.ai_webhook:app`.
3. Manage the lifecycle of the Python/Uvicorn process.
4. Proxy incoming HTTP requests routed to this IIS Application (typically only internal requests from the Escalation Engine) to the `uvicorn` process.
5. Set necessary environment variables required by the `ai_webhook.py` script, including paths, Redis details, alerting configurations, and community reporting settings.

## Placement

This `web.config` file should be placed in the **root physical directory** mapped to the IIS Application created specifically for the AI Service.

## Configuration Placeholders

You **MUST** replace the following placeholders in the `web.config` file with values specific to your Windows server environment:

* **`C:\path\to\your\python\env\Scripts\python.exe`**: Replace with the absolute path to the `python.exe` executable within the Python virtual environment (or system installation) where the application's dependencies (`requirements.txt`) are installed.
* **`C:\inetpub\wwwroot\anti_scraping_defense_iis`**: Replace this value in the `PYTHONPATH` and `APP_BASE_DIRECTORY` environment variables with the absolute path to the root directory of your deployed `anti-scraping-defense-iis` application code.
* **`C:\secrets`**: Replace this value in the `APP_SECRETS_DIRECTORY` environment variable with the absolute path to the directory where your secret files (e.g., `redis_password.txt`, `smtp_password.txt`, `community_blocklist_api_key.txt`) are stored. Ensure the IIS Application Pool identity has read access to this directory and its files.

## Environment Variables

The `<environmentVariables>` section sets configuration values needed by `ai_webhook.py`:

* `PYTHONPATH`: Tells Python where to find the project modules.
* `APP_BASE_DIRECTORY`: Informs the script of its own base location for constructing log paths.
* `APP_SECRETS_DIRECTORY`: Defines the base location for secret files.
* `REDIS_*`: Configures connection to Redis for blocklisting. `REDIS_PASSWORD_FILENAME` specifies the name of the password file within `APP_SECRETS_DIRECTORY`.
* `BLOCKLIST_TTL_SECONDS`: Duration (in seconds) for which an IP remains blocklisted.
* `ALERT_METHOD`: Selects the alerting method (`none`, `webhook`, `slack`, `smtp`).
* `ALERT_MIN_REASON_SEVERITY`: Only triggers alerts for reasons at or above this severity level (e.g., "Local LLM", "High Combined Score").
* `ALERT_GENERIC_WEBHOOK_URL`, `ALERT_SLACK_WEBHOOK_URL`: URLs for specific alert methods.
* `ALERT_SMTP_*`: Configuration details for sending alerts via email (host, port, TLS, credentials). `ALERT_SMTP_PASSWORD_FILENAME` specifies the password file name within `APP_SECRETS_DIRECTORY`.
* `ENABLE_COMMUNITY_REPORTING`: Set to `true` to enable reporting blocked IPs.
* `COMMUNITY_BLOCKLIST_*`: Configuration for the community reporting API (URL, timeout). `COMMUNITY_BLOCKLIST_API_KEY_FILENAME` specifies the API key file name within `APP_SECRETS_DIRECTORY`.
* `LOG_LEVEL`: Sets the logging verbosity.

## Dependencies

* IIS with `HttpPlatformHandler` module installed.
* Python environment with all packages from `requirements.txt` installed (including `fastapi`, `uvicorn`, `redis`, `httpx`, `requests`).
* Accessible Redis instance.
* Network connectivity to configured alerting endpoints (Webhook, Slack, SMTP server) and community blocklist API (if enabled).
* Necessary secret files must exist in the `APP_SECRETS_DIRECTORY`.

## Logging

* The `stdoutLogFile` attribute in `<httpPlatform>` captures the console output from the `uvicorn` process. Check this file (`.\logs\python_aiservice_stdout.log` relative to the app root) for startup errors or tracebacks.
* The Python application itself writes detailed operational logs (blocks, alerts, errors, reports) to files within the `LOGS_DIR` derived from `APP_BASE_DIRECTORY` (e.g., `block_events.log`, `alert_events.log`).
