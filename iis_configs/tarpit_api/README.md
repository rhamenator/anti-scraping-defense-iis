# README for Tarpit API web.config (IIS Hosting)

This document explains the `web.config` file used to host the Python FastAPI Tarpit API service under IIS using the `HttpPlatformHandler` module.

## Purpose

This configuration file instructs IIS to:
1. Launch a Python process using the specified executable.
2. Run the `uvicorn` ASGI server to serve the FastAPI application defined in `tarpit.tarpit_api:app`.
3. Manage the lifecycle of the Python process (start, stop, monitor).
4. Proxy incoming HTTP requests routed to this IIS Application to the `uvicorn` process.
5. Set necessary environment variables required by the `tarpit_api.py` script.

## Placement

This `web.config` file should be placed in the **root physical directory** mapped to the IIS Application created specifically for the Tarpit API service.

## Configuration Placeholders

You **MUST** replace the following placeholders in the `web.config` file with values specific to your Windows server environment:

* **`C:\path\to\your\python\env\Scripts\python.exe`**: Replace with the absolute path to the `python.exe` executable within the Python virtual environment (or system installation) where the application's dependencies (`requirements.txt`) are installed.
* **`C:\inetpub\wwwroot\anti_scraping_defense_iis`**: Replace this value in the `PYTHONPATH` and `APP_BASE_DIRECTORY` environment variables with the absolute path to the root directory of your deployed `anti-scraping-defense-iis` application code.
* **`C:\secrets`**: Replace this value in the `APP_SECRETS_DIRECTORY` environment variable with the absolute path to the directory where your secret files (e.g., `redis_password.txt`, `pg_password.txt`) are stored. Ensure the IIS Application Pool identity has read access to this directory and its files.
* **`your_unique_windows_seed_value_change_me_!`**: Replace this value for the `SYSTEM_SEED` environment variable with a strong, unique, and unpredictable random string. This is critical for the deterministic generation features of the tarpit.

## Environment Variables

The `<environmentVariables>` section sets configuration values needed by `tarpit_api.py`:

* `PYTHONPATH`: Tells Python where to find the project modules (should be the `APP_BASE_DIRECTORY`).
* `APP_BASE_DIRECTORY`: Informs the script of its own base location for constructing other paths.
* `APP_SECRETS_DIRECTORY`: Tells the script where to look for secret files.
* `ESCALATION_ENDPOINT`: URL of the Escalation Engine service. Default assumes it runs locally on port 8003.
* `TAR_PIT_*`: Configures tarpit behavior (delays, hop limits).
* `SYSTEM_SEED`: Used for deterministic content generation. **MUST BE CHANGED.**
* `REDIS_*`: Configuration for connecting to Redis (host, port, password file name, database numbers for different functions).
* `PG_*`: Configuration for connecting to PostgreSQL Markov database (host, port, db name, user, password file name).
* `LOG_LEVEL`: Sets the logging verbosity (e.g., `INFO`, `DEBUG`).

## Logging

* The `stdoutLogFile` attribute in `<httpPlatform>` specifies where IIS will write the standard output/error of the `uvicorn` process (e.g., `.\logs\python_tarpit_stdout.log`). Ensure the IIS Application Pool identity has write permissions to this location (relative to the IIS application's root).
* The Python application itself writes logs based on the `LOGS_DIR` derived from `APP_BASE_DIRECTORY` (e.g., `C:\inetpub\wwwroot\anti_scraping_defense_iis\logs\`).

## Dependencies

* IIS with `HttpPlatformHandler` module installed.
* Python environment with all packages from `requirements.txt` installed.
* Accessible Redis instance.
* Accessible PostgreSQL instance with the Markov database schema initialized (`db/init_markov.sql`) and populated (`rag/train_markov_postgres.py`).
* Other dependent services (Escalation Engine) running and accessible at the configured URLs.