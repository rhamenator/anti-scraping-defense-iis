# README for Admin UI web.config (IIS Hosting)

This document explains the `web.config` file used to host the Python Flask Admin UI service under IIS using the `HttpPlatformHandler` module and the `waitress` WSGI server.

## Purpose

This configuration file instructs IIS to:

1. Launch the `waitress-serve.exe` executable (which should be installed in your Python environment).
2. Run the `waitress` WSGI server to serve the Flask application instance named `app` found within the `admin_ui.py` module (specified as `admin_ui:app`).
3. Manage the lifecycle of the `waitress` process.
4. Proxy incoming HTTP requests routed to this IIS Application to the `waitress` process.
5. Set necessary environment variables required by the `admin_ui.py` script and the imported `metrics.py` module.

## Placement

This `web.config` file should be placed in the **root physical directory** mapped to the IIS Application created specifically for the Admin UI service.

## Configuration Placeholders

You **MUST** replace the following placeholders in the `web.config` file with values specific to your Windows server environment:

* **`C:\path\to\your\python\env\Scripts\waitress-serve.exe`**: Replace with the absolute path to the `waitress-serve.exe` executable within the Python virtual environment (or system installation) where the application's dependencies (`requirements.txt`, including `waitress`) are installed.
* **`C:\inetpub\wwwroot\anti_scraping_defense_iis`**: Replace this value in the `PYTHONPATH` and `APP_BASE_DIRECTORY` environment variables with the absolute path to the root directory of your deployed `anti-scraping-defense-iis` application code.
* **`C:\secrets`**: Replace this value in the `APP_SECRETS_DIRECTORY` environment variable with the absolute path to the directory where your secret files are stored. (Note: `admin_ui` itself may not directly need secrets, but other modules it uses, like `metrics.py`, might reference this base path).

## Environment Variables

The `<environmentVariables>` section sets configuration values:

* `PYTHONPATH`: Tells Python where to find the project modules (should be the `APP_BASE_DIRECTORY`).
* `APP_BASE_DIRECTORY`: Informs the script of its own base location for constructing other paths.
* `APP_SECRETS_DIRECTORY`: Defines the base location for secret files (used by other modules).
* `FLASK_ENV`: Set to `production` for security and performance.
* `LOG_METRICS_TO_JSON`, `METRICS_JSON_FILENAME`, `METRICS_DUMP_INTERVAL_MIN`: Configure the optional metrics JSON dumping feature managed by the `metrics.py` module (and started by `admin_ui.py`).
* `LOG_LEVEL`: Sets the logging verbosity (e.g., `INFO`, `DEBUG`).

## Logging

* The `stdoutLogFile` attribute in `<httpPlatform>` specifies where IIS will write the standard output/error of the `waitress` process (e.g., `.\logs\python_adminui_stdout.log`). Ensure the IIS Application Pool identity has write permissions to this location (relative to the IIS application's root).
* The Python application itself writes logs based on the `LOGS_DIR` derived from `APP_BASE_DIRECTORY`.

## Dependencies

* IIS with `HttpPlatformHandler` module installed.
* Python environment with all packages from `requirements.txt` installed (including `flask` and `waitress`).
* The shared `metrics.py` module must be available via the `PYTHONPATH`.
