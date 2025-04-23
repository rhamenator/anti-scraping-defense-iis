# anti-scraping-defense-iis/admin_ui/admin_ui.py
# Modified for Windows/IIS Compatibility
# Flask application for the Admin Metrics Dashboard

from flask import Flask, render_template, jsonify
import os
import sys
import logging

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Define the base directory for your application on the Windows server
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True) # Ensure log directory exists

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Adjust Python Path ---
# Add parent directory to sys.path to find shared modules
# Assuming this script is in anti-scraping-defense-iis/admin_ui/
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
logger.debug(f"Parent directory added to sys.path: {parent_dir}")

# --- Import Shared Metrics Module ---
try:
    # Use absolute import now that parent dir is in path
    import metrics
    METRICS_AVAILABLE = True
    logger.info("Metrics module imported successfully by Admin UI.")
except ImportError as e:
    logger.error(f"ERROR: Could not import metrics module in Admin UI: {e}. Metrics will be unavailable.", exc_info=True)
    # Define dummy functions if metrics unavailable
    class MockMetrics:
        def get_metrics(self):
            return {"error": "Metrics module not available", "service_uptime_seconds": 0}
        def start_metrics_scheduler(self):
            logger.warning("Metrics scheduler cannot start: metrics module unavailable.")
        def increment_metric(self, key: str, value: int = 1): pass # Add dummy increment

    metrics = MockMetrics() # Use the mock object
    METRICS_AVAILABLE = False

# --- Flask App Setup ---
# Flask automatically looks for a 'templates' folder in the application root
# or relative to the blueprint location. If admin_ui.py is the app root,
# it should find 'templates/index.html'.
# If running via Waitress/Uvicorn, ensure the working directory is correct
# or explicitly set template_folder.
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
if not os.path.isdir(template_dir):
     logger.warning(f"Templates directory not found at default location relative to script: {template_dir}")
     # Optionally set explicit path based on APP_BASE_DIR if structure differs
     # template_dir = os.path.join(APP_BASE_DIR, 'admin_ui', 'templates')
     # logger.info(f"Setting explicit template folder: {template_dir}")

app = Flask(__name__, template_folder=template_dir)
# Optional: Configure static folder if needed
# static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
# app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)


# --- Start Metrics Scheduler ---
# Read environment variable defined in metrics.py (or via app config)
LOG_METRICS_TO_JSON = os.getenv("LOG_METRICS_TO_JSON", "false").lower() == "true"
if LOG_METRICS_TO_JSON and METRICS_AVAILABLE:
    # Start the scheduler in a background thread when the app initializes
    logger.info("LOG_METRICS_TO_JSON is enabled. Starting metrics scheduler...")
    try:
        metrics.start_metrics_scheduler()
    except Exception as e:
        logger.error(f"Failed to start metrics scheduler: {e}", exc_info=True)
else:
     logger.info("JSON metrics logging is disabled or metrics module unavailable. Scheduler not started.")


# --- Routes ---

@app.route('/')
def index():
    """Serves the main dashboard HTML page."""
    # The actual metrics data will be fetched by JavaScript in the template via the /metrics endpoint
    logger.info("Serving admin dashboard page.")
    try:
        return render_template('index.html')
    except Exception as e:
         logger.error(f"Error rendering template 'index.html': {e}", exc_info=True)
         # Provide a fallback error message
         return "<h1>Error loading dashboard</h1><p>Could not render the admin template.</p>", 500


@app.route('/metrics')
def metrics_endpoint():
    """Provides the current metrics as JSON."""
    if not METRICS_AVAILABLE:
        # Return an error status if metrics couldn't be loaded
        logger.warning("Metrics endpoint called, but metrics module is unavailable.")
        return jsonify({"error": "Metrics module unavailable"}), 500

    try:
        current_metrics = metrics.get_metrics()
        # logger.debug(f"Serving metrics: {current_metrics}") # Debug logging
        return jsonify(current_metrics)
    except Exception as e:
        logger.error(f"Error retrieving metrics: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve metrics"}), 500

# --- Hosting ---
# The following block is for direct execution (e.g., local testing).
# For production hosting with IIS + Waitress/Uvicorn + HttpPlatformHandler,
# this block will not be executed. The WSGI server will import the 'app' object.
if __name__ == '__main__':
    logger.warning("Running Flask app directly using development server (for testing only).")
    # Use Waitress for simple WSGI serving during local testing
    try:
        import waitress
        logger.info("Starting server with Waitress on http://127.0.0.1:5002")
        waitress.serve(app, host='127.0.0.1', port=5002)
    except ImportError:
         logger.warning("Waitress not found. Falling back to Flask development server.")
         # Fallback to Flask's built-in server (not recommended for anything but basic debugging)
         # Note: Flask dev server is single-threaded by default.
         app.run(host='127.0.0.1', port=5002, debug=False) # Set debug=True ONLY for development

# To run in production with IIS + HttpPlatformHandler + Waitress:
# 1. Install Waitress: pip install waitress
# 2. Configure HttpPlatformHandler in web.config to execute waitress-serve
#    Example web.config snippet for HttpPlatformHandler:
#    <httpPlatform processPath="C:\path\to\your\python\env\Scripts\waitress-serve.exe"
#                  arguments="--host 127.0.0.1 --port %HTTP_PLATFORM_PORT% admin_ui:app"
#                  stdoutLogEnabled="true"
#                  stdoutLogFile=".\logs\python_waitress.log"
#                  startupTimeLimit="60"
#                  processesPerApplication="1">
#      <environmentVariables>
#        <environmentVariable name="PYTHONPATH" value="C:\inetpub\wwwroot\anti_scraping_defense_iis" />
#        <environmentVariable name="FLASK_ENV" value="production" />
#        #        <environmentVariable name="APP_BASE_DIRECTORY" value="C:\inetpub\wwwroot\anti_scraping_defense_iis" />
#        <environmentVariable name="APP_SECRETS_DIRECTORY" value="C:\secrets" />
#        <environmentVariable name="LOG_METRICS_TO_JSON" value="true" />
#      </environmentVariables>
#    </httpPlatform>
# (Adjust paths and environment variables as needed)