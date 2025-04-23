# anti-scraping-defense-iis/metrics.py
# Modified for Windows/IIS Compatibility
# Simple in-memory metrics tracking for the defense stack.

from collections import Counter
import datetime
import threading
import json
import os
import schedule
import time
import logging

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Define the base directory for your application on the Windows server
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True) # Ensure log directory exists

# --- Setup Logging ---
# Use a distinct logger name for this module
logger = logging.getLogger('metrics_module')
# Basic config if not configured by the calling application
if not logging.getLogger().hasHandlers():
     logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Configuration ---
LOG_METRICS_TO_JSON = os.getenv("LOG_METRICS_TO_JSON", "false").lower() == "true"
# Construct path for the JSON file using LOGS_DIR
METRICS_JSON_FILENAME = os.getenv("METRICS_JSON_FILENAME", "metrics_dump.json")
METRICS_JSON_FILE = os.path.join(LOGS_DIR, METRICS_JSON_FILENAME)
METRICS_DUMP_INTERVAL_MIN = int(os.getenv("METRICS_DUMP_INTERVAL_MIN", 60)) # Dump every hour by default


# Use a thread-safe Counter for basic metrics
metrics_store = Counter()
# Lock for operations that might not be inherently atomic if extended
_lock = threading.Lock()

# Store the start time
start_time = datetime.datetime.utcnow()
logger.info("Metrics store initialized.")

def increment_metric(key: str, value: int = 1):
    """Increments a counter metric."""
    with _lock:
        metrics_store[key] += value
        # logger.debug(f"Metric incremented: {key} = {metrics_store[key]}") # Optional: Verbose debug logging

def get_metrics() -> dict:
    """Returns a dictionary of all current metrics."""
    with _lock:
        # Add uptime calculation
        uptime_seconds = (datetime.datetime.utcnow() - start_time).total_seconds()
        current_metrics = dict(metrics_store)
        current_metrics["service_uptime_seconds"] = round(uptime_seconds, 2)
        current_metrics["last_updated_utc"] = datetime.datetime.utcnow().isoformat() + "Z"
        return current_metrics

def reset_metrics():
    """Resets all metrics (useful for testing)."""
    global start_time
    with _lock:
        metrics_store.clear()
        start_time = datetime.datetime.utcnow()
        logger.info("Metrics have been reset.")

# --- JSON Logging ---
def dump_metrics_to_json():
    """Dumps the current metrics store to a JSON file."""
    # This function is called by the scheduler if enabled
    if not LOG_METRICS_TO_JSON:
        # This check prevents unnecessary logging if the scheduler somehow runs
        # when the feature is disabled after startup.
        return

    logger.info(f"Dumping metrics to {METRICS_JSON_FILE}...")
    try:
        metrics_snapshot = get_metrics() # Get current metrics including uptime etc.
        # Ensure directory exists (redundant if LOGS_DIR creation works, but safe)
        os.makedirs(os.path.dirname(METRICS_JSON_FILE), exist_ok=True)
        with open(METRICS_JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(metrics_snapshot, f, indent=2)
        logger.info(f"Metrics successfully dumped to {METRICS_JSON_FILE}")
    except Exception as e:
        logger.error(f"ERROR: Failed to dump metrics to JSON file {METRICS_JSON_FILE}: {e}", exc_info=True)

def run_scheduled_dump():
    """Wrapper function for the scheduler to call dump_metrics_to_json."""
    # This function is the target for the schedule.every().do() call
    logger.debug("Scheduled metrics dump triggered.")
    dump_metrics_to_json()

# --- Metrics Scheduler (Run in one of the services, e.g., admin_ui or ai_service) ---
# Global flag to prevent starting multiple scheduler threads if imported multiple times
_scheduler_started = False
_scheduler_thread = None
_scheduler_lock = threading.Lock()

def start_metrics_scheduler():
    """Starts the background scheduler for dumping metrics if enabled."""
    global _scheduler_started, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_started:
            logger.debug("Metrics dump scheduler already started.")
            return

        if LOG_METRICS_TO_JSON:
            logger.info(f"Scheduling metrics JSON dump every {METRICS_DUMP_INTERVAL_MIN} minutes to {METRICS_JSON_FILE}")
            # Set up the schedule job
            schedule.every(METRICS_DUMP_INTERVAL_MIN).minutes.do(run_scheduled_dump)

            # Define the function that runs the scheduler loop
            def run_continuously(interval=30): # Check every 30 seconds
                logger.info(f"Metrics scheduler thread started (PID: {os.getpid()}, TID: {threading.get_ident()}). Checking every {interval}s.")
                while True:
                    try:
                        schedule.run_pending()
                        time.sleep(interval)
                    except Exception as e:
                         logger.error(f"Exception in metrics scheduler thread: {e}", exc_info=True)
                         # Avoid busy-looping on continuous errors
                         time.sleep(interval * 2)


            # Start the scheduler loop in a separate daemon thread
            # Daemon threads exit when the main program exits
            _scheduler_thread = threading.Thread(target=run_continuously, daemon=True)
            _scheduler_thread.start()
            _scheduler_started = True
            logger.info("Metrics dump scheduler thread running.")
        else:
            logger.info("JSON metrics logging is disabled. Scheduler not started.")

# --- Predefined Metric Keys (Examples) ---
# (These remain unchanged)
METRIC_ESCALATION_REQUESTS = "escalation_requests_received"
METRIC_HEURISTIC_CHECKS = "heuristic_checks_run"
# ... add other keys as needed ...

# Example: How to start the scheduler from another module
# This block is primarily for testing the metrics module itself.
# if __name__ == "__main__":
#     logger.info("Starting metrics scheduler (example)...")
#     # Need to enable JSON logging via environment variable for this test
#     # Example: set LOG_METRICS_TO_JSON=true (Windows) or export LOG_METRICS_TO_JSON=true (Linux/macOS)
#     if LOG_METRICS_TO_JSON:
#         start_metrics_scheduler()
#         # Keep the main thread alive or let the service run its course
#         try:
#              logger.info("Scheduler started for testing. Press Ctrl+C to stop.")
#              while True: time.sleep(1)
#         except KeyboardInterrupt:
#              logger.info("Stopping scheduler example.")
#     else:
#          logger.warning("Set LOG_METRICS_TO_JSON=true environment variable to test scheduler.")