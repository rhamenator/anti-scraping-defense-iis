# anti-scraping-defense-iis/shared/honeypot_logger.py
# Modified for Windows/IIS Compatibility
# Dedicated logger for honeypot trigger events.

import logging
import json
import datetime
import os

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Define the base directory for your application on the Windows server
# Use the same environment variable as other modules for consistency
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs")

# --- Configuration ---
HONEYPOT_LOG_FILENAME = "honeypot_hits.log"
HONEYPOT_LOG_FILE = os.path.join(LOGS_DIR, HONEYPOT_LOG_FILENAME)

# Ensure the log directory exists
try:
    os.makedirs(LOGS_DIR, exist_ok=True)
except OSError as e:
    # Use standard print here as logger might not be configured yet
    print(f"ERROR: Could not create log directory {LOGS_DIR}: {e}")
    # Fallback or exit might be needed depending on requirements
    HONEYPOT_LOG_FILE = HONEYPOT_LOG_FILENAME # Fallback to current dir

# --- Logger Setup ---
# Use standard logging instead of print for setup messages
log_setup_logger = logging.getLogger(__name__ + '_setup') # Separate logger for setup phase

# Create a specific logger instance
honeypot_logger = logging.getLogger('honeypot_logger')
honeypot_logger.setLevel(logging.INFO) # Set level (e.g., INFO, DEBUG)
honeypot_logger.propagate = False # Prevent duplicating logs to root logger if root is configured

# Create a JSON formatter
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            'timestamp': datetime.datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger_name': record.name, # Added logger name for context
            'message': record.getMessage(),
            # Add extra context passed to the logger
            **(record.details if hasattr(record, 'details') else {})
        }
        # Include standard log record attributes if needed for debugging
        # log_record['pathname'] = record.pathname
        # log_record['lineno'] = record.lineno
        return json.dumps(log_record)

# Configure file handler only if not already configured (prevents duplicates on reload)
if not honeypot_logger.hasHandlers():
    try:
        # Use RotatingFileHandler for production logging if desired
        # from logging.handlers import RotatingFileHandler
        # file_handler = RotatingFileHandler(HONEYPOT_LOG_FILE, maxBytes=10*1024*1024, backupCount=5) # Example: 10MB files, keep 5 backups
        file_handler = logging.FileHandler(HONEYPOT_LOG_FILE, encoding='utf-8')
        formatter = JsonFormatter()
        file_handler.setFormatter(formatter)
        honeypot_logger.addHandler(file_handler)
        log_setup_logger.info(f"Honeypot logger configured to write to {HONEYPOT_LOG_FILE}")
    except Exception as e:
        log_setup_logger.error(f"ERROR setting up honeypot file logger for {HONEYPOT_LOG_FILE}: {e}")
        # Optionally add a StreamHandler as fallback for visibility if file setup fails
        # stream_handler = logging.StreamHandler()
        # stream_handler.setFormatter(formatter)
        # honeypot_logger.addHandler(stream_handler)
        # log_setup_logger.warning("Honeypot logger falling back to console output.")

# --- Logging Function ---

def log_honeypot_hit(details: dict):
    """
    Logs a honeypot hit event with structured details.

    Args:
        details (dict): A dictionary containing information about the hit,
                        e.g., {'ip': '...', 'user_agent': '...', 'path': '...', ...}
    """
    try:
        # Use the 'extra' argument mechanism for structured logging
        honeypot_logger.info("Honeypot triggered", extra={'details': details})
    except Exception as e:
        # Log error using the logger itself if possible, fallback to print
        try:
            honeypot_logger.error(f"ERROR in log_honeypot_hit function: {e}. Details: {details}", exc_info=True)
        except:
            print(f"FATAL ERROR in log_honeypot_hit logging: {e}. Details: {details}")


# Example usage block (for testing this module directly)
# if __name__ == "__main__":
#     log_setup_logger.setLevel(logging.INFO) # Ensure setup messages are visible
#     console_handler = logging.StreamHandler()
#     console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     console_handler.setFormatter(console_formatter)
#     log_setup_logger.addHandler(console_handler)
#     # Also add console handler to honeypot_logger for testing visibility
#     if not any(isinstance(h, logging.StreamHandler) for h in honeypot_logger.handlers):
#          honeypot_logger.addHandler(console_handler)

#     log_setup_logger.info(f"Running honeypot_logger test...")
#     test_details = {
#         "ip": "1.2.3.4",
#         "user_agent": "Test Honeypot Client - Windows",
#         "method": "GET",
#         "path": "/tarpit/decoy-link-abc",
#         "referer": "-",
#         "status": 200,
#         "timestamp_iso": datetime.datetime.utcnow().isoformat() + "Z"
#     }
#     log_honeypot_hit(test_details)
#     log_setup_logger.info(f"Check {HONEYPOT_LOG_FILE} for the JSON log entry.")

#     # Test error logging
#     log_setup_logger.info("Testing error logging within log_honeypot_hit...")
#     try:
#         # Simulate an error within the logging function call (e.g., un-serializable data)
#         unserializable_details = {"ip": "5.6.7.8", "data": datetime.datetime.now()} # datetime is not directly JSON serializable
#         log_honeypot_hit(unserializable_details) # This might fail inside JsonFormatter depending on setup
#     except Exception as e:
#         log_setup_logger.error(f"Caught exception during error logging test: {e}")