# anti-scraping-defense-iis/ai_service/ai_webhook.py
# Modified for Windows/IIS Compatibility
# Receives webhook events, logs, blocklists via Redis, reports, and sends alerts.

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field, ValidationError
from typing import Dict, Any, Literal, Optional
import datetime
import pprint
import os
import sys
import redis # For blocklisting
import json
import httpx # For sending generic webhook alerts
import smtplib # For sending alerts via email
import ssl # For SMTP TLS/SSL
from email.mime.text import MIMEText # For sending alerts via email
import requests # Using requests for Slack webhook simplicity (sync call)
import asyncio # For running sync code in thread pool
import logging

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
SECRETS_DIR = os.getenv("APP_SECRETS_DIRECTORY", r"C:\secrets") # Example path for secrets
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True) # Ensure log directory exists

# --- Adjust Python Path ---
# Add parent directory to sys.path to find shared modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- Import Shared Metrics Module ---
try:
    from metrics import increment_metric
    logger.debug("Metrics module imported successfully.")
except ImportError:
    logger.warning("Could not import metrics module.")
    def increment_metric(key: str, value: int = 1): pass


# --- Configuration ---
# Redis (Blocklist)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB_BLOCKLIST = int(os.getenv("REDIS_DB_BLOCKLIST", 2)) # Use separate DB for blocklist
REDIS_PASSWORD_FILENAME = os.getenv("REDIS_PASSWORD_FILENAME", "redis_password.txt")
REDIS_PASSWORD_FILE = os.path.join(SECRETS_DIR, REDIS_PASSWORD_FILENAME)
BLOCKLIST_KEY_PREFIX = "blocklist:" # Use same prefix as Tarpit blocker (e.g., "blocklist:ip:<ip>") - Adjusted!
BLOCKLIST_TTL_SECONDS = int(os.getenv("BLOCKLIST_TTL_SECONDS", 86400)) # Default to 1 day

# Alerting Method & Config
ALERT_METHOD = os.getenv("ALERT_METHOD", "none").lower() # Options: "webhook", "slack", "smtp", "none"
ALERT_GENERIC_WEBHOOK_URL = os.getenv("ALERT_GENERIC_WEBHOOK_URL")
ALERT_SLACK_WEBHOOK_URL = os.getenv("ALERT_SLACK_WEBHOOK_URL")
ALERT_SMTP_HOST = os.getenv("ALERT_SMTP_HOST")
ALERT_SMTP_PORT = int(os.getenv("ALERT_SMTP_PORT", 587))
ALERT_SMTP_USER = os.getenv("ALERT_SMTP_USER")
ALERT_SMTP_PASSWORD_FILENAME = os.getenv("ALERT_SMTP_PASSWORD_FILENAME", "smtp_password.txt")
ALERT_SMTP_PASSWORD_FILE = os.path.join(SECRETS_DIR, ALERT_SMTP_PASSWORD_FILENAME) # Full path
ALERT_SMTP_USE_TLS = os.getenv("ALERT_SMTP_USE_TLS", "true").lower() == "true"
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", ALERT_SMTP_USER) # Default From to User if not set
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO") # Comma-separated list
ALERT_MIN_REASON_SEVERITY = os.getenv("ALERT_MIN_REASON_SEVERITY", "Local LLM")

# Community Blocklist Reporting Config (NEW)
ENABLE_COMMUNITY_REPORTING = os.getenv("ENABLE_COMMUNITY_REPORTING", "false").lower() == "true"
COMMUNITY_BLOCKLIST_REPORT_URL = os.getenv("COMMUNITY_BLOCKLIST_REPORT_URL") # e.g., AbuseIPDB API endpoint
COMMUNITY_BLOCKLIST_API_KEY_FILENAME = os.getenv("COMMUNITY_BLOCKLIST_API_KEY_FILENAME", "community_blocklist_api_key.txt")
COMMUNITY_BLOCKLIST_API_KEY_FILE = os.path.join(SECRETS_DIR, COMMUNITY_BLOCKLIST_API_KEY_FILENAME) # Full path
COMMUNITY_BLOCKLIST_REPORT_TIMEOUT = float(os.getenv("COMMUNITY_BLOCKLIST_REPORT_TIMEOUT", 10.0))

# Logging Configuration (Using LOGS_DIR)
BLOCK_LOG_FILE = os.path.join(LOGS_DIR, "block_events.log")
ALERT_LOG_FILE = os.path.join(LOGS_DIR, "alert_events.log")
ERROR_LOG_FILE = os.path.join(LOGS_DIR, "aiservice_errors.log")
COMMUNITY_REPORT_LOG_FILE = os.path.join(LOGS_DIR, "community_report.log")

# --- Load Secrets ---
def load_secret(full_file_path: Optional[str]) -> Optional[str]:
    """Loads a secret from a file given its full path."""
    if not full_file_path:
        logger.debug("load_secret called with None path.")
        return None
    if os.path.exists(full_file_path):
        try:
            with open(full_file_path, 'r') as f:
                secret = f.read().strip()
                if secret:
                    logger.info(f"Loaded secret successfully from: {full_file_path}")
                    return secret
                else:
                    logger.warning(f"Secret file is empty: {full_file_path}")
                    return None
        except Exception as e:
            logger.error(f"Failed to read secret from {full_file_path}: {e}")
    else:
        logger.warning(f"Secret file not found: {full_file_path}")
    return None

# Populate password/key variables from secrets using full paths
REDIS_PASSWORD = load_secret(REDIS_PASSWORD_FILE)
ALERT_SMTP_PASSWORD = load_secret(ALERT_SMTP_PASSWORD_FILE)
COMMUNITY_BLOCKLIST_API_KEY = load_secret(COMMUNITY_BLOCKLIST_API_KEY_FILE)

# --- Setup Clients & Validate Config ---

# Redis Client for Blocklisting
BLOCKLISTING_ENABLED = False
redis_client_blocklist = None
try:
    redis_pool_blocklist = redis.ConnectionPool(
        host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB_BLOCKLIST,
        password=REDIS_PASSWORD, decode_responses=True
    )
    redis_client_blocklist = redis.Redis(connection_pool=redis_pool_blocklist)
    redis_client_blocklist.ping()
    logger.info(f"Connected to Redis for blocklisting at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB_BLOCKLIST}")
    BLOCKLISTING_ENABLED = True
except redis.exceptions.AuthenticationError:
     logger.error(f"ERROR: Redis authentication failed for Blocklisting (DB: {REDIS_DB_BLOCKLIST}). Check password.")
     BLOCKLISTING_ENABLED = False
except redis.exceptions.ConnectionError as e:
    logger.error(f"Redis connection failed for Blocklisting: {e}. Blocklisting disabled.")
    BLOCKLISTING_ENABLED = False
except Exception as e:
    logger.error(f"Unexpected error connecting to Redis for Blocklisting: {e}. Blocklisting disabled.")
    BLOCKLISTING_ENABLED = False


# Check SMTP config
if ALERT_METHOD == "smtp":
    if not ALERT_EMAIL_TO or not ALERT_SMTP_HOST or not ALERT_EMAIL_FROM:
         logger.error("SMTP alert method configured but missing required fields: ALERT_EMAIL_TO, ALERT_SMTP_HOST, ALERT_EMAIL_FROM.")
         ALERT_METHOD = "none" # Disable SMTP if misconfigured
    elif not ALERT_SMTP_PASSWORD and ALERT_SMTP_USER:
         logger.warning("SMTP alerting configured with user but SMTP password is not set (via env/secret file). Authentication may fail.")

# Check Community Reporting config
if ENABLE_COMMUNITY_REPORTING:
    if not COMMUNITY_BLOCKLIST_REPORT_URL:
        logger.warning("Community reporting enabled but COMMUNITY_BLOCKLIST_REPORT_URL is not set.")
    if not COMMUNITY_BLOCKLIST_API_KEY:
        logger.warning(f"Community reporting enabled but COMMUNITY_BLOCKLIST_API_KEY secret could not be loaded from {COMMUNITY_BLOCKLIST_API_KEY_FILE}.")


# --- Pydantic Model ---
# (Remains the same)
class WebhookEvent(BaseModel):
    event_type: str = Field(..., description="Type of event, e.g., 'suspicious_activity_detected'")
    reason: str = Field(..., description="Reason for the event/block, e.g., 'High Combined Score (0.95)'")
    timestamp_utc: str | datetime.datetime = Field(..., description="Timestamp of the original detection")
    details: Dict[str, Any] = Field(..., description="Detailed metadata about the request (IP, UA, headers, etc.)")

# --- FastAPI App ---
app = FastAPI(
    title="AI Defense Webhook Service (IIS Version)",
    description="Receives analysis results, manages blocklists (with TTL), reports IPs, and sends alerts."
)

# --- Helper Functions ---

def log_error(message: str, exception: Optional[Exception] = None):
    """Logs errors to a dedicated error log file and standard logger."""
    try:
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        log_entry = f"{timestamp} - ERROR: {message}"
        if exception: log_entry += f" | Exception: {type(exception).__name__}: {exception}"
        logger.error(log_entry, exc_info=exception is not None) # Use standard logger with exception info
        # Use with block for file writing
        with open(ERROR_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    except Exception as log_e:
        # Fallback to print if logging fails
        print(f"FATAL: Could not write to error log file {ERROR_LOG_FILE}: {log_e}")
        print(f"Original error: {log_entry}")

def log_event(log_file: str, event_type: str, data: dict):
    """Logs structured events to a specified file."""
    try:
        # Ensure data is JSON serializable (handle datetime etc.)
        def default_serializer(obj):
            if isinstance(obj, datetime.datetime): return obj.isoformat()
            return str(obj) # Fallback to string representation

        serializable_data = json.loads(json.dumps(data, default=default_serializer))
        log_entry = { "timestamp": datetime.datetime.utcnow().isoformat() + "Z", "event_type": event_type, **serializable_data }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        log_error(f"Failed to write to log file {log_file}", e)

# --- Action Functions ---

# --- MODIFIED BLOCKLIST FUNCTION ---
def add_ip_to_blocklist(ip_address: str, reason: str, event_details: dict = None) -> bool:
    """Adds an IP address as a key in Redis with a TTL."""
    if not BLOCKLISTING_ENABLED or not ip_address or ip_address == "unknown":
        if ip_address == "unknown":
            logger.warning(f"Attempted to blocklist 'unknown' IP. Reason: {reason}. Details: {event_details}")
        elif not BLOCKLISTING_ENABLED:
             logger.warning(f"Blocklisting disabled. Cannot block IP {ip_address}.")
        return False

    try:
        # Use a consistent key prefix - Ensure this matches Tarpit and potential IIS module usage
        # Example: blocklist:ip:1.2.3.4
        block_key = f"{BLOCKLIST_KEY_PREFIX}ip:{ip_address}" # Adjusted key format

        block_metadata = json.dumps({
            "reason": reason,
            "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "user_agent": event_details.get('user_agent', 'N/A') if event_details else 'N/A'
        })

        # Use SETEX to set the key with the TTL
        success = redis_client_blocklist.setex(block_key, BLOCKLIST_TTL_SECONDS, block_metadata)

        if success:
            logger.info(f"Added/Refreshed IP {ip_address} to Redis blocklist (Key: {block_key}) with TTL {BLOCKLIST_TTL_SECONDS}s. Reason: {reason}")
            log_event(BLOCK_LOG_FILE, "BLOCKLIST_ADD_TTL", {
                "ip_address": ip_address,
                "reason": reason,
                "ttl_seconds": BLOCKLIST_TTL_SECONDS,
                "details": event_details # log original details as well
            })
            increment_metric("blocklist_ips_added")
            return True
        else:
            logger.error(f"Redis SETEX command failed for blocklist key {block_key} (IP: {ip_address}).")
            increment_metric("blocklist_redis_errors")
            return False

    except redis.exceptions.RedisError as e:
        log_error(f"Redis error setting blocklist key for IP {ip_address}", e)
        increment_metric("blocklist_redis_errors")
        return False
    except Exception as e:
        log_error(f"Unexpected error setting blocklist key for IP {ip_address}", e)
        increment_metric("blocklist_unexpected_errors")
        return False

# --- Community Reporting Function (NEW) ---
# (Logic remains the same, uses configured API URL and Key)
async def report_ip_to_community(ip: str, reason: str, details: dict) -> bool:
    """Reports a blocked IP address to a configured community blocklist service."""
    if not ENABLE_COMMUNITY_REPORTING or not COMMUNITY_BLOCKLIST_REPORT_URL or not COMMUNITY_BLOCKLIST_API_KEY or not ip:
        if ENABLE_COMMUNITY_REPORTING and ip: logger.debug(f"Community reporting skipped for IP {ip}: URL or API Key not configured/loaded.")
        return False

    increment_metric("community_reports_attempted")
    logger.info(f"Reporting IP {ip} to community blocklist: {COMMUNITY_BLOCKLIST_REPORT_URL}")
    # --- Adapt Payload and Headers for the specific API ---
    # Example for AbuseIPDB API v2
    headers = { 'Accept': 'application/json', 'Key': COMMUNITY_BLOCKLIST_API_KEY }
    categories = "18" # Default: Brute-Force
    if "scan" in reason.lower(): categories = "14" # Port Scan
    elif any(term in reason.lower() for term in ["scraping", "crawler", "llm"]): categories = "19" # Web Scraping
    elif "honeypot" in reason.lower(): categories = "22" # Honeypot
    payload = {
        'ip': ip,
        'categories': categories,
        'comment': f"AI Defense Stack Detection. Reason: {reason}. UA: {details.get('user_agent', 'N/A')}. Path: {details.get('path', 'N/A')}"[:1024]
    }
    try:
        async with httpx.AsyncClient() as client:
            # AbuseIPDB uses POST with form data (data=payload)
            response = await client.post(COMMUNITY_BLOCKLIST_REPORT_URL, headers=headers, data=payload, timeout=COMMUNITY_BLOCKLIST_REPORT_TIMEOUT)
            response.raise_for_status() # Raises HTTPStatusError for 4xx/5xx
            result = response.json()
            logger.info(f"Successfully reported IP {ip} to community blocklist. Response: {result}")
            log_event(COMMUNITY_REPORT_LOG_FILE, "COMMUNITY_REPORT_SUCCESS", {"ip": ip, "reason": reason, "api_response": result})
            increment_metric("community_reports_success")
            return True
    except httpx.TimeoutException: logger.error(f"Timeout reporting IP {ip} to community blocklist"); increment_metric("community_reports_errors_timeout"); return False
    except httpx.RequestError as exc: logger.error(f"Request error reporting IP {ip} to community blocklist: {exc}"); increment_metric("community_reports_errors_request"); return False
    except httpx.HTTPStatusError as exc: logger.error(f"Community blocklist report failed for IP {ip} with status {exc.response.status_code}. Response: {exc.response.text[:500]}"); increment_metric("community_reports_errors_status"); return False
    except json.JSONDecodeError as exc: logger.error(f"JSON decode error processing community blocklist response for IP {ip}: {exc} - Response: {response.text[:500]}"); increment_metric("community_reports_errors_response_decode"); return False
    except Exception as e: logger.error(f"Unexpected error reporting IP {ip} to community blocklist: {e}", exc_info=True); increment_metric("community_reports_errors_unexpected"); return False


# --- Alerting Functions ---
# (Logic remains largely the same, relies on configured URLs/Credentials)
async def send_generic_webhook_alert(event_data: WebhookEvent):
    """Sends alert to a generic webhook URL using httpx."""
    if not ALERT_GENERIC_WEBHOOK_URL: return
    ip = event_data.details.get('ip', 'N/A')
    logger.info(f"Sending generic webhook alert for IP: {ip} to {ALERT_GENERIC_WEBHOOK_URL}")
    payload = { "alert_type": "AI_DEFENSE_BLOCK", "reason": event_data.reason, "timestamp": str(event_data.timestamp_utc), "ip_address": ip, "user_agent": event_data.details.get('user_agent', 'N/A'), "details": event_data.details }
    try:
        # Ensure payload is serializable
        def default_serializer(obj):
            if isinstance(obj, datetime.datetime): return obj.isoformat()
            return str(obj)
        json_payload = json.loads(json.dumps(payload, default=default_serializer))

        async with httpx.AsyncClient() as client:
            response = await client.post(ALERT_GENERIC_WEBHOOK_URL, json=json_payload, timeout=10.0)
            response.raise_for_status()
            logger.info(f"Generic webhook alert sent successfully for IP {ip}.")
            log_event(ALERT_LOG_FILE, "ALERT_SENT_WEBHOOK", {"reason": event_data.reason, "ip": ip})
            increment_metric("alerts_sent_webhook")
    except json.JSONDecodeError as e: log_error(f"Failed to serialize generic webhook payload for IP {ip}", e); increment_metric("alerts_errors_webhook")
    except httpx.RequestError as e: log_error(f"Failed to send generic webhook alert to {ALERT_GENERIC_WEBHOOK_URL} for IP {ip}", e); increment_metric("alerts_errors_webhook")
    except httpx.HTTPStatusError as e: log_error(f"Generic webhook alert failed for IP {ip} with status {e.response.status_code}", e); increment_metric("alerts_errors_webhook")
    except Exception as e: log_error(f"Unexpected error sending generic webhook alert for IP {ip}", e); increment_metric("alerts_errors_webhook")

async def send_slack_alert(event_data: WebhookEvent):
    """Sends alert to Slack via Incoming Webhook using requests (sync in thread pool)."""
    if not ALERT_SLACK_WEBHOOK_URL: return
    ip = event_data.details.get('ip', 'N/A'); ua = event_data.details.get('user_agent', 'N/A'); reason = event_data.reason
    logger.info(f"Sending Slack alert for IP: {ip}")
    message = f":shield: *AI Defense Alert*\n> *Reason:* {reason}\n> *IP Address:* `{ip}`\n> *User Agent:* `{ua}`\n> *Timestamp (UTC):* {event_data.timestamp_utc}"
    payload = {"text": message}
    headers = {'Content-Type': 'application/json'}
    try:
        # Run synchronous requests.post in a separate thread
        response = await asyncio.to_thread(requests.post, ALERT_SLACK_WEBHOOK_URL, headers=headers, json=payload, timeout=10.0)
        response.raise_for_status()
        logger.info(f"Slack alert sent successfully for IP {ip}.")
        log_event(ALERT_LOG_FILE, "ALERT_SENT_SLACK", {"reason": reason, "ip": ip})
        increment_metric("alerts_sent_slack")
    except requests.exceptions.RequestException as e: log_error(f"Failed to send Slack alert using requests to {ALERT_SLACK_WEBHOOK_URL} for IP {ip}", e); increment_metric("alerts_errors_slack")
    except Exception as e: log_error(f"Unexpected error sending Slack alert for IP {ip}", e); increment_metric("alerts_errors_slack")

async def send_smtp_alert(event_data: WebhookEvent):
    """Sends alert via SMTP email using smtplib (sync in thread pool)."""
    if not ALERT_EMAIL_TO or not ALERT_SMTP_HOST or not ALERT_EMAIL_FROM:
        # Already logged error during startup checks
        return
    ip = event_data.details.get('ip', 'N/A'); ua = event_data.details.get('user_agent', 'N/A'); reason = event_data.reason
    logger.info(f"Sending SMTP alert for IP: {ip} to {ALERT_EMAIL_TO}")
    subject = f"[AI Defense Alert] Suspicious Activity Detected - {reason}"
    body = f"""Suspicious activity detected by the AI Defense System:

Reason: {reason}
Timestamp (UTC): {event_data.timestamp_utc}
IP Address: {ip}
User Agent: {ua}

Full Details:
{pprint.pformat(event_data.details)}

---
IP added to local blocklist with TTL: {BLOCKLIST_TTL_SECONDS} seconds.
Check logs in '{LOGS_DIR}' for more context.
"""
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = ALERT_EMAIL_FROM
    msg['To'] = ALERT_EMAIL_TO # smtplib handles comma-separated string

    def smtp_send_sync():
        smtp_conn = None
        try:
            context = ssl.create_default_context()
            if ALERT_SMTP_PORT == 465: # SSL connection
                smtp_conn = smtplib.SMTP_SSL(ALERT_SMTP_HOST, ALERT_SMTP_PORT, timeout=15, context=context)
            else: # Standard connection, potentially upgraded to TLS
                smtp_conn = smtplib.SMTP(ALERT_SMTP_HOST, ALERT_SMTP_PORT, timeout=15)
                if ALERT_SMTP_USE_TLS:
                    smtp_conn.starttls(context=context)

            # Login if username and password are provided
            if ALERT_SMTP_USER and ALERT_SMTP_PASSWORD:
                smtp_conn.login(ALERT_SMTP_USER, ALERT_SMTP_PASSWORD)
            elif ALERT_SMTP_USER:
                logger.warning("SMTP User provided but password missing for login.")

            # Send the email
            smtp_conn.sendmail(ALERT_EMAIL_FROM, ALERT_EMAIL_TO.split(','), msg.as_string())
            logger.info(f"SMTP alert sent successfully for IP {ip} to {ALERT_EMAIL_TO}.")
            log_event(ALERT_LOG_FILE, "ALERT_SENT_SMTP", {"reason": reason, "ip": ip, "to": ALERT_EMAIL_TO})
            increment_metric("alerts_sent_smtp")
        except smtplib.SMTPException as e: log_error(f"SMTP error sending email alert for IP {ip} (Host: {ALERT_SMTP_HOST}:{ALERT_SMTP_PORT}, User: {ALERT_SMTP_USER})", e); increment_metric("alerts_errors_smtp")
        except Exception as e: log_error(f"Unexpected error sending email alert for IP {ip}", e); increment_metric("alerts_errors_smtp")
        finally:
            if smtp_conn:
                try: smtp_conn.quit()
                except Exception: pass # Ignore errors during quit

    try:
        # Run synchronous SMTP logic in a separate thread
        await asyncio.to_thread(smtp_send_sync)
    except Exception as e:
        log_error(f"Error executing SMTP send thread for IP {ip}", e)
        increment_metric("alerts_errors_smtp")

async def send_alert(event_data: WebhookEvent):
    """Dispatches alert based on configured ALERT_METHOD and severity."""
    # Severity mapping (adjust as needed)
    severity_map = {"High Heuristic": 1, "Local LLM": 2, "External API": 3, "High Combined": 1, "Honeypot_Hit": 2, "IP Reputation": 1}
    reason_key = event_data.reason.split("(")[0].strip()
    event_severity = severity_map.get(reason_key, 0)
    min_severity_reason = ALERT_MIN_REASON_SEVERITY.split("(")[0].strip() # Handle potential score in reason
    min_severity = severity_map.get(min_severity_reason, 1)

    if event_severity < min_severity:
        logger.debug(f"Skipping alert for IP {event_data.details.get('ip')}. Severity {event_severity} ('{reason_key}') < Min Severity {min_severity} ('{min_severity_reason}')")
        return

    logger.info(f"Dispatching alert for IP {event_data.details.get('ip')} via method: {ALERT_METHOD} (Severity: {event_severity})")
    increment_metric("alerts_dispatch_attempted")
    dispatch_map = {
        "webhook": send_generic_webhook_alert,
        "slack": send_slack_alert,
        "smtp": send_smtp_alert,
    }
    if ALERT_METHOD in dispatch_map:
        await dispatch_map[ALERT_METHOD](event_data)
    elif ALERT_METHOD != "none":
        log_error(f"Alert method '{ALERT_METHOD}' is invalid or missing configuration.")
        increment_metric("alerts_errors_config")


# --- Webhook Receiver Endpoint ---
@app.post("/analyze", status_code=200) # Changed to 200 OK as action is immediate
async def receive_webhook(event: WebhookEvent, request: Request):
    """
    Receives webhook events, logs, blocklists (with TTL), optionally reports to community lists, and triggers alerts.
    """
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown").split(',')[0].strip()
    flagged_ip = event.details.get("ip", "unknown")
    reason = event.reason or "Unknown Reason"
    increment_metric("webhook_events_received")
    logger.info(f"Webhook Received from {client_ip} for flagged IP: {flagged_ip} - Reason: {reason}")

    # Basic validation
    if flagged_ip == "unknown":
         logger.warning(f"Webhook received with 'unknown' IP address from {client_ip}. Reason: {reason}")
         # Skip blocklisting/reporting if IP is unknown
         return {"status": "processed", "action_taken": "blocklist_skipped_unknown_ip", "ip_processed": flagged_ip}

    action_taken = "logged"
    blocklist_success = False

    # Auto-Blocklist Criteria (Adjust terms as needed based on Escalation Engine reasons)
    # Match reasons generated by Escalation Engine
    auto_block_reasons = ["High Combined Score", "Local LLM Classification", "External API Classification", "High Heuristic Score", "Honeypot_Hit", "IP Reputation Malicious"]

    # Determine if this event should trigger a block
    should_block = any(term in reason for term in auto_block_reasons)

    if should_block:
        blocklist_success = add_ip_to_blocklist(flagged_ip, reason, event.details)
        action_taken = "ip_blocklisted_ttl" if blocklist_success else "blocklist_failed"
        # --- Report to Community Blocklist ---
        if blocklist_success and ENABLE_COMMUNITY_REPORTING:
             reported = await report_ip_to_community(flagged_ip, reason, event.details)
             action_taken += f"_community_report_{'success' if reported else 'failed'}"
    else:
        logger.info(f"Reason '{reason}' for IP {flagged_ip} does not meet auto-block criteria. Skipping blocklist.")
        action_taken = "blocklist_skipped_criteria_not_met"

    # Send alert (checks severity internally)
    try:
        await send_alert(event)
        if ALERT_METHOD != "none": action_taken += "_alert_checked"
    except Exception as e:
        log_error(f"Error during alert processing for IP {flagged_ip}", e)
        action_taken += "_alert_error"

    logger.info(f"Processing complete for IP {flagged_ip}. Action: {action_taken}")
    return {"status": "processed", "action_taken": action_taken, "ip_processed": flagged_ip}


# --- Health Check Endpoint ---
# (Remains the same)
@app.get("/health")
async def health_check():
    """ Basic health check endpoint """
    redis_ok = False
    if redis_client_blocklist:
        try: redis_ok = redis_client_blocklist.ping()
        except Exception: redis_ok = False
    return {"status": "ok", "redis_blocklist_connected": redis_ok}


# --- Main Execution ---
# This part is usually handled by the hosting mechanism (like IIS calling uvicorn/waitress)
if __name__ == "__main__":
    import uvicorn
    logger.info("--- AI Service / Webhook Receiver Starting (IIS Version - Direct Run for Testing) ---")
    logger.info(f"Log Directory: {LOGS_DIR}")
    logger.info(f"Secrets Directory: {SECRETS_DIR}")
    logger.info(f"Blocklisting via Redis: {'Enabled' if BLOCKLISTING_ENABLED else 'Disabled'} (Host: {REDIS_HOST}:{REDIS_PORT} DB:{REDIS_DB_BLOCKLIST})")
    if BLOCKLISTING_ENABLED:
        logger.info(f"Blocklist Entry TTL: {BLOCKLIST_TTL_SECONDS} seconds ({datetime.timedelta(seconds=BLOCKLIST_TTL_SECONDS)})")
        logger.info(f"Blocklist Key Prefix: {BLOCKLIST_KEY_PREFIX}ip:<ip_addr>")
    logger.info(f"Community Reporting Enabled: {ENABLE_COMMUNITY_REPORTING} ({'URL Set' if COMMUNITY_BLOCKLIST_REPORT_URL else 'URL Not Set'})")
    logger.info(f"Alert Method: {ALERT_METHOD}")
    if ALERT_METHOD == "webhook": logger.info(f" -> Generic URL: {'Set' if ALERT_GENERIC_WEBHOOK_URL else 'Not Set'}")
    if ALERT_METHOD == "slack": logger.info(f" -> Slack URL: {'Set' if ALERT_SLACK_WEBHOOK_URL else 'Not Set'}")
    if ALERT_METHOD == "smtp": logger.info(f" -> SMTP Host: {ALERT_SMTP_HOST}:{ALERT_SMTP_PORT} | Use TLS: {ALERT_SMTP_USE_TLS} | From: {ALERT_EMAIL_FROM} | To: {ALERT_EMAIL_TO} | Pass Loaded: {bool(ALERT_SMTP_PASSWORD)}")
    logger.info(f"Minimum Alert Severity Reason: {ALERT_MIN_REASON_SEVERITY}")
    logger.info(f"Logging blocks to: {BLOCK_LOG_FILE}")
    logger.info(f"Logging alerts to: {ALERT_LOG_FILE}")
    logger.info(f"Logging community reports to: {COMMUNITY_REPORT_LOG_FILE}")
    logger.info(f"Logging errors to: {ERROR_LOG_FILE}")
    logger.info("-----------------------------------------------------------------------------------")
    # Standard port 8000 used internally
    uvicorn.run(
        "ai_webhook:app",
        host="127.0.0.1", # Listen on localhost for local testing
        port=8000,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
        # workers=1 # Typically 1 worker for local testing
    )