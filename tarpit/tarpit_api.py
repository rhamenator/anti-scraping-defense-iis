# anti-scraping-defense-iis/tarpit/tarpit_api.py
# Modified for Windows/IIS Compatibility

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
import asyncio
import httpx
import os
import random
import datetime
import sys
import logging
import hashlib
import redis # Added for hop limit check

# --- Setup Logging ---
# Assuming basic logging is configured elsewhere or use:
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Define Windows Paths (REPLACE THESE PLACEHOLDERS) ---
# Define the base directory for your application on the Windows server
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs")
SECRETS_DIR = os.getenv("APP_SECRETS_DIRECTORY", r"C:\secrets") # Example path for secrets
os.makedirs(LOGS_DIR, exist_ok=True) # Ensure log directory exists

# --- Adjust Python Path ---
# Add parent directory to sys.path to find shared modules based on APP_BASE_DIR
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- Import Local & Shared Modules ---
# Using relative imports assuming standard Python module structure
try:
    from shared.honeypot_logger import log_honeypot_hit, HONEYPOT_LOG_FILE as SHARED_HONEYPOT_LOG_FILE
    HONEYPOT_LOGGING_AVAILABLE = True
    # Update honeypot logger path if necessary (assuming it's relative within LOGS_DIR)
    # This might require modifying shared/honeypot_logger.py path logic as well
    logger.debug(f"Honeypot logger imported. Expecting log at: {SHARED_HONEYPOT_LOG_FILE}")
except ImportError as e:
    logger.warning(f"Could not import shared.honeypot_logger: {e}. Honeypot hits will not be logged to dedicated file.")
    def log_honeypot_hit(details: dict): pass
    HONEYPOT_LOGGING_AVAILABLE = False

try:
    # Relative import for modules within the same package (tarpit)
    from .markov_generator import generate_dynamic_tarpit_page, PG_PASSWORD_FILE as MARKOV_PG_PASSWORD_FILE
    GENERATOR_AVAILABLE = True
    logger.debug("PostgreSQL Markov generator imported.")
except ImportError as e:
    logger.warning(f"Could not import markov_generator: {e}. Dynamic content generation disabled.")
    GENERATOR_AVAILABLE = False

try:
    from .ip_flagger import flag_suspicious_ip
    FLAGGING_AVAILABLE = True
    logger.debug("IP Flagger imported.")
except ImportError as e:
    logger.warning(f"Could not import ip_flagger: {e}. IP Flagging disabled.")
    def flag_suspicious_ip(ip: str): pass
    FLAGGING_AVAILABLE = False


# --- Configuration ---
# Read from environment variables (should be set in IIS Application Settings)
ESCALATION_ENDPOINT = os.getenv("ESCALATION_ENDPOINT", "http://localhost:8003/escalate") # Assuming services run on localhost for IIS deployment
MIN_STREAM_DELAY_SEC = float(os.getenv("TAR_PIT_MIN_DELAY_SEC", 0.6))
MAX_STREAM_DELAY_SEC = float(os.getenv("TAR_PIT_MAX_DELAY_SEC", 1.2))
SYSTEM_SEED = os.getenv("SYSTEM_SEED", "default_windows_seed_value_change_me")

# Hop Limit Configuration
TAR_PIT_MAX_HOPS = int(os.getenv("TAR_PIT_MAX_HOPS", 250))
TAR_PIT_HOP_WINDOW_SECONDS = int(os.getenv("TAR_PIT_HOP_WINDOW_SECONDS", 86400)) # 24 hours
HOP_LIMIT_ENABLED = TAR_PIT_MAX_HOPS > 0

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost") # Point to Redis host accessible from IIS server
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
# Construct path to Redis password file using SECRETS_DIR
REDIS_PASSWORD_FILE = os.path.join(SECRETS_DIR, os.getenv("REDIS_PASSWORD_FILENAME", "redis_password.txt"))
REDIS_DB_TAR_PIT = int(os.getenv("REDIS_DB_TAR_PIT", 1))         # For visit flags
REDIS_DB_TAR_PIT_HOPS = int(os.getenv("REDIS_DB_TAR_PIT_HOPS", 4)) # For hop counts
REDIS_DB_BLOCKLIST = int(os.getenv("REDIS_DB_BLOCKLIST", 2))    # For triggering blocks
BLOCKLIST_TTL_SECONDS = int(os.getenv("BLOCKLIST_TTL_SECONDS", 86400))

# --- Redis Connection Pools ---
redis_password = None
if os.path.exists(REDIS_PASSWORD_FILE):
    try:
        with open(REDIS_PASSWORD_FILE, 'r') as f:
            redis_password = f.read().strip()
        logger.info(f"Loaded Redis password from: {REDIS_PASSWORD_FILE}")
    except Exception as e:
        logger.error(f"Failed to read Redis password from {REDIS_PASSWORD_FILE}: {e}")
else:
    logger.warning(f"Redis password file not found at {REDIS_PASSWORD_FILE}. Connecting without password.")


# --- Helper function to initialize Redis connection pools ---
def initialize_redis_pool(db_number):
    try:
        pool = redis.ConnectionPool(
            host=REDIS_HOST, port=REDIS_PORT, db=db_number,
            password=redis_password, decode_responses=True
        )
        client = redis.Redis(connection_pool=pool)
        client.ping() # Test connection
        logger.info(f"Connected to Redis DB {db_number} at {REDIS_HOST}:{REDIS_PORT}")
        return client
    except redis.exceptions.ConnectionError as e:
        logger.error(f"FATAL: Could not connect to Redis DB {db_number} at {REDIS_HOST}:{REDIS_PORT}. Error: {e}")
        return None
    except Exception as e:
        logger.error(f"FATAL: Unexpected error setting up Redis connection for DB {db_number}: {e}", exc_info=True)
        return None

# Initialize Redis clients
redis_hops = initialize_redis_pool(REDIS_DB_TAR_PIT_HOPS)
redis_blocklist = initialize_redis_pool(REDIS_DB_BLOCKLIST)

# Disable features if Redis connection failed
if not redis_hops or not redis_blocklist:
    HOP_LIMIT_ENABLED = False


# --- FastAPI App ---
app = FastAPI(
    title="Tarpit API (IIS Version)",
    description="Handles suspicious requests, slows down bots, generates fake content, escalates metadata."
)

# --- Helper Functions ---
async def slow_stream_content(content: str):
    """Generator function to stream content slowly with randomized delays."""
    lines = content.split('\n')
    for line in lines:
        yield line + '\n'
        # Use the random state potentially seeded by the handler
        delay = random.uniform(MIN_STREAM_DELAY_SEC, MAX_STREAM_DELAY_SEC)
        await asyncio.sleep(delay)

def trigger_ip_block(ip: str, reason: str):
    """Adds IP to the main Redis blocklist."""
    if not redis_blocklist:
        logger.error(f"Cannot block IP {ip}, Redis blocklist connection unavailable.")
        return False
    try:
        # Use a key compatible with the Lua script's expectation (if using Redis directly)
        # If IIS module handles blocking differently, adjust logic here or in the module.
        # For consistency, let's assume the AI Service adds the block via 'blocklist:ip:<ip_addr>' key pattern.
        # This function might just log or signal the IIS module if direct Redis write isn't desired here.
        # However, for self-contained blocking from exceeding hop limit, writing here is simpler.
        key = f"blocklist:{ip}" # Adjust key format if needed
        result = redis_blocklist.set(key, reason, ex=BLOCKLIST_TTL_SECONDS)
        if result:
            logger.warning(f"BLOCKED IP {ip} for {BLOCKLIST_TTL_SECONDS}s. Reason: {reason}")
            # Optionally increment a metric here using shared metrics module
            try:
                from metrics import increment_metric
                increment_metric("tarpit_blocks_hop_limit")
            except ImportError:
                pass
            return True
        else:
            logger.error(f"Failed to set blocklist key for IP {ip} in Redis.")
            return False
    except redis.RedisError as e:
        logger.error(f"Redis error while trying to block IP {ip}: {e}")
        return False
    except Exception as e:
         logger.error(f"Unexpected error while blocking IP {ip}: {e}", exc_info=True)
         return False


# --- API Endpoints ---
@app.get("/tarpit/{path:path}", response_class=StreamingResponse, status_code=200)
async def tarpit_handler(request: Request, path: str = None):
    """
    Handles requests redirected here. Logs hit, flags IP, checks hop limit,
    escalates metadata, and serves a slow, deterministically generated fake response.
    """
    # Extract client IP - handle potential X-Forwarded-For if behind IIS proxy
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown").split(',')[0].strip()
    user_agent = request.headers.get("user-agent", "unknown")
    referer = request.headers.get("referer", "-")
    # Reconstruct original path if needed, or use the path captured by IIS rewrite rule
    # For simplicity, assume IIS passes the relevant path info
    requested_path = str(request.url.path)
    http_method = request.method

    # --- Hop Limit Check ---
    if HOP_LIMIT_ENABLED and client_ip != "unknown" and redis_hops:
        try:
            hop_key = f"tarpit:hops:{client_ip}"
            pipe = redis_hops.pipeline()
            pipe.incr(hop_key)
            pipe.expire(hop_key, TAR_PIT_HOP_WINDOW_SECONDS)
            results = pipe.execute()
            current_hop_count = results[0] if results else 0

            logger.debug(f"IP {client_ip} tarpit hop count: {current_hop_count}/{TAR_PIT_MAX_HOPS}")

            if current_hop_count > TAR_PIT_MAX_HOPS:
                logger.warning(f"Tarpit hop limit ({TAR_PIT_MAX_HOPS}) exceeded for IP: {client_ip}. Blocking IP.")
                block_reason = f"Tarpit hop limit exceeded ({current_hop_count} hits in {TAR_PIT_HOP_WINDOW_SECONDS}s)"
                trigger_ip_block(client_ip, block_reason)
                # Return an immediate 403 Forbidden response
                return HTMLResponse(
                    content="<html><head><title>Forbidden</title></head><body>Access Denied. Request frequency limit exceeded.</body></html>",
                    status_code=403
                )
        except redis.RedisError as e:
            logger.error(f"Redis error during hop limit check for IP {client_ip}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during hop limit check for IP {client_ip}: {e}", exc_info=True)


    # --- Standard Tarpit Operations (Log, Flag, Escalate) ---
    logger.info(f"TAR_PIT HIT: Path={requested_path}, IP={client_ip}, UA='{user_agent}'")
    honeypot_details = {
        "ip": client_ip, "user_agent": user_agent, "method": http_method,
        "path": requested_path, "referer": referer, "headers": dict(request.headers)
    }
    if HONEYPOT_LOGGING_AVAILABLE:
        try: log_honeypot_hit(honeypot_details)
        except Exception as e: logger.error(f"Error logging honeypot hit: {e}", exc_info=True)

    if FLAGGING_AVAILABLE:
        try: flag_suspicious_ip(client_ip)
        except Exception as e: logger.error(f"Error flagging IP {client_ip}: {e}", exc_info=True)

    timestamp_iso = datetime.datetime.utcnow().isoformat() + "Z"
    metadata = {
        "timestamp": timestamp_iso, "ip": client_ip, "user_agent": user_agent,
        "referer": referer, "path": requested_path, "headers": dict(request.headers),
        "source": "tarpit_api"
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(ESCALATION_ENDPOINT, json=metadata, timeout=5.0)
            if response.status_code >= 400:
                 logger.warning(f"Escalation request for IP {client_ip} failed with status {response.status_code}. Response: {response.text[:200]}")
    except Exception as e:
        logger.error(f"Error escalating request for IP {client_ip} to {ESCALATION_ENDPOINT}: {e}", exc_info=True)

    # --- Deterministic Response Generation ---
    content = "<html><body>Tarpit Error</body></html>" # Default fallback
    if GENERATOR_AVAILABLE:
        try:
            # Ensure path uses consistent separators for hashing if needed
            normalized_path = requested_path.replace("\\", "/")
            path_bytes = normalized_path.encode('utf-8')
            path_hash = hashlib.sha256(path_bytes).hexdigest()
            combined_seed = f"{SYSTEM_SEED}-{path_hash}"
            random.seed(combined_seed) # Seed the GLOBAL random state for this request
            logger.debug(f"Seeded RNG for path '{normalized_path}' with combined seed.")
            # Update path to Markov generator password file if needed
            # Ensure markov_generator.py also uses SECRETS_DIR or configured path
            # Example: markov_generator.PG_PASSWORD_FILE = os.path.join(SECRETS_DIR, "pg_password.txt")
            content = generate_dynamic_tarpit_page()
        except Exception as e:
            logger.error(f"Error generating dynamic page for path '{requested_path}': {e}", exc_info=True)
            content = "<html><head><title>Error</title></head><body>Service temporarily unavailable. Please try again later.</body></html>"
    else:
        content = """<!DOCTYPE html>
<html><head><title>Loading Resource...</title><meta name="robots" content="noindex, nofollow"></head>
<body><h1>Please wait</h1><p>Your content is loading slowly...</p><progress></progress>
</body></html>"""

    # --- Stream the response slowly ---
    media_type = "text/html"
    return StreamingResponse(slow_stream_content(content), media_type=media_type)


# --- Root/Health Check ---
@app.get("/health")
async def health_check():
    """ Basic health check endpoint for the Tarpit API (IIS Version). """
    db_ok = False
    if GENERATOR_AVAILABLE:
        try:
             # Placeholder: Assume generator handles checks or modify it to expose one
             # For now, assume if loaded, it's intended to work.
             db_ok = True
        except Exception: db_ok = False

    redis_hops_ok = bool(redis_hops and redis_hops.ping())
    redis_blocklist_ok = bool(redis_blocklist and redis_blocklist.ping())

    status = "ok" if redis_hops_ok and redis_blocklist_ok else "error"

    return {
        "status": status,
        "generator_available": GENERATOR_AVAILABLE,
        "postgres_connection_status": "assumed_ok" if db_ok else "error", # Placeholder
        "redis_hops_connected": redis_hops_ok,
        "redis_blocklist_connected": redis_blocklist_ok,
        "hop_limit_enabled": HOP_LIMIT_ENABLED,
        "max_hops_config": TAR_PIT_MAX_HOPS if HOP_LIMIT_ENABLED else "disabled",
        "log_directory": LOGS_DIR,
        "secrets_directory": SECRETS_DIR
    }

@app.get("/")
async def root():
     """ Basic info endpoint """
     return {"message": "AntiScrape Tarpit API (IIS Version)"}

# --- Main Execution ---
# This part is usually handled by the hosting mechanism (like IIS calling uvicorn/waitress)
# You wouldn't typically run "python tarpit_api.py" directly in production with IIS.
if __name__ == "__main__":
    # This block is mainly for local testing *without* IIS
    import uvicorn
    logger.info("--- Tarpit API Starting (IIS Version - Direct Run for Testing) ---")
    logger.info(f"Escalation Endpoint: {ESCALATION_ENDPOINT}")
    logger.info(f"Generator Available: {GENERATOR_AVAILABLE}")
    logger.info(f"IP Flagging Available: {FLAGGING_AVAILABLE}")
    logger.info(f"System Seed Loaded: {'Yes' if SYSTEM_SEED else 'No (Using Default)'}")
    logger.info(f"Hop Limit Enabled: {HOP_LIMIT_ENABLED} (Max Hops: {TAR_PIT_MAX_HOPS}, Window: {TAR_PIT_HOP_WINDOW_SECONDS}s, DB: {REDIS_DB_TAR_PIT_HOPS})")
    logger.info(f"Redis Blocklist DB for Trigger: {REDIS_DB_BLOCKLIST}")
    logger.info(f"Streaming Delay: {MIN_STREAM_DELAY_SEC:.2f}s - {MAX_STREAM_DELAY_SEC:.2f}s")
    logger.info(f"Log Directory: {LOGS_DIR}")
    logger.info(f"Secrets Directory: {SECRETS_DIR}")
    logger.info(f"Redis Password File Path: {REDIS_PASSWORD_FILE} (Exists: {os.path.exists(REDIS_PASSWORD_FILE)})")
    logger.info(f"Markov PG Password File Path: {MARKOV_PG_PASSWORD_FILE} (Exists: {os.path.exists(MARKOV_PG_PASSWORD_FILE)})")
    logger.info("-------------------------------------------------------------------")
    # Standard port 8001 used internally
    uvicorn.run(
        "tarpit_api:app", # Reference the FastAPI app instance
        host="127.0.0.1", # Listen on localhost for local testing
        port=8001,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
        # workers=1 # Typically 1 worker for local testing
    )