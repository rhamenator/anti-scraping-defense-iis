# anti-scraping-defense-iis/tarpit/ip_flagger.py
# Modified for Windows/IIS Compatibility
# Utility for flagging suspicious IP addresses using Redis

import redis
import os
import datetime
import logging # Using standard logging

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Use the same SECRETS_DIR logic as in other modules
SECRETS_DIR = os.getenv("APP_SECRETS_DIRECTORY", r"C:\secrets") # Example path for secrets

# --- Redis Configuration ---
# Read from environment variables (should be set in IIS Application Settings)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost") # Point to Redis host accessible from IIS server
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB_TAR_PIT", 1)) # Use the specific DB for tarpit flags
FLAG_TTL_SECONDS = int(os.getenv("TAR_PIT_FLAG_TTL", 300)) # Time-to-live for an IP flag
MAX_FLAGS_PER_IP = int(os.getenv("TAR_PIT_MAX_FLAGS", 5)) # Optional: Max flags before longer action

# Construct path to Redis password file using SECRETS_DIR
REDIS_PASSWORD_FILENAME = os.getenv("REDIS_PASSWORD_FILENAME", "redis_password.txt")
REDIS_PASSWORD_FILE = os.path.join(SECRETS_DIR, REDIS_PASSWORD_FILENAME)

# --- Read Redis Password ---
redis_password = None
if os.path.exists(REDIS_PASSWORD_FILE):
    try:
        with open(REDIS_PASSWORD_FILE, 'r') as f:
            redis_password = f.read().strip()
        if redis_password:
             logger.info(f"Loaded Redis password from: {REDIS_PASSWORD_FILE}")
        else:
             logger.warning(f"Redis password file found at {REDIS_PASSWORD_FILE}, but it is empty.")
             redis_password = None # Treat empty file as no password
    except Exception as e:
        logger.error(f"Failed to read Redis password from {REDIS_PASSWORD_FILE}: {e}")
else:
    logger.info(f"Redis password file not found at {REDIS_PASSWORD_FILE}. Will attempt connection without password.")

# --- Initialize Redis Client ---
redis_client = None
try:
    # Use connection pooling for efficiency
    redis_pool = redis.ConnectionPool(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=redis_password, # Pass password if found
        decode_responses=True
    )
    redis_client = redis.Redis(connection_pool=redis_pool)
    redis_client.ping() # Test connection on import
    logger.info(f"Connected to Redis for IP flagging at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}")
except redis.exceptions.AuthenticationError:
     logger.error(f"ERROR: Redis authentication failed at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}. Check password.")
     redis_client = None
except redis.exceptions.ConnectionError as e:
    logger.error(f"ERROR: Could not connect to Redis at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}. IP Flagging disabled. Error: {e}")
    redis_client = None # Disable flagging if Redis is unavailable
except Exception as e:
     logger.error(f"ERROR: Unexpected error connecting to Redis: {e}", exc_info=True)
     redis_client = None

def flag_suspicious_ip(ip_address: str):
    """
    Flags an IP address in Redis with a specific TTL.
    Increments a counter for the IP (Optional logic commented out).
    """
    if not redis_client or not ip_address:
        # Log if Redis is unavailable, but don't flood logs if IP is just missing
        if not redis_client:
             logger.warning("Cannot flag IP, Redis client unavailable.")
        return False

    try:
        flag_key = f"tarpit_flag:{ip_address}"
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        # Set the flag with an expiration time (TTL)
        redis_client.setex(flag_key, FLAG_TTL_SECONDS, timestamp)

        # Optional: Implement a counter for repeated offenses
        # counter_key = f"tarpit_count:{ip_address}"
        # current_count = redis_client.incr(counter_key)
        # redis_client.expire(counter_key, FLAG_TTL_SECONDS * 2) # Expire counter slightly longer than flag
        # if current_count > MAX_FLAGS_PER_IP:
        #     logger.warning(f"IP {ip_address} flagged {current_count} times (max: {MAX_FLAGS_PER_IP}). Consider longer ban.")

        logger.info(f"Flagged IP: {ip_address} in Redis DB {REDIS_DB} for {FLAG_TTL_SECONDS} seconds.")
        return True
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error while flagging IP {ip_address}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error flagging IP {ip_address}: {e}", exc_info=True)
        return False

def check_ip_flag(ip_address: str) -> bool:
    """
    Checks if an IP address is currently flagged in Redis.
    """
    if not redis_client or not ip_address:
         if not redis_client: logger.warning("Cannot check IP flag, Redis client unavailable.")
         return False

    try:
        flag_key = f"tarpit_flag:{ip_address}"
        return redis_client.exists(flag_key) > 0
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error while checking IP flag {ip_address}: {e}")
        return False # Fail safe (assume not flagged if error)
    except Exception as e:
        logger.error(f"Unexpected error checking IP flag {ip_address}: {e}", exc_info=True)
        return False

# Example usage block (mainly for testing the module itself)
# if __name__ == "__main__":
#    if not redis_client:
#        print("Redis client not initialized. Cannot run tests.")
#    else:
#        test_ip = "192.168.1.101"
#        print(f"Checking flag for {test_ip}: {check_ip_flag(test_ip)}")
#        print(f"Flagging {test_ip}...")
#        flag_suspicious_ip(test_ip)
#        print(f"Checking flag for {test_ip}: {check_ip_flag(test_ip)}")
#        import time
#        print(f"Waiting for TTL ({FLAG_TTL_SECONDS}s)... Set low for testing.")
#        # time.sleep(FLAG_TTL_SECONDS + 1)
#        # print(f"Checking flag for {test_ip} after TTL: {check_ip_flag(test_ip)}")