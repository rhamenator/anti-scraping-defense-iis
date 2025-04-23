# anti-scraping-defense-iis/escalation/escalation_engine.py
# Modified for Windows/IIS Compatibility
# Handles incoming suspicious request metadata, analyzes, classifies, and escalates via webhook.

from fastapi import FastAPI, Request, HTTPException, Response
from pydantic import BaseModel, Field, ValidationError
from typing import Dict, Any, Optional
import httpx
import os
import datetime
import time
import json
import joblib # For loading the saved RF model
import numpy as np
from urllib.parse import urlparse
import re
import redis # For real-time frequency tracking
import asyncio
import logging
import sys

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
SECRETS_DIR = os.getenv("APP_SECRETS_DIRECTORY", r"C:\secrets") # Example path for secrets
MODELS_DIR = os.path.join(APP_BASE_DIR, "models")
CONFIG_DIR = os.path.join(APP_BASE_DIR, "config")
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# --- Adjust Python Path ---
# Add parent directory to sys.path to find shared modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- Import Shared Metrics Module ---
try:
    from metrics import increment_metric, get_metrics
    METRICS_AVAILABLE = True
    logger.debug("Metrics module imported successfully.")
except ImportError:
    logger.warning("Could not import metrics module.")
    def increment_metric(key: str, value: int = 1): pass
    def get_metrics(): return {}
    METRICS_AVAILABLE = False

# --- Attempt to import user-agents library ---
try:
    from user_agents import parse as ua_parse
    UA_PARSER_AVAILABLE = True
    logger.debug("user-agents library imported.")
except ImportError:
    UA_PARSER_AVAILABLE = False
    logger.warning("user-agents library not found. Detailed UA parsing disabled.")

# --- Configuration ---
# Service URLs & Keys (Use ENV Variables set in IIS Application Settings)
# Default to localhost for typical single-server IIS deployment
WEBHOOK_URL = os.getenv("ESCALATION_WEBHOOK_URL", "http://localhost:8000/analyze") # To AI Service
LOCAL_LLM_API_URL = os.getenv("LOCAL_LLM_API_URL")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL")
LOCAL_LLM_TIMEOUT = float(os.getenv("LOCAL_LLM_TIMEOUT", 45.0))
EXTERNAL_API_URL = os.getenv("EXTERNAL_CLASSIFICATION_API_URL")
EXTERNAL_API_TIMEOUT = float(os.getenv("EXTERNAL_API_TIMEOUT", 15.0))
# Construct secret file paths
EXTERNAL_API_KEY_FILENAME = os.getenv("EXTERNAL_API_KEY_FILENAME", "external_api_key.txt")
EXTERNAL_API_KEY_FILE = os.path.join(SECRETS_DIR, EXTERNAL_API_KEY_FILENAME)

# IP Reputation Config
ENABLE_IP_REPUTATION = os.getenv("ENABLE_IP_REPUTATION", "false").lower() == "true"
IP_REPUTATION_API_URL = os.getenv("IP_REPUTATION_API_URL")
IP_REPUTATION_TIMEOUT = float(os.getenv("IP_REPUTATION_TIMEOUT", 10.0))
IP_REPUTATION_MALICIOUS_SCORE_BONUS = float(os.getenv("IP_REPUTATION_MALICIOUS_SCORE_BONUS", 0.3))
IP_REPUTATION_MIN_MALICIOUS_THRESHOLD = float(os.getenv("IP_REPUTATION_MIN_MALICIOUS_THRESHOLD", 50)) # Example threshold
IP_REPUTATION_API_KEY_FILENAME = os.getenv("IP_REPUTATION_API_KEY_FILENAME", "ip_reputation_api_key.txt")
IP_REPUTATION_API_KEY_FILE = os.path.join(SECRETS_DIR, IP_REPUTATION_API_KEY_FILENAME)

# CAPTCHA Trigger Config
ENABLE_CAPTCHA_TRIGGER = os.getenv("ENABLE_CAPTCHA_TRIGGER", "false").lower() == "true"
CAPTCHA_SCORE_THRESHOLD_LOW = float(os.getenv("CAPTCHA_SCORE_THRESHOLD_LOW", 0.2))
CAPTCHA_SCORE_THRESHOLD_HIGH = float(os.getenv("CAPTCHA_SCORE_THRESHOLD_HIGH", 0.5))
CAPTCHA_VERIFICATION_URL = os.getenv("CAPTCHA_VERIFICATION_URL") # URL to redirect user for CAPTCHA

# File Paths (Constructed using defined directories)
RF_MODEL_FILENAME = os.getenv("RF_MODEL_FILENAME", "bot_detection_rf_model.joblib")
RF_MODEL_PATH = os.path.join(MODELS_DIR, RF_MODEL_FILENAME)
ROBOTS_TXT_FILENAME = os.getenv("ROBOTS_TXT_FILENAME", "robots.txt")
ROBOTS_TXT_PATH = os.path.join(CONFIG_DIR, ROBOTS_TXT_FILENAME)

# Redis Config
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB_FREQUENCY = int(os.getenv("REDIS_DB_FREQUENCY", 3))
REDIS_PASSWORD_FILENAME = os.getenv("REDIS_PASSWORD_FILENAME", "redis_password.txt")
REDIS_PASSWORD_FILE = os.path.join(SECRETS_DIR, REDIS_PASSWORD_FILENAME)
FREQUENCY_WINDOW_SECONDS = 300
FREQUENCY_KEY_PREFIX = "freq:"

# Thresholds
HEURISTIC_THRESHOLD_LOW = 0.3
HEURISTIC_THRESHOLD_MEDIUM = 0.6
HEURISTIC_THRESHOLD_HIGH = 0.8

# User Agent Lists (Consider making these configurable via ENV or config file)
KNOWN_BAD_UAS_STR = os.getenv("KNOWN_BAD_UAS", 'python-requests,curl,wget,scrapy,java/,ahrefsbot,semrushbot,mj12bot,dotbot,petalbot,bytespider,gptbot,ccbot,claude-web,google-extended,dataprovider,purebot,scan,masscan,zgrab,nmap')
KNOWN_BENIGN_CRAWLERS_UAS_STR = os.getenv("KNOWN_BENIGN_CRAWLERS_UAS", 'googlebot,bingbot,slurp,duckduckbot,baiduspider,yandexbot,googlebot-image')
KNOWN_BAD_UAS = [ua.strip().lower() for ua in KNOWN_BAD_UAS_STR.split(',') if ua.strip()]
KNOWN_BENIGN_CRAWLERS_UAS = [ua.strip().lower() for ua in KNOWN_BENIGN_CRAWLERS_UAS_STR.split(',') if ua.strip()]

# --- Load Secrets ---
def load_secret(file_path: Optional[str]) -> Optional[str]:
    """Loads a secret from a file path."""
    if not file_path or not os.path.exists(file_path):
        logger.debug(f"Secret file not found or path is None: {file_path}")
        return None
    try:
        with open(file_path, 'r') as f:
            secret = f.read().strip()
            if secret:
                logger.info(f"Loaded secret successfully from: {file_path}")
                return secret
            else:
                logger.warning(f"Secret file is empty: {file_path}")
                return None
    except Exception as e:
        logger.error(f"Failed to read secret from {file_path}: {e}")
        return None

EXTERNAL_API_KEY = load_secret(EXTERNAL_API_KEY_FILE)
IP_REPUTATION_API_KEY = load_secret(IP_REPUTATION_API_KEY_FILE)
REDIS_PASSWORD = load_secret(REDIS_PASSWORD_FILE)

# --- Setup Clients & Load Resources ---

# Redis Client for Frequency
FREQUENCY_TRACKING_ENABLED = False
redis_client_freq = None
try:
    redis_pool_freq = redis.ConnectionPool(
        host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB_FREQUENCY,
        password=REDIS_PASSWORD, decode_responses=True
    )
    redis_client_freq = redis.Redis(connection_pool=redis_pool_freq)
    redis_client_freq.ping()
    logger.info(f"Connected to Redis for Frequency Tracking (DB: {REDIS_DB_FREQUENCY}) at {REDIS_HOST}:{REDIS_PORT}")
    FREQUENCY_TRACKING_ENABLED = True
except redis.exceptions.AuthenticationError:
     logger.error(f"ERROR: Redis authentication failed for Frequency Tracking (DB: {REDIS_DB_FREQUENCY}). Check password.")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Redis connection failed for Frequency Tracking (DB: {REDIS_DB_FREQUENCY}): {e}. Tracking disabled.")
except Exception as e:
    logger.error(f"Unexpected error connecting to Redis for Frequency Tracking: {e}. Tracking disabled.")

# Load Robots.txt
disallowed_paths = set()
def load_robots_txt(path):
    global disallowed_paths
    disallowed_paths = set()
    if not os.path.exists(path):
        logger.warning(f"robots.txt not found at {path}. Path checking disabled.")
        return
    try:
        current_ua = None
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith('#'): continue
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    if key == 'user-agent':
                        current_ua = '*' if value == '*' else None # Only care about global rules for now
                    elif key == 'disallow' and current_ua == '*':
                        if value and value != "/":
                            disallowed_paths.add(value)
        logger.info(f"Loaded {len(disallowed_paths)} Disallow rules for '*' from {path}")
    except Exception as e: logger.error(f"Error loading robots.txt from {path}: {e}")

def is_path_disallowed(path_str):
    if not path_str or not disallowed_paths: return False
    try:
        # Ensure path starts with / for consistent matching
        normalized_path = path_str if path_str.startswith('/') else '/' + path_str
        for disallowed in disallowed_paths:
            if normalized_path.startswith(disallowed): return True
    except Exception: pass
    return False

# Load rules immediately
load_robots_txt(ROBOTS_TXT_PATH)

# Load Trained Random Forest Model
model_pipeline = None
MODEL_LOADED = False
if os.path.exists(RF_MODEL_PATH):
    try:
        model_pipeline = joblib.load(RF_MODEL_PATH)
        MODEL_LOADED = True
        logger.info(f"RF model loaded successfully from {RF_MODEL_PATH}.")
    except Exception as e:
        logger.error(f"Failed to load RF model from {RF_MODEL_PATH}: {e}")
else:
    logger.warning(f"Model file not found at {RF_MODEL_PATH}. Heuristic scoring only.")

# --- Feature Extraction Logic ---
# (Remains largely the same, uses is_path_disallowed defined above)
def extract_features(log_entry_dict, freq_features):
    features = {}
    if not isinstance(log_entry_dict, dict): return {}
    ua_string = log_entry_dict.get('user_agent', '')
    referer = log_entry_dict.get('referer', '')
    path = log_entry_dict.get('path') or ''
    # Basic features
    features['ua_length'] = len(ua_string) if ua_string else 0
    features['status_code'] = log_entry_dict.get('status', 0)
    features['bytes_sent'] = log_entry_dict.get('bytes', 0)
    features['http_method'] = log_entry_dict.get('method', 'UNKNOWN')
    # Path features
    features['path_depth'] = path.count('/')
    features['path_length'] = len(path)
    features['path_is_root'] = 1 if path == '/' else 0
    features['path_has_docs'] = 1 if '/docs' in path.lower() else 0 # Case-insensitive check
    features['path_is_wp'] = 1 if ('/wp-' in path or '/xmlrpc.php' in path) else 0
    features['path_disallowed'] = 1 if is_path_disallowed(path) else 0 # Use loaded rules
    # UA features
    ua_lower = ua_string.lower() if ua_string else ''
    features['ua_is_known_bad'] = 1 if any(bad in ua_lower for bad in KNOWN_BAD_UAS) else 0
    features['ua_is_known_benign_crawler'] = 1 if any(good in ua_lower for good in KNOWN_BENIGN_CRAWLERS_UAS) else 0
    features['ua_is_empty'] = 1 if not ua_string else 0
    # Detailed UA parsing (if library available)
    ua_parse_failed = False
    if UA_PARSER_AVAILABLE and ua_string:
        try:
            parsed_ua = ua_parse(ua_string)
            features['ua_browser_family'] = parsed_ua.browser.family or 'Other'
            features['ua_os_family'] = parsed_ua.os.family or 'Other'
            features['ua_device_family'] = parsed_ua.device.family or 'Other'
            features['ua_is_mobile'] = 1 if parsed_ua.is_mobile else 0
            features['ua_is_tablet'] = 1 if parsed_ua.is_tablet else 0
            features['ua_is_pc'] = 1 if parsed_ua.is_pc else 0
            features['ua_is_touch'] = 1 if parsed_ua.is_touch_capable else 0
            features['ua_library_is_bot'] = 1 if parsed_ua.is_bot else 0
        except Exception: ua_parse_failed = True
    if not UA_PARSER_AVAILABLE or ua_parse_failed:
        features['ua_browser_family'] = 'Unknown'
        features['ua_os_family'] = 'Unknown'
        features['ua_device_family'] = 'Unknown'
        features['ua_is_mobile'], features['ua_is_tablet'], features['ua_is_pc'], features['ua_is_touch'] = 0, 0, 0, 0
        features['ua_library_is_bot'] = features['ua_is_known_bad'] # Fallback: if known bad, flag as bot
    # Referer features
    features['referer_is_empty'] = 1 if not referer else 0
    features['referer_has_domain'] = 0
    try:
        if referer and referer != '-': # Check for '-' often used for no referer
            parsed_referer = urlparse(referer)
            features['referer_has_domain'] = 1 if parsed_referer.netloc else 0
    except Exception: pass
    # Time features
    timestamp_iso = log_entry_dict.get('timestamp') # Assume timestamp is passed correctly
    hour, dow = -1, -1
    if timestamp_iso:
        try:
            # Handle potential 'Z' notation or timezone offset
            if isinstance(timestamp_iso, str):
                ts_str = timestamp_iso.replace('Z', '+00:00')
                ts = datetime.datetime.fromisoformat(ts_str)
            elif isinstance(timestamp_iso, datetime.datetime):
                ts = timestamp_iso # Already a datetime object
            else: ts = None

            if ts:
                # Convert to UTC if timezone-aware, otherwise assume UTC
                if ts.tzinfo: ts = ts.astimezone(datetime.timezone.utc)
                hour = ts.hour
                dow = ts.weekday()
        except Exception as e: logger.debug(f"Error parsing timestamp '{timestamp_iso}': {e}")
    features['hour_of_day'] = hour
    features['day_of_week'] = dow
    # Frequency features (passed in)
    features[f'req_freq_{FREQUENCY_WINDOW_SECONDS}s'] = freq_features.get('count', 0)
    features['time_since_last_sec'] = freq_features.get('time_since', -1.0)
    return features

# --- Real-time Frequency Calculation using Redis ---
# (Logic remains the same, relies on initialized redis_client_freq)
def get_realtime_frequency_features(ip: str) -> dict:
    """Gets frequency count and time since last request for an IP from Redis."""
    features = {'count': 0, 'time_since': -1.0}
    if not FREQUENCY_TRACKING_ENABLED or not ip or not redis_client_freq: return features
    try:
        now_unix = time.time()
        window_start_unix = now_unix - FREQUENCY_WINDOW_SECONDS
        now_ms_str = f"{now_unix:.6f}" # Store with microsecond precision
        redis_key = f"{FREQUENCY_KEY_PREFIX}{ip}"

        # Pipeline commands for efficiency
        pipe = redis_client_freq.pipeline()
        # Remove entries older than the window start time
        pipe.zremrangebyscore(redis_key, '-inf', f'({window_start_unix}')
        # Add the current request timestamp
        pipe.zadd(redis_key, {now_ms_str: now_unix})
        # Count entries within the current window
        pipe.zcount(redis_key, window_start_unix, now_unix)
        # Get the last two entries to calculate time since last
        pipe.zrange(redis_key, -2, -1, withscores=True)
        # Set/reset expiration time for the key (slightly longer than window)
        pipe.expire(redis_key, FREQUENCY_WINDOW_SECONDS + 60)
        # Execute pipeline
        results = pipe.execute()

        # Process results (check lengths carefully)
        current_count = results[2] if len(results) > 2 and isinstance(results[2], int) else 0
        features['count'] = max(0, current_count -1) if current_count > 0 else 0 # Count *previous* requests in window

        recent_entries = results[3] if len(results) > 3 and isinstance(results[3], list) else []
        if len(recent_entries) > 1:
            # Second to last entry is the previous request
            last_ts = recent_entries[0][1]
            time_diff = now_unix - last_ts
            features['time_since'] = round(time_diff, 3)
        elif len(recent_entries) == 1: # Only current request in window
             features['time_since'] = -1.0 # Indicate no previous request in window
        # If recent_entries is empty, time_since remains -1.0

    except redis.exceptions.RedisError as e: logger.warning(f"Redis error during frequency check for IP {ip}: {e}"); increment_metric("redis_errors_frequency")
    except Exception as e: logger.warning(f"Unexpected error during frequency check for IP {ip}: {e}", exc_info=True)
    return features

# --- IP Reputation Check (NEW) ---
# (Logic remains the same, uses configured API URL and Key)
async def check_ip_reputation(ip: str) -> Optional[Dict[str, Any]]:
    """Checks IP reputation using a configured external service."""
    if not ENABLE_IP_REPUTATION or not IP_REPUTATION_API_URL or not ip:
        return None
    increment_metric("ip_reputation_checks_run")
    logger.info(f"Checking IP reputation for {ip} using {IP_REPUTATION_API_URL}")
    headers = {'Accept': 'application/json'}
    params = {'ipAddress': ip} # Adapt params based on actual API
    if IP_REPUTATION_API_KEY:
        # Adapt auth method based on actual API (Bearer, Key header, etc.)
        headers['Authorization'] = f"Bearer {IP_REPUTATION_API_KEY}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(IP_REPUTATION_API_URL, params=params, headers=headers, timeout=IP_REPUTATION_TIMEOUT)
            response.raise_for_status()
            result = response.json()
            logger.debug(f"IP Reputation API response for {ip}: {result}")
            # --- Parse the specific API response ---
            is_malicious = False
            # Example field from AbuseIPDB - adapt as needed
            score = result.get("abuseConfidenceScore", result.get("score", 0))
            if score >= IP_REPUTATION_MIN_MALICIOUS_THRESHOLD:
                is_malicious = True
            increment_metric("ip_reputation_success")
            if is_malicious: increment_metric("ip_reputation_malicious")
            return {"is_malicious": is_malicious, "score": score, "raw_response": result}
    except httpx.TimeoutException: logger.error(f"Timeout checking IP reputation for {ip}"); increment_metric("ip_reputation_errors_timeout"); return None
    except httpx.RequestError as exc: logger.error(f"Request error checking IP reputation for {ip}: {exc}"); increment_metric("ip_reputation_errors_request"); return None
    except httpx.HTTPStatusError as exc: logger.error(f"IP Reputation API returned status {exc.response.status_code} for {ip}. Response: {exc.response.text[:500]}"); increment_metric("ip_reputation_errors_status"); return None
    except json.JSONDecodeError as exc: logger.error(f"JSON decode error processing IP reputation response for {ip}: {exc} - Response: {response.text[:500]}"); increment_metric("ip_reputation_errors_response_decode"); return None
    except Exception as e: logger.error(f"Unexpected error checking IP reputation for {ip}: {e}", exc_info=True); increment_metric("ip_reputation_errors_unexpected"); return None

# --- Pydantic Models ---
# (Model remains the same)
class RequestMetadata(BaseModel):
    timestamp: str | datetime.datetime
    ip: str
    user_agent: str | None = None
    referer: str | None = None
    path: str | None = None
    headers: Dict[str, str] | None = None
    source: str # Where the request came from (e.g., 'tarpit_api')

# --- FastAPI App ---
app = FastAPI(
    title="Escalation Engine (IIS Version)",
    description="Analyzes suspicious requests and escalates if necessary."
)

# --- Analysis & Classification Functions ---
# (Logic remains the same, uses updated feature extraction and config)
def run_heuristic_and_model_analysis(metadata: RequestMetadata, ip_rep_result: Optional[Dict] = None) -> float:
    """Analyzes metadata using rules, RF model, Redis frequency, and optional IP reputation."""
    increment_metric("heuristic_checks_run")
    rule_score = 0.0; model_score = 0.5; model_used = False; final_score = 0.5
    # Get frequency features
    frequency_features = get_realtime_frequency_features(metadata.ip)
    increment_metric(f"req_freq_{FREQUENCY_WINDOW_SECONDS}s_count", frequency_features['count']) # Use different keys for metrics

    # Prepare data dict for feature extraction
    log_entry_dict = metadata.model_dump()
    # Ensure timestamp is string format if needed by feature extractor
    if isinstance(log_entry_dict.get('timestamp'), datetime.datetime):
        log_entry_dict['timestamp'] = log_entry_dict['timestamp'].isoformat()

    # Extract features (now includes frequency)
    features_dict = extract_features(log_entry_dict, frequency_features)
    if not features_dict:
         logger.warning(f"Could not extract features for analysis (IP: {metadata.ip})")
         return 0.5 # Return neutral score if features fail

    # --- Apply Heuristics (using extracted features) ---
    ua_lower = (metadata.user_agent or '').lower()
    is_known_benign = features_dict.get('ua_is_known_benign_crawler', 0) == 1
    if features_dict.get('ua_is_known_bad', 0) == 1 and not is_known_benign: rule_score += 0.7
    if features_dict.get('ua_is_empty', 0) == 1: rule_score += 0.5
    if features_dict.get('path_disallowed', 0) == 1 and not is_known_benign: rule_score += 0.6
    # Use frequency features
    req_freq = features_dict.get(f'req_freq_{FREQUENCY_WINDOW_SECONDS}s', 0)
    time_since = features_dict.get('time_since_last_sec', -1.0)
    if req_freq > 60 : rule_score += 0.3
    elif req_freq > 30 : rule_score += 0.1
    if time_since != -1.0 and time_since < 0.3: rule_score += 0.2
    # Adjust score based on known benign status
    if is_known_benign: rule_score -= 0.5 # Significantly reduce score

    rule_score = max(0.0, min(1.0, rule_score)) # Clamp rule score

    # --- Apply RF Model ---
    if MODEL_LOADED and model_pipeline:
        try:
            probabilities = model_pipeline.predict_proba([features_dict])[0] # Pass extracted features
            model_score = probabilities[1] # Probability of class '1' (bot)
            model_used = True
            increment_metric("rf_model_predictions")
            logger.debug(f"RF Model score for IP {metadata.ip}: {model_score:.3f}")
        except Exception as e: logger.error(f"RF model prediction failed for IP {metadata.ip}: {e}"); increment_metric("rf_model_errors")

    # --- Combine Scores ---
    if model_used: final_score = (0.3 * rule_score) + (0.7 * model_score) # Weight model higher
    else: final_score = rule_score # Fallback to rules only

    # --- Factor in IP Reputation (NEW) ---
    if ip_rep_result and ip_rep_result.get("is_malicious"):
        logger.info(f"Adjusting score for malicious IP reputation for {metadata.ip} (Score: {ip_rep_result.get('score', 'N/A')})")
        final_score += IP_REPUTATION_MALICIOUS_SCORE_BONUS
        increment_metric("score_adjusted_ip_reputation")

    final_score = max(0.0, min(1.0, final_score)) # Clamp final score
    logger.info(f"Analyzed IP {metadata.ip}: RuleScore={rule_score:.3f}, ModelScore={model_score:.3f if model_used else 'N/A'}, IPRep={ip_rep_result.get('is_malicious') if ip_rep_result else 'N/A'}, FinalScore={final_score:.3f}")
    return final_score

# --- classify_with_local_llm_api / classify_with_external_api ---
# (Logic remains the same, relies on configured URLs/Keys)
async def classify_with_local_llm_api(metadata: RequestMetadata) -> bool | None:
    """ Classifies using configured local LLM API. """
    if not LOCAL_LLM_API_URL or not LOCAL_LLM_MODEL: return None
    increment_metric("local_llm_checks_run")
    logger.info(f"Attempting classification for IP {metadata.ip} using local LLM API ({LOCAL_LLM_MODEL})...")
    # Simplified prompt example
    prompt = f"""Classify the following request as MALICIOUS_BOT, BENIGN_CRAWLER, or HUMAN. Respond ONLY with the classification.
    Request: IP={metadata.ip}, UA={metadata.user_agent or 'N/A'}, Path={metadata.path or 'N/A'}, Referer={metadata.referer or 'N/A'}"""
    api_payload = { "model": LOCAL_LLM_MODEL, "prompt": prompt, "temperature": 0.1, "stream": False } # Adapt payload structure if needed
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(LOCAL_LLM_API_URL, json=api_payload, timeout=LOCAL_LLM_TIMEOUT)
            response.raise_for_status()
            result = response.json()
            # Adapt response parsing based on actual LLM API
            content = result.get("choices", [{}])[0].get("text", result.get("content", "")).strip().upper()
            logger.info(f"Local LLM API response for {metadata.ip}: '{content}'")
            if "MALICIOUS_BOT" in content: increment_metric("local_llm_classified_malicious"); return True
            elif "HUMAN" in content or "BENIGN_CRAWLER" in content: increment_metric("local_llm_classified_benign"); return False
            else: logger.warning(f"Unexpected classification from local LLM ({metadata.ip}): '{content}'"); increment_metric("local_llm_errors_unexpected_response"); return None
    except httpx.TimeoutException: logger.error(f"Timeout calling local LLM API ({LOCAL_LLM_API_URL}) for IP {metadata.ip} after {LOCAL_LLM_TIMEOUT}s"); increment_metric("local_llm_errors_timeout"); return None
    except httpx.RequestError as exc: logger.error(f"Request error calling local LLM API ({LOCAL_LLM_API_URL}) for IP {metadata.ip}: {exc}"); increment_metric("local_llm_errors_request"); return None
    except httpx.HTTPStatusError as exc: logger.error(f"Local LLM API returned status {exc.response.status_code} for IP {metadata.ip}. Response: {exc.response.text[:500]}"); increment_metric("local_llm_errors_status"); return None
    except json.JSONDecodeError as exc: logger.error(f"JSON decode error processing LLM response for IP {metadata.ip}: {exc} - Response: {response.text[:500]}"); increment_metric("local_llm_errors_response_decode"); return None
    except Exception as e: logger.error(f"Unexpected error processing local LLM API response for IP {metadata.ip}: {e}", exc_info=True); increment_metric("local_llm_errors_unexpected"); return None

async def classify_with_external_api(metadata: RequestMetadata) -> bool | None:
    """ Classifies using configured external API. """
    if not EXTERNAL_API_URL: return None
    increment_metric("external_api_checks_run")
    logger.info(f"Attempting classification for IP {metadata.ip} using External API: {EXTERNAL_API_URL}")
    # Adapt payload based on actual API requirements
    external_payload = {"ipAddress": metadata.ip, "userAgent": metadata.user_agent, "referer": metadata.referer, "requestPath": metadata.path, "headers": dict(metadata.headers or {})}
    headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' }
    if EXTERNAL_API_KEY: headers['Authorization'] = f"Bearer {EXTERNAL_API_KEY}" # Adapt auth
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(EXTERNAL_API_URL, headers=headers, json=external_payload, timeout=EXTERNAL_API_TIMEOUT)
            response.raise_for_status()
            result = response.json()
            # Adapt response parsing based on actual API
            is_bot = result.get("is_bot", result.get("bot_status", None)) # Example fields
            logger.info(f"External API response for {metadata.ip}: IsBot={is_bot}, Raw={result}")
            if isinstance(is_bot, bool): increment_metric("external_api_success"); return is_bot
            else: logger.warning(f"Unexpected response format from external API for {metadata.ip}. Response: {result}"); increment_metric("external_api_errors_unexpected_response"); return None
    except httpx.TimeoutException: logger.error(f"Timeout calling external API ({EXTERNAL_API_URL}) for IP {metadata.ip}"); increment_metric("external_api_errors_timeout"); return None
    except httpx.RequestError as exc: logger.error(f"Request error calling external API ({EXTERNAL_API_URL}) for IP {metadata.ip}: {exc}"); increment_metric("external_api_errors_request"); return None
    except httpx.HTTPStatusError as exc: logger.error(f"External API returned status {exc.response.status_code} for IP {metadata.ip}. Response: {exc.response.text[:500]}"); increment_metric("external_api_errors_status"); return None
    except json.JSONDecodeError as exc: logger.error(f"JSON decode error processing external API response for IP {metadata.ip}: {exc} - Response: {response.text[:500]}"); increment_metric("external_api_errors_response_decode"); return None
    except Exception as e: logger.error(f"Unexpected error processing external API response for IP {metadata.ip}: {e}", exc_info=True); increment_metric("external_api_errors_unexpected"); return None


# --- Webhook Forwarding ---
# (Logic remains the same, uses configured WEBHOOK_URL)
async def forward_to_webhook(payload: Dict[str, Any], reason: str):
    """Sends data to the configured webhook URL."""
    if not WEBHOOK_URL:
        logger.warning(f"Webhook URL not configured. Cannot forward escalation for IP {payload.get('ip')}")
        return
    increment_metric("webhooks_sent")
    serializable_payload = {}
    try:
        # Convert datetime objects before sending
        def default_serializer(obj):
            if isinstance(obj, datetime.datetime): return obj.isoformat()
            raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")
        serializable_payload = json.loads(json.dumps(payload, default=default_serializer))
    except Exception as e:
        logger.error(f"Failed to serialize payload for webhook (IP: {payload.get('ip')}): {e}", exc_info=True)
        serializable_payload = {"ip": payload.get("ip", "unknown"), "error": "Payload serialization failed"}

    webhook_payload = {
        "event_type": "suspicious_activity_detected",
        "reason": reason,
        "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z",
        "details": serializable_payload
    }
    headers = {'Content-Type': 'application/json'}
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(WEBHOOK_URL, headers=headers, json=webhook_payload, timeout=10.0)
            response.raise_for_status()
            logger.info(f"Webhook forwarded successfully for IP {payload.get('ip')} to {WEBHOOK_URL}")
    except httpx.RequestError as exc: logger.error(f"Error forwarding to webhook {WEBHOOK_URL} for IP {payload.get('ip')}: {exc}"); increment_metric("webhook_errors_request")
    except httpx.HTTPStatusError as exc: logger.error(f"Webhook endpoint {WEBHOOK_URL} returned status {exc.response.status_code} for IP {payload.get('ip')}. Response: {exc.response.text[:500]}"); increment_metric("webhook_errors_status")
    except Exception as e: logger.error(f"Unexpected error during webhook forwarding for IP {payload.get('ip')}: {e}", exc_info=True); increment_metric("webhook_errors_unexpected")


# --- CAPTCHA Trigger Placeholder ---
# (Logic remains the same)
async def trigger_captcha_challenge(metadata: RequestMetadata) -> bool:
    """Placeholder function for triggering a CAPTCHA challenge."""
    logger.info(f"CAPTCHA Triggered (Placeholder) for IP {metadata.ip}. Score between {CAPTCHA_SCORE_THRESHOLD_LOW} and {CAPTCHA_SCORE_THRESHOLD_HIGH}. Would need redirect mechanism to {CAPTCHA_VERIFICATION_URL}")
    increment_metric("captcha_challenges_triggered")
    return True # Indicate trigger happened (needs integration with IIS/frontend)


# --- API Endpoint (/escalate) ---
# (Logic remains the same, uses updated analysis function)
@app.post("/escalate")
async def handle_escalation(metadata_req: RequestMetadata, request: Request):
    """Receives request metadata, performs analysis, and triggers actions."""
    # Get client IP respecting X-Forwarded-For if present (common behind proxies)
    client_ip_header = request.headers.get("X-Forwarded-For")
    source_ip = client_ip_header.split(',')[0].strip() if client_ip_header else (request.client.host if request.client else "unknown")
    increment_metric("escalation_requests_received")
    ip_under_test = metadata_req.ip # IP reported by the source (e.g., Tarpit API)

    # Log source IP vs reported IP if they differ significantly (optional)
    if ip_under_test != source_ip and source_ip != "unknown":
         logger.debug(f"Request source IP ({source_ip}) differs from reported IP ({ip_under_test}). Using reported IP for analysis.")

    action_taken = "analysis_complete"
    is_bot_decision = None
    final_score = -1.0 # Default score indicating analysis might not have fully run

    try:
        # --- Step 1: IP Reputation Check (Optional) ---
        ip_rep_result = None
        if ENABLE_IP_REPUTATION:
            ip_rep_result = await check_ip_reputation(ip_under_test)
            # Optional immediate escalation based on reputation (uncomment/adjust if desired)
            # if ip_rep_result and ip_rep_result.get("is_malicious"):
            #     logger.info(f"IP {ip_under_test} flagged by IP Reputation. Escalating immediately.")
            #     is_bot_decision = True
            #     action_taken = "webhook_triggered_ip_reputation"
            #     increment_metric("bots_detected_ip_reputation")
            #     await forward_to_webhook(metadata_req.model_dump(mode='json'), f"IP Reputation Malicious (Score: {ip_rep_result.get('score', 'N/A')})")
            #     # Skip further checks if blocking on reputation alone
            #     logger.info(f"Escalation Complete: IP={ip_under_test}, Source={metadata_req.source}, Score=N/A, Decision={is_bot_decision}, Action={action_taken}, IPRep=True")
            #     return {"status": "processed", "action": action_taken, "is_bot_decision": is_bot_decision, "score": 1.0} # Return high score

        # --- Step 2: Heuristic and Model Analysis ---
        # Proceed only if not already flagged by IP reputation (if above logic enabled)
        if is_bot_decision is None:
            final_score = run_heuristic_and_model_analysis(metadata_req, ip_rep_result)

            # --- Step 3: Decision Logic ---
            if final_score >= HEURISTIC_THRESHOLD_HIGH:
                is_bot_decision = True
                action_taken = "webhook_triggered_high_score"
                increment_metric("bots_detected_high_score")
                await forward_to_webhook(metadata_req.model_dump(mode='json'), f"High Combined Score ({final_score:.3f})")

            elif final_score < CAPTCHA_SCORE_THRESHOLD_LOW: # Clearly low score
                 is_bot_decision = False
                 action_taken = "classified_human_low_score"
                 increment_metric("humans_detected_low_score")

            elif ENABLE_CAPTCHA_TRIGGER and CAPTCHA_SCORE_THRESHOLD_LOW <= final_score < CAPTCHA_SCORE_THRESHOLD_HIGH:
                 # --- Step 3a: CAPTCHA Trigger (Borderline Score) ---
                 logger.info(f"IP {ip_under_test} has borderline score ({final_score:.3f}). Checking CAPTCHA trigger.")
                 captcha_needed = await trigger_captcha_challenge(metadata_req)
                 action_taken = "captcha_triggered"
                 is_bot_decision = None # Remain uncertain until CAPTCHA result (external integration needed)

            else: # Score is medium/high but below threshold, or CAPTCHA disabled/failed
                 # --- Step 3b: Deeper Analysis (LLM / External API) ---
                 logger.info(f"IP {ip_under_test} requires deeper check (Score: {final_score:.3f}). Checking Local LLM...")
                 local_llm_result = await classify_with_local_llm_api(metadata_req)
                 if local_llm_result is True:
                     is_bot_decision = True
                     action_taken = "webhook_triggered_local_llm"
                     increment_metric("bots_detected_local_llm")
                     await forward_to_webhook(metadata_req.model_dump(mode='json'), "Local LLM Classification")
                 elif local_llm_result is False:
                     is_bot_decision = False
                     action_taken = "classified_human_local_llm"
                     increment_metric("humans_detected_local_llm")
                 else: # LLM failed or inconclusive, try External API if configured
                     action_taken = "local_llm_inconclusive"
                     if EXTERNAL_API_URL:
                         logger.info(f"Local LLM inconclusive for IP {ip_under_test}. Checking External API...")
                         external_api_result = await classify_with_external_api(metadata_req)
                         if external_api_result is True:
                             is_bot_decision = True
                             action_taken = "webhook_triggered_external_api"
                             increment_metric("bots_detected_external_api")
                             await forward_to_webhook(metadata_req.model_dump(mode='json'), "External API Classification")
                         elif external_api_result is False:
                             is_bot_decision = False
                             action_taken = "classified_human_external_api"
                             increment_metric("humans_detected_external_api")
                         else: action_taken = "external_api_inconclusive"
                     # If no external API, decision remains None (uncertain) if LLM was inconclusive

    except ValidationError as e:
        logger.error(f"Invalid request payload received from {source_ip}: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid payload: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during escalation processing for IP {ip_under_test}: {e}", exc_info=True)
        action_taken = "internal_server_error"
        is_bot_decision = None # Indicate error state
        final_score = -1.0
        # Return 500 status code directly in the response
        return Response(status_code=500, content=json.dumps({"status": "error", "detail": "Internal server error during escalation"}), media_type="application/json")


    # --- Final Logging & Response ---
    log_msg = f"IP={ip_under_test}, Source={metadata_req.source}, Score={final_score:.3f}, Decision={is_bot_decision}, Action={action_taken}"
    if ip_rep_result: log_msg += f", IPRepMalicious={ip_rep_result.get('is_malicious')}, IPRepScore={ip_rep_result.get('score')}"
    logger.info(f"Escalation Complete: {log_msg}")

    return {"status": "processed", "action": action_taken, "is_bot_decision": is_bot_decision, "score": round(final_score, 3)}

# --- Metrics Endpoint ---
# (Logic remains the same)
@app.get("/metrics")
async def get_metrics_endpoint():
    if not METRICS_AVAILABLE: raise HTTPException(status_code=501, detail="Metrics module not available")
    try: return get_metrics()
    except Exception as e: logger.error(f"Error retrieving metrics: {e}", exc_info=True); raise HTTPException(status_code=500, detail="Failed to retrieve metrics")

# --- Health Check Endpoint ---
# (Logic remains the same)
@app.get("/health")
async def health_check():
    """ Basic health check endpoint """
    redis_ok = False
    if redis_client_freq:
        try: redis_ok = redis_client_freq.ping()
        except Exception: redis_ok = False
    return {"status": "ok", "redis_frequency_connected": redis_ok, "model_loaded": MODEL_LOADED}


# --- Main Execution ---
# This part is usually handled by the hosting mechanism (like IIS calling uvicorn/waitress)
if __name__ == "__main__":
    import uvicorn
    logger.info("--- Escalation Engine Starting (IIS Version - Direct Run for Testing) ---")
    if MODEL_LOADED: logger.info(f"Loaded RF Model from: {RF_MODEL_PATH}")
    else: logger.warning(f"RF Model NOT loaded from {RF_MODEL_PATH}. Using rule-based heuristics only.")
    if FREQUENCY_TRACKING_ENABLED: logger.info(f"Redis Frequency Tracking Enabled (DB: {REDIS_DB_FREQUENCY})")
    else: logger.warning(f"Redis Frequency Tracking DISABLED.")
    if not disallowed_paths: logger.warning(f"No robots.txt rules loaded from {ROBOTS_TXT_PATH}.")
    logger.info(f"Local LLM API configured: {'Yes (' + LOCAL_LLM_API_URL + ')' if LOCAL_LLM_API_URL else 'No'}")
    logger.info(f"External Classification API configured: {'Yes (' + EXTERNAL_API_URL + ')' if EXTERNAL_API_URL else 'No'}")
    logger.info(f"IP Reputation Check Enabled: {ENABLE_IP_REPUTATION} ({'URL Set' if IP_REPUTATION_API_URL else 'URL Not Set'})")
    logger.info(f"CAPTCHA Trigger Enabled: {ENABLE_CAPTCHA_TRIGGER} (Low: {CAPTCHA_SCORE_THRESHOLD_LOW}, High: {CAPTCHA_SCORE_THRESHOLD_HIGH})")
    logger.info(f"Webhook URL configured: {'Yes (' + WEBHOOK_URL + ')' if WEBHOOK_URL else 'No'}")
    logger.info("------------------------------------------------------------------------")
    # Standard port 8003 used internally
    uvicorn.run(
        "escalation_engine:app",
        host="127.0.0.1", # Listen on localhost for local testing
        port=8003,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
        # workers=1 # Typically 1 worker for local testing
    )