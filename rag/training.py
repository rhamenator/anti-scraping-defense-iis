# anti-scraping-defense-iis/rag/training.py
# Modified for Windows/IIS Compatibility
# Parses logs, loads into SQLite DB, labels entries, extracts features,
# trains RandomForest, AND saves data in JSONL format for LLM fine-tuning.

# --- (Imports remain the same) ---
import pandas as pd
import re
import datetime
from collections import defaultdict, deque
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.pipeline import Pipeline
import joblib
import time
import os
from urllib.parse import urlparse
import json
import random
import sqlite3
import logging

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Define Windows Paths ---
# (Paths definitions remain the same as previous IIS version)
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
DATA_DIR = os.path.join(APP_BASE_DIR, "data")
MODELS_DIR = os.path.join(APP_BASE_DIR, "models")
CONFIG_DIR = os.path.join(APP_BASE_DIR, "config")
LOGS_DIR = os.path.join(APP_BASE_DIR, "logs") # For reading feedback logs
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# --- Configuration ---
# (Path constructions remain the same as previous IIS version)
LOG_FILENAME = os.getenv("TRAINING_LOG_FILENAME", "u_exYYMMDD.log") # Example IIS default W3C format
LOG_FILE_PATH = os.path.join(DATA_DIR, LOG_FILENAME) # Log file path to read
DB_FILENAME = os.getenv("TRAINING_DB_FILENAME", "log_analysis.db")
DB_PATH = os.path.join(DATA_DIR, DB_FILENAME)
MODEL_FILENAME = os.getenv("TRAINING_MODEL_FILENAME", "bot_detection_rf_model.joblib")
MODEL_SAVE_PATH = os.path.join(MODELS_DIR, MODEL_FILENAME)
FINETUNE_DATA_DIR = os.path.join(DATA_DIR, "finetuning_data") # Subdir within data
FINETUNE_TRAIN_FILE = os.path.join(FINETUNE_DATA_DIR, "finetuning_data_train.jsonl")
FINETUNE_EVAL_FILE = os.path.join(FINETUNE_DATA_DIR, "finetuning_data_eval.jsonl")
ROBOTS_TXT_FILENAME = os.getenv("ROBOTS_TXT_FILENAME", "robots.txt")
ROBOTS_TXT_PATH = os.path.join(CONFIG_DIR, ROBOTS_TXT_FILENAME)
HONEYPOT_LOG_FILENAME = os.getenv("HONEYPOT_LOG_FILENAME", "honeypot_hits.log")
HONEYPOT_HIT_LOG = os.path.join(LOGS_DIR, HONEYPOT_LOG_FILENAME)
CAPTCHA_LOG_FILENAME = os.getenv("CAPTCHA_LOG_FILENAME", "captcha_success.log")
CAPTCHA_SUCCESS_LOG = os.path.join(LOGS_DIR, CAPTCHA_LOG_FILENAME)

# (Other configurations remain the same)
FINETUNE_SPLIT_RATIO = float(os.getenv("TRAINING_FINETUNE_SPLIT_RATIO", 0.15))
MIN_SAMPLES_FOR_TRAINING = int(os.getenv("TRAINING_MIN_SAMPLES", 100))
FREQUENCY_WINDOW_SECONDS = int(os.getenv("TRAINING_FREQ_WINDOW_SEC", 300))
KNOWN_BAD_UAS_STR = os.getenv("KNOWN_BAD_UAS", 'python-requests,curl,wget,scrapy,java/,ahrefsbot,semrushbot,mj12bot,dotbot,petalbot,bytespider,gptbot,ccbot,claude-web,google-extended,dataprovider,purebot,scan,masscan,zgrab,nmap')
KNOWN_BENIGN_CRAWLERS_UAS_STR = os.getenv("KNOWN_BENIGN_CRAWLERS_UAS", 'googlebot,bingbot,slurp,duckduckbot,baiduspider,yandexbot,googlebot-image')
KNOWN_BAD_UAS = [ua.strip().lower() for ua in KNOWN_BAD_UAS_STR.split(',') if ua.strip()]
KNOWN_BENIGN_CRAWLERS_UAS = [ua.strip().lower() for ua in KNOWN_BENIGN_CRAWLERS_UAS_STR.split(',') if ua.strip()]

# --- Attempt to import user-agents library ---
# (Remains the same)
try:
    from user_agents import parse as ua_parse
    UA_PARSER_AVAILABLE = True
    logger.info("Imported 'user-agents'.")
except ImportError:
    UA_PARSER_AVAILABLE = False
    logger.warning("Warning: 'user-agents' not installed or not found in environment. Detailed UA parsing disabled.")


# --- SQLite Database Setup ---
# (Remains the same as previous IIS version)
def setup_database(db_path):
    logger.info(f"Setting up database at: {db_path}")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = None
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ident TEXT, user TEXT,
                timestamp_iso TEXT NOT NULL, method TEXT, path TEXT, protocol TEXT,
                status INTEGER, bytes INTEGER, referer TEXT, user_agent TEXT )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_timestamp ON requests (ip, timestamp_iso)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON requests (timestamp_iso)')
        conn.commit()
        logger.info("Database table 'requests' verified/created.")
        return conn
    except Exception as e:
        logger.error(f"ERROR: Database setup failed for {db_path}: {e}", exc_info=True)
        if conn: conn.close()
        return None

# --- Robots.txt Parsing ---
# (Remains the same)
disallowed_paths = set()
def load_robots_txt(path):
    global disallowed_paths; disallowed_paths = set()
    if not os.path.exists(path): logger.warning(f"robots.txt not found at {path}."); return
    try:
        # ... (parsing logic remains the same) ...
        logger.info(f"Loaded {len(disallowed_paths)} Disallow rules for '*' from {path}")
    except Exception as e: logger.error(f"Error loading robots.txt from {path}: {e}")
def is_path_disallowed(path_str):
    # ... (logic remains the same) ...
    return False
load_robots_txt(ROBOTS_TXT_PATH)

# --- Log Parsing & Loading into DB ---

# ==============================================================================
# == IMPORTANT: IIS Log Parsing Modification Needed Here ==
# ==============================================================================
# The function below (`parse_iis_w3c_log_line`) is a *template* for parsing
# IIS W3C Extended Log File Format logs. IIS logs are highly configurable.
#
# You MUST:
# 1. Check your IIS logging configuration: In IIS Manager, select your site,
#    open "Logging", and click "Select Fields...". Note exactly which fields
#    are enabled and their order.
# 2. Adapt the `parse_iis_w3c_log_line` function below to match YOUR specific
#    log format. Pay close attention to:
#    - The `#Fields:` directive line in your log file.
#    - The delimiter (usually space).
#    - Date and time formats.
#    - Fields that might contain spaces (like User-Agent or Referer) which are
#      often quoted or require careful splitting.
#    - Mapping the parsed fields to the dictionary keys expected by the rest
#      of this script (ip, timestamp_iso, method, path, status, bytes, referer, user_agent).
#
# Using a dedicated log parsing library might be more robust than regex/split.
# ==============================================================================

def parse_iis_w3c_log_line(line, field_map):
    """
    Parses a line from an IIS W3C log file based on a field map.
    THIS IS A TEMPLATE - YOU MUST ADAPT IT TO YOUR IIS LOG FORMAT.
    """
    if not line or line.startswith('#'):
        return None # Skip comments and empty lines

    parts = line.split(' ') # Default delimiter is space

    if len(parts) != len(field_map):
        logger.debug(f"Skipping log line due to field count mismatch ({len(parts)} vs {len(field_map)} expected): {line[:100]}...")
        return None # Field count doesn't match header

    data = {}
    try:
        # Map parts to fields based on the field_map dictionary
        for i, field_name in field_map.items():
            # IIS uses '-' for null/empty values
            data[field_name] = None if parts[i] == '-' else parts[i]

        # --- Field Conversion and Renaming (Adapt based on your fields) ---
        # IP Address (usually 'c-ip' or 's-ip')
        ip_field = 'c-ip' # Adjust if using 's-ip' or other
        ip_address = data.get(ip_field)

        # Timestamp (combine 'date' and 'time' fields)
        log_date = data.get('date')
        log_time = data.get('time')
        timestamp_iso = None
        if log_date and log_time:
            try:
                # IIS default format: YYYY-MM-DD HH:MM:SS
                timestamp_obj = datetime.datetime.strptime(f"{log_date} {log_time}", '%Y-%m-%d %H:%M:%S')
                # Assume logs are in server's local time, convert to UTC
                # This is a simplification; IIS can log in UTC directly (preferred)
                # If logs are already UTC, use tzinfo=datetime.timezone.utc
                timestamp_utc = timestamp_obj.astimezone(datetime.timezone.utc)
                timestamp_iso = timestamp_utc.isoformat(timespec='seconds').replace('+00:00', 'Z')
            except ValueError as e:
                logger.debug(f"Could not parse IIS timestamp '{log_date} {log_time}': {e}")
                return None # Cannot proceed without timestamp

        # Request Details (often 'cs-method', 'cs-uri-stem', 'cs-uri-query', 'cs-version')
        method = data.get('cs-method')
        uri_stem = data.get('cs-uri-stem') # Path without query
        uri_query = data.get('cs-uri-query') # Query string (or None)
        protocol = data.get('cs-version') # e.g., HTTP/1.1

        # Combine stem and query for full path
        path = uri_stem
        # if uri_query: path = f"{uri_stem}?{uri_query}" # Decide if query string is needed for analysis

        # Status and Bytes ('sc-status', 'sc-bytes', 'cs-bytes')
        status = int(data.get('sc-status', 0))
        bytes_sent = int(data.get('sc-bytes', 0)) # Server to client
        # bytes_received = int(data.get('cs-bytes', 0)) # Client to server

        # Referer ('cs(Referer)') - Note the field name format
        referer = data.get('cs(Referer)')

        # User Agent ('cs(User-Agent)') - Note the field name format
        user_agent = data.get('cs(User-Agent)')
        # IIS often replaces spaces with '+' in UA/Referer, need to replace back
        if user_agent: user_agent = user_agent.replace('+', ' ')
        if referer: referer = referer.replace('+', ' ')

        # --- Map to expected dictionary keys ---
        parsed_data = {
            'ip': ip_address,
            'ident': None, # Typically not logged by IIS
            'user': data.get('cs-username'), # If username logging is enabled
            'timestamp_iso': timestamp_iso,
            'method': method,
            'path': path,
            'protocol': protocol,
            'status': status,
            'bytes': bytes_sent,
            'referer': referer,
            'user_agent': user_agent
        }
        return parsed_data

    except Exception as e:
        logger.warning(f"Error parsing IIS log line: {line[:100]}... Error: {e}", exc_info=True)
        return None


def load_logs_into_db(log_path, conn):
    logger.info(f"Loading IIS logs from {log_path} into database...")
    if not os.path.exists(log_path):
        logger.error(f"ERROR: Log file not found at {log_path}. Cannot load logs.")
        return False

    cursor = conn.cursor()
    inserted_count = 0; line_count = 0; parse_errors = 0; insert_errors = 0
    batch_size = 1000; batch = []
    field_map = None # Dictionary to map column index to field name

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
                line = line.strip()

                # Detect or update field map from #Fields directive
                if line.startswith('#Fields:'):
                    try:
                        fields = line[len('#Fields: '):].strip().split(' ')
                        field_map = {i: field for i, field in enumerate(fields)}
                        logger.info(f"Detected IIS log fields ({len(fields)}): {', '.join(fields)}")
                        # Validate required fields are present
                        required = ['date', 'time', 'c-ip', 'cs-method', 'cs-uri-stem', 'sc-status', 'sc-bytes', 'cs(User-Agent)', 'cs(Referer)'] # Example required
                        if not all(f in fields for f in required):
                             logger.error(f"ERROR: Log file {log_path} is missing required fields in #Fields directive. Required: {required}")
                             return False
                        continue # Skip processing the directive line
                    except Exception as e:
                         logger.error(f"ERROR: Could not parse #Fields directive in {log_path}: {e}. Line: {line}")
                         return False

                # Skip other comment lines
                if line.startswith('#') or not line:
                    continue

                # Ensure field map has been found before processing data lines
                if field_map is None:
                    if line_count > 50: # Check first few lines for header
                        logger.error(f"ERROR: #Fields directive not found near the beginning of {log_path}. Cannot parse.")
                        return False
                    continue # Keep looking for header

                # Parse the data line using the current field map
                parsed = parse_iis_w3c_log_line(line, field_map)

                if parsed and parsed.get('timestamp_iso'): # Ensure timestamp was parsed
                    # Match tuple order with CREATE TABLE statement
                    data_tuple = (
                        parsed.get('ip'), parsed.get('ident'), parsed.get('user'),
                        parsed.get('timestamp_iso'), parsed.get('method'), parsed.get('path'),
                        parsed.get('protocol'), parsed.get('status'), parsed.get('bytes'),
                        parsed.get('referer'), parsed.get('user_agent')
                    )
                    batch.append(data_tuple)
                    if len(batch) >= batch_size:
                        try:
                            cursor.executemany('''
                                INSERT INTO requests (ip, ident, user, timestamp_iso, method, path, protocol, status, bytes, referer, user_agent)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', batch)
                            conn.commit()
                            inserted_count += len(batch)
                            batch = []
                        except sqlite3.Error as e: logger.error(f"ERROR: DB insert error: {e}"); insert_errors += len(batch); batch = []
                        if line_count % 100000 == 0: logger.info(f"Processed {line_count} lines, Inserted {inserted_count}...")
                elif parsed is None:
                    parse_errors += 1 # Count lines skipped by the parser

            # Insert final batch
            if batch:
                try:
                    cursor.executemany('''
                        INSERT INTO requests (ip, ident, user, timestamp_iso, method, path, protocol, status, bytes, referer, user_agent)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', batch)
                    conn.commit(); inserted_count += len(batch)
                except sqlite3.Error as e: logger.error(f"ERROR: DB insert error (final batch): {e}"); insert_errors += len(batch)
    except Exception as e: logger.error(f"ERROR: Failed to read/process log file {log_path}: {e}", exc_info=True); return False
    finally:
        if cursor: cursor.close()

    logger.info(f"DB loading complete. Lines: {line_count}, Skipped/ParseErrs: {parse_errors}, Inserted: {inserted_count}, InsertErrs: {insert_errors}")
    if field_map is None and line_count > 0:
         logger.warning("Processed file but no #Fields directive was found. Parsing might be incorrect.")
    return inserted_count > 0


# --- Feature Engineering ---
# (extract_features_from_db remains the same as previous IIS version)
def extract_features_from_db(log_entry_row, db_cursor):
    # ... (logic remains the same) ...
    col_names = [desc[0] for desc in db_cursor.description]
    log_entry_dict = dict(zip(col_names, log_entry_row))
    ip = log_entry_dict.get('ip')
    current_timestamp_iso = log_entry_dict.get('timestamp_iso')
    freq_features = {'count': 0, 'time_since': -1.0}
    if ip and current_timestamp_iso:
        try:
            # ... (frequency calculation logic remains the same) ...
            current_time_dt = datetime.datetime.fromisoformat(current_timestamp_iso.replace('Z', '+00:00'))
            window_start_dt = current_time_dt - datetime.timedelta(seconds=FREQUENCY_WINDOW_SECONDS)
            window_start_iso = window_start_dt.isoformat(timespec='seconds').replace('+00:00', 'Z')
            db_cursor.execute("SELECT COUNT(*) FROM requests WHERE ip = ? AND timestamp_iso >= ? AND timestamp_iso < ?", (ip, window_start_iso, current_timestamp_iso))
            result = db_cursor.fetchone()
            freq_features['count'] = result[0] if result else 0
            db_cursor.execute("SELECT MAX(timestamp_iso) FROM requests WHERE ip = ? AND timestamp_iso < ?", (ip, current_timestamp_iso))
            result = db_cursor.fetchone()
            if result and result[0]:
                last_time_dt = datetime.datetime.fromisoformat(result[0].replace('Z', '+00:00'))
                time_diff = (current_time_dt - last_time_dt).total_seconds()
                freq_features['time_since'] = round(time_diff, 3)
        except Exception as e: logger.warning(f"Warning: Error calculating frequency features (IP: {ip}, Time: {current_timestamp_iso}): {e}")
    features_dict = extract_features(log_entry_dict, freq_features)
    return features_dict


# --- Labeling (with Scoring / Confidence) ---
# (load_feedback_data remains the same as previous IIS version)
def load_feedback_data():
    # ... (logic remains the same) ...
    honeypot_triggers = set(); captcha_successes = set(); logger.info("Loading feedback data...")
    if os.path.exists(HONEYPOT_HIT_LOG):
        # ... (load honeypot hits) ...
        logger.info(f"Loaded {len(honeypot_triggers)} unique IPs from {HONEYPOT_HIT_LOG}")
    else: logger.warning(f"Honeypot log file not found: {HONEYPOT_HIT_LOG}")
    if os.path.exists(CAPTCHA_SUCCESS_LOG):
        # ... (load captcha successes) ...
        logger.info(f"Loaded {len(captcha_successes)} unique IPs/Sessions from {CAPTCHA_SUCCESS_LOG}")
    else: logger.warning(f"Captcha log file not found: {CAPTCHA_SUCCESS_LOG}")
    return honeypot_triggers, captcha_successes

# (assign_label_and_score remains the same)
def assign_label_and_score(log_entry_dict, honeypot_triggers, captcha_successes):
    # ... (logic remains the same) ...
    return 'suspicious', 0.5, [] # Placeholder return

# (label_data_with_scores remains the same)
def label_data_with_scores(db_conn):
    # ... (logic remains the same) ...
    return [], [], [] # Placeholder return


# --- Model Training & Saving (Random Forest) ---
# (train_and_save_model remains the same)
def train_and_save_model(training_data_features, training_labels, model_path):
    # ... (logic remains the same) ...
    return None # Placeholder return

# --- Save Data for Fine-tuning ---
# (save_data_for_finetuning remains the same)
def save_data_for_finetuning(all_labeled_data, train_file, eval_file, eval_ratio=FINETUNE_SPLIT_RATIO):
    # ... (logic remains the same) ...
    pass # Placeholder

# --- Main Execution ---
if __name__ == "__main__":
    logger.info("--- Starting Bot Detection Model Training & Data Export (IIS Version) ---")
    logger.info(f"Using Log File: {LOG_FILE_PATH}")
    logger.info(f"Using Database: {DB_PATH}")
    logger.info(f"Using Model Path: {MODEL_SAVE_PATH}")
    logger.info(f"Using Robots.txt: {ROBOTS_TXT_PATH}")
    logger.info(f"Feedback Logs: {HONEYPOT_HIT_LOG}, {CAPTCHA_SUCCESS_LOG}")
    db_conn = None
    try:
        # 1. Setup Database
        db_conn = setup_database(DB_PATH)
        if not db_conn: raise Exception("Database setup failed, cannot continue.")

        # 2. Load Logs into DB (Run only if DB is empty or forced)
        force_log_load = os.getenv("FORCE_LOG_LOAD", "false").lower() == "true"
        db_cursor_check = db_conn.cursor()
        db_entry_count = 0
        try:
             db_cursor_check.execute("SELECT COUNT(*) FROM requests")
             db_entry_count = db_cursor_check.fetchone()[0]
        except Exception as e_check:
             logger.error(f"Error checking database count: {e_check}")
        finally:
             db_cursor_check.close()

        if db_entry_count == 0 or force_log_load:
            if force_log_load: logger.info("FORCE_LOG_LOAD enabled, reloading logs...")
            load_logs_into_db(LOG_FILE_PATH, db_conn)
        else:
            logger.info(f"Database already contains {db_entry_count} records. Skipping log loading. Set FORCE_LOG_LOAD=true to override.")

        # 3. Process Data from DB, Label, Extract Features
        all_labeled_logs, high_conf_features, high_conf_labels = label_data_with_scores(db_conn)

        # 4. Train Random Forest Model
        if high_conf_features:
             model = train_and_save_model(high_conf_features, high_conf_labels, MODEL_SAVE_PATH)
        else:
             logger.warning("No high-confidence features generated. Skipping RF model training.")

        # 5. Save Data for LLM Fine-tuning
        save_data_for_finetuning(all_labeled_logs, FINETUNE_TRAIN_FILE, FINETUNE_EVAL_FILE)

        # 6. Analyze 'suspicious' data (Optional)
        suspicious_logs = [log for log in all_labeled_logs if log.get('label') == 'suspicious']
        logger.info(f"\nFound {len(suspicious_logs)} entries labeled 'suspicious'. Consider manual review or refining labeling logic.")

    except Exception as e:
        logger.error(f"An unexpected error occurred in the main training process: {e}", exc_info=True)
    finally:
        if db_conn:
            db_conn.close()
            logger.info("Database connection closed.")
    logger.info("--- Training Script Finished ---")

# --- Feature Extraction Helper (remains the same) ---
def extract_features(log_entry_dict, freq_features):
    features = {};
    if not isinstance(log_entry_dict, dict): return {};
    ua_string = log_entry_dict.get('user_agent', ''); referer = log_entry_dict.get('referer', ''); path = log_entry_dict.get('path') or '';
    features['ua_length'] = len(ua_string) if ua_string else 0; features['status_code'] = log_entry_dict.get('status', 0); features['bytes_sent'] = log_entry_dict.get('bytes', 0); features['http_method'] = log_entry_dict.get('method', 'UNKNOWN');
    features['path_depth'] = path.count('/'); features['path_length'] = len(path); features['path_is_root'] = 1 if path == '/' else 0; features['path_has_docs'] = 1 if '/docs' in path.lower() else 0; features['path_is_wp'] = 1 if ('/wp-' in path or '/xmlrpc.php' in path) else 0; features['path_disallowed'] = 1 if is_path_disallowed(path) else 0;
    ua_lower = ua_string.lower() if ua_string else ''; features['ua_is_known_bad'] = 1 if any(bad in ua_lower for bad in KNOWN_BAD_UAS) else 0; features['ua_is_known_benign_crawler'] = 1 if any(good in ua_lower for good in KNOWN_BENIGN_CRAWLERS_UAS) else 0; features['ua_is_empty'] = 1 if not ua_string else 0;
    ua_parse_failed = False;
    if UA_PARSER_AVAILABLE and ua_string:
        try: parsed_ua = ua_parse(ua_string); features['ua_browser_family'] = parsed_ua.browser.family or 'Other'; features['ua_os_family'] = parsed_ua.os.family or 'Other'; features['ua_device_family'] = parsed_ua.device.family or 'Other'; features['ua_is_mobile'] = 1 if parsed_ua.is_mobile else 0; features['ua_is_tablet'] = 1 if parsed_ua.is_tablet else 0; features['ua_is_pc'] = 1 if parsed_ua.is_pc else 0; features['ua_is_touch'] = 1 if parsed_ua.is_touch_capable else 0; features['ua_library_is_bot'] = 1 if parsed_ua.is_bot else 0
        except Exception: ua_parse_failed = True
    if not UA_PARSER_AVAILABLE or ua_parse_failed: features['ua_browser_family'] = 'Unknown'; features['ua_os_family'] = 'Unknown'; features['ua_device_family'] = 'Unknown'; features['ua_is_mobile'], features['ua_is_tablet'], features['ua_is_pc'], features['ua_is_touch'] = 0, 0, 0, 0; features['ua_library_is_bot'] = features['ua_is_known_bad']
    features['referer_is_empty'] = 1 if not referer or referer == '-' else 0; features['referer_has_domain'] = 0;
    try:
        if referer and referer != '-': parsed_referer = urlparse(referer); features['referer_has_domain'] = 1 if parsed_referer.netloc else 0
    except Exception: pass
    hour, dow = -1, -1;
    if log_entry_dict.get('timestamp_iso'):
        try: ts = datetime.datetime.fromisoformat(log_entry_dict['timestamp_iso'].replace('Z', '+00:00')); hour = ts.hour; dow = ts.weekday()
        except Exception: pass
    features['hour_of_day'] = hour; features['day_of_week'] = dow
    features[f'req_freq_{FREQUENCY_WINDOW_SECONDS}s'] = freq_features.get('count', 0); features['time_since_last_sec'] = freq_features.get('time_since', -1.0);
    return features
