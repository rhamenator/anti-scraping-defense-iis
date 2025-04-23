# anti-scraping-defense-iis/tarpit/markov_generator.py
# Modified for Windows/IIS Compatibility
# Generates deterministic fake HTML content using Markov chains from PostgreSQL.

import psycopg2 # Or asyncpg for async
import os
import random
import string
import datetime
import logging
import hashlib

logger = logging.getLogger(__name__)

# --- Configuration ---
DEFAULT_SENTENCES_PER_PAGE = 15
FAKE_LINK_COUNT = 7
FAKE_LINK_DEPTH = 3
MIN_WORDS_FOR_NEXT = 2

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Use the same SECRETS_DIR logic as in tarpit_api.py
SECRETS_DIR = os.getenv("APP_SECRETS_DIRECTORY", r"C:\secrets") # Example path for secrets

# --- Database Connection ---
# Read from environment variables (should be set in IIS Application Settings)
PG_HOST = os.getenv("PG_HOST", "localhost") # Default to localhost for typical IIS setup
PG_PORT = os.getenv("PG_PORT", "5432")
PG_DBNAME = os.getenv("PG_DBNAME", "markovdb")
PG_USER = os.getenv("PG_USER", "markovuser")
# Construct path to PG password file using SECRETS_DIR
PG_PASSWORD_FILENAME = os.getenv("PG_PASSWORD_FILENAME", "pg_password.txt")
PG_PASSWORD_FILE = os.path.join(SECRETS_DIR, PG_PASSWORD_FILENAME)

_db_conn = None
_db_cursor = None

def _get_pg_password():
    """Loads password from secret file using configured path."""
    if not os.path.exists(PG_PASSWORD_FILE):
        logger.error(f"PostgreSQL password file not found at {PG_PASSWORD_FILE}. Please configure APP_SECRETS_DIRECTORY or PG_PASSWORD_FILENAME correctly.")
        return None
    try:
        with open(PG_PASSWORD_FILE, 'r') as f:
            return f.read().strip()
    except Exception as e:
        logger.error(f"Failed to read PostgreSQL password from {PG_PASSWORD_FILE}: {e}")
        return None

def _get_db_connection():
    """Establishes or returns existing DB connection."""
    global _db_conn, _db_cursor
    if _db_conn and not _db_conn.closed:
        try:
            # Simple check: try executing a trivial query
            _db_cursor.execute("SELECT 1")
            return _db_conn, _db_cursor
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            logger.warning("Database connection lost. Attempting to reconnect.")
            _db_conn.close() # Ensure closed before reconnecting
            _db_conn = None
            _db_cursor = None
        except Exception as e:
            logger.error(f"Unexpected error checking DB connection status: {e}")
            # Attempt reconnect anyway
            if _db_conn: _db_conn.close()
            _db_conn = None
            _db_cursor = None

    # If no connection or check failed, try connecting
    logger.info(f"Connecting to PostgreSQL Markov DB: {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DBNAME}")
    pg_password = _get_pg_password()
    if not pg_password:
        logger.error("PostgreSQL password not available. Cannot connect.")
        return None, None

    try:
        _db_conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DBNAME,
            user=PG_USER,
            password=pg_password,
            connect_timeout=5
        )
        _db_cursor = _db_conn.cursor()
        logger.info("Successfully connected to PostgreSQL Markov DB.")
        return _db_conn, _db_cursor
    except psycopg2.OperationalError as e:
        logger.error(f"ERROR: Failed to connect to PostgreSQL Markov DB: {e}")
        _db_conn = None
        _db_cursor = None
        return None, None
    except Exception as e:
        logger.error(f"ERROR: Unexpected error connecting to PostgreSQL: {e}")
        _db_conn = None
        _db_cursor = None
        return None, None

# --- Helper Functions ---

def generate_random_page_name(length=10):
    """Generates a random alphanumeric string for page/link names."""
    # Use the current random state (should be seeded externally by tarpit_api)
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_fake_links(count=FAKE_LINK_COUNT, depth=FAKE_LINK_DEPTH):
    """Generates a list of plausible but fake internal link targets."""
    links = []
    # Base path should reflect how IIS routes to the tarpit handler
    # If IIS routes /tarpit/* to the handler, use /tarpit
    # If IIS routes /* to the handler, use /
    base_path = "/tarpit" # Adjust if needed based on IIS routing rules

    for _ in range(count):
        link_type = random.choice(["page", "js", "data", "css"])
        num_dirs = random.randint(0, depth)
        dirs = [generate_random_page_name(random.randint(5,8)) for _ in range(num_dirs)]
        filename_base = generate_random_page_name()

        if link_type == "page":
            ext = ".html"
            path_prefix = "/page/"
        elif link_type == "js":
            ext = ".js"
            path_prefix = "/js/"
        elif link_type == "data":
             ext = random.choice([".json", ".xml", ".csv"])
             path_prefix = "/data/"
        else: # css
             ext = ".css"
             path_prefix = "/styles/"

        # Use forward slashes for URL paths, even on Windows
        full_path = base_path + path_prefix + "/".join(dirs) + "/" + filename_base + ext
        # Normalize path (remove double slashes)
        full_path = full_path.replace("//", "/")
        links.append(full_path)

    return links

def get_next_word_from_db(word1_id, word2_id):
    """Queries PostgreSQL for the next word based on the previous two."""
    conn, cursor = _get_db_connection()
    if not conn or not cursor:
        # Attempt a reconnect if connection seems stale
        conn, cursor = _get_db_connection()
        if not conn or not cursor:
            logger.error("No DB connection available to fetch next word.")
            return None

    try:
        # Query optimized slightly - uses table names directly
        cursor.execute(
            """
            SELECT w.word, s.freq
            FROM markov_sequences s
            JOIN markov_words w ON s.next_id = w.id
            WHERE s.p1 = %s AND s.p2 = %s
            ORDER BY s.freq DESC, random()
            LIMIT 20;
            """,
            (word1_id, word2_id)
        )
        results = cursor.fetchall()

        if not results:
            return None

        words = [row[0] for row in results]
        frequencies = [row[1] for row in results]
        total_freq = sum(frequencies)

        if total_freq == 0:
             return random.choice(words)

        probabilities = [f / total_freq for f in frequencies]
        return random.choices(words, weights=probabilities, k=1)[0]

    except (psycopg2.OperationalError, psycopg2.InterfaceError) as db_err:
        logger.error(f"Database connection error fetching next word for ({word1_id}, {word2_id}): {db_err}")
        # Force reconnect on next call by clearing global connection variables
        global _db_conn, _db_cursor
        if _db_conn: _db_conn.close() # Ensure closed
        _db_conn = None
        _db_cursor = None
        return None # Indicate failure for this attempt
    except psycopg2.Error as e:
        logger.error(f"Database query error fetching next word for ({word1_id}, {word2_id}): {e}")
        # Might indicate a schema issue or bad data, don't force reconnect, just return None
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching next word: {e}")
        return None

def get_word_id(word):
    """Gets the ID for a word, returns ID for '' (empty string/ID 1) if not found or error."""
    conn, cursor = _get_db_connection()
    if not conn or not cursor or not word:
        return 1 # ID for empty string (start/end token)

    try:
        cursor.execute("SELECT id FROM markov_words WHERE word = %s", (word,))
        result = cursor.fetchone()
        return result[0] if result else 1 # Default to empty string ID if word not found
    except (psycopg2.OperationalError, psycopg2.InterfaceError) as db_err:
         logger.error(f"Database connection error fetching ID for word '{word}': {db_err}")
         global _db_conn, _db_cursor
         if _db_conn: _db_conn.close()
         _db_conn = None
         _db_cursor = None
         return 1 # Default to empty string ID on error
    except Exception as e:
        logger.error(f"Error fetching ID for word '{word}': {e}")
        return 1 # Default to empty string ID on error

# --- Markov Text Generation using DB ---
def generate_markov_text_from_db(sentences=DEFAULT_SENTENCES_PER_PAGE):
    """Generates paragraphs of Markov text by querying PostgreSQL."""
    # Use pre-seeded random state from calling function (tarpit_api)
    generated_content = ""
    word1_id, word2_id = 1, 1 # Start with empty history (ID 1)

    word_count = 0
    max_words = sentences * random.randint(15, 30)

    current_paragraph = []

    while word_count < max_words:
        next_word = get_next_word_from_db(word1_id, word2_id)

        if next_word is None: # Handle DB error or end of chain gracefully
            logger.warning(f"Markov chain stopped prematurely or DB error occurred after {word_count} words (State: {word1_id}, {word2_id}).")
            break # Exit loop if we can't get the next word

        if next_word == '': # Reached explicit end of a chain
            if current_paragraph:
                 generated_content += "<p>" + " ".join(current_paragraph) + ".</p>\n"
                 current_paragraph = []
            # Restart chain from empty state
            word1_id, word2_id = 1, 1
            continue # Continue generating if max_words not reached

        current_paragraph.append(next_word)
        word_count += 1

        # Shift history
        next_word_id = get_word_id(next_word)
        if next_word_id == 1 and next_word != '': # Check if get_word_id failed
             logger.warning(f"Could not get ID for word '{next_word}'. Resetting chain.")
             # End current paragraph and reset
             if current_paragraph: generated_content += "<p>" + " ".join(current_paragraph) + ".</p>\n"; current_paragraph = []
             word1_id, word2_id = 1, 1
             continue
        else:
             word1_id = word2_id
             word2_id = next_word_id


        # End paragraph on punctuation (simple heuristic)
        if next_word.endswith(('.', '!', '?')) and len(current_paragraph) > 5:
             generated_content += "<p>" + " ".join(current_paragraph) + "</p>\n"
             current_paragraph = []
             word1_id, word2_id = 1, 1 # Reset history after punctuation

    # Add any remaining words in the current paragraph
    if current_paragraph:
         generated_content += "<p>" + " ".join(current_paragraph) + ".</p>\n"

    if not generated_content:
         return "<p>Content generation unavailable due to errors.</p>" # Fallback

    return generated_content

# --- Main Generator Function ---
def generate_dynamic_tarpit_page():
    """
    Generates a full HTML page with deterministically generated
    Markov text (from Postgres) and fake links.
    Assumes random module has been seeded externally by tarpit_api.
    """
    logger.debug("Generating dynamic tarpit page content...")
    # 1. Generate Markov Text from DB
    page_content = generate_markov_text_from_db(DEFAULT_SENTENCES_PER_PAGE)

    # 2. Generate Fake Links
    fake_links = generate_fake_links()
    link_html = "<ul>\n"
    for link in fake_links:
        try:
            link_text = link.split('/')[-1].split('.')[0].replace('_', ' ').replace('-', ' ').capitalize()
            if not link_text: link_text = "Resource Link"
        except:
            link_text = "Link"
        link_html += f'    <li><a href="{link}">{link_text}</a></li>\n'
    link_html += "</ul>\n"

    # 3. Assemble HTML
    page_title = " ".join(word.capitalize() for word in generate_random_page_name(random.randint(2,4)).split())
    html_structure = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{page_title} - System Documentation</title>
    <meta name="robots" content="noindex, nofollow">
    <meta name="generator" content="AntiScrape Tarpit v1.1-IIS">
    <style>
        body {{ font-family: 'Courier New', Courier, monospace; background-color: #f0f0f0; color: #333; padding: 2em; line-height: 1.6; }}
        h1 {{ border-bottom: 1px solid #ccc; padding-bottom: 0.5em; color: #555; }}
        h2 {{ color: #666; margin-top: 2em; }}
        a {{ color: #3478af; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        ul {{ list-style-type: square; padding-left: 2em; }}
        p {{ text-align: justify; }}
        .footer-link {{ display: inline-block; margin-top: 40px; font-size: 0.8em; color: #aaa; visibility: hidden; }}
    </style>
</head>
<body>
    <h1>{page_title}</h1>
    {page_content}
    <h2>Further Reading:</h2>
    {link_html}
    <a href="/internal-docs/admin-credentials.zip" class="footer-link">Admin Console Credentials</a>
</body>
</html>"""

    logger.debug("Dynamic tarpit page content generated.")
    return html_structure

# --- Cleanup ---
# It might be good practice to explicitly close the connection when the app shuts down,
# though connection pooling handles some of this. FastAPI shutdown events could be used.
def close_db_connection():
    global _db_conn, _db_cursor
    if _db_conn:
        try:
            _db_conn.close()
            logger.info("PostgreSQL Markov DB connection closed.")
        except Exception as e:
            logger.error(f"Error closing DB connection: {e}")
        finally:
             _db_conn = None
             _db_cursor = None

# Example Usage (if run directly - requires DB connection details in env)
# This part is less relevant for the IIS-hosted version but useful for testing the module.
if __name__ == "__main__":
   print("--- Generating Sample Tarpit Page (requires DB connection) ---")
   print(f"Attempting to read PG password from: {PG_PASSWORD_FILE}")
   # Seed random for predictable output during test
   random.seed("test_seed_123")
   dynamic_html = generate_dynamic_tarpit_page()
   print("\n--- Generated HTML ---")
   print(dynamic_html)
   close_db_connection()