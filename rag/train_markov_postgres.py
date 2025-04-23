# anti-scraping-defense-iis/rag/train_markov_postgres.py
# Modified for Windows/IIS Compatibility
# Trains the Markov model by populating the PostgreSQL database from a text corpus.

import os
import sys
import time
import re
import psycopg2 # Ensure psycopg2 or psycopg2-binary is installed
from psycopg2.extras import execute_batch
import logging
import argparse
from collections import defaultdict, deque

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
SECRETS_DIR = os.getenv("APP_SECRETS_DIRECTORY", r"C:\secrets") # Example path for secrets
# Data directory is relevant for the input corpus file (passed as argument)
DATA_DIR = os.path.join(APP_BASE_DIR, "data")
os.makedirs(SECRETS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True) # Ensure data dir exists for context

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Database Connection Environment Variables ---
PG_HOST = os.getenv("PG_HOST", "localhost") # Default to localhost for IIS server
PG_PORT = os.getenv("PG_PORT", "5432")
PG_DBNAME = os.getenv("PG_DBNAME", "markovdb")
PG_USER = os.getenv("PG_USER", "markovuser")
# Construct path to PG password file using SECRETS_DIR
PG_PASSWORD_FILENAME = os.getenv("PG_PASSWORD_FILENAME", "pg_password.txt")
PG_PASSWORD_FILE = os.path.join(SECRETS_DIR, PG_PASSWORD_FILENAME)

# --- Constants ---
EMPTY_WORD = ''
EMPTY_WORD_ID = 1 # Ensure the init_markov.sql script reserves ID 1 for ''
BATCH_SIZE = 10000 # Number of sequences to batch insert/update for performance

def get_pg_password():
    """Loads password from the configured secret file path."""
    if not os.path.exists(PG_PASSWORD_FILE):
        logger.error(f"Password file not found at the configured path: {PG_PASSWORD_FILE}")
        return None
    try:
        with open(PG_PASSWORD_FILE, 'r') as f:
            password = f.read().strip()
            if password:
                 logger.info(f"Loaded PostgreSQL password from {PG_PASSWORD_FILE}")
                 return password
            else:
                 logger.error(f"Password file is empty: {PG_PASSWORD_FILE}")
                 return None
    except Exception as e:
        logger.error(f"Failed to read PostgreSQL password from {PG_PASSWORD_FILE}: {e}")
        return None

def connect_db():
    """Establishes connection to the PostgreSQL database."""
    pg_password = get_pg_password()
    if not pg_password:
        logger.error("Cannot connect to database: Password not available.")
        return None

    conn = None # Initialize connection variable
    try:
        logger.info(f"Connecting to PostgreSQL: {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DBNAME}")
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DBNAME,
            user=PG_USER,
            password=pg_password,
            connect_timeout=10
        )
        logger.info("Successfully connected to PostgreSQL.")
        # Set autocommit off for explicit transaction management
        conn.autocommit = False
        return conn
    except psycopg2.OperationalError as e:
        logger.error(f"ERROR: Failed to connect to PostgreSQL: {e}")
        if conn:
            # Ensure connection is closed if partially opened then failed
            conn.close()
        return None
    except Exception as e:
        logger.error(f"ERROR: Unexpected error connecting to PostgreSQL: {e}", exc_info=True)
        if conn:
            conn.close()
        return None

def tokenize_text(text):
    """
    Simple tokenizer: splits by whitespace and converts to lowercase.
    Removes most punctuation, keeping apostrophes within words.
    """
    # Remove punctuation except apostrophes and hyphens within words
    processed_text = re.sub(r"(?<!\w)['\-](?!\w)", '', text) # Remove leading/trailing ' -
    processed_text = re.sub(r"[^\w\s'-]", '', processed_text) # Remove other punctuation
    # Basic split and lowercase
    words = processed_text.lower().split()
    # Filter out empty strings that might result from splitting
    filtered_words = [word for word in words if word]
    return filtered_words

def get_word_id(cursor, word_cache, word):
    """Gets the ID for a word, inserting it if it doesn't exist."""
    # Check cache first
    if word in word_cache:
        return word_cache[word]

    # If not in cache, query DB
    try:
        cursor.execute("SELECT id FROM markov_words WHERE word = %s", (word,))
        result = cursor.fetchone()
        if result:
            word_id = result[0]
        else:
            # Insert the new word and return its ID
            # Use ON CONFLICT just in case of race conditions (though unlikely in single script)
            cursor.execute(
                "INSERT INTO markov_words (word) VALUES (%s) ON CONFLICT (word) DO UPDATE SET word=EXCLUDED.word RETURNING id",
                (word,)
            )
            insert_result = cursor.fetchone()
            if insert_result:
                 word_id = insert_result[0]
                 if word_id % 1000 == 0: # Log progress periodically
                      logger.info(f"Cached {len(word_cache)} unique words (last ID: {word_id})")
            else:
                 # This case should be rare with ON CONFLICT...DO UPDATE RETURNING
                 logger.error(f"Failed to retrieve ID after inserting word '{word}'. Re-querying.")
                 cursor.execute("SELECT id FROM markov_words WHERE word = %s", (word,))
                 refetch_result = cursor.fetchone()
                 if refetch_result:
                      word_id = refetch_result[0]
                 else:
                      # If it still fails, something is wrong
                      raise psycopg2.DatabaseError(f"Could not retrieve ID for word '{word}' even after insert attempt.")

        word_cache[word] = word_id # Cache the ID
        return word_id
    except psycopg2.Error as e:
        logger.error(f"Database error getting/inserting word '{word}': {e}")
        raise # Propagate error to rollback transaction
    except Exception as e:
        logger.error(f"Unexpected error processing word '{word}': {e}")
        raise

def train_from_corpus(corpus_path):
    """Reads corpus file and populates the Markov database."""
    conn = connect_db()
    if not conn:
        logger.error("Cannot start training: Database connection failed.")
        return

    logger.info(f"Starting Markov training from corpus: {corpus_path}")
    start_time = time.time()
    processed_sequences = 0
    total_lines = 0
    word_cache = {EMPTY_WORD: EMPTY_WORD_ID} # Pre-cache empty word ID

    cursor = None # Initialize cursor variable

    try:
        cursor = conn.cursor()

        # Ensure the empty word token exists with ID 1
        cursor.execute("INSERT INTO markov_words (id, word) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING", (EMPTY_WORD_ID, EMPTY_WORD))
        conn.commit() # Commit this essential setup
        logger.debug("Verified/Inserted empty word token (ID: 1).")

        # SQL for inserting/updating sequences
        upsert_sql = """
            INSERT INTO markov_sequences (p1, p2, next_id, freq)
            VALUES (%s, %s, %s, 1)
            ON CONFLICT (p1, p2, next_id) DO UPDATE SET freq = markov_sequences.freq + 1;
        """
        sequence_batch = []

        # Process text file
        with open(corpus_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f):
                total_lines = line_num + 1
                words = tokenize_text(line)
                if not words:
                    continue # Skip empty lines

                # Use deque for efficient history management is an option,
                # but simple variables work for state_size=2.
                p1_id = EMPTY_WORD_ID
                p2_id = EMPTY_WORD_ID

                for word in words:
                    # Check for excessively long words (potential parsing errors)
                    if len(word) > 100:
                        logger.warning(f"Skipping excessively long token on line {total_lines}: '{word[:50]}...'")
                        continue

                    # Find/create ID for the next word
                    next_id = get_word_id(cursor, word_cache, word)

                    # Add sequence (p1_id, p2_id -> next_id) to batch
                    sequence_batch.append((p1_id, p2_id, next_id))
                    processed_sequences += 1

                    # Update history for next iteration
                    p1_id = p2_id
                    p2_id = next_id

                    # Execute batch if full
                    if len(sequence_batch) >= BATCH_SIZE:
                        execute_batch(cursor, upsert_sql, sequence_batch)
                        logger.info(f"Processed {processed_sequences} sequences (batch executed)...")
                        sequence_batch = [] # Reset batch

                # Add final sequence ending with the empty token for this line/chunk
                # This links the last word pair of the line to the "end" state
                sequence_batch.append((p1_id, p2_id, EMPTY_WORD_ID))
                processed_sequences += 1

                # Commit periodically based on line number for very large files
                if total_lines % 50000 == 0: # Commit every 50k lines
                     if sequence_batch: # Commit remaining batch items first
                         execute_batch(cursor, upsert_sql, sequence_batch)
                         sequence_batch = []
                     logger.info(f"Committing transaction at line {total_lines}...")
                     conn.commit()
                     logger.info(f"Commit complete.")


            # Process any remaining sequences in the last batch after loop finishes
            if sequence_batch:
                logger.info(f"Executing final batch of {len(sequence_batch)} sequences...")
                execute_batch(cursor, upsert_sql, sequence_batch)

        # Final commit after processing the entire file
        logger.info("Committing final transaction...")
        conn.commit()
        logger.info("Final commit successful.")

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Markov training complete.")
        logger.info(f"Processed {processed_sequences} sequences from {total_lines} lines.")
        logger.info(f"Final unique words count: {len(word_cache)}")
        logger.info(f"Total time: {duration:.2f} seconds.")

    except FileNotFoundError:
        logger.error(f"ERROR: Corpus file not found at {corpus_path}")
    except psycopg2.Error as e:
        logger.error(f"Database error during training: {e}")
        if conn:
            logger.info("Attempting to rollback transaction due to database error.")
            conn.rollback() # Rollback transaction on DB error
    except Exception as e:
        logger.error(f"ERROR: Unexpected error during training: {e}", exc_info=True)
        if conn:
            logger.info("Attempting to rollback transaction due to unexpected error.")
            conn.rollback() # Rollback on other errors
    finally:
        # Ensure cursor and connection are closed
        if cursor:
            try:
                cursor.close()
            except Exception as cur_e:
                 logger.error(f"Error closing cursor: {cur_e}")
        if conn:
            try:
                conn.close()
                logger.info("Database connection closed.")
            except Exception as con_e:
                 logger.error(f"Error closing connection: {con_e}")


# --- Command Line Argument Parsing ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PostgreSQL Markov model from text corpus (IIS Version).")
    parser.add_argument("corpus_file", help="Path to the text corpus file (Use Windows path).")
    # Example: Add argument for state size if implementing higher-order Markov chains
    # parser.add_argument("--state-size", type=int, default=2, help="Number of previous words to use as state (e.g., 2).")

    args = parser.parse_args()

    corpus_file_path = args.corpus_file
    # Basic validation if the path exists before starting
    if not os.path.exists(corpus_file_path):
        logger.error(f"Error: Input corpus file not found at specified path: {corpus_file_path}")
        sys.exit(1)
    if not os.path.isfile(corpus_file_path):
         logger.error(f"Error: Specified corpus path is not a file: {corpus_file_path}")
         sys.exit(1)

    # Start training
    train_from_corpus(corpus_file_path)

    logger.info("--- Markov Training Script Finished ---")