# anti-scraping-defense-iis/tarpit/rotating_archive.py
# Modified for Windows Task Scheduler Compatibility
# Generates one new fake JS ZIP archive and removes old ones based on MAX_ARCHIVES_TO_KEEP.

import os
import glob
import time
import sys
import logging

# --- Setup Logging ---
# Configure logging (can be basic for a scheduled task)
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format=log_format)
logger = logging.getLogger(__name__)

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Use the same environment variable as other modules for consistency
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
# Define the specific directory for archives relative to the base directory
ARCHIVES_SUBDIR = "archives"
DEFAULT_ARCHIVE_DIR = os.path.join(APP_BASE_DIR, ARCHIVES_SUBDIR)

# --- Adjust Python Path if running standalone ---
# This helps find js_zip_generator if run directly via python.exe path/to/rotating_archive.py
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# --- Import the generator script and its configured path ---
try:
    # Use relative import assuming it's run as part of the 'tarpit' package
    # If run standalone, the sys.path modification above helps
    from .js_zip_generator import create_fake_js_zip, DEFAULT_ARCHIVE_DIR as GENERATOR_ARCHIVE_DIR
    # Use the path defined in the generator module if imported successfully
    ARCHIVE_DIR = GENERATOR_ARCHIVE_DIR
    logger.info(f"Imported generator. Using ARCHIVE_DIR: {ARCHIVE_DIR}")
except ImportError as e:
    logger.error(f"ERROR: Could not import create_fake_js_zip from .js_zip_generator.py: {e}")
    # Fallback path definition if import fails
    ARCHIVE_DIR = DEFAULT_ARCHIVE_DIR # Use path defined in this script
    logger.warning(f"Using fallback ARCHIVE_DIR: {ARCHIVE_DIR}")
    # Define a dummy function to prevent crashes later if import failed
    def create_fake_js_zip(output_dir=None, num_files=None):
        logger.error("create_fake_js_zip function is unavailable due to import error.")
        return None

# --- Configuration ---
# Use os.path.join for cross-platform compatibility
ARCHIVE_PATTERN = os.path.join(ARCHIVE_DIR, "assets_*.zip")
MAX_ARCHIVES_TO_KEEP = int(os.getenv("MAX_ARCHIVES_TO_KEEP", 5))  # Keep the latest N archives

def rotate_archives():
    """Generates a new archive and cleans up old ones."""
    logger.info(f"Running archive rotation task at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
    logger.info(f"Target directory: {ARCHIVE_DIR}")
    logger.info(f"Keeping latest {MAX_ARCHIVES_TO_KEEP} archives.")

    # 1. Generate a new archive
    new_archive = create_fake_js_zip(output_dir=ARCHIVE_DIR)
    if not new_archive:
        logger.error("Archive generation failed. Rotation aborted.")
        return # Exit the function if generation fails

    # 2. Get list of existing archives, sorted by modification time (newest first)
    try:
        # Ensure the directory exists before globbing
        if not os.path.isdir(ARCHIVE_DIR):
             logger.error(f"Archive directory '{ARCHIVE_DIR}' does not exist. Cannot clean up archives.")
             return

        existing_archives = sorted(
            glob.glob(ARCHIVE_PATTERN),
            key=os.path.getmtime,
            reverse=True
        )
        logger.debug(f"Found {len(existing_archives)} existing archives matching pattern.")

    except Exception as e:
        logger.error(f"ERROR: Failed to list existing archives using pattern {ARCHIVE_PATTERN}: {e}")
        return

    # 3. Determine archives to delete
    if len(existing_archives) > MAX_ARCHIVES_TO_KEEP:
        archives_to_delete = existing_archives[MAX_ARCHIVES_TO_KEEP:]
    else:
        archives_to_delete = [] # No archives need deletion

    # 4. Delete old archives
    if archives_to_delete:
        logger.info(f"Found {len(existing_archives)} archives. Keeping {MAX_ARCHIVES_TO_KEEP}, deleting {len(archives_to_delete)}.")
        deleted_count = 0
        for old_archive in archives_to_delete:
            try:
                os.remove(old_archive)
                logger.info(f"  Deleted old archive: {old_archive}")
                deleted_count += 1
            except OSError as e:
                logger.error(f"ERROR: Failed to delete old archive {old_archive}: {e}")
        logger.info(f"Successfully deleted {deleted_count} old archives.")
    else:
        logger.info(f"Found {len(existing_archives)} archives. No old archives to delete (or <= {MAX_ARCHIVES_TO_KEEP} exist).")

    logger.info("Archive rotation task finished.")

# --- Main Execution Logic ---
if __name__ == "__main__":
    logger.info("--- Running Single Archive Rotation Cycle ---")
    # This script is now designed to be run by a scheduler (like Windows Task Scheduler)
    # It performs one rotation and then exits.

    # Set environment variables if needed for testing standalone
    # os.environ['APP_BASE_DIRECTORY'] = r'C:\your\test\path'
    # os.environ['MAX_ARCHIVES_TO_KEEP'] = '3'

    rotate_archives()

    logger.info("--- Single Rotation Cycle Finished ---")
