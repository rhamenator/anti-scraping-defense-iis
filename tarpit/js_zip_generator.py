# anti-scraping-defense-iis/tarpit/js_zip_generator.py
# Modified for Windows/IIS Compatibility
# Generates a ZIP archive containing fake JavaScript files for honeypot purposes.

import zipfile
import os
import random
import string
import datetime
import logging # Using standard logging

# --- Setup Logging ---
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Define Windows Paths (REPLACE PLACEHOLDERS if needed) ---
# Define the base directory for your application on the Windows server
# Use the same environment variable as other modules for consistency
APP_BASE_DIR = os.getenv("APP_BASE_DIRECTORY", r"C:\inetpub\wwwroot\anti_scraping_defense_iis") # Example path
# Define the specific directory for archives relative to the base directory
ARCHIVES_SUBDIR = "archives" # Consistent with original volume mount target name
DEFAULT_ARCHIVE_DIR = os.path.join(APP_BASE_DIR, ARCHIVES_SUBDIR)

# --- Configuration ---
NUM_FAKE_FILES = 15
MIN_FILE_SIZE_KB = 5
MAX_FILE_SIZE_KB = 50
TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"

# Realistic-sounding but ultimately fake JS filenames
FILENAME_PREFIXES = [
    "analytics_bundle", "vendor_lib", "core_framework", "ui_component_pack",
    "polyfills_es6", "runtime_utils", "shared_modules", "feature_flags_data",
    "config_loader", "auth_client_sdk", "graph_rendering_engine", "data_sync_worker"
]
FILENAME_SUFFIXES = [
    "_min", "_pack", "_bundle", "_lib", "_core", ""
]
FILENAME_EXT = ".js"

# --- Helper Functions ---

def generate_random_string(length):
    """Generates a random string of printable ASCII characters."""
    # Include spaces and punctuation for more realistic "junk" content
    chars = string.ascii_letters + string.digits + string.punctuation + ' ' * 10 # Weight spaces
    # Ensure non-negative length
    safe_length = max(0, length)
    return ''.join(random.choice(chars) for _ in range(safe_length))

def generate_realistic_filename():
    """Generates a somewhat plausible JS filename."""
    prefix = random.choice(FILENAME_PREFIXES)
    suffix = random.choice(FILENAME_SUFFIXES)
    random_hash = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{suffix}.{random_hash}{FILENAME_EXT}"

def create_fake_js_zip(output_dir=DEFAULT_ARCHIVE_DIR, num_files=NUM_FAKE_FILES):
    """Creates a ZIP archive with fake JS files in the specified directory."""
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"ERROR: Could not create output directory {output_dir}: {e}")
        return None

    timestamp = datetime.datetime.now().strftime(TIMESTAMP_FORMAT)
    # Use os.path.join for cross-platform path construction
    zip_filename = os.path.join(output_dir, f"assets_{timestamp}.zip")

    logger.info(f"Creating fake JS archive: {zip_filename}")

    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for i in range(num_files):
                fake_filename = generate_realistic_filename()
                file_size_bytes = random.randint(MIN_FILE_SIZE_KB * 1024, MAX_FILE_SIZE_KB * 1024)

                # Generate somewhat plausible JS-like junk content
                content = f"// Fake module: {fake_filename}\n"
                content += f"// Generated: {datetime.datetime.now().isoformat()}\n\n"
                content += "(function() {\n"
                # Add some pseudo-random variables and functions
                num_vars = random.randint(5, 20)
                for _ in range(num_vars):
                    var_name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))
                    var_value = random.choice(['null', 'true', 'false', '[]', '{}', f'"{generate_random_string(random.randint(10, 30))}"', str(random.randint(0, 1000))])
                    content += f"  var {var_name} = {var_value};\n"

                num_funcs = random.randint(2, 8)
                for _ in range(num_funcs):
                     func_name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 15)))
                     content += f"  function {func_name}() {{ /* {generate_random_string(random.randint(50, 150))} */ return {random.choice(['null', 'true', 'false'])}; }}\n"

                # Fill remaining size with random comments/strings to approximate size
                current_size = len(content.encode('utf-8'))
                remaining_size = file_size_bytes - current_size
                if remaining_size > 0:
                     # Adjust padding size calculation to avoid negative values
                     comment_size = max(0, remaining_size - 10) # Ensure non-negative size
                     content += "\n/*\n" + generate_random_string(comment_size) + "\n*/\n"

                content += "\n})();\n"

                # Add file to zip
                # Use forward slashes for paths *inside* the ZIP archive for better cross-platform compatibility
                archive_internal_path = fake_filename # Store files at the root of the archive
                zipf.writestr(archive_internal_path, content)
                # logger.debug(f"  Added: {archive_internal_path} ({len(content)/1024:.1f} KB)") # Optional debug

        logger.info(f"Successfully created {zip_filename} with {num_files} fake files.")
        return zip_filename

    except Exception as e:
        logger.error(f"ERROR: Failed to create ZIP file {zip_filename}: {e}", exc_info=True)
        # Clean up partially created file if error occurs
        if os.path.exists(zip_filename):
            try:
                logger.warning(f"Attempting to remove partially created file: {zip_filename}")
                os.remove(zip_filename)
            except OSError as remove_error:
                 logger.error(f"ERROR: Failed to remove partial file {zip_filename}: {remove_error}")
        return None

# Example Usage (if run directly)
if __name__ == "__main__":
    logger.info("--- JS ZIP Generator Test Run ---")
    logger.info(f"Using archive directory: {DEFAULT_ARCHIVE_DIR}")
    created_file = create_fake_js_zip()
    if created_file:
        logger.info(f"Test archive created successfully at: {created_file}")
    else:
        logger.error("Test archive creation failed.")
    logger.info("--- Test Run Finished ---")