import os
import sys
import json
import time  # For delays and idle timeout
import shutil  # For file operations
import getpass  # For username and secret input
import argparse  # For command-line arguments
import subprocess  # For calling fsutil on Windows
import hashlib  # For hashing script path as a fallback service name
from pathlib import Path

import duo_client.admin
import keyring

# --- Global Configuration ---
DEBUG = False  # Set to False by default, can be enabled via command-line parameter
BACKUP_DIR = "backups"  # Directory for policy backups
LOG_DIR = "logs"  # Directory for logs
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "audit.log")  # Audit log file path
IDLE_TIMEOUT_SECONDS = 30 * 60  # 30 minutes in seconds
TEST_ADD_DELAY_SECONDS = 5  # Delay between test calls in 'test_add_all_countries'

# --- Global Data Structures for Country Code Lookup ---
VALID_ALPHA2_CODES = set()
ALPHA2_TO_NAME_MAP = {}
NAME_TO_ALPHA2_MAP = {}
ALPHA2_JSON_FILE = "alpha-2.json"  # Default path; can be overridden via CLI

# --- Global for Idle Timeout ---
last_activity_time = time.time()

# --- Global for Keyring Service Name ---
service_name = None


# ---------------------------------------------------------------------------
# Keyring / Service Name Helpers
# ---------------------------------------------------------------------------

def get_windows_file_id(file_path: str) -> str | None:
    """
    Retrieves the unique Windows file ID for a given file path using fsutil.
    Returns the file ID string, or None if the query fails.
    """
    abs_path = os.path.abspath(file_path)
    command = fr'fsutil file queryfileid "{abs_path}"'

    try:
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        )
        # Expected format: "File ID is 0x..."
        file_id = output.strip().split("File ID is ")[-1]
        return file_id
    except subprocess.CalledProcessError as e:
        print(f"Warning: fsutil queryfileid failed: {e.output}")
        return None
    except Exception as e:
        print(f"Warning: Unexpected error while querying file ID: {e}")
        return None


def set_service_name() -> None:
    """
    Sets the global service_name used for keyring entries.

    Primary strategy:
        duo_admin_api:<windows_file_id>

    Fallback if file ID can't be retrieved:
        duo_admin_api:<hash_of_script_path>
    """
    script_path = Path(__file__).resolve()
    file_id = get_windows_file_id(script_path)

    SERVICE_BASE_NAME = "duo_admin_api"

    global service_name
    if file_id:
        service_name = f"{SERVICE_BASE_NAME}:{file_id}"
    else:
        # Fallback: hash of the script path, to keep it stable and unique-ish
        digest = hashlib.sha256(str(script_path).encode("utf-8")).hexdigest()[:16]
        service_name = f"{SERVICE_BASE_NAME}:{digest}"
        print(
            "Warning: Could not read Windows file ID; "
            "using path-based hash for keyring service name."
        )


def set_keyring() -> None:
    """
    Interactive setup for Duo Admin API credentials, stored in keyring.

    Stored entries (under the global service_name):
        DUO_HOST
        DUO_IKEY
        DUO_SKEY
        DUO_POLICY_KEY
    """
    global service_name
    if not service_name:
        raise SystemExit("Internal error: service_name not initialized before set_keyring().")

    print("=== Duo Admin API credential setup ===")
    print("These values will be stored securely in your OS keyring.\n")

    DUO_HOST = input("Duo API hostname (e.g. api-xxxxxxxx.duosecurity.com): ").strip()
    if not DUO_HOST:
        raise SystemExit("Error: 'api_host' cannot be empty.")

    DUO_IKEY = input("Integration key (ikey): ").strip()
    if not DUO_IKEY:
        raise SystemExit("Error: 'ikey' cannot be empty.")

    DUO_POLICY_KEY = input("Policy key: ").strip()
    if not DUO_POLICY_KEY:
        raise SystemExit("Error: 'policy_key' cannot be empty.")

    DUO_SKEY = getpass.getpass("Secret key (skey): ").strip()
    if not DUO_SKEY:
        raise SystemExit("Error: 'skey' cannot be empty.")

    # Store values in keyring
    try:
        keyring.set_password(service_name, "DUO_HOST", DUO_HOST)
        keyring.set_password(service_name, "DUO_IKEY", DUO_IKEY)
        keyring.set_password(service_name, "DUO_SKEY", DUO_SKEY)
        keyring.set_password(service_name, "DUO_POLICY_KEY", DUO_POLICY_KEY)
    except Exception as e:
        print(f"Error saving credentials to keyring: {e}")
        raise SystemExit("Failed to save credentials to keyring. Aborting.")

    print("\nCredentials saved successfully to the keyring.")


def get_admin_api_client():
    """
    Loads Duo Admin API credentials from keyring (using global service_name),
    optionally prompting to set them up if missing, and returns a
    duo_client.admin.Admin instance.

    Returns:
        Admin client instance, or None on failure.
    """
    global service_name
    if not service_name:
        print("Internal error: service_name not initialized before get_admin_api_client().")
        return None

    ikey = skey = host = None

    # First attempt: read from keyring
    try:
        ikey = keyring.get_password(service_name, "DUO_IKEY")
        skey = keyring.get_password(service_name, "DUO_SKEY")
        host = keyring.get_password(service_name, "DUO_HOST")
    except Exception as e:
        print(f"Error loading Duo credentials from keyring: {e}")

    # If anything is missing, run setup
    if not all([ikey, skey, host]):
        print("Duo Admin API credentials not found or incomplete in keyring. Starting setup...")
        set_keyring()

        # Second attempt: read from keyring after setup
        ikey = skey = host = None
        try:
            ikey = keyring.get_password(service_name, "DUO_IKEY")
            skey = keyring.get_password(service_name, "DUO_SKEY")
            host = keyring.get_password(service_name, "DUO_HOST")
        except Exception as e:
            print(f"Error loading Duo credentials from keyring after setup: {e}")
            return None

        if not all([ikey, skey, host]):
            print("Error: Duo Admin API credentials could not be loaded from keyring after setup.")
            return None

    # Initialize Duo client
    try:
        return duo_client.admin.Admin(ikey=ikey, skey=skey, host=host)
    except Exception as e:
        print(f"Failed to initialize Duo Admin API client: {e}")
        return None


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

def write_audit_log_entry(message: str, policy_key: str = None):
    """
    Writes an entry to the audit log file.
    """
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        username = getpass.getuser()

        log_message = f"[{timestamp}] User: {username}"
        if policy_key:
            log_message += f" Policy: {policy_key}"
        log_message += f" | {message}\n"

        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_message)
    except Exception as e:
        print(f"Error writing to audit log: {e}")


# ---------------------------------------------------------------------------
# Country Data Loading / Display
# ---------------------------------------------------------------------------

def load_country_data(json_file_path: str) -> bool:
    """
    Loads valid alpha-2 country codes and their names from a JSON file
    into global data structures for validation and lookup.

    Args:
        json_file_path (str): The path to the alpha-2.json file.

    Returns:
        bool: True if data loaded successfully, False otherwise.
    """
    global VALID_ALPHA2_CODES, ALPHA2_TO_NAME_MAP, NAME_TO_ALPHA2_MAP

    VALID_ALPHA2_CODES.clear()
    ALPHA2_TO_NAME_MAP.clear()
    NAME_TO_ALPHA2_MAP.clear()

    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            country_data = json.load(f)
            for entry in country_data:
                alpha2 = entry.get("alpha-2")
                name = entry.get("name")
                if alpha2 and name:
                    alpha2_upper = alpha2.upper()
                    name_lower = name.lower()
                    VALID_ALPHA2_CODES.add(alpha2_upper)
                    ALPHA2_TO_NAME_MAP[alpha2_upper] = name
                    NAME_TO_ALPHA2_MAP[name_lower] = alpha2_upper
        print(f"Successfully loaded {len(VALID_ALPHA2_CODES)} valid country codes from '{json_file_path}'.")
        return True
    except FileNotFoundError:
        print(f"Error: The country code JSON file '{json_file_path}' was not found.")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{json_file_path}'. Check file format.")
    except Exception as e:
        print(f"An unexpected error occurred while loading country codes: {e}")
    return False


# ---------------------------------------------------------------------------
# Duo Policy Helpers
# ---------------------------------------------------------------------------

def fetch_policy(admin_api, policy_key: str, silent: bool = False):
    """
    Fetches the current policy from Duo.
    Added 'silent' parameter to suppress print statements during automated tests.
    """
    try:
        if not silent:
            print(f"Fetching current policy with key: {policy_key}")
        current_policy_response = admin_api.get_policy_v2(policy_key)

        if current_policy_response:
            return current_policy_response
        else:
            if not silent:
                print(f"Error: Received empty or invalid response for policy {policy_key}.")
            return None
    except Exception as e:  # DuoAPIError or similar will probably be a subclass
        if not silent:
            print(f"Error fetching Duo policy: {e}")
            if "401 Unauthorized" in str(e) or "403 Access forbidden" in str(e):
                print("Please check your DUO_IKEY, DUO_SKEY, and ensure the Admin API "
                      "application has 'Read' permissions for Policies.")
            elif "44030" in str(e):
                print(f"Policy key '{policy_key}' might be invalid or not found. "
                      "Please verify DUO_POLICY_KEY.")
        return None


def backup_duo_policy_config(admin_api, policy_key: str, policy_name: str) -> bool:
    """
    Fetches the current Duo policy configuration and saves it to a timestamped JSON file.
    """
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)

        current_config = fetch_policy(admin_api, policy_key, silent=True)
        if not current_config:
            print("Failed to fetch current policy for backup. Aborting backup.")
            return False

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup_filename = f"duo_policy_backup_{policy_key}_{timestamp}.json"
        backup_filepath = os.path.join(BACKUP_DIR, backup_filename)

        with open(backup_filepath, 'w', encoding='utf-8') as f:
            json.dump(current_config, f, indent=4, ensure_ascii=False)
        print(f"Successfully backed up current Duo policy to '{backup_filepath}'.")
        write_audit_log_entry(f"Duo policy backup created: {backup_filepath}", policy_key)
        return True
    except Exception as e:
        print(f"Error creating Duo policy backup: {e}")
        write_audit_log_entry(f"Failed to create Duo policy backup: {e}", policy_key)
        return False


def update_duo_policy(admin_api,
                      policy_key: str,
                      policy_name: str,
                      sections: dict,
                      silent: bool = False,
                      perform_backup: bool = True) -> bool:
    """
    Updates the Duo policy with the given sections.
    Includes an option to perform a backup before writing.
    """
    if perform_backup:
        if not backup_duo_policy_config(admin_api, policy_key, policy_name):
            print("Backup failed. Aborting policy update to prevent unrecoverable changes.")
            write_audit_log_entry(
                f"Policy update aborted due to backup failure for policy '{policy_name}'",
                policy_key
            )
            return False

    # --- Fetch current policy state BEFORE the update for auditing ---
    current_policy_before_update = fetch_policy(admin_api, policy_key, silent=True)
    old_mfa_countries_alpha2 = set()
    old_deny_countries_alpha2 = set()
    old_allow_no_2fa_countries_alpha2 = set()
    old_ignore_countries_alpha2 = set()

    if current_policy_before_update:
        old_user_location_sections = current_policy_before_update.get('sections', {}).get('user_location', {})
        old_mfa_countries_alpha2 = set(old_user_location_sections.get('require_mfa_countries_list', []))
        old_deny_countries_alpha2 = set(old_user_location_sections.get('deny_access_countries_list', []))
        old_allow_no_2fa_countries_alpha2 = set(old_user_location_sections.get('allow_access_no_2fa_countries_list', []))
        old_ignore_countries_alpha2 = set(old_user_location_sections.get('ignore_location_countries_list', []))
    else:
        write_audit_log_entry(
            f"Could not retrieve current policy state for '{policy_name}' "
            f"before update for detailed auditing.",
            policy_key
        )

    write_audit_log_entry(f"Attempting to update policy '{policy_name}'.", policy_key)

    try:
        policy_data = {
            "name": policy_name,
            "sections": sections
        }
        if not silent:
            print(f"\nAttempting to update policy '{policy_name}' with key: {policy_key}")
        response = admin_api.update_policy_v2(policy_key, policy_data)
        if not silent:
            print("\nPolicy updated successfully!")

        new_user_location_sections = sections.get('user_location', {})
        new_mfa_countries_alpha2 = set(new_user_location_sections.get('require_mfa_countries_list', []))
        new_deny_countries_alpha2 = set(new_user_location_sections.get('deny_access_countries_list', []))
        new_allow_no_2fa_countries_alpha2 = set(new_user_location_sections.get('allow_access_no_2fa_countries_list', []))
        new_ignore_countries_alpha2 = set(new_user_location_sections.get('ignore_location_countries_list', []))

        # Calculate changes for require_mfa_countries_list
        added_mfa_countries_alpha2 = new_mfa_countries_alpha2 - old_mfa_countries_alpha2
        removed_mfa_countries_alpha2 = old_mfa_countries_alpha2 - new_mfa_countries_alpha2

        added_mfa_names = [ALPHA2_TO_NAME_MAP.get(c, c) for c in sorted(list(added_mfa_countries_alpha2))]
        removed_mfa_names = [ALPHA2_TO_NAME_MAP.get(c, c) for c in sorted(list(removed_mfa_countries_alpha2))]

        if added_mfa_names:
            write_audit_log_entry(
                f"Countries ADDED to require_mfa_countries_list: "
                f"[{', '.join(added_mfa_names)}].",
                policy_key
            )
        if removed_mfa_names:
            write_audit_log_entry(
                f"Countries REMOVED from require_mfa_countries_list: "
                f"[{', '.join(removed_mfa_names)}].",
                policy_key
            )
        return True
    except Exception as e:
        if not silent:
            print(f"Error updating Duo policy: {e}")
            if "401 Unauthorized" in str(e) or "403 Access forbidden" in str(e):
                print("Please check your DUO_IKEY, DUO_SKEY, and ensure the Admin API "
                      "application has 'Write' permissions for Policies.")
            elif "400 Bad Request" in str(e):
                print("Please verify the policy data structure and values are valid "
                      "according to Duo's API documentation for policies.")
            elif "44030" in str(e):
                print(f"Policy key '{policy_key}' might be invalid or not found. "
                      "Please verify DUO_POLICY_KEY.")
        write_audit_log_entry(f"Failed to update policy '{policy_name}': {e}", policy_key)
        return False


def display_countries(country_set: set,
                      title: str,
                      removable_countries_set: set = None):
    """
    Displays a list of countries in a table format, sorted by country name.
    If removable_countries_set is provided, countries in it will be tagged as *new.
    """
    print(f"\n--- {title} ---")
    if not country_set:
        print("No countries in this list.")
        return

    countries_with_names = []
    for alpha2 in country_set:
        country_name = ALPHA2_TO_NAME_MAP.get(alpha2, "UNKNOWN")
        countries_with_names.append((country_name, alpha2))

    sorted_countries = sorted(countries_with_names, key=lambda x: x[0])

    name_column_width = 40
    if removable_countries_set:
        name_column_width = 55

    print(f"{'Alpha-2':<10} {'Country Name':<{name_column_width}}")
    print(f"{'-'*10:<10} {'-'*name_column_width:<{name_column_width}}")
    for country_name, alpha2 in sorted_countries:
        display_name = country_name
        if removable_countries_set is not None and alpha2 in removable_countries_set:
            display_name += " *new"
        print(f"{alpha2:<10} {display_name:<{name_column_width}}")
    print("-" * (10 + name_column_width + 2))


# ---------------------------------------------------------------------------
# Idle Timeout and User Input Helpers
# ---------------------------------------------------------------------------

def check_idle_timeout():
    """Checks if the script has been idle for too long and exits if so."""
    global last_activity_time
    if time.time() - last_activity_time > IDLE_TIMEOUT_SECONDS:
        print(f"\n\nIdle timeout ({IDLE_TIMEOUT_SECONDS / 60} minutes) reached. Exiting script.")
        write_audit_log_entry(f"Script exited due to idle timeout ({IDLE_TIMEOUT_SECONDS / 60} minutes).")
        sys.exit(0)


def get_country_input(prompt: str) -> str | None:
    """
    Prompts the user for a country (alpha-2 or name) and returns its valid alpha-2 code.
    Updates last_activity_time.
    """
    global last_activity_time
    while True:
        check_idle_timeout()
        user_input = input(prompt).strip()
        last_activity_time = time.time()
        if not user_input:
            return None

        if user_input.upper() in VALID_ALPHA2_CODES:
            return user_input.upper()

        if user_input.lower() in NAME_TO_ALPHA2_MAP:
            return NAME_TO_ALPHA2_MAP[user_input.lower()]

        print(f"'{user_input}' is not a recognized alpha-2 code or country name. "
              f"Please try again or leave blank to cancel.")


def get_confirmation(prompt: str) -> bool:
    """
    Prompts the user for a yes/no confirmation, defaulting to no.
    Accepts 'yes', 'y', 'no', 'n' (case-insensitive).
    Updates last_activity_time.
    """
    global last_activity_time
    while True:
        check_idle_timeout()
        response = input(f"{prompt} (yes/no) [no]: ").strip().lower()
        last_activity_time = time.time()
        if response in ('yes', 'y'):
            return True
        elif response in ('no', 'n', ''):
            return False
        else:
            print("Invalid input. Please enter 'yes', 'no', 'y', or 'n'.")


# ---------------------------------------------------------------------------
# Local JSON Backup / Modification
# ---------------------------------------------------------------------------

def backup_json_file(original_file_path: str) -> str | None:
    """
    Creates a timestamped backup of the specified JSON file.
    Returns the path to the backup file on success, None on failure.
    """
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup_file_path = os.path.join(
            BACKUP_DIR,
            f"{os.path.basename(original_file_path)}.bak_{timestamp}"
        )
        shutil.copy2(original_file_path, backup_file_path)
        print(f"Backup of '{original_file_path}' created at '{backup_file_path}'.")
        write_audit_log_entry(f"Local JSON file backup created: {backup_file_path}")
        return backup_file_path
    except FileNotFoundError:
        print(f"Error: Original file '{original_file_path}' not found for backup.")
        write_audit_log_entry(
            f"Failed to create local JSON file backup: Original file "
            f"'{original_file_path}' not found."
        )
    except Exception as e:
        print(f"Error creating backup of '{original_file_path}': {e}")
        write_audit_log_entry(f"Failed to create local JSON file backup: {e}")
    return None


def remove_countries_from_json(json_file_path: str, countries_to_remove: set) -> bool:
    """
    Removes specified alpha-2 country codes from the JSON file and reloads global data.
    """
    write_audit_log_entry(
        f"Attempting to remove countries {countries_to_remove} "
        f"from local JSON file '{json_file_path}'."
    )
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            country_data = json.load(f)

        original_count = len(country_data)
        updated_country_data = [
            entry for entry in country_data
            if entry.get("alpha-2") not in countries_to_remove
        ]
        removed_count = original_count - len(updated_country_data)

        if removed_count > 0:
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(updated_country_data, f, indent=4, ensure_ascii=False)
            print(f"Successfully removed {removed_count} countries from '{json_file_path}'.")
            write_audit_log_entry(
                f"Successfully removed {removed_count} countries from local JSON "
                f"file '{json_file_path}'."
            )
            load_country_data(json_file_path)
            return True
        else:
            print("No countries to remove were found in the JSON file.")
            write_audit_log_entry(
                f"No countries to remove were found in local JSON file '{json_file_path}'."
            )
            return False
    except FileNotFoundError:
        print(f"Error: JSON file '{json_file_path}' not found for removal.")
        write_audit_log_entry(
            f"Failed to remove countries from local JSON: File '{json_file_path}' not found."
        )
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{json_file_path}'. Check file format.")
        write_audit_log_entry(
            f"Failed to remove countries from local JSON: JSON decode error in "
            f"'{json_file_path}'."
        )
    except Exception as e:
        print(f"An unexpected error occurred while removing countries from JSON: {e}")
        write_audit_log_entry(
            f"An unexpected error occurred while removing countries from local JSON: {e}"
        )
    return False


# ---------------------------------------------------------------------------
# Test Function: Add All Countries
# ---------------------------------------------------------------------------

def test_add_all_countries(admin_api,
                           policy_key: str,
                           policy_name: str,
                           refresh_policy_state_func) -> None:
    """
    Tests adding all countries by country code from the JSON file to the Duo policy,
    with a delay between each add. Tracks errors and cleans up at the end.
    """
    write_audit_log_entry(f"Starting 'Test Add All Countries' for policy '{policy_name}'.", policy_key)
    print("\n--- Starting 'Add All Countries' Test ---")
    if not get_confirmation(
        "This test will attempt to add all countries to your Duo policy one by one, "
        f"then remove them all in a single API call. This may take a long time "
        f"({TEST_ADD_DELAY_SECONDS}s per country). Continue?"
    ):
        print("Test cancelled by user.")
        write_audit_log_entry(
            f"'Test Add All Countries' cancelled by user for policy '{policy_name}'.",
            policy_key
        )
        return

    test_added_countries_tracker = set()
    test_failed_countries = set()

    current_policy_full_data, current_policy_mfa_countries = refresh_policy_state_func(silent_fetch=True)
    if not current_policy_full_data:
        print("Failed to get initial policy state for test. Aborting.")
        write_audit_log_entry(
            f"'Test Add All Countries' aborted due to failure to get initial policy "
            f"state for policy '{policy_name}'.",
            policy_key
        )
        return

    print(f"\nAttempting to add {len(VALID_ALPHA2_CODES)} countries...")
    for i, alpha2_code in enumerate(sorted(list(VALID_ALPHA2_CODES))):
        country_name = ALPHA2_TO_NAME_MAP.get(alpha2_code, alpha2_code)
        print(f"\n[{i+1}/{len(VALID_ALPHA2_CODES)}] Testing add for: {country_name} ({alpha2_code})")

        current_policy_full_data, current_policy_mfa_countries = refresh_policy_state_func(silent_fetch=True)
        if not current_policy_full_data:
            print(f"  Failed to refresh policy state for {country_name}. Skipping add attempt.")
            test_failed_countries.add(alpha2_code)
            write_audit_log_entry(
                f"Test: Failed to refresh policy state for {alpha2_code}. Skipping add attempt.",
                policy_key
            )
            continue

        user_location_policy_sections = current_policy_full_data.get('sections', {}).get('user_location', {})
        deny_list = set(user_location_policy_sections.get('deny_access_countries_list', []))
        allow_no_2fa_list = set(user_location_policy_sections.get('allow_access_no_2fa_countries_list', []))
        ignore_list = set(user_location_policy_sections.get('ignore_location_countries_list', []))

        conflict_found = False
        if alpha2_code in current_policy_mfa_countries:
            print(f"  {country_name} is already in the Duo policy's 'require_mfa_countries_list'. Skipping add attempt.")
            conflict_found = True
        elif alpha2_code in deny_list:
            print(f"  {country_name} is already in 'deny_access_countries_list'. Cannot add to MFA list.")
            conflict_found = True
        elif alpha2_code in allow_no_2fa_list:
            print(f"  {country_name} is already in 'allow_access_no_2fa_countries_list'. Cannot add to MFA list.")
            conflict_found = True
        elif alpha2_code in ignore_list:
            print(f"  {country_name} is already in 'ignore_location_countries_list'. Cannot add to MFA list.")
            conflict_found = True

        if conflict_found:
            test_failed_countries.add(alpha2_code)
            write_audit_log_entry(
                f"Test: Conflict detected for {alpha2_code}. Skipping add attempt.",
                policy_key
            )
        else:
            temp_mfa_countries = set(current_policy_mfa_countries)
            temp_mfa_countries.add(alpha2_code)

            updated_sections = dict(current_policy_full_data.get('sections', {}))
            user_location_policy = dict(updated_sections.get('user_location', {}))
            user_location_policy['require_mfa_countries_list'] = sorted(list(temp_mfa_countries))
            updated_sections['user_location'] = user_location_policy

            if update_duo_policy(admin_api, policy_key, policy_name, updated_sections, silent=True, perform_backup=False):
                print(f"  Successfully added {country_name}.")
                test_added_countries_tracker.add(alpha2_code)
                write_audit_log_entry(
                    f"Test: Successfully added {alpha2_code} to policy.",
                    policy_key
                )
            else:
                print(f"  Failed to add {country_name}.")
                test_failed_countries.add(alpha2_code)
                write_audit_log_entry(
                    f"Test: Failed to add {alpha2_code} to policy.",
                    policy_key
                )

        if i < len(VALID_ALPHA2_CODES) - 1:
            print(f"  Waiting {TEST_ADD_DELAY_SECONDS} seconds...")
            time.sleep(TEST_ADD_DELAY_SECONDS)

    print("\n--- Test Add Phase Complete ---")
    display_countries(test_added_countries_tracker, "Countries Successfully Added During Test")
    display_countries(test_failed_countries, "Countries Failed to Add During Test")

    if not test_added_countries_tracker:
        print("No countries were successfully added during the test to clean up.")
        write_audit_log_entry(
            f"Test: No countries were added, skipping cleanup for policy '{policy_name}'.",
            policy_key
        )
    else:
        print("\n--- Starting Test Cleanup Phase (Removing all countries added during test) ---")
        if not get_confirmation("Confirm removal of all countries added during this test run?"):
            print("Cleanup cancelled by user. Manual cleanup of added countries may be required!")
            write_audit_log_entry(
                f"Test: Cleanup cancelled by user. Manual cleanup of "
                f"{test_added_countries_tracker} may be required for policy '{policy_name}'.",
                policy_key
            )
        else:
            current_policy_full_data, current_policy_mfa_countries = refresh_policy_state_func(silent_fetch=True)
            if not current_policy_full_data:
                print("Failed to get current policy state for cleanup. Manual cleanup may be required!")
                write_audit_log_entry(
                    f"Test: Cleanup failed for policy '{policy_name}' due to failure to get "
                    f"current policy state. Manual cleanup may be required.",
                    policy_key
                )
            else:
                target_mfa_countries_after_cleanup = set(current_policy_mfa_countries)
                for country_to_remove in test_added_countries_tracker:
                    target_mfa_countries_after_cleanup.discard(country_to_remove)

                updated_sections_for_cleanup = dict(current_policy_full_data.get('sections', {}))
                user_location_policy_for_cleanup = dict(updated_sections_for_cleanup.get('user_location', {}))
                user_location_policy_for_cleanup['require_mfa_countries_list'] = sorted(
                    list(target_mfa_countries_after_cleanup)
                )
                updated_sections_for_cleanup['user_location'] = user_location_policy_for_cleanup

                write_audit_log_entry(
                    f"Test: Attempting single API call to remove {test_added_countries_tracker} "
                    f"from policy '{policy_name}'.",
                    policy_key
                )
                if update_duo_policy(
                    admin_api,
                    policy_key,
                    policy_name,
                    updated_sections_for_cleanup,
                    silent=False,
                    perform_backup=False
                ):
                    print("\nAll countries successfully removed from Duo policy that were added during this test.")
                    write_audit_log_entry(
                        f"Test: Successfully removed {test_added_countries_tracker} from policy '{policy_name}'.",
                        policy_key
                    )
                    refresh_policy_state_func()
                else:
                    print("\nFailed to remove all countries added during this test. Manual cleanup may be required!")
                    write_audit_log_entry(
                        f"Test: Failed to remove {test_added_countries_tracker} from policy '{policy_name}'. "
                        f"Manual cleanup may be required.",
                        policy_key
                    )

    if test_failed_countries:
        print("\n--- Failed Countries Cleanup (alpha-2.json) ---")
        display_countries(test_failed_countries, "Countries that Failed to Add to Duo Policy")
        if get_confirmation(
            f"Do you want to remove these {len(test_failed_countries)} failed countries "
            f"from '{ALPHA2_JSON_FILE}'? A backup will be made first."
        ):
            backup_path = backup_json_file(ALPHA2_JSON_FILE)
            if backup_path:
                if remove_countries_from_json(ALPHA2_JSON_FILE, test_failed_countries):
                    print(f"Successfully removed failed countries from '{ALPHA2_JSON_FILE}'.")
                else:
                    print(f"Failed to remove countries from '{ALPHA2_JSON_FILE}'. Please check the file manually.")
            else:
                print("Backup failed, cannot proceed with removing countries from JSON.")

    print("\n--- 'Add All Countries' Test Complete ---")
    write_audit_log_entry(f"'Test Add All Countries' completed for policy '{policy_name}'.", policy_key)


# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------

def main_menu():
    """
    Displays the main menu and handles user input for policy management.
    """
    global last_activity_time
    global DEBUG
    global ALPHA2_JSON_FILE

    admin_api = get_admin_api_client()
    if not admin_api:
        sys.exit(1)

    # DUO_POLICY_KEY: env var first, then keyring
    policy_key = os.environ.get("DUO_POLICY_KEY")
    if not policy_key:
        try:
            policy_key = keyring.get_password(service_name, "DUO_POLICY_KEY")
        except Exception as e:
            print(f"Error loading DUO_POLICY_KEY from keyring: {e}")
            policy_key = None

    if not policy_key:
        print("Error: DUO_POLICY_KEY not found in environment or keyring.")
        write_audit_log_entry("Script exited: DUO_POLICY_KEY not found in environment or keyring.")
        sys.exit(1)

    current_policy_mfa_countries = set()
    current_policy_full_data = {}

    session_successfully_added_countries = set()

    def refresh_policy_state(silent_fetch: bool = False):
        nonlocal current_policy_mfa_countries, current_policy_full_data
        fetched_data = fetch_policy(admin_api, policy_key, silent=silent_fetch)
        if fetched_data:
            current_policy_full_data = fetched_data
            sections = fetched_data.get('sections', {})
            current_policy_mfa_countries = set(
                sections.get('user_location', {}).get('require_mfa_countries_list', [])
            )
            return current_policy_full_data, current_policy_mfa_countries
        else:
            if not silent_fetch:
                print("Failed to refresh policy state. Exiting to prevent inconsistent updates.")
            return None, None

    initial_full_data, initial_mfa_countries = refresh_policy_state()
    if not initial_full_data:
        sys.exit(1)
    current_policy_full_data = initial_full_data
    current_policy_mfa_countries = initial_mfa_countries

    policy_name = current_policy_full_data.get('policy_name', 'Unnamed Policy')
    print(f"\n--- Managing Duo Policy: '{policy_name}' ({policy_key}) ---")

    while True:
        last_activity_time = time.time()
        check_idle_timeout()

        menu_options_display = []
        menu_options_handlers = []

        menu_options_display.append("List All Available Countries")
        menu_options_handlers.append('list_all_json')
        menu_options_display.append("View Current Countries in Duo Policy")
        menu_options_handlers.append('view_current_duo')
        menu_options_display.append("Add Country to MFA list")
        menu_options_handlers.append('add_country')
        menu_options_display.append("Remove Country from MFA list (only those added this session)")
        menu_options_handlers.append('remove_country')
        menu_options_display.append("Exit")
        menu_options_handlers.append('exit')

        if DEBUG:
            menu_options_display.append("Pretty Print Policy JSON (Debug Option)")
            menu_options_handlers.append('pretty_print_json')
            menu_options_display.append("Test Add All Countries (Debug Option)")
            menu_options_handlers.append('test_add_all')

        print("\nMain Menu:")
        for i, option_text in enumerate(menu_options_display):
            print(f"{i+1}. {option_text}")

        valid_choices_range = f"1-{len(menu_options_display)}"
        choice_input = input(f"Enter your choice ({valid_choices_range}): ").strip()
        last_activity_time = time.time()

        try:
            choice_num = int(choice_input)
            if not (1 <= choice_num <= len(menu_options_display)):
                raise ValueError
            choice_action = menu_options_handlers[choice_num - 1]
        except ValueError:
            print(f"Invalid choice. Please enter a number from {valid_choices_range}.")
            continue

        if choice_action == 'list_all_json':
            display_countries(VALID_ALPHA2_CODES, "All Available Countries")

        elif choice_action == 'view_current_duo':
            current_policy_full_data, current_policy_mfa_countries = refresh_policy_state()
            if current_policy_full_data:
                display_countries(
                    current_policy_mfa_countries,
                    "Countries Currently in Duo Policy (requires MFA)",
                    session_successfully_added_countries
                )

        elif choice_action == 'pretty_print_json':
            print("\n--- Full Policy JSON ---")
            current_policy_full_data, current_policy_mfa_countries = refresh_policy_state()
            if current_policy_full_data:
                print(json.dumps(current_policy_full_data, indent=2))
            else:
                print("Could not fetch policy data to display.")
            print("------------------------")

        elif choice_action == 'add_country':
            country_alpha2 = get_country_input("Enter country alpha-2 code or full name to add: ")
            if country_alpha2:
                current_policy_full_data, current_policy_mfa_countries = refresh_policy_state()
                if not current_policy_full_data:
                    continue

                user_location_policy_sections = current_policy_full_data.get('sections', {}).get('user_location', {})
                deny_list = set(user_location_policy_sections.get('deny_access_countries_list', []))
                allow_no_2fa_list = set(user_location_policy_sections.get('allow_access_no_2fa_countries_list', []))
                ignore_list = set(user_location_policy_sections.get('ignore_location_countries_list', []))

                country_name_display = ALPHA2_TO_NAME_MAP.get(country_alpha2, country_alpha2)

                if country_alpha2 in current_policy_mfa_countries:
                    print(f"'{country_name_display}' is already in the Duo policy's 'require_mfa_countries_list'. Cannot add.")
                elif country_alpha2 in deny_list:
                    print(f"'{country_name_display}' is already in 'deny_access_countries_list'. "
                          f"Please remove it from there first if you wish to add it to the MFA list.")
                elif country_alpha2 in allow_no_2fa_list:
                    print(f"'{country_name_display}' is already in 'allow_access_no_2fa_countries_list'. "
                          f"Please remove it from there first if you wish to add it to the MFA list.")
                elif country_alpha2 in ignore_list:
                    print(f"'{country_name_display}' is already in 'ignore_location_countries_list'. "
                          f"Please remove it from there first if you wish to add it to the MFA list.")
                else:
                    if get_confirmation(
                        f"Confirm adding '{country_name_display}' to Duo policy's 'require_mfa_countries_list'?"
                    ):
                        temp_mfa_countries = set(current_policy_mfa_countries)
                        temp_mfa_countries.add(country_alpha2)

                        updated_sections = dict(current_policy_full_data.get('sections', {}))
                        user_location_policy = dict(updated_sections.get('user_location', {}))
                        user_location_policy['require_mfa_countries_list'] = sorted(list(temp_mfa_countries))
                        updated_sections['user_location'] = user_location_policy

                        if update_duo_policy(admin_api, policy_key, policy_name, updated_sections):
                            current_policy_full_data, current_policy_mfa_countries = refresh_policy_state()
                            session_successfully_added_countries.add(country_alpha2)
                            print(f"'{country_name_display}' successfully added to Duo policy.")
                        else:
                            print(f"Failed to add '{country_name_display}' to Duo policy.")
                    else:
                        print("Add operation cancelled by user.")
            else:
                print("Add operation cancelled.")

        elif choice_action == 'remove_country':
            country_alpha2 = get_country_input("Enter country alpha-2 code or full name to remove: ")
            if country_alpha2:
                current_policy_full_data, current_policy_mfa_countries = refresh_policy_state()
                if not current_policy_full_data:
                    continue

                if country_alpha2 not in session_successfully_added_countries:
                    print(
                        f"Error: '{ALPHA2_TO_NAME_MAP.get(country_alpha2, country_alpha2)}' "
                        f"was not added during this session and cannot be removed via this script."
                    )
                elif country_alpha2 not in current_policy_mfa_countries:
                    print(
                        f"Warning: '{ALPHA2_TO_NAME_MAP.get(country_alpha2, country_alpha2)}' "
                        f"was tracked as added, but is not currently in the Duo policy. Skipping removal."
                    )
                    session_successfully_added_countries.discard(country_alpha2)
                else:
                    if get_confirmation(
                        f"Confirm removing '{ALPHA2_TO_NAME_MAP.get(country_alpha2, country_alpha2)}' "
                        f"from Duo policy?"
                    ):
                        temp_mfa_countries = set(current_policy_mfa_countries)
                        temp_mfa_countries.remove(country_alpha2)

                        updated_sections = dict(current_policy_full_data.get('sections', {}))
                        user_location_policy = dict(updated_sections.get('user_location', {}))
                        user_location_policy['require_mfa_countries_list'] = sorted(list(temp_mfa_countries))
                        updated_sections['user_location'] = user_location_policy

                        if update_duo_policy(admin_api, policy_key, policy_name, updated_sections):
                            current_policy_full_data, current_policy_mfa_countries = refresh_policy_state()
                            session_successfully_added_countries.remove(country_alpha2)
                            print(
                                f"'{ALPHA2_TO_NAME_MAP.get(country_alpha2, country_alpha2)}' "
                                f"successfully removed from Duo policy."
                            )
                        else:
                            print(
                                f"Failed to remove '{ALPHA2_TO_NAME_MAP.get(country_alpha2, country_alpha2)}' "
                                f"from Duo policy."
                            )
                    else:
                        print("Remove operation cancelled by user.")
            else:
                print("Remove operation cancelled.")

        elif choice_action == 'test_add_all':
            test_add_all_countries(admin_api, policy_key, policy_name, refresh_policy_state)

        elif choice_action == 'exit':
            print("Exiting.")
            write_audit_log_entry("Script exited normally.", policy_key)
            break

        else:
            print(f"Unhandled choice: {choice_input}. Please report this bug.")


# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Duo Policy Management Script.")
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode (shows extra options).')
    parser.add_argument(
        '--alpha2-file',
        default=ALPHA2_JSON_FILE,
        help=f"Path to alpha-2 country JSON file (default: {ALPHA2_JSON_FILE})."
    )
    args = parser.parse_args()

    DEBUG = args.debug
    if DEBUG:
        write_audit_log_entry("Script started with debug mode enabled via command-line argument.")
    else:
        write_audit_log_entry("Script started.")

    # Allow overriding the alpha-2 JSON file via CLI
    ALPHA2_JSON_FILE = args.alpha2_file

    if not load_country_data(ALPHA2_JSON_FILE):
        print("Failed to load country data. Exiting.")
        write_audit_log_entry("Script exited due to failure to load country data.")
        sys.exit(1)

    set_service_name()
    main_menu()
