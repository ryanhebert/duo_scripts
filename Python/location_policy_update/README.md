# Duo Policy Location Update Script (Windows)

## Table of Contents

1.  [Project Overview](#project-overview)
2.  [Features](#features)
3.  [Prerequisites](#prerequisites)
4.  [Installation](#installation)
5.  [Configuration](#configuration)
    *   [Duo Admin API Credentials](#duo-admin-api-credentials)
    *   [`alpha-2.json` File](#alpha-2json-file)
    *   [Environment Variable (Optional)](#environment-variable-optional)
6.  [Usage](#usage)
    *   [Running the Script](#running-the-script)
    *   [Main Menu Options](#main-menu-options)
    *   [Idle Timeout](#idle-timeout)
    *   [Debug Mode](#debug-mode)
7.  [Audit Logging](#audit-logging)
8.  [Backup Strategy](#backup-strategy)
9.  [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)
11. [Contributing](#contributing)
12. [License](#license)

---

## 1. Project Overview

This Python script provides a command-line interface (CLI) for managing Duo Security policies, specifically focusing on the "User Location" settings which allow administrators to define countries that require MFA. The script simplifies the process of adding or removing countries from the `require_mfa_countries_list` within a specified Duo policy. It includes features for secure credential storage, audit logging, and policy backups to ensure safe and traceable operations.

The script is designed for Windows environments, leveraging `fsutil` for unique script identification to enhance keyring security.

## 2. Features

*   **Secure Credential Storage:** Uses the OS-native `keyring` service to securely store Duo Admin API credentials (hostname, integration key, secret key, policy key).
*   **Duo Policy Management:**
    *   View countries currently configured in the `require_mfa_countries_list` of a Duo policy.
    *   Add individual countries to the `require_mfa_countries_list`.
    *   Remove individual countries that were added during the current session.
    *   Displays potential conflicts if a country is already in other user location lists (deny, allow no 2FA, ignore).
*   **Comprehensive Country Data:** Loads a list of valid alpha-2 country codes and names from a JSON file for accurate input validation and display.
*   **Audit Logging:** Records all significant actions, including script startup, policy updates, and errors, to a local audit log file.
*   **Automated Backups:** Automatically creates a timestamped backup of the Duo policy configuration before any modifications are made.
*   **Local JSON Backup:** Provides an option to backup the `alpha-2.json` file before making changes (e.g., removing failed countries).
*   **Idle Timeout:** Automatically exits after a period of inactivity to enhance security.
*   **Debug Mode:** An optional debug mode provides additional options for testing and diagnostics, such as a "Test Add All Countries" function.

## 3. Prerequisites

*   **Python 3.x:** The script is written in Python 3.
*   **`duo_client` library:** For interacting with the Duo Admin API.
*   **`keyring` library:** For secure credential storage.
*   **`pathlib` library:** Standard Python library.
*   **`hashlib` library:** Standard Python library.
*   **`argparse` library:** Standard Python library.
*   **`getpass` library:** Standard Python library.
*   **`subprocess` library:** Standard Python library.
*   **`shutil` library:** Standard Python library.
*   **`json` library:** Standard Python library.
*   **`time` library:** Standard Python library.
*   **`os`, `sys` libraries:** Standard Python libraries.
*   **`alpha-2.json` file:** A JSON file containing a list of country objects with `alpha-2` codes and `name` fields. An example structure:
    ```json
    [
      {"name": "United States", "alpha-2": "US"},
      {"name": "Canada", "alpha-2": "CA"},
      // ... more countries
    ]
    ```
*   **Duo Admin API Application:** You will need a Duo Admin API application with the following permissions:
    *   **Policies:** "Read" and "Write" permissions are required for the script to fetch and update policies.
*   **Windows Operating System:** The script uses `fsutil` which is a Windows-specific command.

## 4. Installation

1.  **Clone or Download:** Get the script and the `alpha-2.json` file.
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```
    (If not using git, just download `location_update_windows.py` and `alpha-2.json` into the same directory.)

2.  **Install Dependencies:**
    ```bash
    pip install duo_client keyring
    ```

## 5. Configuration

### Duo Admin API Credentials

The script uses `keyring` to securely store your Duo Admin API credentials. The first time you run the script, or if credentials are not found, it will prompt you to enter them interactively:

*   **Duo API hostname:** (e.g., `api-xxxxxxxx.duosecurity.com`)
*   **Integration key (ikey)**
*   **Secret key (skey)**
*   **Policy key:** The unique key for the Duo policy you wish to manage. This can be found in the Duo Admin Panel URL when editing a policy (e.g., `https://admin.duosecurity.com/policies/<policy_key>/edit`).

These credentials will be stored in your OS keyring, associated with a service name derived from the script's unique Windows file ID or a hash of its path.

### `alpha-2.json` File

Ensure you have an `alpha-2.json` file in the same directory as the script, or specify its path using the `--alpha2-file` argument. This file is crucial for country code validation and lookup.

### Environment Variable (Optional)

You can optionally set the `DUO_POLICY_KEY` environment variable instead of storing it in the keyring. The script will check the environment variable first.

```bash
# Example for Windows Command Prompt
set DUO_POLICY_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
