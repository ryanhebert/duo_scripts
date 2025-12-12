# Duo Policy Location Update Script (Windows)


## Table of Contents

1. [1. Project Overview](#1-project-overview)
2. [2. Features](#2-features)
3. [3. Prerequisites](#3-prerequisites)
4. [4. Installation](#4-installation)
5. [Capturing Required Configuration Values from Duo](#capturing-required-configuration-values-from-duo)
   - [Admin API Integration Page (ikey, skey, API Hostname)](#admin-api-integration-page-ikey-skey-api-hostname)
   - [Duo Policy Page (Policy Key – New Policy Editor)](#duo-policy-page-policy-key-new-policy-editor)
6. [5. Configuration](#5-configuration)
7. [First-Time Setup and Credential Handling](#first-time-setup-and-credential-handling)
   - [Initial Credential and Policy Key Setup](#initial-credential-and-policy-key-setup)
   - [Important Security Notice](#important-security-notice)
   - [Duo Admin API Credentials](#duo-admin-api-credentials)
   - [`alpha-2.json` File](#alpha-2json-file)

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
    
    (If not using git, just download `location_update_windows.py` and `alpha-2.json` into the same directory.)

2.  **Install Dependencies:**
    


## Capturing Required Configuration Values from Duo

You will need **four values** from the Duo Admin Panel to configure this script.

### Admin API Integration Page (ikey, skey, API Hostname)

From the **Admin API integration** you created:

Capture the following values (shown on the integration page):
- **Integration Key (ikey)**
- **Secret Key (skey)**
- **API Hostname** (e.g., `api-xxxxxxxx.duosecurity.com`)

### Duo Policy Page (Policy Key – New Policy Editor)

The **Policy Key** is obtained from the Duo policy you want to manage.

1. Navigate to **Policies** in the Duo Admin Panel.
2. Open the policy you want to modify.
3. Ensure you are using the **New Policy Editor**.
4. Locate the **Policy Key** shown in the editor.

Duo policy documentation:
https://duo.com/docs/policy#new-policy-editor

The policy key is required for all Admin API policy operations.


---

## 5. Configuration


## First-Time Setup and Credential Handling

### Initial Credential and Policy Key Setup

On the **first run**, the script will prompt you interactively for all required Duo configuration values:

- **API Hostname**
- **Integration Key (ikey)**
- **Secret Key (skey)**
- **Policy Key**

These values are entered once and are required to establish authenticated access to the Duo Admin API and to identify the policy that will be managed.

After successful entry:

- Credentials (**ikey, skey, API host**) are securely stored using the operating system’s native **keyring** service.
- The **policy key** is also stored securely and associated with this script instance.

On **subsequent runs**, you will **not be prompted again** for these values. The script automatically retrieves them from secure storage, allowing normal operation without re-entering sensitive information.

If credentials or the policy key need to be changed, they must be explicitly cleared from the keyring or updated through the script’s credential reset flow.

---

### Important Security Notice

⚠️ **Protect Access to This Script Once Configured**

After initial configuration, this script has the ability to:
- Authenticate to the Duo Admin API
- Read and modify Duo policy configuration

Anyone with access to the machine and permission to execute this script can perform policy changes **without re-authenticating**.

**Strongly recommended controls:**
- Restrict filesystem access to the script directory (NTFS permissions)
- Limit execution to trusted administrative users only
- Avoid storing or running the script on shared or multi-user systems
- Protect the system with disk encryption and OS-level account controls

Treat this script with the same level of protection as other administrative security tooling.

---

### Duo Admin API Credentials

The script uses `keyring` to securely store your Duo Admin API credentials. The first time you run the script, or if credentials are not found, it will prompt you to enter them interactively:

*   **Duo API hostname:** (e.g., `api-xxxxxxxx.duosecurity.com`)
*   **Integration key (ikey)**
*   **Secret key (skey)**
*   **Policy key:** The unique key for the Duo policy you wish to manage. This can be found in the Duo Admin Panel URL when editing a policy (e.g., `https://admin.duosecurity.com/policies/<policy_key>/edit`).

These credentials will be stored in your OS keyring, associated with a service name derived from the script's unique Windows file ID or a hash of its path.

### `alpha-2.json` File

Ensure you have an `alpha-2.json` file in the same directory as the script, or specify its path using the `--alpha2-file` argument. This file is crucial for country code validation and lookup.



```bash
# Example for Windows Command Prompt
