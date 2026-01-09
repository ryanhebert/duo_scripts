# Cisco Duo Admin Maintenance Tool

A small, interactive Python utility for **Duo Admin API** maintenance tasks:

- **Expired Phones Report**: Identify *active* Duo Mobile devices that are running an **outdated Duo Mobile app version** (default target: `4.85.0`) within a configurable lookback window (default: `365` days).
- **Device Cleanup Utility**: Identify phones that appear **inactive** (not seen in N days) or **stale** (never seen and created more than N days ago), export candidates, and (optionally) **delete** them from Duo.

> ⚠️ **High impact:** The cleanup flow can permanently delete phones from your Duo tenant. Read the safeguards section before using it.

---

## What this tool does

### 1) Expired Phones Report (Outdated Duo Mobile)

The tool pulls all phones from Duo, then filters for:

- **Outdated app version**: `phone.app_version < TARGET_APP_VERSION`
- **Seen recently**: `phone.last_seen` is within the **lookback window** (default: 365 days)

It then builds two reports:

- **Phone-centric report** (`outdated_phones.csv`)
  - One row per phone with assigned usernames, device metadata, last seen date, days since seen, and app version.
- **User-centric report** (`outdated_users.csv`)
  - One row per user with identity fields plus one or more `P#_` columns describing each matching outdated phone.

### 2) Cleanup Utility (Inactive / Stale Phones)

The tool identifies deletion candidates:

- **Inactive phones**: `last_seen` exists and is older than the inactivity threshold (default: 365 days)
- **Stale phones**: never seen (no `last_seen`) and `created` timestamp older than the stale threshold (default: 365 days)

You can export candidates to CSV, create a JSON backup, and—only after a hard confirmation—delete phones.

---

## Requirements

- Python **3.9+** (3.10+ recommended)
- Network access to your Duo Admin API hostname
- Duo Admin API integration with required permissions

### Python dependencies

This script imports:

- `duo_client`
- `pandas`
- `packaging`

Install with pip:

```bash
pip install duo_client pandas packaging
```

Or use a virtual environment:

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install duo_client pandas packaging
```

---

## Duo Admin API setup (required)

1. Log in to the **Duo Admin Panel**.
2. Navigate to **Applications** → **Protect an Application**.
3. Search for **Admin API** and choose **Protect**.
4. Copy the generated:
   - **Integration key** (`IKEY`)
   - **Secret key** (`SKEY`)
   - **API hostname** (`HOST`, e.g., `api-xxxxxxxx.duosecurity.com`)
5. Set the application’s permissions as follows:

### Required Admin API permissions

To run *reports only*:

- **Grant read resource** (`adminapi_read_resource`)

To use the *cleanup deletion* option:

- **Grant write resource** (`adminapi_write_resource`)  
  (covers create/modify/delete for resources like phones)

These permission names/flags are documented in Duo’s Admin API docs.  
See: Duo Admin API documentation: https://duo.com/docs/adminapi

> Principle of least privilege: If you do not plan to delete phones, do **not** enable write permissions.

---

## How authentication works

You provide credentials via command-line arguments:

- `--ikey` (integration key)
- `--skey` (secret key)
- `--host` (API hostname)

Example:

```bash
python script.py --ikey DIXXXXXXXXXXXXXXXXXX --skey deadbeefdeadbeefdeadbeefdeadbeefdeadbeef --host api-xxxxxxx.duosecurity.com
```

> ⚠️ **Security note:** CLI arguments may be visible in shell history and process listings (depending on OS). Use a secure machine, avoid shared terminals, and consider running from a trusted admin jump box.

---

## Usage

Run the script with required parameters:

```bash
python script.py -ikey <IKEY> -skey <SKEY> -host <API_HOSTNAME>
```

You’ll see the main menu:

- **1. Expired Phones Report**
- **2. Device Cleanup Utility**
- **3. Exit**

### Expired Phones Report menu

- **View Phone-Centric Report**
- **View User-Centric Report**
- **Change Lookback Period**
- **Export Both Reports to CSV**

Export files are created in your current working directory:

- `outdated_phones.csv`
- `outdated_users.csv`

### Cleanup Utility menu

- Change inactivity/stale thresholds
- Export candidate list (`cleanup_candidates.csv`)
- Delete phones (with guardrails)

---

## Outputs and file formats

### `outdated_phones.csv`

Columns:

- `phone_id`
- `assigned_users`
- `number`
- `platform`
- `os_version`
- `model`
- `last_seen` (YYYY-MM-DD)
- `days_since_seen`
- `app_version`

### `outdated_users.csv`

Columns include:

- `username`, `realname`, `email`
- For each matching outdated phone: `P1_num`, `P1_id`, `P1_os`, `P1_seen`, `P1_days`, `P1_ver`  
  And so on: `P2_*`, `P3_*`, ...

### `cleanup_candidates.csv`

A raw export of candidate phone objects returned by Duo (all fields the API returned for each phone).

### JSON backup (optional during deletion)

If you choose to create a backup before deleting, a file like:

- `backup_YYYYMMDD_HHMMSS.json`

is written to the working directory.

---

## Safeguards (read before deleting)

The deletion flow includes multiple safety checks:

1. **Candidate preview** (you can export before deleting)
2. **Optional JSON backup prompt**
3. A hard confirmation requiring you to type the exact phrase:

```
DELETE <N> PHONES
```

Where `<N>` is the number of candidate phones.

> **Deletion is permanent** in Duo. Make a backup, export the CSV, and validate candidates before continuing.

---

## Configuration notes

The script contains two global defaults:

- `TARGET_APP_VERSION = "4.85.0"`
- `DEFAULT_LOOKBACK = 365`

You can change these in the script if your organization uses a different minimum Duo Mobile version.

---

## Troubleshooting

### “401 Unauthorized” / “403 Forbidden”
- Verify `IKEY`, `SKEY`, and `HOST` are correct
- Confirm the Admin API application permissions include:
  - `adminapi_read_resource` (reports)
  - `adminapi_write_resource` (deletion)

### Empty report results
- Devices may not have been seen within your lookback window
- Devices may have `app_version` missing or `N/A` (the script treats these as not-outdated)

### API errors or timeouts
- Check network connectivity to your Duo API hostname
- Confirm system time is accurate (signature validation can fail if clock skew exists)

---

## Development

### Suggested `requirements.txt`

```txt
duo_client
pandas
packaging
```

### Linting / formatting (optional)

```bash
python -m pip install ruff black
ruff check .
black .
```

---

## Disclaimer

This project is provided as-is. Test in a non-production tenant if available, and ensure you have appropriate change control and approvals before deleting devices.

---
