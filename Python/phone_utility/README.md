# Duo Admin API Maintenance Tool (Devices & Cleanup)

An interactive Python utility for **Duo Admin API** administrators to:

1. **Identify active devices running an outdated Duo Mobile version** (within a configurable *Last seen* lookback window).
2. **Identify and delete devices that are inactive or never-used** (with export + backup safeguards).

> ⚠️ **High impact:** The cleanup workflow can **permanently delete device records** from Duo. Review the safeguards section before using in production.

---

## What this tool does

### 1) Outdated Duo Mobile Devices (Active Devices)

The tool retrieves **all devices** (paged) from Duo, then filters for:

- **Duo Mobile version earlier than `TARGET_APP_VERSION`** (default: `4.85.0`)
- **Device "Last seen" is within the lookback window** (default: `365` days)

It produces two report views and CSV exports:

- **Report grouped by device** (one row per device)
- **Report grouped by user account** (one row per user account; includes multiple devices per user via `D1_*`, `D2_*`, ... columns)

### 2) Device Cleanup (Inactive / Never-used Devices)

The cleanup workflow evaluates all devices and identifies candidates:

- **Inactive devices:** devices with a `last_seen` timestamp older than the inactivity threshold (default: `365` days)
- **Never-used devices:** devices **without** `last_seen` and with a `created` timestamp older than the never-used threshold (default: `365` days)

You can:

- Export candidates to CSV
- Create a JSON backup (recommended)
- Delete devices (requires an explicit confirmation phrase)

> Note: If your tenant’s device payload does **not** include a `created` field, the **never-used** classification cannot be computed. In that case, the cleanup workflow will still find **inactive** devices, but may find **zero** never-used devices.

---

## Requirements

- Python **3.9+** (3.10+ recommended)
- Network access to your Duo Admin API hostname
- Duo Admin API integration with appropriate permissions

### Python dependencies

This script uses:

- `duo_client`
- `pandas`
- `packaging`

Install:

```bash
pip install duo_client pandas packaging
```

Recommended: virtual environment

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows
.venv\Scripts\activate

pip install duo_client pandas packaging
```

---

## Duo Admin API setup (required)

1. Log in to the **Duo Admin Panel**.
2. Go to **Applications** → **Protect an Application**.
3. Search for **Admin API** and click **Protect**.
4. Copy the generated values:
   - **Integration key** (`IKEY`)
   - **Secret key** (`SKEY`)
   - **API hostname** (`HOST`, e.g., `api-xxxxxxxx.duosecurity.com`)

### Required permissions

Minimum required to run **reports**:

- `adminapi_read_resource`

Required to **delete devices**:

- `adminapi_write_resource`

> Follow least privilege: if you do not plan to delete devices, do **not** grant write permissions.

---

## Usage

Run with required parameters:

```bash
python script.py --ikey <IKEY> --skey <SKEY> --host <API_HOSTNAME>
```

Optional: specify an output directory for exports/backups:

```bash
python script.py --ikey <IKEY> --skey <SKEY> --host <API_HOSTNAME> --outdir ./exports
```

> ⚠️ Security note: CLI arguments can be visible in shell history/process listings depending on OS. Use a secure admin workstation/jump host.

---

## Text UI navigation

### Main Menu

- **1. Identify Active Devices Running Outdated Duo Mobile**
- **2. Identify and Delete Inactive or Never-Used Devices**
- **3. Exit**

### Outdated Duo Mobile Devices

The tool shows inclusion criteria:

- Duo Mobile version earlier than **TARGET_APP_VERSION**
- Device last seen within the past **lookback** days

Actions:

1. View report grouped by device  
2. View report grouped by user account  
3. Modify device activity lookback period  
4. Export reports to CSV  
5. Back to main menu  

### Device Cleanup (Inactive / Never-used)

The tool shows criteria and the current candidate count.

Actions:

1. Change inactivity threshold  
2. Change never-used device threshold  
3. Export device cleanup candidate list (CSV)  
4. **DELETE ALL IDENTIFIED DEVICES (PERMANENT)**  
5. Refresh device inventory from Duo  
6. Back to main menu  

---

## Outputs

All outputs are written to `--outdir` (default: current directory).

### Outdated device reports

- `outdated_devices_by_device_lookback<days>_<timestamp>.csv`
- `outdated_devices_by_user_lookback<days>_<timestamp>.csv`

**Grouped-by-device columns** include:

- `phone_id` (Duo device identifier)
- `assigned_users`
- `number`
- `platform`
- `os_version`
- `model`
- `last_seen` (YYYY-MM-DD)
- `days_since_seen`
- `app_version` (Duo Mobile version)

**Grouped-by-user columns** include:

- `username`, `realname`, `email`
- Per device: `D1_number`, `D1_device_id`, `D1_os_version`, `D1_last_seen`, `D1_days_since_seen`, `D1_duo_mobile_version`  
  Then `D2_*`, `D3_*`, ...

### Cleanup candidate list

- `device_cleanup_candidates_inactive<days>_neverused<days>_<timestamp>.csv`

### JSON backups

If you choose to create a backup prior to deletion:

- `device_cleanup_backup_<timestamp>.json`

### Deletion failure log

If any deletions fail, details are saved to:

- `delete_failures_<timestamp>.json`

---

## Safeguards (read before deleting)

The deletion flow includes multiple protections:

1. Clear banner warning about permanent device deletion
2. Optional CSV export prompt
3. Optional JSON backup prompt
4. Hard confirmation requiring typing an exact phrase:

```
DELETE <N> DEVICES
```

Where `<N>` is the number of devices currently identified for cleanup.

> Deletion is permanent. Export and back up before proceeding.

---

## Configuration

Default values are defined near the top of the script:

- `TARGET_APP_VERSION = "4.85.0"`
- `DEFAULT_LOOKBACK = 365`

You can adjust these to match your organization’s minimum supported Duo Mobile version and reporting window.

---

## Troubleshooting

### “401 Unauthorized” / “403 Forbidden”
- Verify `IKEY`, `SKEY`, and `HOST`
- Confirm permissions:
  - `adminapi_read_resource` (reports)
  - `adminapi_write_resource` (deletion)

### “Never-used devices” always shows zero
- Your device payload may not include a `created` timestamp
- The tool still correctly identifies **inactive** devices based on `last_seen`

### Empty outdated report results
- Devices may not have been seen within your lookback window
- Devices may not report `app_version` (treated as not-outdated)

### API errors/timeouts
- Check network access to the Duo API hostname
- Ensure system clock is correct (API signing can fail with clock skew)

---
