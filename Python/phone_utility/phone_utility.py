import duo_client
import os
import time
import json
import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from packaging import version
from datetime import datetime, timedelta, timezone

import pandas as pd

# --- GLOBAL CONFIGURATION ---
TARGET_APP_VERSION = "4.85.0"
DEFAULT_LOOKBACK = 365

# Parse once
TARGET_PARSED_VERSION = version.parse(TARGET_APP_VERSION)


# -----------------------------
# Console / Utility Helpers
# -----------------------------
def clear_screen():
    if os.name == "nt":
        _ = os.system("cls")
    else:
        _ = os.system("clear")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ts_compact(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now()
    return dt.strftime("%Y%m%d_%H%M%S")


def ensure_outdir(outdir: str) -> Path:
    p = Path(outdir).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def api_call_with_retry(fn, *, tries: int = 3, base_sleep: float = 0.6, what: str = "Admin API request"):
    """
    Simple retry/backoff wrapper for transient failures.
    """
    last_exc = None
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            if attempt < tries:
                sleep_s = base_sleep * (2 ** (attempt - 1))
                print(f"[WARN] {what} failed (attempt {attempt}/{tries}): {e}. Retrying in {sleep_s:.1f}s...")
                time.sleep(sleep_s)
            else:
                raise last_exc


# -----------------------------
# Duo Admin API Helpers
# -----------------------------
def get_api_client(ikey: str, skey: str, host: str):
    """Initializes the Duo Admin API client."""
    try:
        return duo_client.Admin(ikey=ikey, skey=skey, host=host)
    except Exception as e:
        print(f"[ERROR] Failed to initialize Duo Admin API client: {e}")
        sys.exit(1)


def fetch_all_devices(admin_api, *, limit: int = 500) -> List[Dict[str, Any]]:
    """
    Retrieves all devices from Duo using Admin API pagination.
    'limit' is the page size per request (not a cap).
    """
    print(f"[INFO] Retrieving all devices from Duo using Admin API pagination ({limit} devices per request)...")

    all_devices: List[Dict[str, Any]] = []
    offset = 0

    while True:
        def _call():
            # duo_client expects strings for limit/offset
            return admin_api.get_phones(limit=str(limit), offset=str(offset))

        batch = api_call_with_retry(_call, what="GET /admin/v1/phones")
        if not batch:
            break

        all_devices.extend(batch)
        offset += limit

        # Optional progress line for large tenants (kept concise)
        # print(f"[INFO] Retrieved {len(all_devices)} devices so far...")

        if len(batch) < limit:
            break

    return all_devices


# -----------------------------
# Version / Parsing Helpers
# -----------------------------
def safe_parse_version(v) -> Optional[version.Version]:
    if pd.isna(v) or not v or v == "N/A":
        return None
    try:
        return version.parse(str(v))
    except Exception:
        return None


# -----------------------------
# Outdated Duo Mobile Reporting
# -----------------------------
def fetch_and_filter_outdated_devices(
    admin_api,
    lookback_days: int,
    *,
    user_cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """
    Retrieves all devices, filters for:
      - Duo Mobile version earlier than TARGET_APP_VERSION
      - device last seen within lookback window
    Then retrieves user account profiles only for relevant usernames (batched).
    """
    print("\n[INFO] Building outdated Duo Mobile device dataset...")

    all_devices = fetch_all_devices(admin_api)
    if not all_devices:
        return pd.DataFrame(), []

    df_devices = pd.DataFrame(all_devices)

    now_utc = utc_now()
    cutoff_date = now_utc - timedelta(days=lookback_days)

    # Parse last seen once
    df_devices["last_seen_dt"] = pd.to_datetime(df_devices.get("last_seen"), errors="coerce", utc=True)
    df_devices["days_since_seen_val"] = (now_utc - df_devices["last_seen_dt"]).dt.days

    # Parse Duo Mobile versions once and compare to target
    df_devices["app_parsed"] = df_devices.get("app_version").map(safe_parse_version)
    version_mask = df_devices["app_parsed"].notna() & (df_devices["app_parsed"] < TARGET_PARSED_VERSION)

    # "Active" for this report = has last_seen and within window
    date_mask = df_devices["last_seen_dt"].notna() & (df_devices["last_seen_dt"] >= cutoff_date)

    filtered_devices_df = df_devices[version_mask & date_mask].copy()

    # Collect usernames without iterrows
    unique_usernames: set[str] = set()
    users_lists = filtered_devices_df.get("users").tolist() if not filtered_devices_df.empty else []
    for users_on_device in users_lists:
        if isinstance(users_on_device, list):
            for user_entry in users_on_device:
                if isinstance(user_entry, dict):
                    uname = user_entry.get("username")
                    if uname:
                        unique_usernames.add(uname)

    username_list = list(unique_usernames)
    if not username_list:
        return filtered_devices_df, []

    # Cache user lookups across lookback changes
    cache = user_cache if user_cache is not None else {}
    need = [u for u in username_list if u not in cache]

    if need:
        print(f"[INFO] Retrieving user account profiles for {len(need)} usernames (cached: {len(cache)})...")
        for i in range(0, len(need), 100):
            chunk = need[i : i + 100]
            params = {"username_list": json.dumps(chunk)}

            def _call():
                return admin_api.json_api_call("GET", "/admin/v1/users", params)

            try:
                user_batch = api_call_with_retry(_call, what="GET /admin/v1/users")
                for u in user_batch:
                    if isinstance(u, dict) and u.get("username"):
                        cache[u["username"]] = u
            except Exception as e:
                print(f"[WARN] Failed to retrieve a user account batch ({i}-{i+len(chunk)-1}): {e}")

    outdated_users: List[Dict[str, Any]] = []
    for uname in username_list:
        u = cache.get(uname)
        if u:
            outdated_users.append(u)

    return filtered_devices_df, outdated_users


def prepare_report_grouped_by_device(filtered_devices_df: pd.DataFrame) -> Optional[pd.DataFrame]:
    if filtered_devices_df is None or filtered_devices_df.empty:
        return None

    df = filtered_devices_df.copy()

    def _assigned_users(x):
        if isinstance(x, list):
            return ", ".join([u.get("username") for u in x if isinstance(u, dict) and u.get("username")])
        return "Unassigned"

    df["assigned_users"] = df.get("users").apply(_assigned_users)
    df["last_seen"] = df["last_seen_dt"].dt.strftime("%Y-%m-%d")
    df["days_since_seen"] = df["days_since_seen_val"].apply(lambda x: str(int(x)) if pd.notna(x) else "-")

    cols = [
        "phone_id",
        "assigned_users",
        "number",
        "platform",
        "os_version",
        "model",
        "last_seen",
        "days_since_seen",
        "app_version",
    ]
    return df.reindex(columns=cols)


def prepare_report_grouped_by_user(filtered_devices_df: pd.DataFrame, outdated_users: List[Dict[str, Any]]) -> Optional[pd.DataFrame]:
    if filtered_devices_df is None or filtered_devices_df.empty or not outdated_users:
        return None

    phone_lookup: Dict[str, Dict[str, str]] = {}
    for p in filtered_devices_df.to_dict("records"):
        pid = p.get("phone_id")
        if not pid:
            continue
        last_seen_dt = p.get("last_seen_dt")
        seen_str = last_seen_dt.strftime("%Y-%m-%d") if isinstance(last_seen_dt, datetime) else "N/A"
        days_val = p.get("days_since_seen_val")
        days_str = str(int(days_val)) if days_val is not None and pd.notna(days_val) else "N/A"

        phone_lookup[pid] = {
            "id": pid,
            "num": p.get("number", "N/A"),
            "os": p.get("os_version", "N/A"),
            "ver": p.get("app_version", "N/A"),
            "seen": seen_str,
            "days": days_str,
        }

    user_rows: List[Dict[str, Any]] = []
    for u in outdated_users:
        row: Dict[str, Any] = {
            "username": u.get("username"),
            "realname": u.get("realname"),
            "email": u.get("email"),
        }

        match_count = 0
        for p_summary in u.get("phones", []) if isinstance(u, dict) else []:
            if not isinstance(p_summary, dict):
                continue
            p_meta = phone_lookup.get(p_summary.get("phone_id"))
            if p_meta:
                match_count += 1
                pre = f"D{match_count}_"
                row.update(
                    {
                        f"{pre}number": p_meta["num"],
                        f"{pre}device_id": p_meta["id"],
                        f"{pre}os_version": p_meta["os"],
                        f"{pre}last_seen": p_meta["seen"],
                        f"{pre}days_since_seen": p_meta["days"],
                        f"{pre}duo_mobile_version": p_meta["ver"],
                    }
                )

        if match_count > 0:
            user_rows.append(row)

    return pd.DataFrame(user_rows).fillna("-") if user_rows else None


def export_outdated_reports(
    outdir: Path,
    *,
    lookback_days: int,
    report_by_device: Optional[pd.DataFrame],
    report_by_user: Optional[pd.DataFrame],
) -> Tuple[Optional[Path], Optional[Path]]:
    stamp = ts_compact()
    p_path = None
    u_path = None

    if report_by_device is not None and not report_by_device.empty:
        p_path = outdir / f"outdated_devices_by_device_lookback{lookback_days}_{stamp}.csv"
        report_by_device.to_csv(p_path, index=False)

    if report_by_user is not None and not report_by_user.empty:
        u_path = outdir / f"outdated_devices_by_user_lookback{lookback_days}_{stamp}.csv"
        report_by_user.to_csv(u_path, index=False)

    return p_path, u_path


def outdated_duo_mobile_manager(api, outdir: Path):
    lookback_days = DEFAULT_LOOKBACK
    user_cache: Dict[str, Dict[str, Any]] = {}

    devices_df, users = fetch_and_filter_outdated_devices(api, lookback_days, user_cache=user_cache)

    while True:
        print("\n--- OUTDATED DUO MOBILE DEVICES ---")
        print("\nInclusion criteria:")
        print(f"• Duo Mobile version earlier than {TARGET_APP_VERSION}")
        print(f"• Device last seen within the past {lookback_days} days")

        count = 0 if devices_df is None or devices_df.empty else len(devices_df)
        print(f"\n[INFO] Devices matching criteria: {count}")

        print("\nAvailable actions:")
        print("1. View report grouped by device")
        print("2. View report grouped by user account")
        print("3. Modify device activity lookback period")
        print("4. Export reports to CSV")
        print("5. Back to main menu")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":
            report = prepare_report_grouped_by_device(devices_df)
            if report is not None:
                print("\n", report.to_string(index=False))
            else:
                print("\n[INFO] No devices match the current criteria.")
        elif choice == "2":
            report = prepare_report_grouped_by_user(devices_df, users)
            if report is not None:
                print("\n", report.to_string(index=False))
            else:
                print("\n[INFO] No user accounts match the current criteria.")
        elif choice == "3":
            try:
                print("\nEnter device activity lookback period (in days):")
                print("Only devices with a 'last seen' timestamp within this window will be included.")
                lookback_days = int(input("> ").strip())
                devices_df, users = fetch_and_filter_outdated_devices(api, lookback_days, user_cache=user_cache)
            except ValueError:
                print("[WARN] Invalid input. Please enter a whole number.")
        elif choice == "4":
            r_dev = prepare_report_grouped_by_device(devices_df)
            r_user = prepare_report_grouped_by_user(devices_df, users)
            p_path, u_path = export_outdated_reports(outdir, lookback_days=lookback_days, report_by_device=r_dev, report_by_user=r_user)

            if p_path or u_path:
                print("\n[SUCCESS] Reports exported successfully.\n")
                print("Files created:")
                if p_path:
                    print(f"• {p_path}")
                if u_path:
                    print(f"• {u_path}")
            else:
                print("\n[INFO] Nothing to export for the current criteria.")
        elif choice == "5":
            break
        else:
            print("[WARN] Invalid selection.")


# -----------------------------
# Device Cleanup
# -----------------------------
def compute_cleanup_candidates(
    devices: List[Dict[str, Any]],
    *,
    inactivity_days: int,
    never_used_days: int,
) -> List[Dict[str, Any]]:
    """
    Identifies:
      • Inactive devices: last seen older than inactivity_days
      • Never-used devices: no last seen and created older than never_used_days
    """
    if not devices:
        return []

    now_utc = utc_now()
    inactive_cutoff = now_utc - timedelta(days=inactivity_days)
    never_used_cutoff_ts = (now_utc - timedelta(days=never_used_days)).timestamp()

    df = pd.DataFrame(devices)

    last_seen_dt = pd.to_datetime(df.get("last_seen"), errors="coerce", utc=True)
    df["_last_seen_dt"] = last_seen_dt

    inactive_mask = df["_last_seen_dt"].notna() & (df["_last_seen_dt"] < inactive_cutoff)

    # Ensure created_num is ALWAYS a Series (fixes your crash)
    created_series = df["created"] if "created" in df.columns else pd.Series([None] * len(df), index=df.index)
    created_num = pd.to_numeric(created_series, errors="coerce")

    never_used_mask = (
        df["_last_seen_dt"].isna()
        & created_num.notna()
        & (created_num < never_used_cutoff_ts)
    )

    candidates_df = df[inactive_mask | never_used_mask]
    return candidates_df.drop(columns=["_last_seen_dt"], errors="ignore").to_dict("records")



def export_cleanup_candidates(outdir: Path, *, inactivity_days: int, never_used_days: int, candidates: List[Dict[str, Any]]) -> Optional[Path]:
    if not candidates:
        return None
    stamp = ts_compact()
    path = outdir / f"device_cleanup_candidates_inactive{inactivity_days}_neverused{never_used_days}_{stamp}.csv"
    pd.DataFrame(candidates).to_csv(path, index=False)
    return path


def write_json(outdir: Path, name: str, obj: Any) -> Path:
    path = outdir / name
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
    return path


def device_cleanup_manager(admin_api, outdir: Path):
    inactivity_days = 365
    never_used_days = 365

    # Fetch once per session; refresh is explicit
    device_inventory = fetch_all_devices(admin_api)
    refresh_needed = False

    while True:
        if refresh_needed:
            device_inventory = fetch_all_devices(admin_api)
            refresh_needed = False

        print("\n[INFO] Evaluating devices for inactivity and non-usage using Duo Admin API data...")

        candidates = compute_cleanup_candidates(
            device_inventory,
            inactivity_days=inactivity_days,
            never_used_days=never_used_days,
        )

        print("\n--- DEVICE CLEANUP (DUO ADMIN API) ---")
        print(f"\nDevices identified for cleanup: {len(candidates)}")
        print("\nCurrent criteria:")
        print(f"• Inactive devices: Not seen for more than {inactivity_days} days")
        print(f"• Never-used devices: No 'last seen' timestamp and created more than {never_used_days} days ago")

        print("\nAvailable actions:")
        print("1. Change inactivity threshold")
        print("2. Change never-used device threshold")
        print("3. Export device cleanup candidate list (CSV)")
        print("4. DELETE ALL IDENTIFIED DEVICES (PERMANENT)")
        print("5. Refresh device inventory from Duo")
        print("6. Back to main menu")

        choice = input("\nSelect an option (1-6): ").strip()

        if choice == "1":
            try:
                print("\nEnter inactivity threshold (in days):")
                print("Devices not seen for longer than this period will be flagged as inactive.")
                inactivity_days = int(input("> ").strip())
            except ValueError:
                print("[WARN] Invalid input. Please enter a whole number.")
        elif choice == "2":
            try:
                print("\nEnter never-used device threshold (in days):")
                print("Devices with no 'last seen' value and older than this period will be flagged.")
                never_used_days = int(input("> ").strip())
            except ValueError:
                print("[WARN] Invalid input. Please enter a whole number.")
        elif choice == "3":
            path = export_cleanup_candidates(outdir, inactivity_days=inactivity_days, never_used_days=never_used_days, candidates=candidates)
            if path:
                print(f"\n[SUCCESS] Candidate list exported:\n• {path}")
            else:
                print("\n[INFO] No devices match the current cleanup criteria.")
        elif choice == "4":
            if not candidates:
                print("\n[INFO] No devices match the current cleanup criteria.")
                continue

            print("\n" + "!" * 60)
            print("        CRITICAL WARNING: DEVICE DELETION")
            print("!" * 60)
            print("\nThis operation permanently deletes device records from Duo.\n")
            print("• User accounts are NOT deleted")
            print("• Authentication logs are NOT modified")
            print("• This action cannot be undone\n")
            print(f"You are about to delete {len(candidates)} device records from Duo.\n")
            print("Strongly recommended before proceeding:")
            print("• Export the device list for review")
            print("• Create a JSON backup of all device records\n")

            if input("Export the device list now? (yes/no): ").strip().lower() == "yes":
                path = export_cleanup_candidates(outdir, inactivity_days=inactivity_days, never_used_days=never_used_days, candidates=candidates)
                if path:
                    print(f"[SUCCESS] Candidate list exported:\n• {path}")

            if input("Create a JSON backup of all identified device records before deletion? (yes/no): ").strip().lower() == "yes":
                bname = f"device_cleanup_backup_{ts_compact()}.json"
                bpath = write_json(outdir, bname, candidates)
                print(f"[SUCCESS] JSON backup created:\n• {bpath}")

            print("\nTo confirm permanent deletion, type the following exactly:\n")
            print(f"DELETE {len(candidates)} DEVICES")
            confirm = input("\n> ").strip()

            if confirm != f"DELETE {len(candidates)} DEVICES":
                print("\n[INFO] Confirmation did not match. No devices were deleted.")
                continue

            print("\n[ACTION] Deleting device records via Duo Admin API...")

            failures: List[Dict[str, Any]] = []
            success = 0

            for d in candidates:
                device_id = d.get("phone_id")
                if not device_id:
                    failures.append({"device_id": None, "error": "missing phone_id"})
                    continue

                def _del():
                    return admin_api.json_api_call("DELETE", f"/admin/v1/phones/{device_id}", {})

                try:
                    api_call_with_retry(_del, what=f"DELETE /admin/v1/phones/{device_id}")
                    success += 1
                except Exception as e:
                    failures.append({"device_id": device_id, "error": str(e)})

            print("\n--- DEVICE DELETION SUMMARY ---\n")
            print(f"Devices successfully deleted: {success}")
            print(f"Devices that failed deletion: {len(failures)}")

            if failures:
                fname = f"delete_failures_{ts_compact()}.json"
                fpath = write_json(outdir, fname, failures)
                print("\n[WARN] One or more devices could not be deleted.")
                print("Failure details have been saved to:")
                print(f"• {fpath}")

            # End after a deletion attempt (matches original behavior)
            break

        elif choice == "5":
            refresh_needed = True
            print("\n[INFO] Refresh requested. Device inventory will be reloaded from Duo.")
        elif choice == "6":
            break
        else:
            print("[WARN] Invalid selection.")


# -----------------------------
# Entrypoint
# -----------------------------
def main():
    clear_screen()

    parser = argparse.ArgumentParser(
        description="Duo Admin API Maintenance Tool: Identify outdated Duo Mobile devices and perform device cleanup.",
        epilog="Usage: python script.py -ikey <IKEY> -skey <SKEY> -host <API_HOSTNAME>",
    )
    parser.add_argument("-ikey", "--ikey", required=True, help="Duo Admin API Integration Key (IKEY)")
    parser.add_argument("-skey", "--skey", required=True, help="Duo Admin API Secret Key (SKEY)")
    parser.add_argument("-host", "--host", required=True, help="Duo API hostname (e.g., api-xxxx.duosecurity.com)")
    parser.add_argument("--outdir", default=".", help="Directory for exports/backups (default: current directory)")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    outdir = ensure_outdir(args.outdir)
    api = get_api_client(args.ikey, args.skey, args.host)

    while True:
        print("\n--- DUO ADMIN API MAINTENANCE TOOL ---")
        print("\nSelect an operation:\n")
        print("1. Identify Active Devices Running Outdated Duo Mobile")
        print("2. Identify and Delete Inactive or Never-Used Devices")
        print("3. Exit")

        choice = input("\nSelect an option (1-3): ").strip()

        if choice == "1":
            outdated_duo_mobile_manager(api, outdir)
        elif choice == "2":
            device_cleanup_manager(api, outdir)
        elif choice == "3":
            break
        else:
            print("[WARN] Invalid selection.")


if __name__ == "__main__":
    main()
