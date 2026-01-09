import duo_client
import os
import pandas as pd
import json
import argparse
import sys
from packaging import version
from datetime import datetime, timedelta, timezone

# --- GLOBAL CONFIGURATION ---
TARGET_APP_VERSION = "4.85.0" 
DEFAULT_LOOKBACK = 365  

def get_api_client(ikey, skey, host):
    """Initializes the Duo Admin API client."""
    try:
        return duo_client.Admin(ikey=ikey, skey=skey, host=host)
    except Exception as e:
        print(f"[Error] Failed to initialize Duo Client: {e}")
        sys.exit(1)

def is_outdated(v):
    """Checks if a version string is lower than the target version."""
    if pd.isna(v) or not v or v == 'N/A': return False 
    try: return version.parse(str(v)) < version.parse(TARGET_APP_VERSION)
    except: return False

def fetch_and_filter_data(admin_api, days_to_look_back):
    """Fetches phones, filters them, then fetches ONLY relevant users in batches of 100."""
    print(f"\n[System] Fetching phones seen within the last {days_to_look_back} days...")
    all_phones = []
    offset, limit = 0, 500
    while True:
        batch = admin_api.get_phones(limit=str(limit), offset=str(offset))
        if not batch: break
        all_phones.extend(batch)
        offset += limit
        if len(batch) < limit: break

    df_phones = pd.DataFrame(all_phones)
    now_utc = datetime.now(timezone.utc)
    cutoff_date = now_utc - timedelta(days=days_to_look_back)

    df_phones['last_seen_dt'] = pd.to_datetime(df_phones['last_seen'], errors='coerce', utc=True)
    df_phones['days_since_seen_val'] = (now_utc - df_phones['last_seen_dt']).dt.days
    
    # Filter for outdated and active (seen within window)
    version_mask = df_phones['app_version'].apply(is_outdated)
    date_mask = (df_phones['last_seen_dt'] >= cutoff_date) & (df_phones['last_seen_dt'].notna())
    
    filtered_phones_df = df_phones[version_mask & date_mask].copy()

    unique_usernames = set()
    for _, phone in filtered_phones_df.iterrows():
        users_on_phone = phone.get('users', [])
        if isinstance(users_on_phone, list):
            for user_entry in users_on_phone:
                uname = user_entry.get('username')
                if uname: unique_usernames.add(uname)
    
    username_list = list(unique_usernames)
    outdated_users = []
    if username_list:
        print(f"[System] Requesting profiles for {len(username_list)} users...")
        for i in range(0, len(username_list), 100):
            chunk = username_list[i:i + 100]
            params = {'username_list': json.dumps(chunk)}
            try:
                user_batch = admin_api.json_api_call('GET', '/admin/v1/users', params)
                outdated_users.extend(user_batch)
            except Exception as e:
                print(f"Error fetching user batch: {e}")

    return filtered_phones_df, outdated_users

def prepare_phone_report(filtered_phones_df):
    if filtered_phones_df.empty: return None
    df = filtered_phones_df.copy()
    df['assigned_users'] = df['users'].apply(
        lambda x: ", ".join([u.get('username') for u in x]) if isinstance(x, list) else "Unassigned"
    )
    df['last_seen_display'] = df['last_seen_dt'].dt.strftime('%Y-%m-%d')
    df['days_since_seen'] = df['days_since_seen_val'].apply(lambda x: str(int(x)))
    cols = ['phone_id', 'assigned_users', 'number', 'platform', 'os_version', 'model', 'last_seen_display', 'days_since_seen', 'app_version']
    return df[cols].rename(columns={'last_seen_display': 'last_seen'})

def prepare_user_report(filtered_phones_df, outdated_users):
    if filtered_phones_df.empty or not outdated_users: return None
    phone_lookup = {}
    for _, p in filtered_phones_df.iterrows():
        seen_str = p['last_seen_dt'].strftime('%Y-%m-%d')
        days_str = str(int(p['days_since_seen_val']))
        phone_lookup[p['phone_id']] = {
            'id': p['phone_id'], 'num': p.get('number', 'N/A'),
            'os': p.get('os_version', 'N/A'), 'ver': p.get('app_version', 'N/A'),
            'seen': seen_str, 'days': days_str
        }
    user_rows = []
    for u in outdated_users:
        row = {'username': u.get('username'), 'realname': u.get('realname'), 'email': u.get('email')}
        match_count = 0
        for p_summary in u.get('phones', []):
            p_meta = phone_lookup.get(p_summary.get('phone_id'))
            if p_meta:
                match_count += 1
                pre = f"P{match_count}_"
                row.update({f"{pre}num": p_meta['num'], f"{pre}id": p_meta['id'], f"{pre}os": p_meta['os'], f"{pre}seen": p_meta['seen'], f"{pre}days": p_meta['days'], f"{pre}ver": p_meta['ver']})
        if match_count > 0: user_rows.append(row)
    return pd.DataFrame(user_rows).fillna('-') if user_rows else None

def expired_phones_manager(api):
    current_lookback = DEFAULT_LOOKBACK
    filtered_phones, outdated_users = fetch_and_filter_data(api, current_lookback)

    while True:
        print(f"\n--- EXPIRED PHONES REPORT (Lookback: {current_lookback} days) ---")
        print("1. View Phone-Centric Report")
        print("2. View User-Centric Report")
        print("3. Change Lookback Period")
        print("4. Export Both Reports to CSV")
        print("5. Return to Main Menu")
        
        choice = input("\nSelect an option (1-5): ")
        
        if choice == '1':
            report = prepare_phone_report(filtered_phones)
            if report is not None: print("\n", report.to_string(index=False))
            else: print("\nNo data found.")
        elif choice == '2':
            report = prepare_user_report(filtered_phones, outdated_users)
            if report is not None: print("\n", report.to_string(index=False))
            else: print("\nNo data found.")
        elif choice == '3':
            try:
                current_lookback = int(input("Enter new lookback period: "))
                filtered_phones, outdated_users = fetch_and_filter_data(api, current_lookback)
            except ValueError: print("Invalid input.")
        elif choice == '4':
            p_report = prepare_phone_report(filtered_phones)
            u_report = prepare_user_report(filtered_phones, outdated_users)
            if p_report is not None: p_report.to_csv('outdated_phones.csv', index=False)
            if u_report is not None: u_report.to_csv('outdated_users.csv', index=False)
            print("[Success] Reports exported.")
        elif choice == '5':
            break

def cleanup_manager(admin_api):
    inactivity_days = 365
    stale_days = 365
    
    while True:
        print(f"\n[System] Scanning for cleanup candidates...")
        all_phones = []
        offset, limit = 0, 500
        while True:
            batch = admin_api.get_phones(limit=str(limit), offset=str(offset))
            if not batch: break
            all_phones.extend(batch)
            offset += limit
            if len(batch) < limit: break

        now_utc = datetime.now(timezone.utc)
        inactive_cutoff = now_utc - timedelta(days=inactivity_days)
        stale_cutoff_ts = (now_utc - timedelta(days=stale_days)).timestamp()
        
        to_delete = []
        for p in all_phones:
            last_seen_str = p.get('last_seen')
            created_ts = p.get('created')
            if last_seen_str:
                ls_dt = pd.to_datetime(last_seen_str, errors='coerce', utc=True)
                if pd.notna(ls_dt) and ls_dt < inactive_cutoff: to_delete.append(p)
            elif created_ts and created_ts < stale_cutoff_ts:
                to_delete.append(p)

        print(f"\n--- CLEANUP MENU (Candidates: {len(to_delete)}) ---")
        print(f"Current Thresholds: Inactive > {inactivity_days} days | Stale New > {stale_days} days")
        print("1. Change Inactivity Threshold")
        print("2. Change Stale (Never Seen) Threshold")
        print("3. Export Candidate List (CSV)")
        print("4. DELETE PHONES")
        print("5. Return to Main Menu")
        
        choice = input("\nSelect an option (1-5): ")

        if choice == '1':
            try: inactivity_days = int(input("Enter threshold (days): "))
            except ValueError: print("Invalid input.")
        elif choice == '2':
            try: stale_days = int(input("Enter threshold (days): "))
            except ValueError: print("Invalid input.")
        elif choice == '3':
            if to_delete:
                pd.DataFrame(to_delete).to_csv('cleanup_candidates.csv', index=False)
                print("[Success] Exported to cleanup_candidates.csv")
            else: print("No candidates.")
        elif choice == '4':
            if not to_delete: continue
            print("\n" + "!"*60 + "\n      CRITICAL WARNING: PERMANENT DATA DELETION\n" + "!"*60)
            if input("\nCreate JSON backup? (yes/no): ").lower() == 'yes':
                fname = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(fname, 'w') as f: json.dump(to_delete, f, indent=4)
                print(f"[Backup] Saved to {fname}")
            if input(f"\nType 'DELETE {len(to_delete)} PHONES' to confirm: ") == f"DELETE {len(to_delete)} PHONES":
                success = 0
                for p in to_delete:
                    try:
                        admin_api.json_api_call('DELETE', f'/admin/v1/phones/{p["phone_id"]}', {})
                        success += 1
                    except Exception as e: print(f"Error: {e}")
                print(f"\n[Success] {success} devices removed.")
                break 
        elif choice == '5':
            break

def main():
    parser = argparse.ArgumentParser(
        description="Cisco Duo Admin Maintenance Tool: Manage outdated devices and perform directory cleanup.",
        epilog="Usage: python script.py -ikey <IKEY> -skey <SKEY> -host <API_HOSTNAME>"
    )
    parser.add_argument("-ikey", "--ikey", required=True, help="Duo Admin API Integration Key (IKEY)")
    parser.add_argument("-skey", "--skey", required=True, help="Duo Admin API Secret Key (SKEY)")
    parser.add_argument("-host", "--host", required=True, help="Duo API Hostname (e.g., api-xxxx.duosecurity.com)")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    api = get_api_client(args.ikey, args.skey, args.host)
    
    while True:
        print(f"\n--- DUO ADMIN TOOL MAIN MENU ---")
        print("1. Expired Phones Report")
        print("2. DEVICE CLEANUP UTILITY")
        print("3. Exit")
        
        choice = input("\nSelect an option (1-3): ")
        if choice == '1': expired_phones_manager(api)
        elif choice == '2': cleanup_manager(api)
        elif choice == '3': break
        else: print("Invalid selection.")

if __name__ == "__main__":
    main()
