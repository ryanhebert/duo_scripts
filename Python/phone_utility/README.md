Cisco Duo Admin Maintenance Tool

A powerful, Python-based CLI utility for Cisco Duo administrators. This tool simplifies the management of mobile devices by identifying outdated Duo Mobile app versions, generating user-centric audit reports, and performing automated cleanup of inactive or unactivated devices.


🚀 Features

1. Expired Phones Reporting

Phone-Centric View: Lists every outdated device, its last seen date, and the assigned users.
User-Centric View: Groups outdated devices by user, including the user's email and phone numbers for direct outreach.
Version Filtering: Automatically targets devices running Duo Mobile versions older than 4.85.0.
Activity Filtering: Filter reports based on a customizable "last seen" lookback period (Default: 365 days).

2. Device Cleanup Utility

Inactive Cleanup: Identify and delete devices that haven't been seen by Duo in a specified number of days.
Stale New Device Cleanup: Automatically targets "ghost" devices—those created more than 30 days ago that have never performed an authentication.
Safety First:
JSON Backups: Generates a full attribute backup of all devices before deletion.
Audit Exports: Export a list of cleanup candidates to CSV for review before pulling the trigger.
Two-Stage Confirmation: Requires a manual challenge string entry to execute deletions.

3. High Efficiency

Pagination Support: Handles large environments with more than 500+ devices.
Targeted Fetching: Only requests user profiles for the specific devices that are outdated, significantly reducing API overhead.


🛠 Prerequisites

Python 3.9+
Duo Admin API Credentials: An API application with Grant read information, Grant write information, and Grant read resource permissions.
Required Libraries:
bash
Copy Code
pip install duo_client pandas packaging


💻 Usage

The script uses command-line arguments for secure credential handling.


Starting the Tool

bash
Copy Code
python phone_utility.py -ikey <YOUR_IKEY> -skey <YOUR_SKEY> -host <YOUR_API_HOSTNAME>

Command Line Arguments

Flag	Description
-ikey	Duo Admin API Integration Key
-skey	Duo Admin API Secret Key
-host	Duo API Hostname (e.g., api-xxxx.duosecurity.com)
--help	Displays the help menu and usage instructions


📖 Menu Navigation

Main Menu

Expired Phones Report: Enter the reporting sub-menu.
DEVICE CLEANUP UTILITY: Enter the cleanup sub-menu.
Exit: Close the application.

Cleanup Sub-Menu

Change Thresholds: Adjust the days of inactivity required to flag a device.
Export Candidate List: Save a CSV of exactly what the tool intends to delete.
DELETE PHONES: Begins the deletion process (includes backup and confirmation steps).


🔒 Security Best Practices

Credential Safety: Never hardcode your skey inside the script. This tool is designed to take credentials via CLI flags to keep the source code clean.
API Permissions: Ensure your Duo Admin API key is restricted to the minimum permissions required.
Environment: Run this script in a secure environment. Be aware that some terminal shells store command history in plain text (e.g., ~/.bash_history). Clear your history or use environment variables if working on shared machines.


📄 License

This project is intended for internal administrative use. Please ensure compliance with your organization's data retention and device management policies before performing bulk deletions.


Disclaimer: This tool is not an official Cisco Duo product. Always perform a backup before executing cleanup operations.

