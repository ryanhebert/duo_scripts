# Duo Enrollment Email Forwarding Rule

## Overview
This PowerShell script retrieves a user's personal email address from a custom "x" attribute in **Entra ID (Azure AD)** and creates or updates an **inbox rule** in **Exchange Online** that forwards Duo enrollment emails to the user's personal email.

## Features
- Retrieves the user's personal email from the `x` attribute in **Entra ID**.
- Creates or updates an **email forwarding rule** in the user's Exchange **Inbox Rules**.
- Prevents duplicate rules by removing an existing rule before applying a new one.
- Checks for Microsoft Graph PowerShell module installation and prompts for installation if missing.
- Automatically connects to Microsoft Graph if not already connected.
- Forwards emails that match the following conditions:
  - **Sender:** `no-reply@duosecurity.com`
  - **Subject Contains:** `Duo Security Enrollment`
  - **Body Contains:** `Your organization invites you to set up a user account for Duo.`

## Prerequisites
### 1. Install the Microsoft Graph PowerShell Module
If you haven't installed the **Microsoft Graph** module, the script will prompt you to install it. Alternatively, you can install it manually by running:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### 2. Permissions
The script requires Microsoft Graph API permissions:
- `User.Read.All`
- `MailboxSettings.ReadWrite`

To sign in with the necessary permissions, use:
```powershell
Connect-MgGraph -Scopes "User.Read.All", "MailboxSettings.ReadWrite"
```

### 3. Exchange Online Mailbox
Ensure the target user has a **Microsoft Exchange Online mailbox**.

## Usage
### 1. Run the Script
```powershell
.\duo-enrollment.ps1 -UserPrincipalName user@yourdomain.com
```
Alternatively, you can use:
```powershell
.\duo-enrollment.ps1 -UPN user@yourdomain.com
```
or
```powershell
.\duo-enrollment.ps1 -User user@yourdomain.com
```
**Note:** Only one of `-UserPrincipalName`, `-UPN`, or `-User` should be used at a time.

### 2. Verify Rule Creation
To check if the rule was successfully applied:
```powershell
Get-MgUserMailFolderMessageRule -UserId "user@yourdomain.com" -MailFolderId "Inbox"
```

## Removing the Rule
To remove the forwarding rule, run:
```powershell
$RuleName = "Duo: Forward enrollment emails"
$Rules = Get-MgUserMailFolderMessageRule -UserId "user@yourdomain.com" -MailFolderId "Inbox"
$RuleToRemove = $Rules | Where-Object { $_.DisplayName -eq $RuleName }

if ($RuleToRemove) {
    Remove-MgUserMailFolderMessageRule -UserId "user@yourdomain.com" -MailFolderId "Inbox" -MessageRuleId $RuleToRemove.Id
    Write-Host "Rule '$RuleName' removed successfully."
} else {
    Write-Host "No rule found with the name '$RuleName'."
}
```

## Troubleshooting
### Error: `No personal email found in 'x' attribute`
- Ensure the `x` attribute is correctly set in Entra ID.
- Run `Get-MgUser -UserId "user@yourdomain.com" -Property extensionAttributeX` to check if the attribute exists.

### Error: `Insufficient permissions`
- Ensure you're signed in with an **admin account** with permissions to modify mailbox settings.
- Reconnect with `Connect-MgGraph -Scopes "User.Read.All", "MailboxSettings.ReadWrite"`.

### Error: `Microsoft Graph module not installed`
- The script will prompt for installation, but you can also install it manually using:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

## License
This script is open-source and can be modified as needed.

## Contact
For questions or improvements, feel free to reach out!
