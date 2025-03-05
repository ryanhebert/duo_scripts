# Email Forwarding Rule via PowerShell

## Overview
This PowerShell script retrieves a user's personal email address from a custom "x" attribute in **Entra ID (Azure AD)** and creates an **inbox rule** in **Exchange Online** that forwards emails matching specific conditions to the user's personal email.

## Features
- Retrieves the user's personal email from the `x` attribute in **Entra ID**.
- Creates an **email forwarding rule** in the user's Exchange **Inbox Rules**.
- Forwards emails that match the following conditions:
  - **Sender:** `x@x.com`
  - **Subject Contains:** `welcome to x`
  - **Body Contains:** `hi from x`
- **No expiration logic**—the rule stays active unless manually removed.

## Prerequisites
### 1. Install the Microsoft Graph PowerShell Module
If you haven't installed the **Microsoft Graph** module, run:
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
### 1. Modify Script Variables
Edit the script and update the following:
- **UserPrincipalName** → The target user's email (e.g., `user@yourdomain.com`)
- **XAttributeName** → The custom attribute storing the user's personal email
- **Forwarding Conditions** → Modify sender, subject, or body filters as needed

### 2. Run the Script
```powershell
.\duo-enrollment.ps1
```

### 3. Verify Rule Creation
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

## License
This script is open-source and can be modified as needed.

## Contact
For questions or improvements, feel free to reach out!

