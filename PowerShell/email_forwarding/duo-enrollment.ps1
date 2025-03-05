param (
    [string]$UserPrincipalName,
    [string]$UPN,
    [string]$User
)

# Ensure only one parameter is used
$UserInputs = @($UserPrincipalName, $UPN, $User) | Where-Object { $_ -ne $null }

if ($UserInputs.Count -eq 0) {
    Write-Host "Error: Please provide a User Principal Name using -UserPrincipalName, -UPN, or -User."
    Write-Host "Example: ./duo-enrollment.ps1 -User user@yourdomain.com"
    Exit
}

if ($UserInputs.Count -gt 1) {
    Write-Host "Error: Please specify only one of -UserPrincipalName, -UPN, or -User."
    Exit
}

# Assign the validated input to a single variable
$UserPrincipalName = $UserInputs[0]

# Check if Microsoft Graph module is installed
if (!(Get-Module -ListAvailable -Name Microsoft.Graph)) {
    $install = Read-Host "Microsoft Graph module is not installed. Would you like to install it now? (Y/N)"
    if ($install -match "[Yy]") {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    } else {
        Write-Host "Microsoft Graph module is required. Exiting script."
        Exit
    }
}

# Import Microsoft Graph module
Import-Module Microsoft.Graph

# Check if already connected to Microsoft Graph
try {
    Get-MgUser -Top 1 | Out-Null
} catch {
    Write-Host "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "User.Read.All", "MailboxSettings.ReadWrite"
}

# Define static rule variables
$XAttributeName = "extensionAttributeX"  # Change this if needed to match the actual Entra ID attribute
$RuleName = "Duo: Forward enrollment emails"
$FromAddress = "no-reply@duosecurity.com"
$SubjectContains = "Duo Security Enrollment"
$BodyContains = "Your organization invites you to set up a user account for Duo."

# Get the user's personal email from the "x" attribute
$User = Get-MgUser -UserId $UserPrincipalName -Property $XAttributeName
$PersonalEmail = $User.$XAttributeName

if (-not $PersonalEmail) {
    Write-Host "Error: No personal email found in '$XAttributeName' for $UserPrincipalName."
    Exit
}

Write-Host "Personal email found: $PersonalEmail"

# Check if the rule already exists
$ExistingRules = Get-MgUserMailFolderMessageRule -UserId $UserPrincipalName -MailFolderId "Inbox"
$ExistingRule = $ExistingRules | Where-Object { $_.DisplayName -eq $RuleName }

if ($ExistingRule) {
    Write-Host "A rule named '$RuleName' already exists for $UserPrincipalName. Updating rule..."
    Remove-MgUserMailFolderMessageRule -UserId $UserPrincipalName -MailFolderId "Inbox" -MessageRuleId $ExistingRule.Id
    Start-Sleep -Seconds 2  # Wait briefly to ensure the old rule is deleted
}

# Define rule parameters
$InboxRule = @{
    DisplayName = $RuleName
    IsEnabled = $true
    Conditions = @{
        SenderContains = @($FromAddress)
        SubjectContains = @($SubjectContains)
        BodyContains = @($BodyContains)
    }
    Actions = @{
        ForwardTo = @($PersonalEmail)
        StopProcessingRules = $true
    }
}

# Apply the rule to the user's mailbox
New-MgUserMailFolderMessageRule -UserId $UserPrincipalName -MailFolderId "Inbox" -Body $InboxRule

Write-Host "Email forwarding rule '$RuleName' created or updated successfully for $UserPrincipalName."
