param (
    [string]$UserPrincipalName,
    [string]$UPN,
    [string]$User
)

# Ensure only one parameter is used
$UserInputs = @($UserPrincipalName, $UPN, $User) | Where-Object { $_ -ne $null }

if ($UserInputs.Count -eq 0) {
    Write-Host "Error: Please provide a User Principal Name using -UserPrincipalName, -UPN, or -User."
    Write-Host "Example: ./script.ps1 -User user@yourdomain.com"
    Exit
}

if ($UserInputs.Count -gt 1) {
    Write-Host "Error: Please specify only one of -UserPrincipalName, -UPN, or -User."
    Exit
}

# Assign the validated input to a single variable
$UserPrincipalName = $UserInputs[0]

# Install Microsoft Graph module if not already installed
if (!(Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Import Microsoft Graph module
Import-Module Microsoft.Graph

# Connect to Microsoft Graph (ensure you have the necessary permissions)
Connect-MgGraph -Scopes "User.Read.All", "MailboxSettings.ReadWrite"

# Define static rule variables
$XAttributeName = "extensionAttributeX"  # Change this if needed to match the actual Entra ID attribute
$RuleName = "Forward Duo Enrollment Emails"
$FromAddress = "no-reply@duosecurity.com"
$SubjectContains = "Duo Security Enrollment"
$BodyContains = "Your organization invites you to set up a user account for Duo."

# Get the user's personal email from the "x" attribute
$User = Get-MgUser -UserId $UserPrincipalName -Property $XAttributeName
$PersonalEmail = $User.$XAttributeName

if (-not $PersonalEmail) {
    Write-Host "No personal email found in '$XAttributeName' for $UserPrincipalName"
    Exit
}

Write-Host "Personal email found: $PersonalEmail"

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

Write-Host "Email forwarding rule created successfully for $UserPrincipalName."
