 # User defined variables
$attribute = "msDS-cloudExtensionAttribute1"
$admin_prefix = "adm_"

# Change to $true to add simple logging
$log_file = $false

# Limit changes to a specific group of users
$admin_group = ""

# Script defined variables
$filter = 'sAMAccountName -like "' + $admin_prefix + '*"'

if($admin_group)
{
    try
    {
        $group = (Get-ADGroup -Identity $admin_group).distinguishedName
        $filter += ' -AND Memberof -eq $group'
    }
    catch
    {
        Write-Host "Error fetching group '$admin_group'."
        exit
    }
}
    

# Get a list of all admins that match the admin prfix #'sAMAccountName -like $filter'
$admins = Get-ADUser -Filter $filter


$skipped_users = @()
$updated_users = @()
$not_found = @()

foreach ($admin in $admins) {
    try
    {
        $sam = ($admin.SamAccountName -split $admin_prefix)[1]
        $user = Get-ADUser -Identity $sam -Properties $attribute
    
        # Check to see if the user already has a difined value for the specified attribute.
    
        if($user.$attribute){ # Skip user if attribute has value
            $skipped_users += $user
        } else{
            $user | Add-Member -Force -NotePropertyMembers @{AdminSamAccountName=$admin.SamAccountName}
            $updated_users += $user # Update user if attribute is blank
        }
    }
    catch
    {
        $not_found += $admin
        #Write-Host "Couldn't find corresponding user for '$($admin.SamAccountName)'."
    }
}

#Clear-Host

if($updated_users)
{
    Write-Host "`nThe following users will be updated:`n" -ForegroundColor White -BackgroundColor DarkGreen
    $updated_users | Format-Table Name,SamAccountName, userprincipalname, $attribute -A
}
if($skipped_users)
{
    Write-Host "`nThe following users will be skipped because the attribute already exists:`n" -ForegroundColor White -BackgroundColor DarkRed
    $skipped_users | Format-Table Name,SamAccountName, userprincipalname, $attribute -A
}
if($not_found)
{
    Write-Host "`nThe following admins don't have corresponding users:`n" -ForegroundColor White -BackgroundColor DarkRed
    $not_found | Format-Table Name,SamAccountName, userprincipalname, $attribute -A
}

if($updated_users) {

    $Consent = Read-Host -Prompt 'Type "UPDATE" to update users'
    if($Consent -eq "UPDATE"){

        if($log_file)
        {
            $file = "log-$(Get-Date -Format "yyyyMMddHHmmss").txt"
            New-Item $file | Out-Null
        }


        foreach($user in $updated_users)
        {
            Set-ADUser -Identity $user.SamAccountName -Replace @{$attribute=$user.AdminSamAccountName}
            if($log_file)
            {
                Add-Content $file "user=$($user.SamAccountName), $($attribute)=$($user.AdminSamAccountName)"
            }
        }

        Write-Host `n $updated_users.Length "users have been updated.`n"
    }
    else{Write-Host "`nNo changes were made.`n"}
} else{Write-Host "`nNo changes were made.`n"} 
