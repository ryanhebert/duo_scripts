$group = "Hebert Pets"
$emailDomain = "lab21.ryan.am"
$property = "wWWHomePage"

$users = Get-ADGroupMember -Identity $group -Recursive

foreach ($user in $users){

    $userProperties = Get-ADUser -Identity $user -Properties *

    if($userProperties.mail) {
        Write-Host $userProperties.samaccountname ": User already has an email value in the 'mail' attribute."
    }
    else {

        $oldValue = $userProperties | Select-Object -ExpandProperty $property
        $newValue = $userProperties.SamAccountName + "@" + $emailDomain
        
        if($oldValue -eq $newValue){
        
            Write-Host $userProperties.samaccountname ": User already has an email value in the '$property' attribute."
        }

        elseif( Get-ADUser -LDAPFilter "(|($property=$newValue)(mail=$newValue))"){

            Write-Host $userProperties.samaccountname ": Another user is identified as '$newValue'"
        }

        else{
            if($oldValue){
                Set-ADUser -Identity $user -Replace @{$property=$oldValue}
                Write-Host $userProperties.samaccountname ": Changed $property from '$oldValue' to '$newValue'"
            }
            else{
                Set-ADUser -Identity $user -Add @{$property=$newValue}
                Write-Host $userProperties.samaccountname ": Set attribute '$property' to '$newValue'"
            }
            
        }
    }
} 
