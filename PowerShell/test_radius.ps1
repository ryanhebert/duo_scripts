###################################################################
# This code is a sample meant to be a template or starting point. #
# It is not official and shouldn't be used in production without  #
# being reviewed by a qualified engineer.                         #
###################################################################

$I_Agree = $true
if($I_Agree)
{
    Write-Host "`n😊 😊 😊 😊 😊 😊`n" -ForegroundColor Yellow
    Write-Host "So it begins..." -ForegroundColor Green -BackgroundColor Black
    Write-Host "`n😊 😊 😊 😊 😊 😊`n" -ForegroundColor Yellow
}
else
{
    Write-Host "`nYou must review the code before running it.`n" -ForegroundColor White -BackgroundColor DarkRed
    exit
} 

###################################################################

$radius_host = 'CHANGE_ME'
$radius_secret = 'CHANGE_ME'

$creds = Get-Credential  -Message 'Please authenticate with your Duo test user.'
 
$Radius_installed = [appdomain]::CurrentDomain.GetAssemblies() | foreach {$_.Fullname.Split(",")[0]} | where{$_ -eq 'Radius'}
 
if(!$Radius_installed){
 
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 
    $NuGet_registered = Get-PackageSource | foreach {$_} | where{$_.ProviderName -eq 'NuGet'}
     
    if(!$NuGet_registered){
        Install-PackageProvider -Name NuGet -Force
        Register-PackageSource -Name Duo-NuGet -Location https://www.nuget.org/api/v2 -ProviderName NuGet
    }
 
    $install_path = $env:USERPROFILE + '\.net\'
    Install-Package -Name Radius -ProviderName NuGet -RequiredVersion 2.0.0.2 -Destination $install_path -Force
 
    $radius_path = $install_path + "\Radius.2.0.0.2\lib\net45\Radius.dll"
    [System.Reflection.Assembly]::LoadFrom($radius_path)
}
 
$radius_session = New-Object -TypeName FP.Radius.RadiusClient $radius_host,$radius_secret

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($creds.Password)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$auth_packet = $radius_session.Authenticate($creds.UserName,$password)

 
$radius_test = $radius_session.SendAndReceivePacket($auth_packet).Result

if($radius_test){ $radius_test }
else{"radius failed"} 
