$radius_host = 'CHANGE ME - IP of AuthProxy Server'
$radius_secret = 'CHANGE ME'
$ad_username = 'CHANGE ME - test user'
$ad_password = 'Change ME - test user password'
 
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
$auth_packet = $radius_session.Authenticate($ad_username,$ad_password)
 
$radius_test = $radius_session.SendAndReceivePacket($auth_packet).Result
$radius_test
