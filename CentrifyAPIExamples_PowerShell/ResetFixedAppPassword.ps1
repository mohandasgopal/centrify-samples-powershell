#UpdateFixedAppPassword in PowerScript
#Created by Nick Gamb (nick.gamb@centrify.com)
#Verion 1.0

#INSTALL#
# "Set-ExecutionPolicy Unrestricted" Must be set using the following PowerShell Management Shells run as Administrator
# C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#Can be ran from ISE
#Commandline Syntax .\UpdateFixedAppPassword.ps1 -server "pod.centrify.com" -username "username" -password "password" -appkey "AppKey" -newpass "NewPass" 
#Param Will retrieve default variables if not in command line. If Variables are set in commandline, defaults will not be used.

param (
    #Main Variables 
    [string]$server = "pod.centrify.com",
    [string]$username = "admin@domain.com",
    [string]$password = "AdminPass",
    [string]$appkey = "28252b66-ead9-4750-89bf-a35a1a091e78",
    [string]$newpass = "Test123",
    [string]$ContentType = "application/json"
 )

#API FUNCTIONS#

#Login is required for all other rest calls to get auth token
Function Login()
{ 
    $LoginJson = "{user:'$username', password:'$password'}"
    $LoginHeader = @{"X-CENTRIFY-NATIVE-CLIENT"="1"}
    $Login = Invoke-RestMethod -Method Post -Uri "https://$server/security/login" -Body $LoginJson -ContentType $ContentType -Headers $LoginHeader

    Write-Host $Login.Result.Auth

    return $Login.Result.Auth
    
}

#Update App
Function UpdateApp($Auth, $AppKey, $NewPass)
{   
    $UpdateAppJson = "{""UserNameStrategy"":""Fixed"",""Password"":""$NewPass""}"
    Write-Host $Auth

    $UpdateAppHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Auth" = $Auth}
    $UpdateApp = Invoke-RestMethod -Method Post -Uri "https://$server/saasManage/UpdateApplicationDE?_RowKey=$AppKey" -Body $UpdateAppJson -ContentType $ContentType -Headers $UpdateAppHeaders

    Write-Host $UpdateApp.result

    return $UpdateApp.result

}

#Main Implementations#

Write-Host "Resetting Password for App" + $appkey

$AuthToken = Login
UpdateApp $AuthToken $appkey $newpass










