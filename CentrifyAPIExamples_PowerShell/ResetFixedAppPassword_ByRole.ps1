#UpdateFixedAppPassword_ByRole in PowerScript
#Created by Nick Gamb (nick.gamb@centrify.com)
#Verion 1.0

#INSTALL#
# "Set-ExecutionPolicy Unrestricted" Must be set using the following PowerShell Management Shells run as Administrator
# C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#Can be ran from ISE
#Commandline Syntax .\UpdateFixedAppPassword_ByRole.ps1 -server "pod.centrify.com" -username "username" -password "password"
#Param Will retrieve default variables if not in command line. If Variables are set in commandline, defaults will not be used.

param (
    #Main Variables 
    [string]$server = "pod.centrify.com",
    [string]$username = "adminuser@domain.com",
    [string]$password = "AdminPass",
    [string]$ContentType = "application/json"
 )

#API FUNCTIONS#

#Login is required for all other rest calls to get auth token
Function Login()
{ 
    $LoginJson = "{user:'$username', password:'$password'}"
    $LoginHeader = @{"X-CENTRIFY-NATIVE-CLIENT"="1"}
    $Login = invoke-WebRequest -Uri "https://$server/security/login" -ContentType $ContentType -Method Post -Body $LoginJson -SessionVariable websession -UseBasicParsing

    $cookies = $websession.Cookies.GetCookies("https://$server/security/login") 

    $ASPXAuth = $cookies[".ASPXAUTH"].value
    return $ASPXAuth
}

#Get Apps By Role
Function GetAppsByRole($Auth, $Role)
{   
    $GetAppsHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Authorization" = "Bearer " + $Auth}
    $GetAppsByRole = Invoke-RestMethod -Method Get -Uri "https://$server/SaasManage/GetRoleApps?role=$Role" -ContentType $ContentType -Headers $GetAppsHeaders

    Write-Host $GetAppsByRole.result

    return $GetAppsByRole.result

}

#Update App
Function UpdateApp($Auth, $AppKey, $NewUser, $NewPass)
{   
    $UpdateAppJson = "{""UserNameStrategy"":""Fixed"",""Password"":""$NewPass"",""UserNameArg"":""$NewUser""}"
    Write-Host $Auth

    $UpdateAppHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Authorization" = "Bearer " + $Auth}
    $UpdateApp = Invoke-RestMethod -Method Post -Uri "https://$server/saasManage/UpdateApplicationDE?_RowKey=$AppKey" -Body $UpdateAppJson -ContentType $ContentType -Headers $UpdateAppHeaders

    Write-Host $UpdateApp.result

    return $UpdateApp.result

}

#Main Implementations#

$Role = "test"

Write-Host "Getting Apps For Role" + $Role

$AuthToken = Login

if ($AuthToken -ne "")
{

	$Apps = GetAppsByRole $AuthToken $Role

	Write-Host "Applications Gathered"
	Write-Host $Apps.Results

	#To Add To An Array
	#$AppKeys = @()

	$NewUserName = "newUser1@domain.com"
	$NewUserPassword = "NewPass1"

	foreach ($app in $Apps.Results)
	{
		#To Add To An Array
		#$AppKeys += ,@($app.Row.ID)
		$AuthToken = Login
		UpdateApp $AuthToken $app.Row.ID $NewUserName $NewUserPassword
	}
}
else
{
	Write-Host "Error: ASPXAuth token was null"
}







