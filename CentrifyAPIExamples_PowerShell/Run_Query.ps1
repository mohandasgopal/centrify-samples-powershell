#Run Query in PowerScript
#Created by Nick Gamb (nick.gamb@centrify.com)
#Verion 1.0

#INSTALL#
# "Set-ExecutionPolicy Unrestricted" Must be set using the following PowerShell Management Shells run as Administrator
# C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#Can be ran from ISE
#Commandline Syntax .\Run_Query.ps1 -server "pod.centrify.com" -username "username" -password "password" -ReportQuery "SQLQuery"
#Param Will retrieve default variables if not in command line. If Variables are set in commandline, defaults will not be used.

param (
    #Main Variables 
    [string]$server = "pod.centrify.com/",
    [string]$username = "admin@domain",
    [string]$password = "AdminPass",
    [string]$ReportQuery = "SELECT * FROM CDUser",
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

#Used for all SQL Queries
Function RunQuery($Auth, $Query)
{
    $QueryHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Authorization" = "Bearer " + $Auth}
    $QueryJson = $Query

    $ExicuteQuery = Invoke-RestMethod -Method Post -Uri "https://$server/RedRock/query" -Body $QueryJson -ContentType $ContentType -Headers $QueryHeaders 

    Write-Host "Query Success = $ExicuteQuery.success"
    Write-Host $ExicuteQuery.MessageID

    return $ExicuteQuery.result
}


#Main Implementations#
Write-Host "Running Query"

$AuthToken = Login

if ($AuthToken -ne "")
{
    $QueryResult = RunQuery $AuthToken "{""Script"":""$ReportQuery""}"

    $ReportBody = ""

    foreach ($result in $QueryResult)
    {
        foreach ($row in $result.Results)
        {
            $ReportBody = $ReportBody + $row.Row           
        }
    }

    Write-Host "Final Query Is:"

    Write-Host "$ReportBody" 
}
else
{
	Write-Host "Error: ASPXAuth token was null"
}






