#Federate Multiple O365 Domains in PowerScript
#Created by Nick Gamb (nick.gamb@centrify.com)
#Verion 1.0

#INSTALL#
# "Set-ExecutionPolicy Unrestricted" Must be set using the following PowerShell Management Shells run as Administrator
# C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#Can be ran from ISE
#Commandline Syntax .\Federate_O365_Domains.ps1 -server "pod.centrify.com" -username "username" -password "password"
#Param Will retrieve default variables if not in command line. If Variables are set in commandline, defaults will not be used.

param (
    #Main Variables 
    [string]$server = "pod.centrify.com/",
    [string]$username = "admin@domain.com",
    [string]$password = "AdminPass",
    [string]$ContentType = "application/json"
 )

#API FUNCTIONS#

#Login is required for all other rest calls to get auth token
Function Login()
{ 
    $LoginJson = "{user:'$username', password:'$password'}"
    $LoginHeader = @{"X-CENTRIFY-NATIVE-CLIENT"="1"}
    $Login = Invoke-RestMethod -Method Post -Uri "https://$server/security/login" -Body $LoginJson -ContentType $ContentType -Headers $LoginHeader

    Write-Host $Login.Result
    return $Login.Result.Auth
    
}

#Federate Domain
Function FederateDomain($Auth, $Domain, $AppKey)
{
    $FederateDomainHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Auth" = $Auth}
	$FederateDomainParams = @{domainName='$Domain';applicationRowKey='$AppKey'}
    
    $FederateDomain = try { Invoke-RestMethod -Method Post -Uri "https://$server/O365/FederateDomain" -Body $FederateDomainParams -ContentType $ContentType -Headers $FederateDomainHeaders } catch { $_.Exception.Response }  

    Write-Host "Create User Success = $CreateUser.success"
    Write-Host $FederateDomain.MessageID
}

#UnFederate Domain
Function UnFederateDomain($Auth, $Domain, $AppKey)
{
    $UnFederateDomainHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Auth" = $Auth}
	$UnFederateDomainParams = @{domainName='$Domain';applicationRowKey='$AppKey'}
    
    $UnFederateDomain = try { Invoke-RestMethod -Method Post -Uri "https://$server/O365/UnfederateDomain" -Body $UnFederateDomainParams -ContentType $ContentType -Headers $UnFederateDomainHeaders } catch { $_.Exception.Response }  

    Write-Host "Create User Success = $CreateUser.success"
    Write-Host $UnFederateDomain.MessageID
}

#Get List Of Domains
Function GetDomains($Auth, $AppKey)
{
    $GetDomainsHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Auth" = $Auth}
	$GetDomainsJSON = "{""Args"":{""PageNumber"":1,""PageSize"":10000,""Limit"":10000,""SortBy"":"""",""direction"":""False"",""Caching"":-1}}"
    
    $GetDomains = try { Invoke-RestMethod -Method Post -Uri "https://$server/O365/GetOffice365Domains?rowKey=" + $AppKey -Body $GetDomainsJSON -ContentType $ContentType -Headers $GetDomainsHeaders } catch { $_.Exception.Response }  

    Write-Host "Create User Success = $CreateUser.success"
    Write-Host $GetDomains.MessageID
}

#Example of use:
#Create code to pull in a list of domains from a file or table, like Excel, into a hash table or dictionary
#Have the table hold 2 columns, one containing an O365 domain, and the other containing a Centrify app key for the app that should be used to Federate with.
#
#The Table Would Look As Follows
#
#Domains | AppKeys
#CentrifyDemo108.mail.onmicrosoft.com | 4e87084b-57d4-4049-a547-1405ca65d656
#CentrifyDemo108.mail.onmicrosoft.com | 4e87084b-57d4-4049-a547-1405ca65d656
#CentrifyDemo108.mail.onmicrosoft.com | 4e87084b-57d4-4049-a547-1405ca65d656
#CentrifyDemo108.mail.onmicrosoft.com | 4e87084b-57d4-4049-a547-1405ca65d656
#
#
#Do a for each loop for each row in the table and call FederateDomain, UnFederateDomain, or GetDomains in each loop.
#New code should be added to Main Implementations section below.
#

#Main Implementations#
Write-Host "Federating Domains"

$Domain = "CentrifyDemo108.mail.onmicrosoft.com"
$AppKey = "4e87084b-57d4-4049-a547-1405ca65d656"
$AuthToken = Login

FederateDomain $AuthToken $Domain $AppKey

#Sample Code to Unfederate a domain
#FederateDomain $AuthToken $Domain $AppKey

#Sample Code to Get a list of all domains in the app
#GetDomains $AuthToken $Domain $AppKey







