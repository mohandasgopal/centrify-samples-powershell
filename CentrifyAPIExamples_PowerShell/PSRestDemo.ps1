########INTERNAL USE ONLY##########
#Rest API Demo in PowerScript
#Created by Nick Gamb (nick.gamb@centrify.com)
#Verion 1.0

#INSTALL#
# "Set-ExecutionPolicy Unrestricted" Must be set using the following PowerShell Management Shells run as Administrator
# C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#Can be ran from ISE
#Commandline Syntax .\PSRestDemo.ps1 -server "kibble.centrify.com" -username "username" -password "password" -api "CreateUser"
#Param Will retrieve default variables if not in command line. If Variables are set in commandline, defaults will not be used.

param (
    #Main Variables 
    [string]$server = "pod.centrify.com/",
    [string]$username = "admin@domain.com",
    [string]$password = "AdminPass",
    [string]$ContentType = "application/json",
    [string]$api = "RunReport",
    #Create User Variables
    [string]$CreateUserName = "testuser2",
    [string]$CreateUserPass = "Password123!",
    [string]$CreateUserDomain = "domain.com",
    [string]$CreateUserEmail = "testuser2@domain.com",
    #Delete Device Varaibles
    [string]$DeviceName = "SAMSUNG-SM-G900V (PN: 1111111111)",
    #Report Variables
    [string]$ReportQuery = "SELECT * FROM CDUser",
    [string]$EmailAddress = "email@domain.com" 
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

#create user function
#JSON can be further customized to create all user fields if desired.
Function CreateUser($Auth)
{
    $CreateUserHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Authorization" = "Bearer " + $Auth}
    $CreateUserJson = "{""textfield-1295-inputEl"":""testname1"",""Mail"":""$CreateUserName"",""Password"":""$CreateUserPass"",""confirmPassword"":""$CreateUserPass"",""enableState"":false,""ForcePasswordChangeNext"":true,""InEverybodyRole"":true,""SendEmailInvite"":true,""DisplayName"":""$CreateUserName"",""Description"":"""",""OfficeNumber"":"""",""HomeNumber"":"""",""MobileNumber"":"""",""fileName"":"""",""ID"":"""",""state"":""None"",""ReportsTo"":""Unassigned"",""combobox-1333-inputEl"":""$CreateUserDomain"",""Name"":""$CreateUserEmail""}"
    
    $CreateUser = try { Invoke-RestMethod -Method Post -Uri "https://$server/cdirectoryservice/createuser" -Body $CreateUserJson -ContentType $ContentType -Headers $CreateUserHeaders } catch { $_.Exception.Response }  

    Write-Host "Create User Success = $CreateUser.success"
    Write-Host $CreateUSer.MessageID
}

#Used for all SQL Queries
Function RunQuery($Auth, $Query)
{
    $QueryHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Authorization" = "Bearer " + $Auth}
    $QueryJson = $Query

    $ExicuteQuery = Invoke-RestMethod -Method Post -Uri "https://$server/RedRock/query" -Body $QueryJson -ContentType $ContentType -Headers $CreateUserHeaders 

    Write-Host "Query Success = $ExicuteQuery.success"
    Write-Host $ExicuteQuery.MessageID

    Write-Host $ExicuteQuery.result

    return $ExicuteQuery.result
}

#Delete Device. Required a call to RunQuery to get DeviceID
Function DeleteDevice($Auth, $DeviceID)
{
    $DeviceHeaders = @{"X-CENTRIFY-NATIVE-CLIENT"="1";"Authorization" = "Bearer " + $Auth}
    $Delete = Invoke-RestMethod -Method Post -Uri "https://$server/mobile/deletedevice?systemID=&deviceID=$DeviceID" -Headers $CreateUserHeaders 

    Write-Host "Delete Success = $Delete.success"
    Write-Host $Delete.MessageID
    
}

#Send MAil. Required working SMTP
Function SendEmail ($Email, $Result)
{
    send-mailmessage -to "$Email" -from "OnceClickDemo@Centrify.com" -subject "Query Result" -body "$Result" -smtpServer smtp.centrify.com
}

#Main Implementations#

#Create User API
if($api -eq "CreateUser")
{
    Write-Host "Creating User"
    $AuthToken = Login

	if ($AuthToken -ne "")
	{
		CreateUser $AuthToken
	}
	else
	{
		 Write-Host "Error: ASPXAuth token was null"
	}

}

#Delete Device API
#All Query Results are nested and must be enumerated through a couple of levels

if($api -eq "DeleteDevice")
{
     Write-Host "Deleting Device $DeviceName..."
     $AuthToken = Login

	 if ($AuthToken -ne "")
	 {
		$DeviceList = RunQuery $AuthToken "{""Script"":""SELECT DeviceID FROM Device WHERE Name = '$DeviceName'""}"

		foreach ($Device in $DeviceList.Results)
		{
			foreach ($DeviceID in $Device.Row.DeviceID)
			{
				DeleteDevice $AuthToken $DeviceID $Entity
			}
		}
	 }
	 else
	 {
		Write-Host "Error: ASPXAuth token was null"
	 }     
}

#RunReport Combines a custom SQL Query using RunQuery and a call to SendEmail
#All Query Results are nested and must be enumerated through a couple of levels

if($api -eq "RunReport")
{
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

		Write-Host "Report Body Will Be $ReportBody"
		#SendEmail $EmailAddress $ReportBody
	}
	else
	{
		 Write-Host "Error: ASPXAuth token was null"
	}
    
}

if($api -eq "SimpleLogin")
{
    $AuthToken = Login

	if ($AuthToken -ne "")
	{
		Write-Host "Login successful. ASPXAuth token is: " + $AuthToken
	}
	else
	{
		 Write-Host "Error: ASPXAuth token was null"
	}
}





