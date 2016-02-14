# Copyright 2016 Centrify Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$username = "",
    [string]$endpoint = "https://cloud.centrify.com"
)

# Get the directory the example script lives in
$exampleRootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import the Centrify.Samples.Powershell module 
Import-Module $exampleRootDir\Centrify.Samples.Powershell.psm1 3>$null 4>$null

# If Verbose is enabled, we'll pass it through
$enableVerbose = ($PSBoundParameters['Verbose'] -eq $true)

# Import sample function definitions
. $exampleRootDir\Centrify.Samples.Powershell.QueryFunction.ps1

try
{
    # MFA login and get a bearer token as the provided user, uses interactive Read-Host/Write-Host to perform MFA
    #  If you already have a bearer token and endpoint, no need to do this, just start using Centrify-InvokeREST
    $token = Centrify-InteractiveLogin-GetToken -Username $username -Endpoint $endpoint -Verbose:$enableVerbose    
            
    # Get information about the user who owns this token via /security/whoami     
    $userInfo = Centrify-InvokeREST -Endpoint $token.Endpoint -Method "/security/whoami" -Token $token.BearerToken -Verbose:$enableVerbose     
    Write-Host "Current user: " $userInfo.Result.User
    
    # Run a query for top user logins from last 30 days
    $query = "select NormalizedUser as User, Count(*) as Count from Event where EventType = 'Cloud.Core.Login' and WhenOccurred >= DateFunc('now', '-30') group by User order by count desc"
    $queryResult = Query -Endpoint $token.Endpoint -BearerToken $token.BearerToken -Query $query            
    Write-Host "Query resulted in " $queryResult.FullCount " results, first row is: " $queryResult.Results[0].Row    
        
    # We're done, and don't want to use this token for anything else, so invalidate it by logging out
    $logoutResult = Centrify-InvokeREST -Endpoint $token.Endpoint -Method "/security/logout" -Token $token.BearerToken -Verbose:$enableVerbose           
}
finally
{
    # Always remove the Centrify.Samples.Powershell module, makes development iteration on the module itself easier
    Remove-Module Centrify.Samples.Powershell 4>$null
}