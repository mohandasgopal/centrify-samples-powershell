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

try
{
    # MFA login and get a bearer token as the provided user, uses interactive Read-Host/Write-Host to perform MFA
    $token = Centrify-InteractiveLogin-GetToken -Username $username -Endpoint $endpoint -Verbose:($PSBoundParameters['Verbose'] -eq $true)    
            
    # Get information about the user who owns this token via /security/whoami     
    $userInfo = Centrify-InvokeREST -Endpoint $token.Endpoint -Method "/security/whoami" -Token $token.BearerToken -Verbose:($PSBoundParameters['Verbose'] -eq $true)     
    Write-Host $userInfo.Result
        
    # We're done, and don't want to use this token for anything else, so invalidate it by logging out
    Centrify-InvokeREST -Endpoint $endpoint -Method "/security/logout" -Token $bearerToken -Verbose:($PSBoundParameters['Verbose'] -eq $true)       
}
finally
{
    # Always remove the Centrify.Samples.Powershell module, makes development iteration on the module itself easier
    Remove-Module Centrify.Samples.Powershell 4>$null
}