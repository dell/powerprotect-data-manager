<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/PowerShell/releases/tag/v7.3.4
#>

# VARS
$ppdm = 'ppdm-01.vcorp.local'
$user = 'VCORP\powerprotect'

<#
    DO NOT MODIFY BELOW THIS LINE
#>

# GLOBAL VARS
$global:ApiVersion = 'v2'
$global:Port = 8443
$global:AuthObject = $null

# PAGE SIZE RETURNED FROM POWERPROTECT DATA MANAGER
$pagesize = 100

function connect-dmapi {
<#
    .SYNOPSIS
    Connect to the PowerProtect Data Manager REST API.

    .DESCRIPTION
    Creates a credentials file for PowerProtect Data Manager if one does not exist.
    Connects to the PowerProtect Data Manager REST API

    .PARAMETER Server
    Specifies the FQDN of the PowerProtect Data Manager server.

    .OUTPUTS
    System.Object 
    $global:AuthObject

    .EXAMPLE
    PS> connect-dmapi -Server 'ppdm-01.vcorp.local'

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/docs/getting%20started/authentication-and-authorization.md

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [string]$Server
    )
    begin {
        # CHECK TO SEE IF CREDS FILE EXISTS IF NOT CREATE ONE
        $Exists = Test-Path -Path ".\$($Server).xml" -PathType Leaf
        if($Exists) {
            $Credential = Import-CliXml ".\$($Server).xml"
        } else {
            $Credential = Get-Credential -Message "Credentials for $($Server)"
            $Credential | Export-CliXml ".\$($Server).xml"
        } 
    }
    process {
        $Login = @{
            username="$($Credential.username)"
            password="$(ConvertFrom-SecureString -SecureString $Credential.password -AsPlainText)"
        }
        # LOGON TO THE POWERPROTECT API 
        $Auth = Invoke-RestMethod -Uri "https://$($Server):$($Port)/api/$($ApiVersion)/login" `
                    -Method POST `
                    -ContentType 'application/json' `
                    -Body (ConvertTo-Json $Login) `
                    -SkipCertificateCheck
        $Object = @{
            server ="https://$($Server):$($Port)/api/$($ApiVersion)"
            token= @{
                authorization="Bearer $($Auth.access_token)"
            } #END TOKEN
        } #END AUTHOBJ

        $global:AuthObject = $Object

        $global:AuthObject | Format-List

    } # END PROCESS
} # END FUNCTION
    
function disconnect-dmapi {
<#
    .SYNOPSIS
    Disconnect from the PowerProtect Data Manager REST API.

    .DESCRIPTION
    Destroys the bearer token contained with $global:AuthObject

    .OUTPUTS
    System.Object 
    $global:AuthObject

    .EXAMPLE
    PS> disconnect-dmapi

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/docs/getting%20started/authentication-and-authorization.md

#>
    [CmdletBinding()]
    param (
    )
    begin {}
    process {
        #LOGOFF OF THE POWERPROTECT API
        Invoke-RestMethod -Uri "$($AuthObject.server)/logout" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $global:AuthObject = $null
    }
} # END FUNCTION

function get-dmactivities {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager activities

    .DESCRIPTION
    Get PowerProtect Data Manager activities based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET ACTIVITIES BASED ON A FILTER
    PS> $Date = (Get-Date).AddDays(-1)
    PS> $Filters = @(
    "classType eq `"JOB`""
    "and category eq `"PROTECT`""
    "and startTime ge `"$($Date.ToString('yyyy-MM-dd'))T00:00:00.000Z`""
    "and result.status eq `"FAILED`""
    )
    PS> $Activities = get-dmactivities -Filters $Filters -PageSize $PageSize

    .EXAMPLE
    PS> # GET ALL ACTIVITIES
    PS> $Activities = get-dmactivities -PageSize $PageSize

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1activities/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [array]$Filters,
        [Parameter( Mandatory=$true)]
        [int]$PageSize
    )
    begin {}
    process {
        $Results = @()
        $Endpoint = "activities"
        
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)&pageSize=$($PageSize)"
        } else {
            $Endpoint = "$($Endpoint)?pageSize=$($PageSize)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)&queryState=BEGIN" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results += $Query.content

        $Page = 1
        do {
            $Token = "$($Query.page.queryState)"
            if($Page -gt 1) {
                $Token = "$($Paging.page.queryState)"
            }
            $Paging = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)&queryState=$($Token)" `
            -Method GET `
            -ContentType 'application/json' `
            -Headers ($AuthObject.token) `
            -SkipCertificateCheck
            $Results += $Paging.content

            $Page++;
        } 
        until ($Paging.page.queryState -eq "END")
        return $Results
    }
}

function start-dmactivity {
<#
    .SYNOPSIS
    Retry an activity

    .DESCRIPTION
    Retry an activity

    .EXAMPLE
    PS> retry-dmactivity -Id $Id

    .LINK
    https://developer.dell.com/apis/4378/versions/19.15.0/reference/ppdm-public.yaml/paths/~1api~1v2~1activities~1%7Bid%7D~1retry/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [string]$Id
    )
    begin {}
    process {
        
        $Endpoint = "activities/$($Id)/retry"
        # LOGOFF OF THE POWERPROTECT API
        $action = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        return $action
    }
} # END FUNCTION

<#
    WORKFLOW
#>

# CONNECT TO THE API
connect-dmapi -Server $ppdm

# QUERY FOR FAILED ACTIVITIES
$Date = (Get-Date).AddDays(-$Days)
$Filters = @(
    "classType eq `"JOB`"",
    "and category eq `"PROTECT`"",
    "and subcategory eq `"FULL`"",
    "and protectionPolicy.type eq `"MICROSOFT_SQL_DATABASE`"",
    "and result.status eq `"FAILED`"",
    "and startTime ge `"$($Date.ToString('yyyy-MM-ddThh:mm:ss.fffZ'))`""
)

$Hosts = @()
$Query = get-dmactivities -Filters $Filters -PageSize $PageSize
$Query | foreach-object {
    $Object = [ordered]@{
        name = $_.host.Name
        parentId = $_.parentId
        errorCode = $_.result.error.code
        serviceacct = $user
    }
    $Hosts += (New-Object -TypeName psobject -Property $Object)
}

# GET THE LIST OF IMPACTED HOSTS AND THE ACTIVITY PARENT ID
$Unique = $Hosts | select-Object name,parentId,errorCode,serviceacct -Unique

Write-host "[INFO]: MSSQL hosts to remediate..."
$Unique | format-table -AutoSize

foreach($item in $Unique) {

    switch($item.errorCode) {
        'ABS0016'{
            try {
                Write-host "[INFO]: Querying local administrators on $($item.name) for user: $($item.serviceacct)"
                Invoke-Command -ComputerName $item.name -ScriptBlock {
                    [CmdletBinding()]
                    param (
                        [object]$Item
                    )
                    $Item | format-list
                    $member = Get-LocalGroupMember -Name 'Administrators' | `
                    where-object {$_.PrincipalSource -eq 'ActiveDirectory' -and $_.ObjectClass -eq 'User' -and $_.Name -eq $Item.serviceacct}

                    if($member.length -eq 0 ) {
                        Write-Host "[WARNING]: $($Item.serviceacct) not found. Adding them to the local administrators group.`n" -foregroundcolor Yellow
                        Add-LocalGroupMember -Group Administrators -Member $Item.serviceacct

                        Write-Host "[WARNING]: This is the user that broke your backups!...`n" -foregroundcolor Yellow
                        Get-EventLog -LogName Security -InstanceId 4733 -Newest 1 | format-list
                    } else {
                        $member | format-list
                    }
                } -ArgumentList $item
            } catch {
                $Error
            }

            Write-Host "[INFO]: Restarting failed activity: $($item.parentId)`n" -foregroundcolor Green
            $Retry = start-dmactivity -Id $item.parentId
            $Retry.retryResults.newJobId
        }
        'ABS0018'{
            Write-Host "[INFO]: We would do something else for this error code: $($_)"
        }
    } # END SWITCH
}

# DISCONNECT THE API
disconnect-dmapi