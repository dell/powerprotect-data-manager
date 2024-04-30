<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100
$Poll = 10
$Date = (get-date).AddHours(-7)
$Path = ".\"
$SqlHost = "win-sql-02.vcorp.local"

# NOTHING TO CHANGE BELOW THIS LINE
$global:ApiVersion = 'v2'
$global:Port = 8443
$global:AuthObject = $null

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
    PS> connect-ppdmapi -Server 'ppdm-01.vcorp.local'

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
            $Credential = Get-Credential
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

    } #END PROCESS
} #END FUNCTION

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
} #END FUNCTION

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

function new-dmlogexport {
<#
    .SYNOPSIS
    Start PowerProtect Data Manager backup
    
    .DESCRIPTION
    Start PowerProtect Data Manager backup either client or policy based

    .PARAMETER AssetIds
    An array of values asset ids to execute a backup against

    .PARAMETER Policy
    An object representing the defined policy

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Start a new log export job
    PS>  $Export = new-dmlogexport -ActivityId $ActivityId


#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [array]$ActivityId
    )
    begin {}
    process {
                
        $Endpoint = "log-exports"
        <#
            CREATE THE REQUEST BODY
        #>
        $Body = [ordered]@{
            filterType = "ACTIVITY_ID"
            filterValue = "$($ActivityId)"
        }

        $Action =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | convertto-json -Depth 10) `
        -SkipCertificateCheck
               
        return $Action

    } # END PROCESS
}

function new-dmlogexportmonitor {
<#
    .SYNOPSIS
    Get the latest copy for a PowerProtect Data Manager assets
    
    .DESCRIPTION
    Get the latest copy for a PowerProtect Data Manager assets

    .PARAMETER ActivityId
    A string representing the activity id you want to monitor

    .PARAMETER Poll
    an int representing the polling interval for the API

    .OUTPUTS
    System.Array

    .EXAMPLE
    # MONITOR THE EXPORT
    PS> $Filters = @(
        "id in (`"$($Export.id)`")"
    )
    PS> new-dmlogexportmonitor -Filters $Filters -Poll $Poll

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1activities~1%7Bid%7D/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [array]$Filters,
        [Parameter( Mandatory=$true)]
        [int]$Poll
    )
    begin {}
    process {
        $Endpoint = "log-exports"
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)"
        } else {
            $Endpoint = "$($Endpoint)"
        }
        
        do {
            #POLL THE RECOVERY ACTIVITY EVERY 60 SECONDS UNTIL COMPLETE
            
            $Content = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
            -Method GET `
            -ContentType 'application/json' `
            -Headers ($AuthObject.token) `
            -SkipCertificateCheck

            $Monitor = $Content.content
            if($Monitor.status -ne "COLLECTED"){
                Write-Host "[ACTIVITY]: $($Monitor.logExportTargetActivityId), Status = $($Monitor.status), Progress: $($Monitor.progress), Sleeping $($Poll) seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $Poll
            } else {
                Write-Host "[ACTIVITY]: $($Monitor.logExportTargetActivityId), Status = $($Monitor.status), Progress: $($Monitor.progress)`n" -ForegroundColor Green
            }
        } until($Monitor.status -eq "COLLECTED")
    }
}

function get-dmlogexportfile {
<#
    .SYNOPSIS
    Start PowerProtect Data Manager backup
    
    .DESCRIPTION
    Start PowerProtect Data Manager backup either client or policy based

    .PARAMETER AssetIds
    An array of values asset ids to execute a backup against

    .PARAMETER Policy
    An object representing the defined policy

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Download the exported logs
    PS>  get-dmlogexportfile -ActivityId $ActivityId -Path $Path

    .EXAMPLE
    PS> # Start backup for defined clients
    PS> $Backup = new-dmbackup -Clients $Clients -Policy $Policy -PageSize 100

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [array]$ActivityId,
        [Parameter( Mandatory=$false)]
        [String]$Path

    )
    begin {}
    process {
                
        $Endpoint = "log-exports/$($ActivityId)/file"
        <#
            CREATE THE REQUEST BODY
        #>
            
        $Action =  Invoke-WebRequest -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
               
        $Content = $Action.Headers.'Content-Disposition'
        $FileName = $Content -split('=') | Select-Object -Last 1

        $File = [System.IO.FileStream]::new("$($Path)\$($FileName)", [System.IO.FileMode]::Create)
        $File.write($Action.Content, 0, $Action.RawContentLength)
        $File.close()


    } # END PROCESS
}
# CONNECT TO THE REST API
connect-dmapi -Server $Server

$Filters = @(
    "category eq `"PROTECT`"",
    "and classType eq `"JOB`"",
    "and subcategory eq `"FULL`"",
    "and state eq `"COMPLETED`"",
    "and host.name eq `"$($SqlHost)`"",
    "and startTime gt `"$($Date.ToString('o'))`""
)
# GET ASSETS BASED ON FILTERS
$Activities = get-dmactivities -Filters $Filters -PageSize $PageSize

$Activities | foreach-object {
    Write-Host "[$($Server)]: Exporting logs for $($SqlHost)\$($_.asset.name)"
    # GENERATE THE EXPORT
    $Export = new-dmlogexport -ActivityId $_.id

    # MONITOR THE EXPORT
    $Filters = @(
        "id in (`"$($Export.id)`")"
    )
    new-dmlogexportmonitor -Filters $Filters -Poll $Poll

    # DOWNLOAD THE EXPORT
    get-dmlogexportfile -ActivityId $_.id -Path $Path
}

# DISCONNECT FROM THE REST API
disconnect-dmapi