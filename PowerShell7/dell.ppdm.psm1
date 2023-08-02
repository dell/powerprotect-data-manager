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

function get-dmassets {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager assets

    .DESCRIPTION
    Get PowerProtect Data Manager assets based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET ASSETS BASED ON A FILTER
    PS> $Filters = @(
    "name eq `"vc1-ubu-01`""
    )
    PS> $Assets = get-dmassets -Filters $Filters -PageSize $PageSize

    .EXAMPLE
    PS> # GET ALL ASSETS
    PS> $Assets = get-dmassets -PageSize $PageSize

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1assets/get

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
        
        $Endpoint = "assets"
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

    } # END PROCESS
}

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

function get-dmalerts {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager alerts

    .DESCRIPTION
    Get PowerProtect Data Manager alerts

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET ALERTS BASED ON A FILTER
    PS> $Filters = @(
        "acknowledgement.acknowledgeState eq `"UNACKNOWLEDGED`""
    )
    PS> $Alerts = get-dmalerts -Filters $Filters -PageSize $PageSize

    .EXAMPLE
    PS> # GET ALL ALERTS
    PS> $Alerts = get-dmalerts -PageSize $PageSize

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1alerts/get

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
        $Endpoint = "alerts"
        
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

function get-dmvirtualcontainers {
    <#
    .SYNOPSIS
    Get PowerProtect Data Manager virtual containers (vCenter)

    .DESCRIPTION
    Get PowerProtect Data Manager virtual containers (vCenter) based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get the vCenter(s)
    PS> $Filters = @(
        "viewType eq `"HOST`""
    )
    PS>  $vCenter = get-dmvirtualcontainers -Filters $Filters -PageSize 100 | `
    where-object {$_.name -eq "$($VMware)"}

    .EXAMPLE
    PS> # Get the datacenter
    PS> $Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($vCenter.id)`""
    )
    PS>  $Datacenter = get-dmvirtualcontainers -Filters $Filters -PageSize 100 | `
    where-object {$_.name -eq "$($DC)"}

    .EXAMPLE
    PS> # Get a folder
    PS> $Filters = @(
    "viewType eq `"VM`"",
    "and parentId eq `"$($Datacenter.id)`""
    )
    PS>  $Folder= get-dmvirtualcontainers -Filters $Filters -PageSize 100 | `
    where-object {$_.name -eq "$($FolderName)"}

    .EXAMPLE
    PS> # Get a cluster
    PS>  $Filters = @(
     "viewType eq `"HOST`"",
     "and parentId eq `"$($Datacenter.id)`""

    )
    $Cluster = get-dmvirtualcontainers -Filters $Filters -PageSize 100 | `
    where-object {$_.name -eq "$($ClusterName)"}

    .EXAMPLE
    PS> # Get a resource pool
    PS> $Filters = @(
        "viewType eq `"HOST`"",
        "and parentId eq `"$($Cluster.id)`""
    )
    $Pool = get-dmvirtualcontainers -Filters $Filters -PageSize 100 | `
    where-object {$_.name -eq "$($RP)"}

    .EXAMPLE
    PS> # Get an ESX host
    PS> $Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Cluster.id)`""
    )
    PS> $Esx = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
    where-object {$_.name -eq "$($EsxName)"}

    PS> Get a datastore
    PS> $Datastores = get-dmesxdatastore `
        -InventorySourceId $vCenter.inventorySourceId `
        -HostSystemId $Esx.details.esxHost.attributes.esxHost.hostMoref | `
        where-object {$_.name -eq "$($DS)"}

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [array]$Filters,
        [Parameter( Mandatory=$true)]
        [int]$PageSize
    )
    begin {}
    process {
        
        $Results = @()
        
        $Endpoint = "vm-containers"
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filterType=vCenterInventory&filter=$($Join)&pageSize=$($PageSize)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results = $Query.content
        
        return $Results

    } # END PROCESS
}

function get-dmstoragesystems {
    <#
    .SYNOPSIS
    Get PowerProtect Data Manager attached storage systems
    
    .DESCRIPTION
    Get PowerProtect Data Manager attached storage systems based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get the storage system
    PS> $Filters = @(
        "name eq `"ddve-01.vcorp.local`""
    )
    PS>  $Storage = get-dmstoragesystems -Filters $Filters -PageSize 100

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1storage-systems/get

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
        $Endpoint = "storage-systems"

        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)&pageSize=$($PageSize)"
        } else {
            $Endpoint = "$($Endpoint)?pageSize=$($PageSize)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results = $Query.content
        
        return $Results

    } # END PROCESS
}

function new-dmbackup {
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
    PS> # Start backup for all clients
    PS>  $Backup = new-dmbackup -Policy $Policy -PageSize 100

    .EXAMPLE
    PS> # Start backup for defined clients
    PS> $Backup = new-dmbackup -Clients $Clients -Policy $Policy -PageSize 100

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1protection-policies~1%7Bid%7D~1protections/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [array]$AssetIds,
        [Parameter( Mandatory=$true)]
        [object]$Policy
    )
    begin {}
    process {
                
        $Endpoint = "protection-policies/$($Policy.id)/protections"
        <#
            CREATE THE REQUEST BODY
            NOTE:
                Omitting the clients var will backup all clients within the policy
        #>
        $Body = [ordered]@{
            assetIds = $AssetIds
            stages = @(
                @{
                    id = $Policy.stages[0].id
                    retention = [ordered]@{
                        interval = 5
                        unit = "DAY"
                    }
                    operation = @{
                        backupType = "FULL"
                    }
                }
            )
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

function get-dmprotectionpolicies {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager protection policies
    
    .DESCRIPTION
    Get PowerProtect Data Manager protection policies based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get a protection policy
    PS> $Filters = @(
        "name eq `"Policy-VM01`""
    )
    PS>  $Policy = get-dmprotectionpolicies -Filters $Filters -PageSize 100

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1protection-policies/get

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
        $Endpoint = "protection-policies"

        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)&pageSize=$($PageSize)"
        } else {
            $Endpoint = "$($Endpoint)?pageSize=$($PageSize)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results = $Query.content
        
        return $Results

    } # END PROCESS
}

function new-dmprotectionpolicy {
    <#
    .SYNOPSIS
    Create a new PowerProtect Data Manager protection policy
    
    .DESCRIPTION
    Create a new PowerProtect Data Manager protection policy

    .PARAMETER Body
    An object representing the protection policy

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS>  $Policy = new-dmprotectionpolicy -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1protection-policies/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {}
    process {
        
        $Endpoint = "protection-policies"
     
        $Action =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | convertto-json -Depth 10)`
        -SkipCertificateCheck

        return $Action

    } # END PROCESS
}

function get-dmlatestcopies {
<#
    .SYNOPSIS
    Get the latest copy for a PowerProtect Data Manager assets
    
    .DESCRIPTION
    Get the latest copy for a PowerProtect Data Manager assets

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get a protection policy
    PS> $Filters = @(
        "assetId in (`"$($Asset.id)`")"
        )
    PS>  $Copy = get-dmlatestcopies -Filters $Filters -PageSize 100

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1latest-copies/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [array]$Filters,
        [Parameter( Mandatory=$true)]
        [int]$PageSize
    )
    begin {}
    process {
        
        $Results = @()
        $Endpoint = "latest-copies"

       if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)&pageSize=$($PageSize)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results = $Query.content
        
        return $Results

    } # END PROCESS
}

function get-dmesxdatastore {
<#
    .SYNOPSIS
    Get the datastores attached to an esx host
    
    .DESCRIPTION
    Get the datastores attached to an esx host

    .PARAMETER InventorySourceId
    A string representing the inventory source id of the esx host

    .PARAMETER HostSystemId
    A string representing the esx host system id

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get the datastores
    PS>  $Datastores = get-dmesxdatastore -InventorySourceId $InventorySourceId -HostSystemId $HostSystemId


#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [string]$InventorySourceId,
        [Parameter( Mandatory=$true)]
        [string]$HostSystemId

    )
    begin {}
    process {
        $Endpoint = "vcenter/$($InventorySourceId)/data-stores/$($HostSystemId)?orderby=freeSpace DESC"
        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results = $Query.datastores

        return $Results
    }
}

function new-dmrecover {
<#
    .SYNOPSIS
    Create a recovery job for a PowerProtect Data Manager asset
    
    .DESCRIPTION
    Create a recovery job for a PowerProtect Data Manager asset

    .PARAMETER Body
    An object representing the recovery process

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Start a new recovery job
    PS>  $Recover = new-dmrecover -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1restored-copies/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {}
    process {
        $Endpoint = "restored-copies"
        $Action =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | Convertto-Json -Depth 10) `
        -SkipCertificateCheck
        
        return $Action
    }
}

function new-dmmonitor {
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
    PS> # Start a new recovery job
    PS>  $Recover = new-dmrecover -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1activities~1%7Bid%7D/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [string]$ActivityId,
        [Parameter( Mandatory=$true)]
        [int]$Poll
    )
    begin {}
    process {
        do {
            #POLL THE RECOVERY ACTIVITY EVERY 60 SECONDS UNTIL COMPLETE
            $Endpoint = "activities"
            $Monitor = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)/$($ActivityId)" `
            -Method GET `
            -ContentType 'application/json' `
            -Headers ($AuthObject.token) `
            -SkipCertificateCheck

            if($Monitor.state -ne "COMPLETED"){
                if($Monitor.state -ne "RUNNING") {
                    Write-Host "[ACTIVITY]: $($ActivityId), State = $($Monitor.state), Sleeping $($Poll) seconds..." -ForegroundColor Yellow
                } else {
                    Write-Host "[ACTIVITY]: $($ActivityId), State = $($Monitor.state), Sleeping $($Poll) seconds..." -ForegroundColor Green
                }
                
                Start-Sleep -Seconds $Poll
            }
        } until($Monitor -and $Monitor.state -eq "COMPLETED")
    }
}

function get-dmexportedcopies {
<#
    .SYNOPSIS
    Get the exported copies for a PowerProtect Data Manager assets
    
    .DESCRIPTION
    Get the exported copies for a PowerProtect Data Manager assets

    .PARAMETER Filters
    An array of values used to filter the query

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET THE INSTANT ACCESS SESSION
    PS> $Filters = @(
        "copyId eq `"$($Copy.id)`"",
        "and exportType ne `"RESTORED_COPIES`""
        "and dataSourceSubType eq `"VIRTUALMACHINE`""
    )
    PS> $Ia = get-dmexportedcopies -Filters $Filters

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1exported-copies/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [array]$Filters
    )
    begin {}
    process {
        $Results = @()

        # GET THE INSTANT ACCESS SESSION
        $Endpoint = "exported-copies"
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)"
        }
        $Query = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $Results = $Query.content[0].exportedCopiesDetails.targetExportedVmInfo[0]

        return $Results
    }
}

function new-dmvmotion {
<#
    .SYNOPSIS
    Start a vMotion
    
    .DESCRIPTION
    Start a vMotion for an exported copy

    .PARAMETER Ia
    A string representing the instant access session id

    .PARAMETER Body
    An object representing the vMotion request

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # START THE VMOTION
    PS> $Vmotion = new-dmvmotion -Ia $Ia.restoredCopyId -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1restored-copies~1%7Bid%7D~1vmotion/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [string]$Ia,
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {
        
    }
    process {
        $Endpoint = "restored-copies/$($Ia)/vmotion"
        Write-Host "`n[POST]: /$($Endpoint)`n $( ($Body | Convertto-Json -Depth 10) )"

        $Action =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | Convertto-Json -Depth 10) `
        -SkipCertificateCheck

        return $Action
    }
}

function get-dmagentregistration {
<#
    .SYNOPSIS
    Get the agents registered with PowerProtect Data Manager
    
    .DESCRIPTION
    Get the agents registered with PowerProtect Data Manager based on a filter

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET THE INSTANT ACCESS SESSION
    PS> $Filters = @(
        "name eq `"vc1-sql-02`""
        )
    PS> $agent = get-dmagentregistration -Filters $Filters

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1agent-registration-status/get

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

        # GET THE INSTANT ACCESS SESSION
        $Endpoint = "agent-registration-status"
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)&pageSize=$($PageSize)"
        } else {
            $Endpoint = "$($Endpoint)?pageSize=$($PageSize)"
        }
        $Query = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $Results = $Query.content

        return $Results
    }
}

function get-dmcertificates {
<#
    .SYNOPSIS
    Get the certificate from a 3rd party application
    
    .DESCRIPTION
    Get the certificate from a 3rd party application for use with PowerProtect Data Manager

    .PARAMETER Path
    An array of values used to filter the query


    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET A CERTIFICATE
    PS> $Path = @(
        "host=192.168.1.11",
        "port=636"
    )
    PS> $Certificate = get-dmcertificates -Path $Path

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1certificates/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [array]$Path
    )
    begin {}
    process {
        $Results = @()

        # GET A CERTIFICATE
        $Endpoint = "certificates"
        if($Path.Length -gt 0) {
            $Join = ($Path -join '&')
            $Endpoint = "$($Endpoint)?$($Join)"
        }

        $Query = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $Results = $Query

        return $Results
    }
}

function get-dmengines {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager Protection Engines
    
    .DESCRIPTION
    Get PowerProtect Data Manager Protection Engines

    .PARAMETER Filters
    An array of values used to filter the query


    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET A CERTIFICATE
    PS> $Filters = @(
        "type eq `"VPE`""
    )
    PS> $Pe = get-dmengines -Filters $Filters

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1protection-engines/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [array]$Filters
    )
    begin {}
    process {
        $Results = @()

        # GET A CERTIFICATE
        $Endpoint = "protection-engines"
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join '&') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)"
        }

        $Query = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $Results = $Query.content

        return $Results
    }
}

function new-dmengine {
<#
    .SYNOPSIS
    Deploy a new PowerProtect Data Manager Protection Engine
    
    .DESCRIPTION
    Deploy a new PowerProtect Data Manager Protection Engine

    .PARAMETER Id
    A string representing the protection engine id you want to deploy

    .PARAMETER Body
    An object representing the request body for a protection engine deployment

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # DEPLOY A PROTECTION ENGINE

    PS> $Engine = new-dmengine -Id $Pe.id -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1certificates/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [string]$Id,
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {}
    process {

        # GET A CERTIFICATE
        $Endpoint = "protection-engines/$($Id)/proxies"
        
        $Action = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | convertto-json -Depth 10) `
        -SkipCertificateCheck

        return $Action
    }
}

function get-dmcredentials {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager Credentials
    
    .DESCRIPTION
    Get PowerProtect Data Manager Credentials

    .PARAMETER Filters
    An array of values used to filter the query

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET CREDENTIALS BASED ON A FILTER
    PS> $Filters = @(
        "name eq `"SYSADMIN`""
    )
    PS> $Credentials = get-dmcredentials -Filters $Filters -PageSize $PageSize

    .EXAMPLE
    PS> # GET ALL CREDENTIALS
    PS>  $Credentials = get-dmcredentials -PageSize $PageSize

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1credentials/get

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
        $Page = 1
        $Results = @()
        $Endpoint = "credentials"

        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)"
        }else {
            $Endpoint = "$($Endpoint)?"
        }
        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)pageSize=$($PageSize)&page=$($Page)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        # CAPTURE THE RESULTS
        $Results = $Query.content
        
        if($Query.page.totalPages -gt 1) {
            # INCREMENT THE PAGE NUMBER
            $Page++
            # PAGE THROUGH THE RESULTS
            do {
                $Paging = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)pageSize=$($PageSize)&page=$($Page)" `
                -Method GET `
                -ContentType 'application/json' `
                -Headers ($AuthObject.token) `
                -SkipCertificateCheck

                # CAPTURE THE RESULTS
                $Results += $Paging.content

                # INCREMENT THE PAGE NUMBER
                $Page++   
            } 
            until ($Paging.page.number -eq $Query.page.totalPages)
        }
        return $Results

    } # END PROCESS
}  # END FUNCTION

function set-dmdiskexclusions {
<#
    .SYNOPSIS
    Set PowerProtect Data Manager asset disk exclusions
    
    .DESCRIPTION
    Set PowerProtect Data Manager asset disk exclusions

    .PARAMETER Asset
    An object representing the asset

    .PARAMETER Config
    An array representing the the desired disk exclusion configuration for the asset

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> set-dmdiskexclusions -Asset $Asset -Config $_.disks

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1assets~1%7Bid%7D/patch

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [object]$Asset,
        [Parameter( Mandatory=$true)]
        [array]$Config
    )
    begin {
        
    } #END BEGIN
    process {
        $Results = @()
        $Endpoint = "assets/$($Asset.id)"

        $Disks = $Asset.details.vm.disks
        [array]$Settings = @()
   

        # ENUMERATE THE CONFIG ARRAY
        foreach($Disk in $Config) {

            # ALWAYS SET HARD DISK 1 TO EXCLUDE = $false
            if($Disk.label -eq 'Hard disk 1') {
                # CREATE THE SETTINGS
                    $object = @{
                        excluded = $false
                        key = ($Disks | where-object {$_.label -eq $Disk.label}).key
                        name = ($Disks | where-object {$_.label -eq $Disk.label}).name
                    }
                } else {
                    $object = @{
                        excluded = $Disk.excluded
                        key = ($Disks | where-object {$_.label -eq $Disk.label}).key
                        name = ($Disks | where-object {$_.label -eq $Disk.label}).name
                    }
            } # END IF

            # ADD THE SETTINGS TO THE SETTINGS ARRAY
            $Settings += (New-Object -TypeName pscustomobject -Property $object)

        } # END FOREACH
        # CREATE THE REQUEST BODY WITH THE NEW SETTINGS
        $Body = [ordered]@{
            id = $Asset.id
            details = @{
                vm = [ordered]@{
                    disks = $Settings | sort-object key
                }
            }
        }
        
        $Action =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method PATCH `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | convertto-json -Depth 25) `
        -SkipCertificateCheck
        $Results += $Action

        return $Results

    }
}

function new-dmcredential {
<#
    .SYNOPSIS
    Creates a new set of credentials for PowerProtect Data Manager
    
    .DESCRIPTION
    Creates a new set of credentials for PowerProtect Data Manager

    .PARAMETER Body
    An object representing the request body for a protection engine deployment

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # CREATES A NEW SET OF CREDENTIALS
    PS> $Credentials = new-dmcredential -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1credentials/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {}
    process {

        # GET A CERTIFICATE
        $Endpoint = "credentials"
        
        $Action = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | convertto-json -Depth 10) `
        -SkipCertificateCheck

        return $Action
    }
}

function new-dmsearchnode {
<#
    .SYNOPSIS
    Deploy a new PowerProtect Data Manager Search Node
    
    .DESCRIPTION
    Deploy a new PowerProtect Data Manager Search Node

    .PARAMETER Id
    A string representing the search node id

    .PARAMETER Body
    An object representing the request body for a search node deployment

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # DEPLOY A SEARCH NODE
    PS> $SearchNode = new-dmsearchnode -Body $Body

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1search-clusters/get

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1search-clusters~1%7Bid%7D~1nodes/post

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {}
    process {

        # GET THE SEARCH NODE ID
        $Endpoint = "search-clusters"
        $Query = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $Id = ($Query.content | where-object {$_.name -eq "Search"}).id

        # DEPLOY A NEW SEARCH NODE
        $Endpoint = "search-clusters/$($Id)/nodes"
        
        $Action = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -Body ($Body | convertto-json -Depth 10) `
        -SkipCertificateCheck

        return $Action
    }
}

function get-dmauditlogs {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager audit logs

    .DESCRIPTION
    Get PowerProtect Data Manager audit logs

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # GET AUDIT LOGS BASED ON A FILTER
    PS> $Filters = @(
        "auditType eq `"SECURITY`"",
        "and changedObject.resourceType eq `"/login`""
    )
    PS> $Audit = get-dmauditlogs -Filters $Filters -PageSize $PageSize

    .EXAMPLE
    PS> # GET ALL AUDIT LOGS
    PS> $Audit = get-dmauditlogs -PageSize $PageSize

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1audit-logs/get

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
        $Endpoint = "audit-logs"
        
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

Export-ModuleMember -Function *