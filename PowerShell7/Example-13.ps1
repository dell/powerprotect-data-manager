<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

    Example-01.ps1
#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET ASSETS BASED ON FILTERS
$Filters = @(
    "name eq `"ddve-01.vcorp.local`""
)

$Storage = get-dmstoragesystems -Filters $Filters -PageSize $PageSize

# GUIDS FOR THE NEW POLICY AN STAGE
$Guid1 = (New-Guid).guid
$Guid2 = (New-Guid).guid

# PREFERRED NETWROK INTERFACE
$Preferred = $Storage.details.dataDomain.preferredInterfaces

# CREATE THE REQUEST BODY
$Body = [ordered]@{
    name = "Policy-VM01"
    description = "Protect VMWare Virtual Machines"
    assetType = "VMWARE_VIRTUAL_MACHINE"
    type = "ACTIVE"
    encrypted = $false
    enabled = $true
    priority = 1
    dataConsistency = "CRASH_CONSISTENT"
    passive = $false
    forceFull = $false
    details = [ordered]@{
        vm = @{
            protectionEngine = "VMDIRECT"
            metadataIndexingEnabled = $true
        }
    }
    stages = @(
        [ordered]@{
            id = $Guid1
            type = "PROTECTION"
            passive = $false
            attributes = [ordered]@{
                vm = [ordered]@{
                    excludeSwapFiles = $false
                    disableQuiescing = $true
                    dataMoverType = "VADP"
                }
                protection = [ordered]@{
                    backupMode = "FSS"
                }
            }
            target = [ordered]@{
                storageSystemId = $Storage.id
                dataTargetId = $null
                preferredInterface = $Preferred[1].networkAddress
            }
            slaId = $null
            sourceStageId = $null
            operations = @(
                [ordered]@{
                    id = $Guid2
                    backupType = "SYNTHETIC_FULL"
                    schedule = [ordered]@{
                        frequency = "DAILY"
                        startTime = "2023-01-01T02:00:00.000Z"
                        endTime = "2023-01-01T06:00:00.000Z"
                        duration = "PT10H"
                        interval = $null
                    }
                }
            )
            retention = [ordered]@{
                unit = "DAY"
                storageSystemRetentionLock = $false
                interval = 5
            }
            extendedRetentions = @(
                [ordered]@{
                    selector = [ordered]@{
                        operationId = $Guid2
                        backupType = "SYNTHETIC_FULL"
                    }
                    retention = [ordered]@{
                        unit = "DAY"
                        storageSystemRetentionLock = $false
                        interval = 5
                    }
                }
            )
        }
    )
    filterIds = @()
    credentials = $null
    slaId = ""
}

# CREATE THE NEW PROTECTION POLICY
$Policy = new-dmprotectionpolicy -Body $Body
$Policy | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi