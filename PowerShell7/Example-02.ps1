<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100
$File = ".\myReport.csv"

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET ACTIVITIES BASED ON FILTERS
$Date = (Get-Date).AddDays(-1)
$Filters = @(
    "classType eq `"JOB_GROUP`""
    "and category eq `"PROTECT`""
    "and startTime ge `"$($Date.ToString('yyyy-MM-dd'))T00:00:00.000Z`""
)

$Activities = get-dmactivities -Filters $Filters -PageSize $PageSize

# GET ALL ACTIVITIES
# $Activities = get-dmactivities -PageSize $PageSize

$Activities | Select-Object id, name, category, subcategory, parentId, classType, startTime, endTime, duration, state,
    @{n="status";e={$_.result.status}},
    @{n="assetName";e={$_.asset.name}},
    @{n="assetType";e={$_.asset.type}},
    @{n="hostName";e={$_.host.name}},
    @{n="hostType";e={$_.host.type}},
    @{n="policyName";e={$_.protectionPolicy.name}},
    @{n="policyType";e={$_.protectionPolicy.type}},
    @{n="numberOfAssets";e={$_.stats.numberOfAssets}},
    @{n="storageSystem";e={$_.storageSystem.name}},
    @{n="numberOfProtectedAssets";e={$_.stats.numberOfProtectedAssets}},
    @{n="bytesTransferredThroughputMB";e={[math]::Round([decimal]$_.stats.bytesTransferredThroughput/1000/1000,4)}},
    @{n="bytesTransferredThroughputUnitOfTime";e={$_.stats.bytesTransferredThroughputUnitOfTime}},
    @{n="assetSizeInMB";e={[math]::Round([decimal]$_.stats.assetSizeInBytes/1000/1000,4)}},
    @{n="preCompMB";e={[math]::Round([decimal]$_.stats.preCompBytes/1000/1000,4)}},
    @{n="postCompMB";e={[math]::Round([decimal]$_.stats.postCompBytes/1000/1000,4)}},
    @{n="bytesTransferredMB";e={[math]::Round([decimal]$_.stats.bytesTransferred/1000/1000,4)}},
    @{n="dedupeRatio";e={$_.stats.dedupeRatio}},
    @{n="reductionPercentage";e={$_.stats.reductionPercentage}} | `
Export-CSV -Path $File -NoTypeInformation

# DISCONNECT FROM THE REST API
disconnect-dmapi