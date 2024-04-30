<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-04.vcorp.local"
$PageSize = 100
# $File = ".\myReport.csv"

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET ACTIVITIES BASED ON FILTERS
$Date = (Get-Date).AddDays(-1)
$Filters = @(
    "classType eq `"JOB`""
    "and category eq `"PROTECT`""
    "and startTime ge `"$($Date.ToString('yyyy-MM-dd'))T00:00:00.000Z`"",
    "and result.status eq `"FAILED`""
)

$Activities = get-dmactivities -Filters $Filters -PageSize $PageSize

# GET ALL ACTIVITIES
# $Activities = get-dmactivities -PageSize $PageSize

$Activities | Select-Object `
    @{n="Asset";e={$_.asset.name}},
    @{n="Asset Source";e={$_.host.name}},
    @{n="Status";e={$_.result.status}},
    @{n="Precent Complete";e={$_.progress}},
    @{n="Policy Name";e={$_.protectionPolicy.name}},
    @{n="Job Type";e={$_.category}},
    @{n="Asset Type";e={$_.asset.type}},
    @{n="Start Time";e={$_.startTime}},
    @{n="Activity Duration";e={$_.duration}},
    @{n="Error Code";e={$_.result.error.code}} ` |
Format-Table -AutoSize


# DISCONNECT FROM THE REST API
disconnect-dmapi