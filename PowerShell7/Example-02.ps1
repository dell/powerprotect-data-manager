<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET ACTIVITIES BASED ON FILTERS
$Date = (Get-Date).AddDays(-1)
$Filters = @(
    "classType eq `"JOB`""
    "and category eq `"PROTECT`""
    "and startTime ge `"$($Date.ToString('yyyy-MM-dd'))T00:00:00.000Z`""
    "and result.status eq `"OK`""
    )
$Activities = get-dmactivities -Filters $Filters -PageSize $PageSize

# GET ALL ACTIVITIES
# $Activities = get-dmactivities -PageSize $PageSize

$Activities | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi