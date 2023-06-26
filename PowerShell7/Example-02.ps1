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
get-dmactivities -Filters $Filters -PageSize $PageSize

# GET ALL ACTIVITIES
# get-dmactivities -PageSize $PageSize

# DISCONNECT FROM THE REST API
disconnect-dmapi