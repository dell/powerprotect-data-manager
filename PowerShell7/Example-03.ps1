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

# GET ALERTS BASED ON FILTERS
$Filters = @(
    "acknowledgement.acknowledgeState eq `"UNACKNOWLEDGED`""
)
get-dmalerts -Filters $Filters -PageSize $PageSize

# GET ALL ALERTS
# get-dmalerts -PageSize $PageSize

# DISCONNECT FROM THE REST API
disconnect-dmapi