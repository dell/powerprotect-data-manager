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

$Filters = @(
    "name eq `"vc1-ubu-01`""
)
# GET ASSETS BASED ON FILTERS
get-dmassets -Filters $Filters -PageSize $PageSize

# GET ALL ASSETS
# get-dmassets -PageSize $PageSize

# DISCONNECT FROM THE REST API
disconnect-dmapi