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

# GET STORAGE SYSTEMS BASED ON FILTERS
$Filters = @(
    "name eq `"ddve-01.vcorp.local`""
)

$Storage = get-dmstoragesystems -Filters $Filters -PageSize $PageSize

# GET ALL STORAGE SYSTEMS
# $Storage = get-dmstoragesystems -PageSize $PageSize

$Storage | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi