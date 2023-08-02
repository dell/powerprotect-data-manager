<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 1

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET CREDENTIALS BASED ON FILTER
$Filters = @(
    "name eq `"SYSADMIN`""
)
$Credentials = get-dmcredentials -Filters $Filters -PageSize $PageSize

# GET ALL CREDENTIALS
# $Credentials = get-dmcredentials -PageSize $PageSize


$Credentials | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi