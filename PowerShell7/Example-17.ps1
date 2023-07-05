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

# GET A PROTECTION POLICY
$Filters = @(
    "name eq `"Policy-VM01`""
)
$Policy = get-dmprotectionpolicies -Filters $Filters -PageSize $PageSize

# GET ALL PROTECTION POLICIES
# $Policy = get-dmprotectionpolicies -PageSize $PageSize

$Policy | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi