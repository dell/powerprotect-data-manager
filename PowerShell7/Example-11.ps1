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

# START THE POLICY BASED BACKUP
$Backup = new-dmbackup -Policy $Policy

# DISCONNECT FROM THE REST API
disconnect-dmapi