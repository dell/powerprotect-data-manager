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
$Client = get-dmassets -Filters $Filters -PageSize $PageSize

# GET A PROTECTION POLICY
$Filters = @(
    "name eq `"Policy-VM01`""
)
$Policy = get-dmprotectionpolicies -Filters $Filters -PageSize $PageSize

# START THE CLIENT BASED BACKUP
$Backup = new-dmbackup -AssetIds $Client.id -Policy $Policy

# DISCONNECT FROM THE REST API
disconnect-dmapi