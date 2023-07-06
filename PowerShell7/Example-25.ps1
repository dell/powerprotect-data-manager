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

# GET AUDIT LOGS BASED ON A FILTER
$Filters = @(
    "auditType eq `"SECURITY`"",
    "and changedObject.resourceType eq `"/login`""
)
$Audit = get-dmauditlogs -Filters $Filters -PageSize $PageSize

# GET ALL AUDIT LOGS
# $Audit = get-dmauditlogs -PageSize $PageSize

$Audit | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi