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
    "hostname eq `"win-sql-01.vcorp.local`""
)
# GET AGENT REGISTRATION STATUS BASED ON A FILTER
$Agent = get-dmagentregistration -Filters $Filters -PageSize $PageSize
# $Agent = get-dmagentregistration -PageSize $PageSize
$Agent | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi