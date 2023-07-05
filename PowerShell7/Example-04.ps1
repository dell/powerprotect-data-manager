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

# GET THE vCENTER
$Filters = @(
    "viewType eq `"HOST`""
)
get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "vc-01.vcorp.local"}

# DISCONNECT FROM THE REST API
disconnect-dmapi