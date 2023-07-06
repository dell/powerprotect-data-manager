<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100
$VMware = "vc-01.vcorp.local"
$DC = "DC01-VC01"

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET THE vCenter
$Filters = @(
    "viewType eq `"HOST`""
)
$vCenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($VMware)"}

# GET THE Datacenter
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($vCenter.id)`""
)
$Datacenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($DC)"}

$Datacenter | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi