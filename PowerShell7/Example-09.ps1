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

# GET THE vCenter
$Filters = @(
    "viewType eq `"HOST`""
)
$vCenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "vc-01.vcorp.local"}

# GET THE DATACENTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($vCenter.id)`""
)
$Datacenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "DC01-VC01"}

# GET A CLUSTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Datacenter.id)`""

)
$Cluster = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "Cluster01"}

# GET AN ESX HOST
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Cluster.id)`""
)
$Esx = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "esx-physical-01.vcorp.local"}

$Esx | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi