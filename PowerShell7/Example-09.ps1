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
$ClusterName = "Cluster01"
$EsxName = "esx-physical-01.vcorp.local"

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET THE vCenter
$Filters = @(
    "viewType eq `"HOST`""
)
$vCenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($VMware)"}

# GET THE DATACENTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($vCenter.id)`""
)
$Datacenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($DC)"}

# GET A CLUSTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Datacenter.id)`""

)
$Cluster = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($ClusterName)"}

# GET AN ESX HOST
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Cluster.id)`""
)
$Esx = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($EsxName)"}

$Esx | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi