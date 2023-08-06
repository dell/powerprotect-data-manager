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
$DS = "Unity7496-DS-01"

# SEARCH NODE
$HostName = "ppdm-01-search-01.vcorp.local"
$IpAddress = "192.168.3.53"
$Dns = "192.168.1.11"
$Gateway = "192.168.1.250"
$Netmask = "255.255.252.0"

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

# PARSE OUT THE MOREF
$EsxMoRef = `
$Esx.details.esxHost.attributes.esxHost.hostMoref `
-split ':' | select-object -last 1

# PARSE OUT THE MOREF
$NetMoRef = `
$Esx.details.esxHost.attributes.esxHost.networks.moref

$Datastore = get-dmesxdatastore `
-InventorySourceId $vCenter.inventorySourceId `
-HostSystemId $Esx.details.esxHost.attributes.esxHost.hostMoref | `
where-object {$_.name -eq "$($DS)"}

# PARSE OUT THE MOREF
$DsMoRef = ($Datastore | select-object moref).moref -split ':' | `
select-object -last 1

# GET THE SEARCH NODE ID

$Body = @{
    hostName = $HostName
    inventorySourceId = $vCenter.inventorySourceId
    deploymentConfig = [ordered]@{
        fqdn = $HostName
        ipAddress = $IpAddress
        dns = $Dns
        gateway = $Gateway
        netMask = $Netmask
        networkMoref = $NetMoRef
        ipProtocol="IPv4"
        location = [ordered]@{
            datastoreMoref = $DsMoRef
            hostMoref = $EsxMoRef
        }
    }
    additionalVMNetworks = @()
}

$SearchNode = new-dmsearchnode -Body $Body

$SearchNode | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi