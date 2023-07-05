<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100

$VmName = "vc1-ubu-01"
$VcenterName = "vc-01.vcorp.local"
$DcName = "DC01-VC01"
$FolderName = "Recover"
$ClusterName = "Cluster01"
$PoolName = "Web"
$EsxName = "esx-physical-01.vcorp.local"
$DsName = "Unity7496-DS-01"

# CONNECT THE THE REST API
connect-dmapi -Server $Server

$Filters = @(
    "name eq `"$($VmName)`""
)
# GET ASSETS BASED ON FILTERS
$Asset = get-dmassets -Filters $Filters -PageSize $PageSize
$AssetMoRef = $Asset.details.vm.vmMoref -split ':' | select-object -last 1

# GET THE LATEST COPY
$Filters = @(
    "assetId in (`"$($Asset.id)`")"
)
$Copy = get-dmlatestcopies -Filters $Filters -PageSize 100

# GET THE vCenter
$Filters = @(
    "viewType eq `"HOST`""
)
$vCenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($VcenterName)"}

# GET THE DATACENTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($vCenter.id)`""
)
$Datacenter = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($DcName)"}
$DcMoRef = $Datacenter.id -split ':' | select-object -last 1

# GET A FOLDER
$Filters = @(
    "viewType eq `"VM`"",
    "and parentId eq `"$($Datacenter.id)`""
)
$Folder = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($FolderName)"}
$FolderMoRef = $Folder.id -split ':' | select-object -last 1

# GET A CLUSTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Datacenter.id)`""

)
$Cluster = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($ClusterName)"}
$ClusterMoRef = $Cluster.id -split ':' | select-object -last 1

# GET A RESOURCE POOL
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Cluster.id)`""
)
$Pool = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "Web"}
$PoolMoRef = $Pool.id -split ':' | select-object -last 1

# GET AN ESX HOST
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Cluster.id)`""
)
$Esx = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($EsxName)"}
$EsxMoRef = $Esx.id -split ':' | select-object -last 1
$NetMoref = $Esx.details.esxHost.attributes.esxHost.networks[0].moref

$Datastores = get-dmesxdatastore `
-InventorySourceId $vCenter.inventorySourceId `
-HostSystemId $Esx.details.esxHost.attributes.esxHost.hostMoref | `
where-object {$_.name -eq "$($DsName)"}
$DsMoRef = $Datastores.moref -split ':' | select-object -last 1


# BUILD THE JSON REQUEST BODY
$Body = [ordered]@{
    description = "DR_$($Asset.name) instant access recovery"
    copyIds = @("$($Copy.id)")
    restoreType = "INSTANT_ACCESS"
    options = @{
        enableCompressedRestore = $false
    }
    restoredCopiesDetails = [ordered]@{
        targetVmInfo = [ordered]@{
            inventorySourceId = "$($Esx.inventorySourceId)"
            vmName = "DR_$($Asset.name)"
            dataCenterMoref = "$($DcMoRef)"
            hostMoref = "$($EsxMoRef)"
            dataStoreMoref = "$($DsMoRef)"
            clusterMoref = "$($ClusterMoRef)"
            folderMoref = "$($FolderMoRef)"
            resourcePoolMoref = "$($PoolMoRef)"
            disks = @()
            vmPowerOn = $true
            vmReconnectNic = $false
            tagRestoreDirective = "OFF"
            spbmRestoreDirective = "OFF"
            networks = @(
                [ordered]@{
                    networkLabel = "Network adapter 1"
                    networkMoref = "$($NetMoref)"
                    networkName = "VM Network"
                    reconnectNic = $true
                }
            )
            recoverConfig = $true
        }
    }
} #END BODY

$Recover = new-dmrecover -Body $Body

$Monitor = new-dmmonitor -ActivityId $Recover.activityId -Poll 15

# GET THE INSTANT ACCESS SESSION
$Filters = @(
    "copyId eq `"$($Copy.id)`"",
    "and exportType ne `"RESTORED_COPIES`""
    "and dataSourceSubType eq `"VIRTUALMACHINE`""
)
$Ia = get-dmexportedcopies -Filters $Filters

$Body = [ordered]@{
    description = "Relocate virtual machine for DR_$($Asset.name)"
    copyId = "$($Copy.id)"
    vmMoref = "$($AssetMoRef)"
    targetDatastoreMoref = "$($DsMoRef)"
    disks = @()
}
$Vmotion = new-dmvmotion -Ia $Ia.restoredCopyId -Body $Body

$Vmotion | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi