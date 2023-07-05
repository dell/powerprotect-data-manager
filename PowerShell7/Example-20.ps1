<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$vCenter = "vc-01.vcorp.local"
$Datacenter = "DC01-VC01"
$Cluster = "Cluster01"
$EsxHost = "esx-physical-01.vcorp.local"
$Datastore = "Unity7496-DS-01"
$Network = "VM Network"

$Proxy = "ppdm01-vprxy01.vcorp.local"
$Ip = "192.168.3.249"
$Netmask = "255.255.252.0"
$Gateway = "192.168.1.250"
$Dns = "192.168.1.11"

$PageSize = 100

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET THE vCenter
$Filters = @(
    "viewType eq `"HOST`""
)
$Vc = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($vCenter)"}

# GET THE DATACENTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Vc.id)`""
)
$Dc = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($Datacenter)"}

# GET A CLUSTER
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Dc.id)`""

)
$Cls = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($Cluster)"}

# GET AN ESX HOST
$Filters = @(
    "viewType eq `"HOST`"",
    "and parentId eq `"$($Cls.id)`""
)
$Esx = get-dmvirtualcontainers -Filters $Filters -PageSize $PageSize | `
where-object {$_.name -eq "$($EsxHost)"}

# PARSE OUT THE MOREF
$EsxMoRef = `
$Esx.details.esxHost.attributes.esxHost.hostMoref `
-split ':' | select-object -last 1

# PARSE OUT THE MOREF
$NetMoRef = `
$Esx.details.esxHost.attributes.esxHost.networks.moref

# GET THE DATASTORE
$Ds = get-dmesxdatastore `
-InventorySourceId $VC.inventorySourceId `
-HostSystemId $Esx.details.esxHost.attributes.esxHost.hostMoref | `
where-object {$_.name -eq $Datastore}
# PARSE OUT THE MOREF
$DsMoRef = ($Ds | where-object {$_.name -eq $Datastore}).moref -split ':' | `
select-object -last 1


# GET THE PROTECTION ENGINE
$Filters = @(
    "type eq `"VPE`""
)
$Pe = get-dmengines -Filters $Filters

# DEPLOY THE PROTECTION ENGINE
$Body = [ordered]@{
    Config = [ordered]@{
        ProxyType = "External"
        DeployProxy = $true
        Port = 9090
        Disabled = $false
        MORef = ""
        Credential = @{
            Type = "ObjectId"
        }
        AdvancedOptions = @{
            TransportSessions = [ordered]@{
                Mode = "HotaddPreferred"
                UserDefined = $true
            }
        }
        SupportedProtectionTypes = @(
            "VM"
        )
        ProxyDeploymentConfig = [ordered]@{
            Location = [ordered]@{
                HostMoref = $EsxMoRef
                DatastoreMoref = $DsMoRef
                NetworkMoref = $NetMoRef
            }
            Timezone = ""
            AdditionalVMNetworks = @()
            Fqdn = $Proxy
            IpAddress = $Ip
            NetMask = $NetMask
            Gateway = $Gateway
            PrimaryDns = $Dns
            Dns = $Dns
            IPProtocol = "IPv4"
        }
        VimServerRef = [ordered]@{
            Type ="ObjectId"
            ObjectId = $Esx.inventorySourceId
        }
    }
}

$Engine = new-dmengine -Id $Pe.id -Body $Body

$Activity = $Engine._links.task.href -split '/' | select-object -last 1

new-dmmonitor -ActivityId $activity -Poll 15

# DISCONNECT FROM THE REST API
disconnect-dmapi