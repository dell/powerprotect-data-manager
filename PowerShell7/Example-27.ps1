<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

    vMWare PowerCLI
#>

Import-Module .\dell.ppdm.psm1 -Force
$vCenter = "vc-01.vcorp.local"
$Regex = "^splunk-0[1|2|3]"

$Server = "ppdm-01.vcorp.local"
$PageSize = 100
$assets = @()


# IMPORT THE DEPLOYMENT CONFIGURATION
$exists = test-path ".\$($vCenter).xml" -PathType Leaf
if($exists) {
    $credential = Import-Clixml ".\$($vCenter).xml"
    # CONNECT TO VCENTER
    connect-viserver -Server $vCenter `
    -Protocol https `
    -Credential $credential

    # GET ALL VIRTUAL MACHINES
    $query = Get-View -ViewType VirtualMachine -Filter @{"name"="$($Regex)"}

    # FILTER MY LIST
    foreach ($vm in $query) {
        $disks = @()

        # GET THE DEVICES
        $devices = $vm.Config.Hardware.Device
        # FILTER THE DEVICES
        $harddisks = $devices | where-object {$_.DeviceInfo.Label -match "^Hard disk"}

        foreach($disk in $harddisks) {
            if(
                $disk.Backing.DiskMode `
                -eq "independent_persistent"
            ) {
                $object = @{
                    key = $disk.key
                    label = $disk.DeviceInfo.Label
                    excluded = $true
                }
            } else {
                $object = @{
                    key = $disk.key
                    label = $disk.DeviceInfo.Label
                    excluded = $false
                }
            }
            
            $disks += (new-object -typename pscustomobject -property $object)
        }

        $object = [ordered]@{
            name = $vm.name
            disks = $disks
        }

        $assets += (new-object -typename pscustomobject -property $object)
        
    }

    # DISCONNECT VCENTER
    disconnect-viserver -Force -Confirm:$false

    # CONNECT THE THE REST API
    connect-dmapi -Server $Server

    $assets | foreach-object {
        $Filters = @(
            "name eq `"$($_.name)`""
        )
        $Asset = get-dmassets -Filters $Filters -PageSize $PageSize

        set-dmdiskexclusions -Asset $Asset -Config $_.disks

    } # END FOREACH
   
    # DISCONNECT FROM THE REST API
    disconnect-dmapi

} else {
    throw "Unable to find the credentials file for vCenter"
}