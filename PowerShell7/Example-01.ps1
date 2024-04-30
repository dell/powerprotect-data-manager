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
    "name eq `"win-fsa-01`""
)
# GET ASSETS BASED ON FILTERS
$Assets = get-dmassets -Filters $Filters -PageSize $PageSize

# GET ALL ASSETS
# $Assets = get-dmassets -PageSize $PageSize

Write-Host "[$($Server)]: All disks for asset: $($Assets.name)" -ForegroundColor Yellow
$Assets.details.vm.disks | sort-object label | Format-List

Write-Host "[$($Server)]: We want to exclude with regex for asset: $($Assets.name)" -ForegroundColor Yellow
$Assets.details.vm.disks | Where-Object {$_.label -notmatch "^Hard disk 1$"} | sort-object label

# DISCONNECT FROM THE REST API
disconnect-dmapi