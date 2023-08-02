<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases
#>

Import-Module .\dell.ppdm.psm1 -Force
$Server = "ppdm-01.vcorp.local"
$PageSize = 100
$Config = @(
    @{
        name = "vc1-win-01"
        disks = @(
            @{
                label = "Hard disk 1"
                excluded = $false
            },
            @{
                label = "Hard disk 2"
                excluded = $true
            },
            @{
                label = "Hard disk 3"
                excluded = $false
            },
            @{
                label = "Hard disk 4"
                excluded = $false
            }
            ,@{
                label = "Hard disk 5"
                excluded = $false
            }
        )
    },
    @{
        name = "vc1-win-02"
        disks = @(
            @{
                label = "Hard disk 1"
                excluded = $false
            },
            @{
                label = "Hard disk 2"
                excluded = $true
            },
            @{
                label = "Hard disk 3"
                excluded = $false
            },
            @{
                label = "Hard disk 4"
                excluded = $false
            }
            ,@{
                label = "Hard disk 5"
                excluded = $false
            }
        )
    }
)

# CONNECT THE THE REST API
connect-dmapi -Server $Server

<#
    INCLUDE OR EXCLUDE ALL DISKS FOR VRTUAL MACHINE ASSETS EXCEPT:
    Hard disk 1
#>

$Config | foreach-object {
    $Filters = @(
        "name eq `"$($_.name)`""
    )
    $Asset = get-dmassets -Filters $Filters -PageSize $PageSize

    set-dmdiskexclusions -Asset $Asset -Config $_.disks

}

# DISCONNECT FROM THE REST API
disconnect-dmapi