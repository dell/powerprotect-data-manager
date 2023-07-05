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

$Path = @(
    "host=192.168.1.11",
    "port=636"
)
# GET A CERTIFICATE
$Certificate = get-dmcertificates -Path $Path

$Certificate | format-list


# DISCONNECT FROM THE REST API
disconnect-dmapi