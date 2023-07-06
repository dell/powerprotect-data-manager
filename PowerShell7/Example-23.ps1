<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases
#>

Import-Module .\dell.ppdm.psm1 -Force
$Server = "ppdm-01.vcorp.local"

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# PROMPT THE USER FOR THE DESIERED PASSWORD
$Credential = Get-Credential `
-Title "Create Linux OS Credentials in PowerProtect Data Manager" `
-Message "Please enter the password for root" `
-UserName "root"

$Body = [ordered]@{
    type="OS"
    username="$($Credential.username)"
    password="$(ConvertFrom-SecureString -SecureString $Credential.password -AsPlainText)"
    name="Linux2"
}

# CREATE THE NEW CREDENTIALS
$Credentials = new-dmcredential -Body $Body

$Credentials | format-list

# DISCONNECT FROM THE REST API
disconnect-dmapi