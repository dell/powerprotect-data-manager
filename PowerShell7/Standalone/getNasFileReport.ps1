[CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [switch]$PDF
    )
<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
        https://github.com/PowerShell/powershell/releases

    IMPORT THE EXCEL INTEROP ASSEMBLY
        I HAD TO DROP THIS ASSEMBLY IN THE SCRIPT FOLDER FROM HERE:
        C:\Program Files\Microsoft Office\root\vfs\ProgramFilesX86\Microsoft Office\Office16\DCF
#>
Add-Type -AssemblyName Microsoft.Office.Interop.Excel
# .NET ASSEMPLY FOR IMAGES
Add-Type -AssemblyName System.Drawing

# GLOBAL VARS
$global:ApiVersion = 'v2'
$global:Port = 8443
$global:AuthObject = $null

# VARS
$Servers = @(
    "10.239.100.131"
)
$Retires = @(1..5)
$Seconds = 10
$PageSize = 100

# REPORT OPTIONS
$ReportName = "NasFileReport"
$ReportOutPath = "C:\Reports\output"
$ReportOutFile = "$($ReportOutPath)\$((Get-Date).ToString('yyyy-MM-dd'))-$($ReportName).xlsx"
# WHAT ROW TO START THE DATA ON
$HeaderRow = 7
<#
    SCALE THE RENDERED PDF DOWN TO $Zoom
    SO IT WILL FIT WITHDH WISE ON THE PAGE
#>
$Zoom = 35
# VALUES: PORTRIAIT = 1, LANDSCAPE = 2
$Orientation = 2

# LOGO
$LogoPath = "C:\Reports\logo.png"

# SCALE TO SIZE
$LogoScale = .16

<#
    ENUMERATIONS FOR THE TABLE STYLES CAN BE FOUND HERE:
        https://learn.microsoft.com/en-us/javascript/api/excel/excel.builtintablestyle?view=excel-js-preview

    SO SWAP IT OUT FOR ONE YOU LIKE BETTER
#>
$TableName = "Activities"
$TableStyle = "TableStyleMedium9"

# GET FILES BASED ON FILTERS
$Filters = @(
    "objectType eq `"NAS`"",
    "and not exists (tags.skippedAcl or tags.skippedData or tags.skippedFiltered)",
    "and itemType eq `"file`""
)

function connect-dmapi {
<#
    .SYNOPSIS
    Connect to the PowerProtect Data Manager REST API.

    .DESCRIPTION
    Creates a credentials file for PowerProtect Data Manager if one does not exist.
    Connects to the PowerProtect Data Manager REST API

    .PARAMETER Server
    Specifies the FQDN of the PowerProtect Data Manager server.

    .OUTPUTS
    System.Object 
    $global:AuthObject

    .EXAMPLE
    PS> connect-ppdmapi -Server 'ppdm-01.vcorp.local'

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/docs/getting%20started/authentication-and-authorization.md

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [string]$Server
    )
    begin {
        # CHECK TO SEE IF CREDS FILE EXISTS IF NOT CREATE ONE
        $Exists = Test-Path -Path ".\$($Server).xml" -PathType Leaf
        if($Exists) {
            $Credential = Import-CliXml ".\$($Server).xml"
        } else {
            $Credential = Get-Credential
            $Credential | Export-CliXml ".\$($Server).xml"
        } 
    }
    process {
        $Login = @{
            username="$($Credential.username)"
            password="$(ConvertFrom-SecureString -SecureString $Credential.password -AsPlainText)"
        }
        # LOGON TO THE POWERPROTECT API 
        $Auth = Invoke-RestMethod -Uri "https://$($Server):$($Port)/api/$($ApiVersion)/login" `
                    -Method POST `
                    -ContentType 'application/json' `
                    -Body (ConvertTo-Json $Login) `
                    -SkipCertificateCheck
        $Object = @{
            server ="https://$($Server):$($Port)/api/$($ApiVersion)"
            token= @{
                authorization="Bearer $($Auth.access_token)"
            } #END TOKEN
        } #END AUTHOBJ

        $global:AuthObject = $Object

        $global:AuthObject | Format-List

    } #END PROCESS
} #END FUNCTION

function disconnect-dmapi {
<#
    .SYNOPSIS
    Disconnect from the PowerProtect Data Manager REST API.

    .DESCRIPTION
    Destroys the bearer token contained with $global:AuthObject

    .OUTPUTS
    System.Object 
    $global:AuthObject

    .EXAMPLE
    PS> disconnect-dmapi

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/docs/getting%20started/authentication-and-authorization.md

#>
    [CmdletBinding()]
    param (
    )
    begin {}
    process {
        #LOGOFF OF THE POWERPROTECT API
        Invoke-RestMethod -Uri "$($AuthObject.server)/logout" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        $global:AuthObject = $null
    }
} #END FUNCTION

function get-dmprotectionpolicies {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager protection policies
    
    .DESCRIPTION
    Get PowerProtect Data Manager protection policies based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get a protection policy
    PS> $Filters = @(
        "name eq `"Policy-VM01`""
    )
    PS>  $Policy = get-dmprotectionpolicies -Filters $Filters -PageSize 100

    .LINK
    https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1protection-policies/get

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [array]$Filters,
        [Parameter( Mandatory=$true)]
        [int]$PageSize
    )
    begin {}
    process {
        
        $Page = 1
        $Results = @()
        $Endpoint = "protection-policies"

        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)"
        }else {
            $Endpoint = "$($Endpoint)?"
        }
        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)pageSize=$($PageSize)&page=$($Page)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        # CAPTURE THE RESULTS
        $Results = $Query.content
        
        if($Query.page.totalPages -gt 1) {
            # INCREMENT THE PAGE NUMBER
            $Page++
            # PAGE THROUGH THE RESULTS
            do {
                $Paging = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)pageSize=$($PageSize)&page=$($Page)" `
                -Method GET `
                -ContentType 'application/json' `
                -Headers ($AuthObject.token) `
                -SkipCertificateCheck

                # CAPTURE THE RESULTS
                $Results += $Paging.content

                # INCREMENT THE PAGE NUMBER
                $Page++   
            } 
            until ($Paging.page.number -eq $Query.page.totalPages)
        }
        return $Results

    } # END PROCESS
}
function get-dmfileinstances {
<#
    .SYNOPSIS
    Get PowerProtect Data Manager file instances
    
    .DESCRIPTION
    Get PowerProtect Data Manager file instances based on filters

    .PARAMETER Filters
    An array of values used to filter the query

    .PARAMETER PageSize
    An int representing the desired number of elements per page

    .OUTPUTS
    System.Array

    .EXAMPLE
    PS> # Get file instances
    PS> $Filters = @(
        "objectType eq `"NAS`"",
        "and not exists (tags.skippedAcl or tags.skippedData or tags.skippedFiltered)",
        "and itemType eq `"file`""
    )
    PS>  $Query = get-dmfileinstances -Filters $Filters -PageSize $PageSize

#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [array]$Filters,
        [Parameter( Mandatory=$true)]
        [int]$PageSize
    )
    begin {}
    process {
        
        $Page = 1
        $Results = @()
        $Endpoint = "file-instances"

        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)&pageSize=$($PageSize)&page=$($Page)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck

        # CAPTURE THE RESULTS
        $Results = $Query.content
        
        if($Query.page.totalPages -gt 1) {
            # INCREMENT THE PAGE NUMBER
            $Page++
            # PAGE THROUGH THE RESULTS
            do {
                $Paging = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)&pageSize=$($PageSize)&page=$($Page)" `
                -Method GET `
                -ContentType 'application/json' `
                -Headers ($AuthObject.token) `
                -SkipCertificateCheck

                # CAPTURE THE RESULTS
                $Results += $Paging.content

                # INCREMENT THE PAGE NUMBER
                $Page++   
            } 
            until ($Paging.page.number -eq $Query.page.totalPages)
        }
        return $Results

    } # END PROCESS
}
Function Convert-BytesToSize
{
<#
    .SYNOPSIS
    Converts any integer size given to a user friendly size.
    
    .DESCRIPTION
    Converts any integer size given to a user friendly size.

    .PARAMETER size
    Used to convert into a more readable format.
    Required Parameter

    .EXAMPLE
    Convert-BytesToSize -Size 134217728
    Converts size to show 128MB

    .LINK
    https://learn-powershell.net/2010/08/29/convert-bytes-to-highest-available-unit/
#>

[CmdletBinding()]
Param
(
    [parameter(Mandatory=$false,Position=0)][int64]$Size

)

# DETERMINE SIZE IN BASE2
Switch ($Size)
{
    {$Size -gt 1PB}
    {
        $NewSize = “$([math]::Round(($Size /1PB),1))PB”
        Break;
    }
    {$Size -gt 1TB}
    {
        $NewSize = “$([math]::Round(($Size /1TB),1))TB”
        Break;
    }
    {$Size -gt 1GB}
    {
        $NewSize = “$([math]::Round(($Size /1GB),1))GB”
        Break;
    }
    {$Size -gt 1MB}
    {
        $NewSize = “$([math]::Round(($Size /1MB),1))MB”
        Break;
    }
    {$Size -gt 1KB}
    {
        $NewSize = “$([math]::Round(($Size /1KB),1))KB”
        Break;
    }
    Default
    {
        $NewSize = “$([math]::Round($Size,2))Bytes”
        Break;
    }
}
Return $NewSize

}


# ITERATE OVER THE PPDM HOSTS
$Files = @()
$Servers | ForEach-Object { 
    foreach($Retry in $Retires) {
        try {
            # CONNECT THE THE REST API
            connect-dmapi -Server $_
            # QUERY FILES
            $Query = get-dmfileinstances -Filters $Filters -PageSize $PageSize

            
            $Query | ForEach-Object {
                $Filters = @("id eq `"$($_.protectionPolicyId)`"")
                $Policy = get-dmprotectionpolicies -Filters $Filters -PageSize $PageSize
                $Object = [ordered]@{
                    id = $_.id
                    type = $_.type
                    itemType = $_.itemType
                    backupType = $_.backupType
                    name = $_.name
                    location = $_.location
                    size = Convert-BytesToSize -Size $_.size
                    copyStartDate = $_.copyStartDate
                    copyEndDate = $_.copyEndDate
                    updatedAt = $_.updatedAt
                    createdAt = $_.createdAt
                    protectionPolicyId = $_.protectionPolicyId
                    protectionPolicyName = $Policy.name
                    sourceServer = $_.sourceServer
                    assetName = $_.assetName
                    assetId = $_.assetId
                    diskLabel = $_.diskLabel
                    diskName = $_.diskName
                    objectType = $_.objectType
                }
                $Files += (New-Object -TypeName pscustomobject -Property $Object)
            }
        
            # DISCONNECT THE THE REST API
            disconnect-dmapi
            # BREAK OUT OF THE CURRENT LOOP (RETRIES)
            break;
        } catch {
            if($Retry -lt $Retires.length) {
                Write-Host "[WARNING]: $($_). Sleeping $($Seconds) seconds... Attempt #: $($Retry)" -ForegroundColor Yellow
                Start-Sleep -Seconds $Seconds
            } else {
                Write-Host "[ERROR]: $($_). Attempts: $($Retry), moving on..." -ForegroundColor Red
            }
        }
    } # END RETRIES
}

# LAUNCH EXCEL
$Excel = New-Object -ComObject excel.application 
$xlFixedFormat = "Microsoft.Office.Interop.Excel.xlFixedFormatType" -as [type]

# SURPRESS THE UI
$Excel.visible = $false

# CREATE A WORKBOOK
$Workbook = $Excel.Workbooks.Add()

# GET A HANDLE ON THE FIRST WORKSHEET
$Worksheet = $Workbook.Worksheets.Item(1)

# ADD A NAME TO THE FIRST WORKSHEET
$Worksheet.Name = "Activities"

# LOGO PROPERTIES
$Logo = New-Object System.Drawing.Bitmap $LogoPath

# ADD IMAGE TO THE FIRST WORKSHEET
$Logo = New-Object System.Drawing.Bitmap $LogoPath
$Worksheet.Shapes.AddPicture("$($LogoPath)",1,0,0,0,$Logo.Width*$LogoScale,$Logo.Height*$LogoScale) `
| Out-Null

# DEFINE THE HEADER ROW (row, column)
$Excel.cells.item($HeaderRow,1) = "row"
$Excel.cells.item($HeaderRow,2) = "id"
$Excel.cells.item($HeaderRow,3) = "type"
$Excel.cells.item($HeaderRow,4) = "itemType"
$Excel.cells.item($HeaderRow,5) = "backupType"
$Excel.cells.item($HeaderRow,6) = "name"
$Excel.cells.item($HeaderRow,7) = "location"
$Excel.cells.item($HeaderRow,8) = "size"
$Excel.cells.item($HeaderRow,9) = "copyStartDate"
$Excel.cells.item($HeaderRow,10) = "copyEndDate"
$Excel.cells.item($HeaderRow,11) = "updatedAt"
$Excel.cells.item($HeaderRow,12) = "createdAt"
$Excel.cells.item($HeaderRow,13) = "protectionPolicyName"
$Excel.cells.item($HeaderRow,14) = "sourceServer"
$Excel.cells.item($HeaderRow,15) = "assetName"
$Excel.cells.item($HeaderRow,16) = "assetId"
$Excel.cells.item($HeaderRow,17) = "diskLabel"
$Excel.cells.item($HeaderRow,18) = "diskName"
$Excel.cells.item($HeaderRow,19) = "objectType"

for($i=0;$i -lt $Files.length; $i++) {

    Write-Progress -Activity "Processing records..." `
    -Status "$($i-1) of $($Files.length) - $([math]::round((($i/$Files.length)*100),2))% " `
    -PercentComplete (($i/$Files.length)*100)
    
    # SET THE ROW OFFSET
    $RowOffSet = $HeaderRow+1+$i
    $Excel.cells.item($RowOffSet,1) = $i+1
    $Excel.cells.item($RowOffSet,2) = $Files[$i].id
    $Excel.cells.item($RowOffSet,3) = $Files[$i].type
    $Excel.cells.item($RowOffSet,4) = $Files[$i].itemType
    $Excel.cells.item($RowOffSet,5) = $Files[$i].backupType
    $Excel.cells.item($RowOffSet,6) = $Files[$i].name
    $Excel.cells.item($RowOffSet,7) = $Files[$i].location
    $Excel.cells.item($RowOffSet,8) = $Files[$i].size
    $Excel.cells.item($RowOffSet,9) = $Files[$i].copyStartDate
    $Excel.cells.item($RowOffSet,10) = $Files[$i].copyEndDate
    $Excel.cells.item($RowOffSet,11) = $Files[$i].updatedAt
    $Excel.cells.item($RowOffSet,12) = $Files[$i].createdAt
    $Excel.cells.item($RowOffSet,13) = $Files[$i].protectionPolicyName
    $Excel.cells.item($RowOffSet,14) = $Files[$i].sourceServer
    $Excel.cells.item($RowOffSet,15) = $Files[$i].assetName
    $Excel.cells.item($RowOffSet,16) = $Files[$i].assetId
    $Excel.cells.item($RowOffSet,17) = $Files[$i].diskLabel
    $Excel.cells.item($RowOffSet,18) = $Files[$i].diskName
    $Excel.cells.item($RowOffSet,19) = $Files[$i].objectType

}

<#
    SET CELLS FOR ALL ROWS TO 1.5 TIMES NORAML SIZE
    SET CELLS FOR ALL ROWS TO VERTICALLY ALIGN CENTER
    SO IT DOESN'T HIDE _ CHARACTERS WHEN EXPORTING TO PDF
#>
$WorksheetRange = $Worksheet.UsedRange
$WorksheetRange.EntireRow.RowHeight = $WorksheetRange.EntireRow.RowHeight * 1.5
$WorksheetRange.EntireRow.VerticalAlignment = `
    [Microsoft.Office.Interop.Excel.XLVAlign]::xlVAlignCenter

# AUTO SIZE COLUMNS
$WorksheetRange.EntireColumn.AutoFit() | Out-Null

# CREATE A TABLE IN EXCEL
$TableObject = $Excel.ActiveSheet.ListObjects.Add(`
    [Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,`
    $Worksheet.UsedRange,$null,[Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes `
)
# TABLE NAME & STYLE
$TableObject.Name = $TableName
$TableObject.TableStyle = $TableStyle

# EXPORT TO PDF
if($PDF) {
    # PDF SETTINGS
    $Worksheet.PageSetup.Zoom = $Zoom
    $Worksheet.PageSetup.Orientation = $Orientation
    $ReportOutFile = "$($ReportOutPath)\$((Get-Date).ToString('yyyy-MM-dd'))-$($ReportName).pdf"
    $Worksheet.ExportAsFixedFormat($xlFixedFormat::xlTypePDF,$ReportOutFile)
} else {
    $Workbook.SaveAs($ReportOutFile) 
}

# EXIT EXCEL
$Excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null 
Stop-Process -Name "EXCEL"