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
$ReportName = "ActivityReport"
$ReportOutPath = "C:\Reports\output"
$ReportOutFile = "$($ReportOutPath)\$((Get-Date).ToString('yyyy-MM-dd'))-$($ReportName).xlsx"
# WHAT ROW TO START THE DATA ON
$HeaderRow = 7
<#
    SCALE THE RENDERED PDF DOWN TO $Zoom
    SO IT WILL FIT WITHDH WISE ON THE PAGE
#>
$Zoom = 25
# VALUES: PORTRIAIT = 1, LANDSCAPE = 2
$Orientation = 2

# LOGO
$LogoPath = "C:\Reports\logo.png"

# SCALE TO SIZE
$LogoScale = .28

<#
    ENUMERATIONS FOR THE TABLE STYLES CAN BE FOUND HERE:
        https://learn.microsoft.com/en-us/javascript/api/excel/excel.builtintablestyle?view=excel-js-preview

    SO SWAP IT OUT FOR ONE YOU LIKE BETTER
#>
$TableName = "Activities"
$TableStyle = "TableStyleMedium9"

# GET ACTIVITIES BASED ON FILTERS
$Date = (Get-Date).AddDays(-1)
$Filters = @(
    "classType eq `"JOB`""
    "and category eq `"PROTECT`""
    "and startTime ge `"$($Date.ToString('yyyy-MM-ddThh:mm:ss.fffZ'))`""
    # "and asset.name eq `"ORAPROD`""
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

function get-dmactivities {
    <#
        .SYNOPSIS
        Get PowerProtect Data Manager activities
    
        .DESCRIPTION
        Get PowerProtect Data Manager activities based on filters
    
        .PARAMETER Filters
        An array of values used to filter the query
    
        .PARAMETER PageSize
        An int representing the desired number of elements per page
    
        .OUTPUTS
        System.Array
    
        .EXAMPLE
        PS> # GET ACTIVITIES BASED ON A FILTER
        PS> $Date = (Get-Date).AddDays(-1)
        PS> $Filters = @(
        "classType eq `"JOB`""
        "and category eq `"PROTECT`""
        "and startTime ge `"$($Date.ToString('yyyy-MM-dd'))T00:00:00.000Z`""
        "and result.status eq `"FAILED`""
        )
        PS> $Activities = get-dmactivities -Filters $Filters -PageSize $PageSize
    
        .EXAMPLE
        PS> # GET ALL ACTIVITIES
        PS> $Activities = get-dmactivities -PageSize $PageSize
    
        .LINK
        https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1activities/get
    
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
        $Results = @()
        $Endpoint = "activities"
        
        if($Filters.Length -gt 0) {
            $Join = ($Filters -join ' ') -replace '\s','%20' -replace '"','%22'
            $Endpoint = "$($Endpoint)?filter=$($Join)&pageSize=$($PageSize)"
        } else {
            $Endpoint = "$($Endpoint)?pageSize=$($PageSize)"
        }

        $Query =  Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)&queryState=BEGIN" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObject.token) `
        -SkipCertificateCheck
        $Results += $Query.content

        $Page = 1
        do {
            $Token = "$($Query.page.queryState)"
            if($Page -gt 1) {
                $Token = "$($Paging.page.queryState)"
            }
            $Paging = Invoke-RestMethod -Uri "$($AuthObject.server)/$($Endpoint)&queryState=$($Token)" `
            -Method GET `
            -ContentType 'application/json' `
            -Headers ($AuthObject.token) `
            -SkipCertificateCheck
            $Results += $Paging.content

            $Page++;
        } 
        until ($Paging.page.queryState -eq "END")
        return $Results
    }
}
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
function get-dmmtrees {
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
        PS> # Get dd mtrees
        PS>  $Mtrees = get-dmmtrees -PageSize 100
    
        .LINK
        https://developer.dell.com/apis/4378/versions/19.14.0/reference/ppdm-public.yaml/paths/~1api~1v2~1datadomain-mtrees/get
    
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
        $Endpoint = "datadomain-mtrees"

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


#Requires -version 2.0


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
$Activities = @()
$Servers | ForEach-Object { 
    foreach($Retry in $Retires) {
        try {
            # CONNECT THE THE REST API
            connect-dmapi -Server $_
            # QUERY FOR THE ACTIVITIES
            $Query = get-dmactivities -Filters $Filters -PageSize $PageSize
            
            # QUERY FOR POLICIES
            $Mtrees = get-dmmtrees -PageSize $PageSize

            # QUERY FOR POLICIES
            $Policies = get-dmprotectionpolicies -PageSize $PageSize

            foreach($Record in $Query) {
                $Policy = $Policies | Where-Object {$_.id -eq $Record.protectionPolicy.id}
                $Protection = $Policy.stages | where-object {$_.type -eq "PROTECTION"}
                $Replication = $Policy.stages | where-object {$_.type -eq "REPLICATION"}
                $storageMtree = $Mtrees | Where-Object {$_.id -eq $Protection.target.dataTargetId}
                $replicationMtree = $Mtrees | Where-Object {$_.id -eq $Replication.target.dataTargetId}
                $timeSpan = New-TimeSpan -Milliseconds $Record.duration

                $Object = [ordered]@{
                    assetName = $Record.asset.name
                    assetType = $Record.asset.type
                    jobId = $Record.id
                    ppdmServer = $_
                    policyName = $Record.protectionPolicy.name
                    scheduleType = $Record.scheduleInfo.type
                    startTime = $Record.startTime
                    endTime = $Record.endTime
                    duration = "{0:dd}d:{0:hh}h:{0:mm}m:{0:ss}s" -f $timeSpan
                    nextScheduledTime = $Record.nextScheduledTime
                    jobStatus = $Record.result.status
                    assetSize = Convert-BytesToSize -Size $Record.stats.assetSizeInBytes
                    bytesTransferred = Convert-BytesToSize -Size $Record.stats.bytesTransferred
                    storageTarget = "$($Record.storageSystem.name)/$($storageMtree.name)"
                    replicationTarget = "$($replicationMtree._embedded.storageSystem.name)/$($replicationMtree.name)"
                    hostName = $Record.host.name

                }

                $Activities += New-Object -TypeName psobject -Property $Object
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
$Excel.cells.item($HeaderRow,2) = "hostName"
$Excel.cells.item($HeaderRow,3) = "assetName"
$Excel.cells.item($HeaderRow,4) = "assetType"
$Excel.cells.item($HeaderRow,5) = "jobId"
$Excel.cells.item($HeaderRow,6) = "ppdmServer"
$Excel.cells.item($HeaderRow,7) = "policyName"
$Excel.cells.item($HeaderRow,8) = "scheduleType"
$Excel.cells.item($HeaderRow,9) = "startTime"
$Excel.cells.item($HeaderRow,10) = "endTime"
$Excel.cells.item($HeaderRow,11) = "duration (dd:hh:mm:ss)"
$Excel.cells.item($HeaderRow,12) = "nextScheduledTime"
$Excel.cells.item($HeaderRow,13) = "jobStatus"
$Excel.cells.item($HeaderRow,14) = "assetSize"
$Excel.cells.item($HeaderRow,15) = "bytesTransferred"
$Excel.cells.item($HeaderRow,16) = "storageTarget"
$Excel.cells.item($HeaderRow,17) = "replicationTarget"

for($i=0;$i -lt $Activities.length; $i++) {

    Write-Progress -Activity "Processing records..." `
    -Status "$($i-1) of $($Activities.length) - $([math]::round((($i/$Activities.length)*100),2))% " `
    -PercentComplete (($i/$Activities.length)*100)
    
    # SET THE ROW OFFSET
    $RowOffSet = $HeaderRow+1+$i
    $Excel.cells.item($RowOffSet,1) = $i+1
    $Excel.cells.item($RowOffSet,2) = $Activities[$i].hostName
    $Excel.cells.item($RowOffSet,3) = $Activities[$i].assetName
    $Excel.cells.item($RowOffSet,4) = $Activities[$i].assetType
    $Excel.cells.item($RowOffSet,5) = $Activities[$i].jobId
    $Excel.cells.item($RowOffSet,6) = $Activities[$i].ppdmServer
    $Excel.cells.item($RowOffSet,7) = $Activities[$i].policyName
    $Excel.cells.item($RowOffSet,8) = $Activities[$i].scheduleType -join ','
    $Excel.cells.item($RowOffSet,9) = $Activities[$i].startTime
    $Excel.cells.item($RowOffSet,10) = $Activities[$i].endTime
    $Excel.cells.item($RowOffSet,11) = $Activities[$i].duration
    $Excel.cells.item($RowOffSet,12) = $Activities[$i].nextScheduledTime

    if($Activities[$i].jobStatus -eq "FAILED") {
        $Excel.cells.item($RowOffSet,13).Interior.ColorIndex = 3 
    }
    
    $Excel.cells.item($RowOffSet,13) = $Activities[$i].jobStatus
    $Excel.cells.item($RowOffSet,14) = $Activities[$i].assetSize
    $Excel.cells.item($RowOffSet,15) = $Activities[$i].bytesTransferred
    $Excel.cells.item($RowOffSet,16) = $Activities[$i].storageTarget
    $Excel.cells.item($RowOffSet,17) = $Activities[$i].replicationTarget

}

<#
    SET CELLS FOR ALL ROWS TO 1.5 TIMES NORAML SIZE
    SET CELLS FOR ALL ROWS TO VERTICALLY ALIGN CENTER
    SO IT DOESN'T HIDE _ CHARACTERS WHEN EXPORTING TO PDF
#>
$WorksheetRange = $Worksheet.UsedRange
$WorksheetRange.EntireRow.RowHeight = $WorksheetRange.EntireRow.RowHeight * 1.5
$WorksheetRange.EntireRow.VerticalAlignment = [Microsoft.Office.Interop.Excel.XLVAlign]::xlVAlignCenter

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