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

# GLOBAL VARS
$global:ApiVersion = 'v2'
$global:Port = 8443
$global:AuthObject = $null

# VARS
$Servers = @(
    "myfakehost.vcorp.local"
    "10.239.100.131"
)
$Retires = @(1..5)
$Seconds = 10
$PageSize = 100
$ReportName = "ActivityReport"
$OutPath = "C:\Reports"
$OutFile = "$($OutPath)\$((Get-Date).ToString('yyyy-MM-dd'))-$($ReportName).xlsx"
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
    "and startTime ge `"$($Date.ToString('yyyy-MM-dd'))T00:00:00.000Z`""
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

            foreach($Item in $Query) {
                $Policy = $Policies | Where-Object {$_.id -eq $Item.protectionPolicy.id}
                $Protection = $Policy.stages | where-object {$_.type -eq "PROTECTION"}
                $Replication = $Policy.stages | where-object {$_.type -eq "REPLICATION"}
                $storageMtree = $Mtrees | Where-Object {$_.id -eq $Protection.target.dataTargetId}
                $replicationMtree = $Mtrees | Where-Object {$_.id -eq $Replication.target.dataTargetId}
        
                $Object = [ordered]@{
                    assetName = $Item.asset.name
                    assetType = $Item.asset.type
                    jobId = $Item.id
                    ppdmServer = $_
                    policyName = $Item.protectionPolicy.name
                    scheduleType = $Protection.operations.schedule.frequency
                    startTime = $Item.startTime
                    endTime = $Item.endTime
                    duration = $Item.duration
                    nextScheduledTime = $Item.nextScheduledTime
                    jobStatus = $Item.result.status
                    assetSize = $Item.stats.assetSizeInBytes
                    bytesTransferred = $Item.stats.bytesTransferredThroughput
                    storageTarget = "$($Item.storageSystem.name)/$($storageMtree.name)"
                    replicationTarget = "$($replicationMtree._embedded.storageSystem.name)/$($replicationMtree.name)"
                    hostName = $Item.host.name

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

# DEFINE THE HEADER ROW (row, column)
$Excel.cells.item(1,1) = "row"
$Excel.cells.item(1,2) = "assetName"
$Excel.cells.item(1,3) = "assetType"
$Excel.cells.item(1,4) = "jobId"
$Excel.cells.item(1,5) = "ppdmServer"
$Excel.cells.item(1,6) = "policyName"
$Excel.cells.item(1,7) = "scheduleType"
$Excel.cells.item(1,8) = "startTime"
$Excel.cells.item(1,9) = "endTime"
$Excel.cells.item(1,10) = "duration (ms)"
$Excel.cells.item(1,11) = "nextScheduledTime"
$Excel.cells.item(1,12) = "jobStatus"
$Excel.cells.item(1,13) = "assetSize"
$Excel.cells.item(1,14) = "bytesTransferred"
$Excel.cells.item(1,15) = "storageTarget"
$Excel.cells.item(1,16) = "replicationTarget"

for($i=0;$i -lt $Activities.count; $i++) {

    Write-Progress -Activity "Processing records..." `
    -Status "$($i-1) of $($Activities.count) - $([math]::round((($i/$Activities.count)*100),2))% " `
    -PercentComplete (($i/$Activities.count)*100)
    
    $Excel.cells.item($i+2,1) = $i+1
    $Excel.cells.item($i+2,2) = $Activities[$i].assetName
    $Excel.cells.item($i+2,3) = $Activities[$i].assetType
    $Excel.cells.item($i+2,4) = $Activities[$i].jobId
    $Excel.cells.item($i+2,5) = $Activities[$i].ppdmServer
    $Excel.cells.item($i+2,6) = $Activities[$i].policyName
    $Excel.cells.item($i+2,7) = $Activities[$i].scheduleType -join ','
    $Excel.cells.item($i+2,8) = $Activities[$i].startTime
    $Excel.cells.item($i+2,9) = $Activities[$i].endTime
    $Excel.cells.item($i+2,10) = $Activities[$i].duration
    $Excel.cells.item($i+2,11) = $Activities[$i].nextScheduledTime

    if($Activities[$i].jobStatus -eq "FAILED") {
        $Excel.cells.item($i+2,12).Interior.ColorIndex = 3 
    }
    
    $Excel.cells.item($i+2,12) = $Activities[$i].jobStatus
    $Excel.cells.item($i+2,13) = $Activities[$i].assetSize
    $Excel.cells.item($i+2,14) = $Activities[$i].bytesTransferred
    $Excel.cells.item($i+2,15) = $Activities[$i].storageTarget
    $Excel.cells.item($i+2,16) = $Activities[$i].replicationTarget

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
    # LANDSCAPE
    $Worksheet.PageSetup.Orientation = 2
    # ZOOM
    $Worksheet.PageSetup.Zoom = 30
    $OutFile = "$($OutPath)\$((Get-Date).ToString('yyyy-MM-dd'))-$($ReportName).pdf"
    $Worksheet.ExportAsFixedFormat($xlFixedFormat::xlTypePDF,$OutFile)
} else {
    $Workbook.SaveAs($OutFile) 
}

# EXIT EXCEL
$Excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null 
Stop-Process -Name "EXCEL"