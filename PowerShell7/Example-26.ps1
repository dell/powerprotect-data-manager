<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/powershell/releases

#>
Import-Module .\dell.ppdm.psm1 -Force

# VARS
$Server = "ppdm-01.vcorp.local"
$PageSize = 100
$Poll = 15
$Recover = @()
$SourceDatabase = "data_warehouse_s01"
$SourceSqlHost = "win-sql-01.vcorp.local"

$TargetSqlHosts = @(
    @{
        name="win-sql-02.vcorp.local"
        dbAltName = "test_restore_s02"
        dbAltPath = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA"
        logAltPath = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA"
        forceDatabaseOverwrite = $false
        enableDebug = $false
        enableCompressedRestore = $false
        disconnectDatabaseUsers = $false
    },
    @{
        name="win-sql-03.vcorp.local"
        dbAltName = "test_restore_s03"
        dbAltPath = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA"
        logAltPath = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA"
        forceDatabaseOverwrite = $false
        enableDebug = $false
        enableCompressedRestore = $false
        disconnectDatabaseUsers = $false
    },
    @{
        name="win-sql-04.vcorp.local"
        dbAltName = "test_restore_s04"
        dbAltPath = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA"
        logAltPath = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA"
        forceDatabaseOverwrite = $false
        enableDebug = $false
        enableCompressedRestore = $false
        disconnectDatabaseUsers = $false
    }
)

# CONNECT THE THE REST API
connect-dmapi -Server $Server

# GET ASSETS BASED ON FILTERS
$Filters = @(
    "name eq `"$($SourceDatabase)`""
    "and details.database.clusterName eq `"$($SourceSqlHost)`""
)

$Asset = get-dmassets -Filters $Filters -PageSize $PageSize

# GET THE LATEST FULL COPY 
$Filters = @(
    "assetId in (`"$($Asset.id)`")",
    "and copyType in (`"FULL`")",
    "and replicatedCopy eq false",
    "and location in (`"LOCAL`", `"LOCAL_RECALLED`")",
    "and not state in (`"DELETED`", `"DELETING`", `"SOFT_DELETED`", `"DELETE_FAILED`")"
)

$LatestCopy = get-dmlatestcopies -Filters $Filters -PageSize $PageSize

# ITERATE OVER THE DEFINED SQL HOSTS
$TargetSqlHosts | foreach-object {
    $Filters = @(
        "name eq `"$($_.name)`""
        "and attributes.appHost.protectionEngineFlow eq `"APPDIRECT`"",
        "and not (lastDiscoveryStatus eq `"DELETED`")",
        "and attributes.appHost.os eq `"WINDOWS`""
    )
    $Node = get-dminfrastructurenodes -Filters $Filters -Type MICROSOFT_SQL_DATABASE_VIEW -PageSize $PageSize
    
    $Filters = @(
        "clusterType in (`"NONE`", `"FCI`")",
        "and lastDiscoveryStatus eq `"NEW`""
    )
    
    $AppSys = get-dminfrastructurenodeschildren -Id $Node.id -Filters $Filters -Type MICROSOFT_SQL_DATABASE_VIEW -PageSize $PageSize

    $Body = [ordered]@{
        restoreType = "TO_ALTERNATE"
        description = "Restore to alternate location custom location"
        copyIds = [array]$LatestCopy.id
        restoredCopiesDetails = @{
            targetDatabaseInfo = [ordered]@{
                hostId = $Node.details.host.id
                applicationSystemId = $AppSys.details.appServer.id
                assetName = $_.dbAltName
            }
        }
        options= [ordered]@{
            forceDatabaseOverwrite = $_.forceDatabaseOverwrite
            enableDebug = $_.enableDebug
            recoveryState = "RECOVERY"
            enableCompressedRestore = $_.enableCompressedRestore
            disconnectDatabaseUsers = $_.disconnectDatabaseUsers
            fileRelocationOptions = [ordered]@{
                type="CUSTOM_LOCATION"
                targetDataFileLocation = $_.dbAltPath
                targetLogFileLocation = $_.logAltPath
            }
        }
    }
    # KICK OFF THE RECOVERY AND GRAB YHE ACTIVITY ID
    $Recover += new-dmrecover -Body $Body

}
# MONITOR THE ACTIVITIES
$Recover | Foreach-Object {
    new-dmmonitor -ActivityId $_.activityId -Poll $Poll
} 

# DISCONNECT FROM THE REST API
disconnect-dmapi