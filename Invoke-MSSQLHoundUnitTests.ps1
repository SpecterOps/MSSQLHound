# PowerShell MSSQL Collector Unit Test Kit for BloodHound OpenGraph
#   by Chris Thompson (@_Mayyhem) at SpecterOps
#
# Required Permissions:
#   - MSSQL sysadmin server role

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ServerInstance="ps1-db.mayyhem.com",
    
    [Parameter(Mandatory=$false)]
    [string]$EnumerationScript = ".\MSSQLHound.ps1",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Setup", "Test", "Coverage", "Report", "Teardown", "MissingTests")]
    [string]$Action = "All",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("offensive", "defensive", "both")]
    [string]$Perspective = "offensive",

    # Credentials used to create test objects -- must be sysadmin
    [Parameter(Mandatory=$false)]
    [string]$UserID,#="test",

    [Parameter(Mandatory=$false)]
    [string]$Password,#="password",

    [Parameter(Mandatory=$false)]
    [string]$LogFile = $null,

    [Parameter(Mandatory=$false)]
    [string]$LimitToEdge = "",

    [Parameter(Mandatory=$false)]
    [string]$InputFile = "",

    [switch]$SkipCreateDomainUsers,
    [switch]$SkipDomainObjects,
    [switch]$SkipHTMLReport,

    [Parameter(Mandatory=$false)]
    [switch]$ShowDebugOutput
)

# If InputFile is specified, default to Test action (unless explicitly overridden)
if ($InputFile -and $PSBoundParameters.ContainsKey('Action') -eq $false) {
    $Action = "Test"
    Write-Host "[INFO] InputFile specified, defaulting to -Action Test" -ForegroundColor Cyan
}

# Save debug flag at script level
$script:ShowDebugOutput = $ShowDebugOutput

# Script-wide variables
$script:TestResults = @{
    Timestamp = Get-Date
    ServerInstance = $ServerInstance
    Domain = $Domain
    SetupSuccess = $false
    TestRuns = @()
    Coverage = @{}
}

# Define edge types by perspective
# Edges with test coverage have a # after the edge name
$script:OffensiveOnlyEdges = @(
    "MSSQL_AddMember", #
    "MSSQL_Alter", #
    "MSSQL_ChangeOwner", #
    "MSSQL_ChangePassword", #
    "MSSQL_Control", #
    "MSSQL_ExecuteAs", #
    "MSSQL_Impersonate" #
)

$script:DefensiveOnlyEdges = @(
    "MSSQL_AlterDB",
    "MSSQL_AlterDBRole",
    "MSSQL_AlterServerRole",
    "MSSQL_ControlDBRole",
    "MSSQL_ControlDBUser",
    "MSSQL_ControlLogin",
    "MSSQL_ControlServerRole",
    "MSSQL_DBTakeOwnership",
    "MSSQL_ImpersonateDBUser",
    "MSSQL_ImpersonateLogin"
)

$script:BothPerspectivesEdges = @(
    "CoerceAndRelayToMSSQL", #
    "HasSession", #
    "MSSQL_AlterAnyAppRole", #
    "MSSQL_AlterAnyDBRole", #
    "MSSQL_AlterAnyLogin", #
    "MSSQL_AlterAnyServerRole", #
    "MSSQL_Connect", #
    "MSSQL_ConnectAnyDatabase", #
    "MSSQL_Contains", #
    "MSSQL_ControlDB", #
    "MSSQL_ControlServer", #
    "MSSQL_ExecuteAsOwner", #
    "MSSQL_ExecuteOnHost", #
    "MSSQL_GetAdminTGS", #
    "MSSQL_GetTGS", #
    "MSSQL_GrantAnyDBPermission", #
    "MSSQL_GrantAnyPermission", #
    "MSSQL_HasDBScopedCred", #
    "MSSQL_HasLogin", #
    "MSSQL_HasMappedCred", #
    "MSSQL_HasProxyCred", #
    "MSSQL_HostFor", #
    "MSSQL_ImpersonateAnyLogin", #
    "MSSQL_IsMappedTo", #
    "MSSQL_IsTrustedBy", #
    "MSSQL_LinkedAsAdmin", #
    "MSSQL_LinkedTo", #
    "MSSQL_MemberOf", #
    "MSSQL_Owns", #
    "MSSQL_ServiceAccountFor", #
    "MSSQL_TakeOwnership" #
)

# Combine all edge types
$script:AllEdgeTypes = $script:OffensiveOnlyEdges + $script:DefensiveOnlyEdges + $script:BothPerspectivesEdges | Sort-Object

$script:CleanupSQL = @'
USE master;
GO

-- First, kill all connections to EdgeTest databases
DECLARE @kill NVARCHAR(MAX);
SET @kill = '';
DECLARE @sql NVARCHAR(MAX);

-- Get SQL Server version
DECLARE @version INT;
SET @version = CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR(20)), 4) AS INT);

-- Build the kill command dynamically based on version
IF @version >= 10  -- SQL Server 2008 and later
BEGIN
    SET @sql = '
    SELECT @killList = @killList + ''KILL '' + CAST(session_id AS VARCHAR(10)) + ''; ''
    FROM sys.dm_exec_sessions
    WHERE database_id IN (SELECT database_id FROM sys.databases WHERE name LIKE ''EdgeTest_%'' OR name LIKE ''ExecuteAsOwnerTest_%'')';
    
    EXEC sp_executesql @sql, N'@killList NVARCHAR(MAX) OUTPUT', @killList = @kill OUTPUT;
END
ELSE  -- SQL Server 2005
BEGIN
    SELECT @kill = @kill + 'KILL ' + CAST(spid AS VARCHAR(10)) + '; '
    FROM sys.sysprocesses
    WHERE dbid IN (SELECT dbid FROM sys.sysdatabases WHERE name LIKE 'EdgeTest_%' OR name LIKE 'ExecuteAsOwnerTest_%');
END

IF @kill != ''
BEGIN
    BEGIN TRY
        EXEC(@kill);
    END TRY
    BEGIN CATCH
        PRINT 'Some connections could not be killed';
    END CATCH
END
GO

-- Drop all test databases first (this resolves login ownership issues)
DECLARE @sql NVARCHAR(MAX);
SET @sql = '';
SELECT @sql = @sql + 
    'IF EXISTS (SELECT * FROM sys.databases WHERE name = ''' + name + ''')
    BEGIN
        ALTER DATABASE [' + name + '] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
        DROP DATABASE [' + name + '];
    END
    '
FROM sys.databases 
WHERE name LIKE 'EdgeTest_%' OR name LIKE 'ExecuteAsOwnerTest_%';

IF @sql != ''
BEGIN
    EXEC sp_executesql @sql;
END
GO

-- Remove all role members before dropping roles
DECLARE @roleName NVARCHAR(128);
DECLARE @memberName NVARCHAR(128);
DECLARE @sql2 NVARCHAR(MAX);
DECLARE @memberCursorSQL NVARCHAR(MAX);

-- Check SQL Server version for is_fixed_role support
DECLARE @version2 INT;
SET @version2 = CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR(20)), 4) AS INT);

IF @version2 >= 11  -- SQL Server 2012+
BEGIN
    SET @memberCursorSQL = '
    DECLARE role_member_cursor CURSOR FOR
        SELECT r.name as RoleName, p.name as MemberName
        FROM sys.server_role_members rm
        JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
        JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
        WHERE r.type = ''R'' 
        AND r.is_fixed_role = 0
        AND r.name LIKE ''%Test_%'';';
END
ELSE  -- SQL Server 2005-2008 R2
BEGIN
    SET @memberCursorSQL = '
    DECLARE role_member_cursor CURSOR FOR
        SELECT r.name as RoleName, p.name as MemberName
        FROM sys.server_role_members rm
        JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
        JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
        WHERE r.type = ''R'' 
        AND r.name NOT IN (''sysadmin'', ''securityadmin'', ''serveradmin'', ''setupadmin'', ''processadmin'', ''diskadmin'', ''dbcreator'', ''bulkadmin'', ''public'')
        AND r.name LIKE ''%Test_%'';';
END

EXEC sp_executesql @memberCursorSQL;

OPEN role_member_cursor;
FETCH NEXT FROM role_member_cursor INTO @roleName, @memberName;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        SET @sql2 = 'ALTER SERVER ROLE [' + @roleName + '] DROP MEMBER [' + @memberName + ']';
        EXEC(@sql2);
        PRINT 'Removed ' + @memberName + ' from role ' + @roleName;
    END TRY
    BEGIN CATCH
        PRINT 'Could not remove member from role: ' + ERROR_MESSAGE();
    END CATCH
    
    FETCH NEXT FROM role_member_cursor INTO @roleName, @memberName;
END

CLOSE role_member_cursor;
DEALLOCATE role_member_cursor;
GO

-- Now drop all test server roles
DECLARE @roleName2 NVARCHAR(128);
DECLARE @roleCursorSQL NVARCHAR(MAX);
DECLARE @version3 INT;
SET @version3 = CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR(20)), 4) AS INT);

IF @version3 >= 11  -- SQL Server 2012+
BEGIN
    SET @roleCursorSQL = '
    DECLARE role_cursor CURSOR FOR
        SELECT name FROM sys.server_principals 
        WHERE type = ''R'' 
        AND is_fixed_role = 0
        AND name LIKE ''%Test_%'';';
END
ELSE  -- SQL Server 2005-2008 R2
BEGIN
    SET @roleCursorSQL = '
    DECLARE role_cursor CURSOR FOR
        SELECT name FROM sys.server_principals 
        WHERE type = ''R'' 
        AND name NOT IN (''sysadmin'', ''securityadmin'', ''serveradmin'', ''setupadmin'', ''processadmin'', ''diskadmin'', ''dbcreator'', ''bulkadmin'', ''public'')
        AND name LIKE ''%Test_%'';';
END

EXEC sp_executesql @roleCursorSQL;

OPEN role_cursor;
FETCH NEXT FROM role_cursor INTO @roleName2;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        EXEC('DROP SERVER ROLE [' + @roleName2 + ']');
        PRINT 'Dropped server role: ' + @roleName2;
    END TRY
    BEGIN CATCH
        PRINT 'Could not drop server role: ' + @roleName2 + ' - ' + ERROR_MESSAGE();
    END CATCH
    
    FETCH NEXT FROM role_cursor INTO @roleName2;
END

CLOSE role_cursor;
DEALLOCATE role_cursor;
GO

-- Drop all test logins
DECLARE @loginName NVARCHAR(128);
DECLARE login_cursor CURSOR FOR
    SELECT name FROM sys.server_principals 
    WHERE type IN ('S', 'U', 'G')
    AND name LIKE '%Test%';

OPEN login_cursor;
FETCH NEXT FROM login_cursor INTO @loginName;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        EXEC('DROP LOGIN [' + @loginName + ']');
        PRINT 'Dropped login: ' + @loginName;
    END TRY
    BEGIN CATCH
        PRINT 'Could not drop login: ' + @loginName + ' - ' + ERROR_MESSAGE();
    END CATCH
    
    FETCH NEXT FROM login_cursor INTO @loginName;
END

CLOSE login_cursor;
DEALLOCATE login_cursor;
GO

-- Drop credentials
IF EXISTS (SELECT * FROM sys.credentials WHERE name LIKE 'EdgeTest_%')
BEGIN
    DECLARE @credName NVARCHAR(128);
    DECLARE cred_cursor CURSOR FOR
        SELECT name FROM sys.credentials WHERE name LIKE 'EdgeTest_%';
    
    OPEN cred_cursor;
    FETCH NEXT FROM cred_cursor INTO @credName;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC('DROP CREDENTIAL [' + @credName + ']');
            PRINT 'Dropped credential: ' + @credName;
        END TRY
        BEGIN CATCH
            PRINT 'Could not drop credential: ' + @credName;
        END CATCH
        
        FETCH NEXT FROM cred_cursor INTO @credName;
    END
    
    CLOSE cred_cursor;
    DEALLOCATE cred_cursor;
END
GO

-- Drop linked servers
IF EXISTS (SELECT * FROM sys.servers WHERE is_linked = 1 AND name LIKE '%TESTLINKEDTO%')
BEGIN
    DECLARE @linkedName NVARCHAR(128);
    DECLARE linked_cursor CURSOR FOR
        SELECT name FROM sys.servers WHERE is_linked = 1 AND name LIKE '%TESTLINKEDTO%';
    
    OPEN linked_cursor;
    FETCH NEXT FROM linked_cursor INTO @linkedName;
    
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC sp_dropserver @linkedName, 'droplogins';
            PRINT 'Dropped linked server: ' + @linkedName;
        END TRY
        BEGIN CATCH
            PRINT 'Could not drop linked server: ' + @linkedName;
        END CATCH
        
        FETCH NEXT FROM linked_cursor INTO @linkedName;
    END
    
    CLOSE linked_cursor;
    DEALLOCATE linked_cursor;
END
GO

PRINT 'Cleanup completed';
'@

#region Helper Functions

function Write-TestLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Test", "Debug")]
        [string]$Level = "Info"
    )
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Test" { "Cyan" }
        "Debug" { "Magenta" }
    }
    
    $prefix = switch ($Level) {
        "Info" { "[INFO]" }
        "Success" { "[$([char]0x2713)]" }
        "Warning" { "[!]" }
        "Error" { "[$([char]0x2717)]" }
        "Test" { "[TEST]" }
        "Debug" { "[DEBUG]" }
    }
    
    # Skip empty messages and single "=" characters
    if ([string]::IsNullOrWhiteSpace($Message) -or $Message -eq "=") {
        return
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp $prefix $Message"
    
    # Write to console
    Write-Host "$prefix $Message" -ForegroundColor $color
    
    # Write to log file if specified
    if ($script:LogFile) {
        $logMessage | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }
}

# Helper function to extract and read MSSQL output from ZIP
function Get-MSSQLOutputFromZip {
    param(
        [string]$ZipPattern = "mssql-bloodhound-*.zip",
        [string]$SpecificFile = ""
    )

    # If a specific file is provided, use it directly
    if ($SpecificFile) {
        if (-not (Test-Path $SpecificFile)) {
            Write-TestLog "Specified file not found: $SpecificFile" -Level Error
            return $null
        }
        $zipFile = Get-Item $SpecificFile
        Write-TestLog "Using specified ZIP file: $($zipFile.FullName)" -Level Info
    }
    else {
        # Find the most recent ZIP file matching the pattern
        $zipFiles = Get-ChildItem -Path . -Filter $ZipPattern | Sort-Object LastWriteTime -Descending
        if (-not $zipFiles) {
            return $null
        }
        $zipFile = $zipFiles[0]
        Write-TestLog "Found ZIP file: $($zipFile.FullName)" -Level Info
    }
    
    # Create temp directory for extraction
    $tempDir = Join-Path $env:TEMP "MSSQLEnum_$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    try {
        # Extract ZIP
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile.FullName, $tempDir)
        
        # Find all JSON files in the extracted content
        $jsonFiles = Get-ChildItem -Path $tempDir -Filter "*.json" -Recurse
        Write-TestLog "Found $($jsonFiles.Count) JSON files in ZIP" -Level Info
        
        # Combine all nodes and edges from all files
        $combinedOutput = @{
            graph = @{
                nodes = @()
                edges = @()
            }
        }
        
        foreach ($jsonFile in $jsonFiles) {
            Write-TestLog "Reading JSON from: $($jsonFile.Name)" -Level Info
            $content = Get-Content $jsonFile.FullName -Raw | ConvertFrom-Json
            
            # Add nodes and edges to combined output
            if ($content.graph) {
                if ($content.graph.nodes) {
                    $combinedOutput.graph.nodes += $content.graph.nodes
                }
                if ($content.graph.edges) {
                    $combinedOutput.graph.edges += $content.graph.edges
                }
            }
        }
        
        Write-TestLog "Combined output: $($combinedOutput.graph.nodes.Count) nodes, $($combinedOutput.graph.edges.Count) edges" -Level Info
        
        # Clean up temp directory
        Remove-Item $tempDir -Recurse -Force

        # Clean up ZIP file only if it was auto-detected (not user-specified)
        if (-not $SpecificFile) {
            Remove-Item $zipFile.FullName -Force
            Write-TestLog "Cleaned up ZIP file: $($zipFile.Name)" -Level Info
        }
        
        return $combinedOutput
    }
    catch {
        Write-TestLog "Error extracting ZIP: $_" -Level Error
        if (Test-Path $tempDir) {
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    return $null
}

# SQL execution function
function Invoke-TestSQL {
    param(
        [string]$ServerInstance,
        [string]$Query,
        [int]$QueryTimeout = 30
    )
    
    $connection = New-Object System.Data.SqlClient.SqlConnection

    # Create a connection to SQL Server
    $connectionString = "Server=${ServerInstance};Database=master"

    if ($UserID -and $Password) {
        $connectionString += ";User ID=$UserID;Password=$Password"
    } else {
        $connectionString += ";Integrated Security=True"
    }

    $connection.ConnectionString = $connectionString

    
    # Capture SQL messages and errors
    $messages = @()
    $errorMessages = @()
    
    # Event handlers for SQL messages
    $connection.add_InfoMessage({
        param($sender, $e)
        $messages += $e.Message
        Write-Verbose "SQL Info: $($e.Message)"
    })
    
    try {
        $connection.Open()
        
        # Split by GO statements
        $queries = $Query -split '(?:\r?\n|^)\s*GO\s*(?:\r?\n|$)'
        Write-Verbose "Split into $($queries.Count) batches"

        if ($ShowDebugOutput) {
            # Debug: Show all batches
            for ($i = 0; $i -lt $queries.Count; $i++) {
                $trimmed = $queries[$i].Trim()
                if ($trimmed.Length -gt 0) {
                    $firstLine = ($trimmed -split "`n")[0].Trim()
                    if ($firstLine.Length -gt 80) {
                        $firstLine = $firstLine.Substring(0, 80) + "..."
                    }
                    Write-TestLog "Batch $($i+1)/$($queries.Count) (length: $($queries[$i].Length)): $firstLine" -Level Debug
                } else {
                    Write-TestLog "Batch $($i+1)/$($queries.Count) (length: 0): [EMPTY]" -Level Debug
                }
            }
        }
        
        foreach ($q in $queries) {
            if ([string]::IsNullOrWhiteSpace($q)) { 
                Write-Verbose "Skipping empty batch"
                continue 
            }
            
            # Show which part we're executing
            $trimmedQ = $q.Trim()
            $firstLine = ($trimmedQ -split "`n")[0].Trim()
            if ($firstLine.Length -gt 100) {
                $firstLine = $firstLine.Substring(0, 100) + "..."
            }

            if ($ShowDebugOutput) {
                Write-TestLog "Executing batch with length $($q.Length): $firstLine" -Level Debug
            }

            # Handle USE statements - but don't skip the rest of the batch!
            if ($q -match '^\s*USE\s+\[?(\w+)\]?\s*;?\s*(.*)$' -and $matches[1]) {
                $dbName = $matches[1]
                $remainingSQL = $matches[2]
                
                try {
                    $connection.ChangeDatabase($dbName)
                    Write-Verbose "Changed to database: $dbName"
                    
                    # If there's more SQL after the USE statement, execute it
                    if ($remainingSQL -and $remainingSQL.Trim().Length -gt 0) {
                        if ($ShowDebugOutput) {
                            Write-TestLog "Executing remaining SQL after USE statement (length: $($remainingSQL.Length))" -Level Debug
                        }
                        $q = $remainingSQL
                        # Don't continue - let it fall through to execute the remaining SQL
                    } else {
                        # Only USE statement, nothing else
                        continue
                    }
                }
                catch {
                    Write-Error "Failed to change to database '$dbName': $_"
                    throw
                }
            }
            
            try {
                $command = $connection.CreateCommand()
                $command.CommandText = $q
                $command.CommandTimeout = $QueryTimeout
                
                # Determine if this is a SELECT query or not
                $trimmedQuery = $q.Trim()
                if ($trimmedQuery -match '^\s*SELECT' -and $trimmedQuery -notmatch '^\s*SELECT\s+@') {
                    # Use ExecuteReader for SELECT queries
                    $reader = $command.ExecuteReader()
                    while ($reader.Read()) { }
                    $reader.Close()
                } else {
                    # Use ExecuteNonQuery for DDL/DML statements
                    $result = $command.ExecuteNonQuery()
                    if ($ShowDebugOutput) {
                        Write-TestLog "ExecuteNonQuery returned: $result" -Level Debug
                        Write-TestLog "Query affected $result rows" -Level Debug
                    }
                }
                
                Write-Verbose "Query executed successfully"
            }
            catch {
                $errorMessages += $_.Exception.Message
                Write-Error "SQL Error at line: $($_.Exception.LineNumber)`nMessage: $($_.Exception.Message)`nQuery: $preview"
                
                # Don't throw - continue to next batch to see all errors
                # throw
            }
        }
    }
    catch {
        Write-Error "Connection Error: $_"
        throw
    }
    finally {
        if ($connection.State -eq 'Open') {
            $connection.Close()
        }
    }
    
    # Report all collected errors
    if ($errorMessages.Count -gt 0) {
        Write-Error "SQL Execution completed with $($errorMessages.Count) errors:"
        foreach ($err in $errorMessages) {
            Write-Error "  - $err"
        }
        throw "SQL script failed with errors: $($errorMessages -join '; ')"
    }
}

# Add Active Directory module if needed
if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        Import-Module ActiveDirectory
    }
}

function Test-DomainUser {
    param([string]$Username)
    
    try {
        $searcher = [adsisearcher]"(&(objectClass=user)(samAccountName=$Username))"
        $searcher.SearchRoot = [adsi]"LDAP://$Domain"
        $result = $searcher.FindOne()
        return ($null -ne $result)
    }
    catch {
        return $false
    }
}

function New-DomainTestUser {
    param(
        [string]$Username,
        [string]$Password = "TestP@ssw0rd123!"
    )
    
    if ($SkipDomainObjects) {
        Write-TestLog "Skipping domain user creation (SkipDomainObjects flag set)" -Level Warning
        return $false
    }
    
    try {
        # Check if we have domain admin rights
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-TestLog "Not running as administrator - cannot create domain users" -Level Warning
            return $false
        }
        
        # Try to create user in AD
        if (Get-Command New-ADUser -ErrorAction SilentlyContinue) {
            if (-not (Test-DomainUser -Username $Username)) {
                New-ADUser -Name $Username `
                          -SamAccountName $Username `
                          -UserPrincipalName "$Username@$Domain" `
                          -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
                          -Enabled $true `
                          -PasswordNeverExpires $true `
                          -CannotChangePassword $true
                
                Write-TestLog "Created domain user: $Domain\$Username" -Level Success
                return $true
            }
            else {
                Write-TestLog "Domain user already exists: $Domain\$Username" -Level Warning
                return $true
            }
        }
        else {
            Write-TestLog "AD PowerShell module not available" -Level Warning
            return $false
        }
    }
    catch {
        Write-TestLog "Failed to create domain user $Username : $_" -Level Warning
        return $false
    }
}

#endregion

#region Setup Functions

# Define setup SQL for MSSQL_AddMember
$script:SetupSQL_AddMember = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_AddMember EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_AddMember edges

-- Note: Principals cannot be assigned ALTER/CONTROL on a fixed server role or database role

-- Create test database if it doesn't exist
CREATE DATABASE [EdgeTest_AddMember];
GO

-- =====================================================
-- SERVER LEVEL: Login -> ServerRole
-- =====================================================

-- Login with ALTER permission on user-defined server role
CREATE LOGIN [AddMemberTest_Login_CanAlterServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE SERVER ROLE [AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole];
GRANT ALTER ON SERVER ROLE::[AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole] TO [AddMemberTest_Login_CanAlterServerRole];

-- Login with CONTROL permission on user-defined server role
CREATE LOGIN [AddMemberTest_Login_CanControlServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE SERVER ROLE [AddMemberTest_ServerRole_TargetOf_Login_CanControlServerRole];
GRANT CONTROL ON SERVER ROLE::[AddMemberTest_ServerRole_TargetOf_Login_CanControlServerRole] TO [AddMemberTest_Login_CanControlServerRole];

-- Login with ALTER ANY SERVER ROLE permission can add to any user-defined role
CREATE LOGIN [AddMemberTest_Login_CanAlterAnyServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ANY SERVER ROLE TO [AddMemberTest_Login_CanAlterAnyServerRole];

-- Login with ALTER ANY SERVER ROLE and member of fixed role can add to that fixed role
ALTER SERVER ROLE [processadmin] ADD MEMBER [AddMemberTest_Login_CanAlterAnyServerRole];

-- Login with ALTER ANY SERVER ROLE cannot add to sysadmin even as member (negative test)
ALTER SERVER ROLE [sysadmin] ADD MEMBER [AddMemberTest_Login_CanAlterAnyServerRole];
-- Even though member of sysadmin, cannot add members to sysadmin role

-- =====================================================
-- SERVER LEVEL: ServerRole -> ServerRole
-- =====================================================

-- Server role with ALTER permission on user-defined role
CREATE SERVER ROLE [AddMemberTest_ServerRole_CanAlterServerRole];
CREATE SERVER ROLE [AddMemberTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole];
GRANT ALTER ON SERVER ROLE::[AddMemberTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole] TO [AddMemberTest_ServerRole_CanAlterServerRole];

-- Server role with CONTROL permission on user-defined role
CREATE SERVER ROLE [AddMemberTest_ServerRole_CanControlServerRole];
CREATE SERVER ROLE [AddMemberTest_ServerRole_TargetOf_ServerRole_CanControlServerRole];
GRANT CONTROL ON SERVER ROLE::[AddMemberTest_ServerRole_TargetOf_ServerRole_CanControlServerRole] TO [AddMemberTest_ServerRole_CanControlServerRole];

-- Server role with ALTER ANY SERVER ROLE can add to any user-defined role
CREATE SERVER ROLE [AddMemberTest_ServerRole_CanAlterAnyServerRole];
GRANT ALTER ANY SERVER ROLE TO [AddMemberTest_ServerRole_CanAlterAnyServerRole];

-- Server role with ALTER ANY SERVER ROLE and member of fixed role can add to that fixed role
ALTER SERVER ROLE [processadmin] ADD MEMBER [AddMemberTest_ServerRole_CanAlterAnyServerRole];

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_AddMember];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser -> DatabaseRole
-- =====================================================

-- Database user with ALTER on user-defined role
CREATE USER [AddMemberTest_User_CanAlterDbRole] WITHOUT LOGIN;
CREATE ROLE [AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole];
GRANT ALTER ON ROLE::[AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole] TO [AddMemberTest_User_CanAlterDbRole];

-- Database user with CONTROL on user-defined role
CREATE USER [AddMemberTest_User_CanControlDbRole] WITHOUT LOGIN;
CREATE ROLE [AddMemberTest_DbRole_TargetOf_User_CanControlDbRole];
GRANT CONTROL ON ROLE::[AddMemberTest_DbRole_TargetOf_User_CanControlDbRole] TO [AddMemberTest_User_CanControlDbRole];

-- Database user with ALTER ANY ROLE can add to any user-defined role
CREATE USER [AddMemberTest_User_CanAlterAnyDbRole] WITHOUT LOGIN;
GRANT ALTER ANY ROLE TO [AddMemberTest_User_CanAlterAnyDbRole];

-- Database user with ALTER on database (grants ALTER ANY ROLE) can add to user-defined roles
CREATE USER [AddMemberTest_User_CanAlterDb] WITHOUT LOGIN;
GRANT ALTER ON DATABASE::[EdgeTest_AddMember] TO [AddMemberTest_User_CanAlterDb];

-- Create target roles for principals with ALTER on database
CREATE ROLE [AddMemberTest_DbRole_TargetOf_User_CanAlterDb];
CREATE ROLE [AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDb];
CREATE ROLE [AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDb];

-- =====================================================
-- DATABASE LEVEL: DatabaseRole -> DatabaseRole
-- =====================================================

-- Database role with ALTER on a user-defined role
CREATE ROLE [AddMemberTest_DbRole_CanAlterDbRole];
CREATE ROLE [AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDbRole];
GRANT ALTER ON ROLE::[AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDbRole] TO [AddMemberTest_DbRole_CanAlterDbRole];

-- Database role with CONTROL on a user-defined role
CREATE ROLE [AddMemberTest_DbRole_CanControlDbRole];
CREATE ROLE [AddMemberTest_DbRole_TargetOf_DbRole_CanControlDbRole];
GRANT CONTROL ON ROLE::[AddMemberTest_DbRole_TargetOf_DbRole_CanControlDbRole] TO [AddMemberTest_DbRole_CanControlDbRole];

-- Database role with ALTER ANY ROLE can add to any user-defined role
CREATE ROLE [AddMemberTest_DbRole_CanAlterAnyDbRole];
GRANT ALTER ANY ROLE TO [AddMemberTest_DbRole_CanAlterAnyDbRole];

-- Database role with ALTER on database (grants ALTER ANY ROLE) can add to user-defined roles
CREATE ROLE [AddMemberTest_DbRole_CanAlterDb]
GRANT ALTER ON DATABASE::[EdgeTest_AddMember] TO [AddMemberTest_DbRole_CanAlterDb]

-- =====================================================
-- DATABASE LEVEL: ApplicationRole -> DatabaseRole
-- =====================================================

-- Application role with ALTER on user-defined role
CREATE APPLICATION ROLE [AddMemberTest_AppRole_CanAlterDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE ROLE [AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDbRole];
GRANT ALTER ON ROLE::[AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDbRole] TO [AddMemberTest_AppRole_CanAlterDbRole];

-- Application role with CONTROL on user-defined role
CREATE APPLICATION ROLE [AddMemberTest_AppRole_CanControlDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE ROLE [AddMemberTest_DbRole_TargetOf_AppRole_CanControlDbRole];
GRANT CONTROL ON ROLE::[AddMemberTest_DbRole_TargetOf_AppRole_CanControlDbRole] TO [AddMemberTest_AppRole_CanControlDbRole];

-- Application role with ALTER ANY ROLE can add to any user-defined role
CREATE APPLICATION ROLE [AddMemberTest_AppRole_CanAlterAnyDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ANY ROLE TO [AddMemberTest_AppRole_CanAlterAnyDbRole];

-- Application role with ALTER on database (grants ALTER ANY ROLE) can add to user-defined roles
CREATE APPLICATION ROLE [AddMemberTest_AppRole_CanAlterDb] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ON DATABASE::[EdgeTest_AddMember] TO [AddMemberTest_AppRole_CanAlterDb];

USE master;
GO

PRINT 'MSSQL_AddMember test setup completed';
'@


# Define setup SQL for MSSQL_Alter
$script:SetupSQL_Alter = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_Alter EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_Alter edges (offensive, non-traversable)

-- Create test database if it doesn't exist
CREATE DATABASE [EdgeTest_Alter];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> ServerRole
-- =====================================================
-- Note: There is no ALTER permission on the server itself

-- Login with ALTER permission on login
CREATE LOGIN [AlterTest_Login_CanAlterLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [AlterTest_Login_TargetOf_Login_CanAlterLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ON LOGIN::[AlterTest_Login_TargetOf_Login_CanAlterLogin] TO [AlterTest_Login_CanAlterLogin];

-- Login with ALTER permission on server role
CREATE LOGIN [AlterTest_Login_CanAlterServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE SERVER ROLE [AlterTest_ServerRole_TargetOf_Login_CanAlterServerRole];
GRANT ALTER ON SERVER ROLE::[AlterTest_ServerRole_TargetOf_Login_CanAlterServerRole] TO [AlterTest_Login_CanAlterServerRole];

-- ServerRole with ALTER permission on login
CREATE SERVER ROLE [AlterTest_ServerRole_CanAlterLogin];
CREATE LOGIN [AlterTest_Login_TargetOf_ServerRole_CanAlterLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ON LOGIN::[AlterTest_Login_TargetOf_ServerRole_CanAlterLogin] TO [AlterTest_ServerRole_CanAlterLogin];

-- ServerRole with ALTER permission on server role
CREATE SERVER ROLE [AlterTest_ServerRole_CanAlterServerRole];
CREATE SERVER ROLE [AlterTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole];
GRANT ALTER ON SERVER ROLE::[AlterTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole] TO [AlterTest_ServerRole_CanAlterServerRole];

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_Alter];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> Database
-- =====================================================

-- DatabaseUser with ALTER on database
CREATE USER [AlterTest_User_CanAlterDb] WITHOUT LOGIN;
GRANT ALTER ON DATABASE::[EdgeTest_Alter] TO [AlterTest_User_CanAlterDb];

-- DatabaseRole with ALTER on database
CREATE ROLE [AlterTest_DbRole_CanAlterDb];
GRANT ALTER ON DATABASE::[EdgeTest_Alter] TO [AlterTest_DbRole_CanAlterDb];

-- ApplicationRole with ALTER on database
CREATE APPLICATION ROLE [AlterTest_AppRole_CanAlterDb] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ON DATABASE::[EdgeTest_Alter] TO [AlterTest_AppRole_CanAlterDb];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseUser
-- =====================================================

-- DatabaseUser with ALTER on database user
CREATE USER [AlterTest_User_CanAlterDbUser] WITHOUT LOGIN;
CREATE USER [AlterTest_User_TargetOf_User_CanAlterDbUser] WITHOUT LOGIN;
GRANT ALTER ON USER::[AlterTest_User_TargetOf_User_CanAlterDbUser] TO [AlterTest_User_CanAlterDbUser];

-- DatabaseRole with ALTER on database user
CREATE ROLE [AlterTest_DbRole_CanAlterDbUser];
CREATE USER [AlterTest_User_TargetOf_DbRole_CanAlterDbUser] WITHOUT LOGIN;
GRANT ALTER ON USER::[AlterTest_User_TargetOf_DbRole_CanAlterDbUser] TO [AlterTest_DbRole_CanAlterDbUser];

-- ApplicationRole with ALTER on database user
CREATE APPLICATION ROLE [AlterTest_AppRole_CanAlterDbUser] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE USER [AlterTest_User_TargetOf_AppRole_CanAlterDbUser] WITHOUT LOGIN;
GRANT ALTER ON USER::[AlterTest_User_TargetOf_AppRole_CanAlterDbUser] TO [AlterTest_AppRole_CanAlterDbUser];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
-- =====================================================

-- DatabaseUser with ALTER on database role
CREATE USER [AlterTest_User_CanAlterDbRole] WITHOUT LOGIN;
CREATE ROLE [AlterTest_DbRole_TargetOf_User_CanAlterDbRole];
GRANT ALTER ON ROLE::[AlterTest_DbRole_TargetOf_User_CanAlterDbRole] TO [AlterTest_User_CanAlterDbRole];

-- DatabaseRole with ALTER on database role
CREATE ROLE [AlterTest_DbRole_CanAlterDbRole];
CREATE ROLE [AlterTest_DbRole_TargetOf_DbRole_CanAlterDbRole];
GRANT ALTER ON ROLE::[AlterTest_DbRole_TargetOf_DbRole_CanAlterDbRole] TO [AlterTest_DbRole_CanAlterDbRole];

-- ApplicationRole with ALTER on database role
CREATE APPLICATION ROLE [AlterTest_AppRole_CanAlterDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE ROLE [AlterTest_DbRole_TargetOf_AppRole_CanAlterDbRole];
GRANT ALTER ON ROLE::[AlterTest_DbRole_TargetOf_AppRole_CanAlterDbRole] TO [AlterTest_AppRole_CanAlterDbRole];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> ApplicationRole
-- =====================================================

-- DatabaseUser with ALTER on application role
CREATE USER [AlterTest_User_CanAlterAppRole] WITHOUT LOGIN;
CREATE APPLICATION ROLE [AlterTest_AppRole_TargetOf_User_CanAlterAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ON APPLICATION ROLE::[AlterTest_AppRole_TargetOf_User_CanAlterAppRole] TO [AlterTest_User_CanAlterAppRole];

-- DatabaseRole with ALTER on application role
CREATE ROLE [AlterTest_DbRole_CanAlterAppRole];
CREATE APPLICATION ROLE [AlterTest_AppRole_TargetOf_DbRole_CanAlterAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ON APPLICATION ROLE::[AlterTest_AppRole_TargetOf_DbRole_CanAlterAppRole] TO [AlterTest_DbRole_CanAlterAppRole];

-- ApplicationRole with ALTER on application role
CREATE APPLICATION ROLE [AlterTest_AppRole_CanAlterAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE APPLICATION ROLE [AlterTest_AppRole_TargetOf_AppRole_CanAlterAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ON APPLICATION ROLE::[AlterTest_AppRole_TargetOf_AppRole_CanAlterAppRole] TO [AlterTest_AppRole_CanAlterAppRole];

USE master;
GO

PRINT 'MSSQL_Alter test setup completed';
'@

# Define setup SQL for MSSQL_AlterAnyAppRole
$script:SetupSQL_AlterAnyAppRole = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_AlterAnyAppRole EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_AlterAnyAppRole edges

-- Create test database if it doesn't exist
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'EdgeTest_AlterAnyAppRole')
    CREATE DATABASE [EdgeTest_AlterAnyAppRole];
GO

USE [EdgeTest_AlterAnyAppRole];
GO

-- =====================================================
-- OFFENSIVE: DatabaseUser/DatabaseRole/ApplicationRole -> Database
-- =====================================================

-- DatabaseUser with ALTER ANY APPLICATION ROLE
CREATE USER [AlterAnyAppRoleTest_User_HasAlterAnyAppRole] WITHOUT LOGIN;
GRANT ALTER ANY APPLICATION ROLE TO [AlterAnyAppRoleTest_User_HasAlterAnyAppRole];

-- DatabaseRole with ALTER ANY APPLICATION ROLE
CREATE ROLE [AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole];
GRANT ALTER ANY APPLICATION ROLE TO [AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole];

-- ApplicationRole with ALTER ANY APPLICATION ROLE
CREATE APPLICATION ROLE [AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ANY APPLICATION ROLE TO [AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole];

-- Fixed role db_securityadmin has ALTER ANY APPLICATION ROLE by default

-- =====================================================
-- DEFENSIVE: Create target application roles
-- =====================================================
-- For defensive perspective, we need actual application roles as targets

-- Create several application roles to serve as targets
CREATE APPLICATION ROLE [AlterAnyAppRoleTest_TargetAppRole1] WITH PASSWORD = 'TargetP@ss123!';
CREATE APPLICATION ROLE [AlterAnyAppRoleTest_TargetAppRole2] WITH PASSWORD = 'TargetP@ss123!';

USE master;
GO

PRINT 'MSSQL_AlterAnyAppRole test setup completed';
'@

$script:SetupSQL_AlterAnyDBRole = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_AlterAnyDBRole EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_AlterAnyDBRole edges

-- Create test database if it doesn't exist
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'EdgeTest_AlterAnyDBRole')
    CREATE DATABASE [EdgeTest_AlterAnyDBRole];
GO

USE [EdgeTest_AlterAnyDBRole];
GO

-- =====================================================
-- OFFENSIVE: DatabaseUser/DatabaseRole/ApplicationRole -> Database
-- =====================================================

-- DatabaseUser with ALTER ANY ROLE
CREATE USER [AlterAnyDBRoleTest_User_HasAlterAnyRole] WITHOUT LOGIN;
GRANT ALTER ANY ROLE TO [AlterAnyDBRoleTest_User_HasAlterAnyRole];

-- DatabaseRole with ALTER ANY ROLE
CREATE ROLE [AlterAnyDBRoleTest_DbRole_HasAlterAnyRole];
GRANT ALTER ANY ROLE TO [AlterAnyDBRoleTest_DbRole_HasAlterAnyRole];

-- ApplicationRole with ALTER ANY ROLE
CREATE APPLICATION ROLE [AlterAnyDBRoleTest_AppRole_HasAlterAnyRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ANY ROLE TO [AlterAnyDBRoleTest_AppRole_HasAlterAnyRole];

-- Fixed role db_securityadmin has ALTER ANY ROLE

-- =====================================================
-- DEFENSIVE: Create target database roles
-- =====================================================
-- For defensive perspective, we need actual database roles as targets

-- Create user-defined database roles to serve as targets
CREATE ROLE [AlterAnyDBRoleTest_TargetRole1];
CREATE ROLE [AlterAnyDBRoleTest_TargetRole2];

USE master;
GO

PRINT 'MSSQL_AlterAnyDBRole test setup completed';
'@

$script:SetupSQL_AlterAnyLogin = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_AlterAnyLogin EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_AlterAnyLogin edges

-- =====================================================
-- OFFENSIVE: Login/ServerRole -> Server
-- =====================================================

-- Login with ALTER ANY LOGIN permission
CREATE LOGIN [AlterAnyLoginTest_Login_HasAlterAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ANY LOGIN TO [AlterAnyLoginTest_Login_HasAlterAnyLogin];

-- ServerRole with ALTER ANY LOGIN permission
CREATE SERVER ROLE [AlterAnyLoginTest_ServerRole_HasAlterAnyLogin];
GRANT ALTER ANY LOGIN TO [AlterAnyLoginTest_ServerRole_HasAlterAnyLogin];

-- Note: securityadmin fixed role has ALTER ANY LOGIN by default
-- We'll test the role itself, not members of the role

-- =====================================================
-- DEFENSIVE: Create target SQL logins (not Windows logins)
-- =====================================================

-- Regular SQL logins that can be targeted
CREATE LOGIN [AlterAnyLoginTest_TargetLogin1] WITH PASSWORD = 'TargetP@ss123!';
CREATE LOGIN [AlterAnyLoginTest_TargetLogin2] WITH PASSWORD = 'TargetP@ss123!';

-- Login with sysadmin (should NOT be targetable without CONTROL SERVER)
CREATE LOGIN [AlterAnyLoginTest_TargetLogin_WithSysadmin] WITH PASSWORD = 'TargetP@ss123!';
ALTER SERVER ROLE [sysadmin] ADD MEMBER [AlterAnyLoginTest_TargetLogin_WithSysadmin];

-- Login with CONTROL SERVER (should NOT be targetable without CONTROL SERVER)
CREATE LOGIN [AlterAnyLoginTest_TargetLogin_WithControlServer] WITH PASSWORD = 'TargetP@ss123!';
GRANT CONTROL SERVER TO [AlterAnyLoginTest_TargetLogin_WithControlServer];

-- =====================================================
-- ADDITIONAL: Nested CONTROL SERVER through role
-- =====================================================

-- Create user-defined server role with CONTROL SERVER
CREATE SERVER ROLE [AlterAnyLoginTest_UserRole_WithControlServer];
GRANT CONTROL SERVER TO [AlterAnyLoginTest_UserRole_WithControlServer];

-- Create a login that's member of the role (nested CONTROL SERVER)
CREATE LOGIN [AlterAnyLoginTest_TargetLogin_NestedControlServer] WITH PASSWORD = 'TargetP@ss123!';
ALTER SERVER ROLE [AlterAnyLoginTest_UserRole_WithControlServer] ADD MEMBER [AlterAnyLoginTest_TargetLogin_NestedControlServer];

-- Can't add server roles to sysadmin
-- Note: sa login cannot be targeted
-- Note: Windows logins cannot have passwords changed

PRINT 'MSSQL_AlterAnyLogin test setup completed';
'@

$script:SetupSQL_AlterAnyServerRole = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_AlterAnyServerRole EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_AlterAnyServerRole edges

-- =====================================================
-- OFFENSIVE: Login/ServerRole -> Server
-- =====================================================

-- Login with ALTER ANY SERVER ROLE permission
CREATE LOGIN [AlterAnyServerRoleTest_Login_HasAlterAnyServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ANY SERVER ROLE TO [AlterAnyServerRoleTest_Login_HasAlterAnyServerRole];

-- ServerRole with ALTER ANY SERVER ROLE permission
CREATE SERVER ROLE [AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole];
GRANT ALTER ANY SERVER ROLE TO [AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole];

-- Note: sysadmin has ALTER ANY SERVER ROLE by default but edges not drawn (handled by ControlServer)

-- =====================================================
-- DEFENSIVE: Create target server roles and test membership
-- =====================================================

-- Create user-defined server roles as targets
CREATE SERVER ROLE [AlterAnyServerRoleTest_TargetRole1];
CREATE SERVER ROLE [AlterAnyServerRoleTest_TargetRole2];

-- Make the login a member of a fixed role to test fixed role membership requirement
ALTER SERVER ROLE [processadmin] ADD MEMBER [AlterAnyServerRoleTest_Login_HasAlterAnyServerRole];

-- Make the server role a member of a different fixed role
ALTER SERVER ROLE [bulkadmin] ADD MEMBER [AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole];

PRINT 'MSSQL_AlterAnyServerRole test setup completed';
'@

# Define setup SQL for MSSQL_ChangeOwner
$script:SetupSQL_ChangeOwner = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_ChangeOwner EDGE TESTING
-- =====================================================
-- This creates all objects needed to test MSSQL_ChangeOwner edges
-- IMPORTANT: MSSQL_ChangeOwner is created in offensive perspective only (traversable)
-- In defensive perspective, these become MSSQL_TakeOwnership or MSSQL_DBTakeOwnership edges

-- Create test database if it doesn't exist
CREATE DATABASE [EdgeTest_ChangeOwner];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> ServerRole
-- =====================================================

-- Login with TAKE OWNERSHIP on specific server role
CREATE LOGIN [ChangeOwnerTest_Login_CanTakeOwnershipServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE SERVER ROLE [ChangeOwnerTest_ServerRole_TargetOf_Login];
GRANT TAKE OWNERSHIP ON SERVER ROLE::[ChangeOwnerTest_ServerRole_TargetOf_Login] TO [ChangeOwnerTest_Login_CanTakeOwnershipServerRole];

-- Login with CONTROL on specific server role
CREATE LOGIN [ChangeOwnerTest_Login_CanControlServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE SERVER ROLE [ChangeOwnerTest_ServerRole_TargetOf_Login_CanControlServerRole];
GRANT CONTROL ON SERVER ROLE::[ChangeOwnerTest_ServerRole_TargetOf_Login_CanControlServerRole] TO [ChangeOwnerTest_Login_CanControlServerRole];

-- ServerRole with TAKE OWNERSHIP on another server role
CREATE SERVER ROLE [ChangeOwnerTest_ServerRole_CanTakeOwnershipServerRole];
CREATE SERVER ROLE [ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanTakeOwnershipServerRole];
GRANT TAKE OWNERSHIP ON SERVER ROLE::[ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanTakeOwnershipServerRole] TO [ChangeOwnerTest_ServerRole_CanTakeOwnershipServerRole];

-- ServerRole with CONTROL on another server role
CREATE SERVER ROLE [ChangeOwnerTest_ServerRole_CanControlServerRole];
CREATE SERVER ROLE [ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanControlServerRole];
GRANT CONTROL ON SERVER ROLE::[ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanControlServerRole] TO [ChangeOwnerTest_ServerRole_CanControlServerRole];

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_ChangeOwner];
GO

-- Create some database roles that will be targets for TAKE OWNERSHIP on database
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDb];
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDb];
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDb];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser -> Database/DatabaseRole
-- =====================================================

-- DatabaseUser with TAKE OWNERSHIP on database (creates edges to all database roles)
CREATE USER [ChangeOwnerTest_User_CanTakeOwnershipDb] WITHOUT LOGIN;
GRANT TAKE OWNERSHIP ON DATABASE::[EdgeTest_ChangeOwner] TO [ChangeOwnerTest_User_CanTakeOwnershipDb];

-- DatabaseUser with TAKE OWNERSHIP on specific database role
CREATE USER [ChangeOwnerTest_User_CanTakeOwnershipDbRole] WITHOUT LOGIN;
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDbRole];
GRANT TAKE OWNERSHIP ON ROLE::[ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDbRole] TO [ChangeOwnerTest_User_CanTakeOwnershipDbRole];

-- DatabaseUser with CONTROL on specific database role
CREATE USER [ChangeOwnerTest_User_CanControlDbRole] WITHOUT LOGIN;
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_User_CanControlDbRole];
GRANT CONTROL ON ROLE::[ChangeOwnerTest_DbRole_TargetOf_User_CanControlDbRole] TO [ChangeOwnerTest_User_CanControlDbRole];

-- =====================================================
-- DATABASE LEVEL: DatabaseRole -> Database/DatabaseRole
-- =====================================================

-- DatabaseRole with TAKE OWNERSHIP on database
CREATE ROLE [ChangeOwnerTest_DbRole_CanTakeOwnershipDb];
GRANT TAKE OWNERSHIP ON DATABASE::[EdgeTest_ChangeOwner] TO [ChangeOwnerTest_DbRole_CanTakeOwnershipDb];

-- DatabaseRole with TAKE OWNERSHIP on another database role
CREATE ROLE [ChangeOwnerTest_DbRole_CanTakeOwnershipDbRole];
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDbRole];
GRANT TAKE OWNERSHIP ON ROLE::[ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDbRole] TO [ChangeOwnerTest_DbRole_CanTakeOwnershipDbRole];

-- DatabaseRole with CONTROL on another database role
CREATE ROLE [ChangeOwnerTest_DbRole_CanControlDbRole];
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_DbRole_CanControlDbRole];
GRANT CONTROL ON ROLE::[ChangeOwnerTest_DbRole_TargetOf_DbRole_CanControlDbRole] TO [ChangeOwnerTest_DbRole_CanControlDbRole];

-- =====================================================
-- DATABASE LEVEL: ApplicationRole -> Database/DatabaseRole
-- =====================================================

-- ApplicationRole with TAKE OWNERSHIP on database
CREATE APPLICATION ROLE [ChangeOwnerTest_AppRole_CanTakeOwnershipDb] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT TAKE OWNERSHIP ON DATABASE::[EdgeTest_ChangeOwner] TO [ChangeOwnerTest_AppRole_CanTakeOwnershipDb];

-- ApplicationRole with TAKE OWNERSHIP on database role
CREATE APPLICATION ROLE [ChangeOwnerTest_AppRole_CanTakeOwnershipDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDbRole];
GRANT TAKE OWNERSHIP ON ROLE::[ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDbRole] TO [ChangeOwnerTest_AppRole_CanTakeOwnershipDbRole];

-- ApplicationRole with CONTROL on database role
CREATE APPLICATION ROLE [ChangeOwnerTest_AppRole_CanControlDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE ROLE [ChangeOwnerTest_DbRole_TargetOf_AppRole_CanControlDbRole];
GRANT CONTROL ON ROLE::[ChangeOwnerTest_DbRole_TargetOf_AppRole_CanControlDbRole] TO [ChangeOwnerTest_AppRole_CanControlDbRole];

USE master;
GO

PRINT 'MSSQL_ChangeOwner test setup completed';
'@

# Define setup SQL for MSSQL_ChangePassword
$script:SetupSQL_ChangePassword = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_ChangePassword EDGE TESTING
-- =====================================================
-- This creates all objects needed to test MSSQL_ChangePassword edges
-- MSSQL_ChangePassword is created in offensive perspective (traversable)

-- Create test database if it doesn't exist
CREATE DATABASE [EdgeTest_ChangePassword];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> Login
-- =====================================================

-- Login with ALTER ANY LOGIN permission
CREATE LOGIN [ChangePasswordTest_Login_CanAlterAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT ALTER ANY LOGIN TO [ChangePasswordTest_Login_CanAlterAnyLogin];

-- ServerRole with ALTER ANY LOGIN permission
CREATE SERVER ROLE [ChangePasswordTest_ServerRole_CanAlterAnyLogin];
GRANT ALTER ANY LOGIN TO [ChangePasswordTest_ServerRole_CanAlterAnyLogin];

-- Target SQL logins (not Windows logins)
CREATE LOGIN [ChangePasswordTest_Login_TargetOf_Login_CanAlterAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [ChangePasswordTest_Login_TargetOf_ServerRole_CanAlterAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create a login with sysadmin that should NOT be targetable without CONTROL SERVER
CREATE LOGIN [ChangePasswordTest_Login_WithSysadmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [sysadmin] ADD MEMBER [ChangePasswordTest_Login_WithSysadmin];

-- Create a login with CONTROL SERVER that should NOT be targetable without CONTROL SERVER
CREATE LOGIN [ChangePasswordTest_Login_WithControlServer] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL SERVER TO [ChangePasswordTest_Login_WithControlServer];

-- Fixed role: securityadmin has ALTER ANY LOGIN
-- Create a target for securityadmin to test
CREATE LOGIN [ChangePasswordTest_Login_TargetOf_SecurityAdmin] WITH PASSWORD = 'EdgeTestP@ss123!';

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_ChangePassword];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> ApplicationRole
-- =====================================================

-- DatabaseUser with ALTER ANY APPLICATION ROLE
CREATE USER [ChangePasswordTest_User_CanAlterAnyAppRole] WITHOUT LOGIN;
GRANT ALTER ANY APPLICATION ROLE TO [ChangePasswordTest_User_CanAlterAnyAppRole];

-- DatabaseRole with ALTER ANY APPLICATION ROLE
CREATE ROLE [ChangePasswordTest_DbRole_CanAlterAnyAppRole];
GRANT ALTER ANY APPLICATION ROLE TO [ChangePasswordTest_DbRole_CanAlterAnyAppRole];

-- ApplicationRole with ALTER ANY APPLICATION ROLE
CREATE APPLICATION ROLE [ChangePasswordTest_AppRole_CanAlterAnyAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT ALTER ANY APPLICATION ROLE TO [ChangePasswordTest_AppRole_CanAlterAnyAppRole];

-- Target application roles
CREATE APPLICATION ROLE [ChangePasswordTest_AppRole_TargetOf_User_CanAlterAnyAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE APPLICATION ROLE [ChangePasswordTest_AppRole_TargetOf_DbRole_CanAlterAnyAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE APPLICATION ROLE [ChangePasswordTest_AppRole_TargetOf_AppRole_CanAlterAnyAppRole] WITH PASSWORD = 'AppRoleP@ss123!';

-- Fixed role: db_securityadmin has ALTER ANY APPLICATION ROLE
-- Create a target for db_securityadmin to test
CREATE APPLICATION ROLE [ChangePasswordTest_AppRole_TargetOf_DbSecurityAdmin] WITH PASSWORD = 'AppRoleP@ss123!';

-- Note: ALTER or CONTROL on a specific application role does NOT allow password change
-- Only ALTER ANY APPLICATION ROLE allows password changes

USE master;
GO

PRINT 'MSSQL_ChangePassword test setup completed';
'@

$script:SetupSQL_CoerceAndRelayToMSSQL = @'
-- =====================================================
-- SETUP FOR CoerceAndRelayToMSSQL EDGE TESTING
-- =====================================================
-- This edge is created from Authenticated Users (S-1-5-11) to computer accounts
-- when the computer has a SQL login that is enabled with CONNECT SQL permission
-- and Extended Protection is Off
USE master;
GO

-- Create computer account logins with CONNECT SQL permission (enabled by default)
-- These represent computers that can be coerced and relayed to
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\CoerceTestEnabled1$')
    CREATE LOGIN [MAYYHEM\CoerceTestEnabled1$] FROM WINDOWS;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\CoerceTestEnabled2$')
    CREATE LOGIN [MAYYHEM\CoerceTestEnabled2$] FROM WINDOWS;

-- Create disabled computer account login (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\CoerceTestDisabled$')
    CREATE LOGIN [MAYYHEM\CoerceTestDisabled$] FROM WINDOWS;
ALTER LOGIN [MAYYHEM\CoerceTestDisabled$] DISABLE;

-- Create computer account login with CONNECT SQL denied (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\CoerceTestNoConnect$')
    CREATE LOGIN [MAYYHEM\CoerceTestNoConnect$] FROM WINDOWS;
DENY CONNECT SQL TO [MAYYHEM\CoerceTestNoConnect$];

-- Create regular user login (negative test - not a computer account)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\EdgeTestCoerce')
    CREATE LOGIN [MAYYHEM\CoerceTestUser] FROM WINDOWS;

-- Create SQL login (negative test - not a Windows login)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'CoerceTestSQLLogin')
    CREATE LOGIN [CoerceTestSQLLogin] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Note: Extended Protection is a server configuration setting, not set via T-SQL
-- For testing, ensure Extended Protection is set to Off on the test server

PRINT 'CoerceAndRelayToMSSQL test setup completed';
PRINT 'IMPORTANT: Ensure Extended Protection is set to Off on the SQL Server for this edge to be created';
PRINT 'Edges will be created from Authenticated Users (S-1-5-11) to computer account SIDs';
'@

# Define setup SQL for MSSQL_Connect
$script:SetupSQL_Connect = @'
-- =====================================================
-- SETUP FOR MSSQL_Connect EDGE TESTING
-- =====================================================
USE master;
GO

-- Create test database
CREATE DATABASE [EdgeTest_Connect];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> Server
-- =====================================================

-- Login with explicit CONNECT SQL permission (granted by default)
CREATE LOGIN [ConnectTest_Login_HasConnectSQL] WITH PASSWORD = 'EdgeTestP@ss123!';
GO

-- Login with explicit CONNECT ANY DATABASE permission
CREATE LOGIN [ConnectAnyDatabaseTest_Login_HasConnectAnyDatabase] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONNECT ANY DATABASE TO [ConnectAnyDatabaseTest_Login_HasConnectAnyDatabase];
GO

-- Login with CONNECT SQL denied
CREATE LOGIN [ConnectTest_Login_NoConnectSQL] WITH PASSWORD = 'EdgeTestP@ss123!';
DENY CONNECT SQL TO [ConnectTest_Login_NoConnectSQL];
GO

-- Server role with explicit CONNECT SQL permission
CREATE SERVER ROLE [ConnectTest_ServerRole_HasConnectSQL];
GRANT CONNECT SQL TO [ConnectTest_ServerRole_HasConnectSQL];
GO

-- Server role with explicit CONNECT ANY DATABASE permission
CREATE SERVER ROLE [ConnectAnyDatabaseTest_ServerRole_HasConnectAnyDatabase];
GRANT CONNECT ANY DATABASE TO [ConnectAnyDatabaseTest_ServerRole_HasConnectAnyDatabase];
GO

-- Disabled login (should not create edge even with CONNECT SQL)
CREATE LOGIN [ConnectTest_Login_Disabled] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER LOGIN [ConnectTest_Login_Disabled] DISABLE;
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole -> Database
-- =====================================================
USE [EdgeTest_Connect];
GO

-- Database user with CONNECT permission (granted by default)
CREATE USER [ConnectTest_User_HasConnect] WITHOUT LOGIN;
GO

-- Database user with CONNECT denied
CREATE USER [ConnectTest_User_NoConnect] WITHOUT LOGIN;
DENY CONNECT TO [ConnectTest_User_NoConnect];
GO

-- Database role with explicit CONNECT permission
CREATE ROLE [ConnectTest_DbRole_HasConnect];
GRANT CONNECT TO [ConnectTest_DbRole_HasConnect];
GO

-- Application role (cannot have CONNECT permission)
CREATE APPLICATION ROLE [ConnectTest_AppRole] WITH PASSWORD = 'EdgeTestP@ss123!';
GO

USE master;
GO
'@

$script:SetupSQL_Contains = @'
-- =====================================================
-- SETUP FOR MSSQL_Contains EDGE TESTING
-- =====================================================
USE master;
GO

-- Create test database
CREATE DATABASE [EdgeTest_Contains];
GO

-- =====================================================
-- SERVER LEVEL: Server -> Login/ServerRole/Database
-- =====================================================

-- Create test logins
CREATE LOGIN [ContainsTest_Login1] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [ContainsTest_Login2] WITH PASSWORD = 'EdgeTestP@ss123!';
GO

-- Create test server roles
CREATE SERVER ROLE [ContainsTest_ServerRole1];
CREATE SERVER ROLE [ContainsTest_ServerRole2];
GO

-- =====================================================
-- DATABASE LEVEL: Database -> DatabaseUser/DatabaseRole/ApplicationRole
-- =====================================================
USE [EdgeTest_Contains];
GO

-- Create database users
CREATE USER [ContainsTest_User1] WITHOUT LOGIN;
CREATE USER [ContainsTest_User2] WITHOUT LOGIN;
GO

-- Create database roles
CREATE ROLE [ContainsTest_DbRole1];
CREATE ROLE [ContainsTest_DbRole2];
GO

-- Create application roles
CREATE APPLICATION ROLE [ContainsTest_AppRole1] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE APPLICATION ROLE [ContainsTest_AppRole2] WITH PASSWORD = 'EdgeTestP@ss123!';
GO

USE master;
GO
'@

# Define setup SQL for MSSQL_Control
$script:SetupSQL_Control = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_Control EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_Control edges (offensive, non-traversable)

-- Create test database if it doesn't exist
CREATE DATABASE [EdgeTest_Control];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> ServerRole
-- =====================================================

-- Login with CONTROL permission on login
CREATE LOGIN [ControlTest_Login_CanControlLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [ControlTest_Login_TargetOf_Login_CanControlLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL ON LOGIN::[ControlTest_Login_TargetOf_Login_CanControlLogin] TO [ControlTest_Login_CanControlLogin];

-- Login with CONTROL permission on server role
CREATE LOGIN [ControlTest_Login_CanControlServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE SERVER ROLE [ControlTest_ServerRole_TargetOf_Login_CanControlServerRole];
GRANT CONTROL ON SERVER ROLE::[ControlTest_ServerRole_TargetOf_Login_CanControlServerRole] TO [ControlTest_Login_CanControlServerRole];

-- ServerRole with CONTROL permission on login
CREATE SERVER ROLE [ControlTest_ServerRole_CanControlLogin];
CREATE LOGIN [ControlTest_Login_TargetOf_ServerRole_CanControlLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL ON LOGIN::[ControlTest_Login_TargetOf_ServerRole_CanControlLogin] TO [ControlTest_ServerRole_CanControlLogin];

-- ServerRole with CONTROL permission on server role
CREATE SERVER ROLE [ControlTest_ServerRole_CanControlServerRole];
CREATE SERVER ROLE [ControlTest_ServerRole_TargetOf_ServerRole_CanControlServerRole];
GRANT CONTROL ON SERVER ROLE::[ControlTest_ServerRole_TargetOf_ServerRole_CanControlServerRole] TO [ControlTest_ServerRole_CanControlServerRole];

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_Control];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> Database
-- =====================================================

-- DatabaseUser with CONTROL on database
CREATE USER [ControlTest_User_CanControlDb] WITHOUT LOGIN;
GRANT CONTROL ON DATABASE::[EdgeTest_Control] TO [ControlTest_User_CanControlDb];

-- DatabaseRole with CONTROL on database
CREATE ROLE [ControlTest_DbRole_CanControlDb];
GRANT CONTROL ON DATABASE::[EdgeTest_Control] TO [ControlTest_DbRole_CanControlDb];

-- ApplicationRole with CONTROL on database
CREATE APPLICATION ROLE [ControlTest_AppRole_CanControlDb] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT CONTROL ON DATABASE::[EdgeTest_Control] TO [ControlTest_AppRole_CanControlDb];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseUser
-- =====================================================

-- DatabaseUser with CONTROL on database user
CREATE USER [ControlTest_User_CanControlDbUser] WITHOUT LOGIN;
CREATE USER [ControlTest_User_TargetOf_User_CanControlDbUser] WITHOUT LOGIN;
GRANT CONTROL ON USER::[ControlTest_User_TargetOf_User_CanControlDbUser] TO [ControlTest_User_CanControlDbUser];

-- DatabaseRole with CONTROL on database user
CREATE ROLE [ControlTest_DbRole_CanControlDbUser];
CREATE USER [ControlTest_User_TargetOf_DbRole_CanControlDbUser] WITHOUT LOGIN;
GRANT CONTROL ON USER::[ControlTest_User_TargetOf_DbRole_CanControlDbUser] TO [ControlTest_DbRole_CanControlDbUser];

-- ApplicationRole with CONTROL on database user
CREATE APPLICATION ROLE [ControlTest_AppRole_CanControlDbUser] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE USER [ControlTest_User_TargetOf_AppRole_CanControlDbUser] WITHOUT LOGIN;
GRANT CONTROL ON USER::[ControlTest_User_TargetOf_AppRole_CanControlDbUser] TO [ControlTest_AppRole_CanControlDbUser];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
-- =====================================================

-- DatabaseUser with CONTROL on database role
CREATE USER [ControlTest_User_CanControlDbRole] WITHOUT LOGIN;
CREATE ROLE [ControlTest_DbRole_TargetOf_User_CanControlDbRole];
GRANT CONTROL ON ROLE::[ControlTest_DbRole_TargetOf_User_CanControlDbRole] TO [ControlTest_User_CanControlDbRole];

-- DatabaseRole with CONTROL on database role
CREATE ROLE [ControlTest_DbRole_CanControlDbRole];
CREATE ROLE [ControlTest_DbRole_TargetOf_DbRole_CanControlDbRole];
GRANT CONTROL ON ROLE::[ControlTest_DbRole_TargetOf_DbRole_CanControlDbRole] TO [ControlTest_DbRole_CanControlDbRole];

-- ApplicationRole with CONTROL on database role
CREATE APPLICATION ROLE [ControlTest_AppRole_CanControlDbRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE ROLE [ControlTest_DbRole_TargetOf_AppRole_CanControlDbRole];
GRANT CONTROL ON ROLE::[ControlTest_DbRole_TargetOf_AppRole_CanControlDbRole] TO [ControlTest_AppRole_CanControlDbRole];

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> ApplicationRole
-- =====================================================

-- DatabaseUser with CONTROL on application role
CREATE USER [ControlTest_User_CanControlAppRole] WITHOUT LOGIN;
CREATE APPLICATION ROLE [ControlTest_AppRole_TargetOf_User_CanControlAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT CONTROL ON APPLICATION ROLE::[ControlTest_AppRole_TargetOf_User_CanControlAppRole] TO [ControlTest_User_CanControlAppRole];

-- DatabaseRole with CONTROL on application role
CREATE ROLE [ControlTest_DbRole_CanControlAppRole];
CREATE APPLICATION ROLE [ControlTest_AppRole_TargetOf_DbRole_CanControlAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT CONTROL ON APPLICATION ROLE::[ControlTest_AppRole_TargetOf_DbRole_CanControlAppRole] TO [ControlTest_DbRole_CanControlAppRole];

-- ApplicationRole with CONTROL on application role
CREATE APPLICATION ROLE [ControlTest_AppRole_CanControlAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE APPLICATION ROLE [ControlTest_AppRole_TargetOf_AppRole_CanControlAppRole] WITH PASSWORD = 'AppRoleP@ss123!';
GRANT CONTROL ON APPLICATION ROLE::[ControlTest_AppRole_TargetOf_AppRole_CanControlAppRole] TO [ControlTest_AppRole_CanControlAppRole];

USE master;
GO

PRINT 'MSSQL_Control test setup completed';
'@

$script:SetupSQL_ControlDB = @'
-- =====================================================
-- SETUP FOR MSSQL_ControlDB EDGE TESTING
-- =====================================================
USE master;
GO

-- Create test database
CREATE DATABASE [EdgeTest_ControlDB];
GO

USE [EdgeTest_ControlDB];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> Database
-- =====================================================

-- DatabaseUser with CONTROL permission on database
CREATE USER [ControlDBTest_User_HasControlOnDb] WITHOUT LOGIN;
GRANT CONTROL ON DATABASE::[EdgeTest_ControlDB] TO [ControlDBTest_User_HasControlOnDb];
GO

-- DatabaseRole with CONTROL permission on database
CREATE ROLE [ControlDBTest_DbRole_HasControlOnDb];
GRANT CONTROL ON DATABASE::[EdgeTest_ControlDB] TO [ControlDBTest_DbRole_HasControlOnDb];
GO

-- ApplicationRole with CONTROL permission on database
CREATE APPLICATION ROLE [ControlDBTest_AppRole_HasControlOnDb] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL ON DATABASE::[EdgeTest_ControlDB] TO [ControlDBTest_AppRole_HasControlOnDb];
GO

USE master;
GO
'@

$script:SetupSQL_ControlServer = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_ControlServer EDGE TESTING
-- =====================================================
-- This creates all objects needed to test CONTROL SERVER permissions
-- Source node types: MSSQL_ServerLogin, MSSQL_ServerRole
-- Target node type: MSSQL_Server

-- =====================================================
-- OFFENSIVE: Login/ServerRole -> Server
-- =====================================================

-- Login with CONTROL SERVER permission
CREATE LOGIN [ControlServerTest_Login_HasControlServer] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL SERVER TO [ControlServerTest_Login_HasControlServer];

-- ServerRole with CONTROL SERVER permission
CREATE SERVER ROLE [ControlServerTest_ServerRole_HasControlServer];
GRANT CONTROL SERVER TO [ControlServerTest_ServerRole_HasControlServer];

-- Note: sysadmin fixed role has CONTROL SERVER by default

PRINT 'MSSQL_ControlServer test setup completed';
'@

# Define setup SQL for MSSQL_ExecuteAs
$script:SetupSQL_ExecuteAs = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_ExecuteAs EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_ExecuteAs edges (offensive, traversable)

-- Create test database if it doesn't exist
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'EdgeTest_ExecuteAs')
    CREATE DATABASE [EdgeTest_ExecuteAs];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> Login
-- =====================================================

-- Login with IMPERSONATE permission on another login
CREATE LOGIN [ExecuteAsTest_Login_CanImpersonateLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [ExecuteAsTest_Login_TargetOf_Login_CanImpersonateLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ON LOGIN::[ExecuteAsTest_Login_TargetOf_Login_CanImpersonateLogin] TO [ExecuteAsTest_Login_CanImpersonateLogin];

-- Login with CONTROL permission on another login
CREATE LOGIN [ExecuteAsTest_Login_CanControlLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [ExecuteAsTest_Login_TargetOf_Login_CanControlLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL ON LOGIN::[ExecuteAsTest_Login_TargetOf_Login_CanControlLogin] TO [ExecuteAsTest_Login_CanControlLogin];

-- ServerRole with IMPERSONATE permission on login
CREATE SERVER ROLE [ExecuteAsTest_ServerRole_CanImpersonateLogin];
CREATE LOGIN [ExecuteAsTest_Login_TargetOf_ServerRole_CanImpersonateLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ON LOGIN::[ExecuteAsTest_Login_TargetOf_ServerRole_CanImpersonateLogin] TO [ExecuteAsTest_ServerRole_CanImpersonateLogin];

-- ServerRole with CONTROL permission on login
CREATE SERVER ROLE [ExecuteAsTest_ServerRole_CanControlLogin];
CREATE LOGIN [ExecuteAsTest_Login_TargetOf_ServerRole_CanControlLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL ON LOGIN::[ExecuteAsTest_Login_TargetOf_ServerRole_CanControlLogin] TO [ExecuteAsTest_ServerRole_CanControlLogin];

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_ExecuteAs];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser -> DatabaseUser
-- =====================================================

-- DatabaseUser with IMPERSONATE permission on another database user
CREATE USER [ExecuteAsTest_User_CanImpersonateDbUser] WITHOUT LOGIN;
CREATE USER [ExecuteAsTest_User_TargetOf_User_CanImpersonateDbUser] WITHOUT LOGIN;
GRANT IMPERSONATE ON USER::[ExecuteAsTest_User_TargetOf_User_CanImpersonateDbUser] TO [ExecuteAsTest_User_CanImpersonateDbUser];

-- DatabaseUser with CONTROL permission on another database user
CREATE USER [ExecuteAsTest_User_CanControlDbUser] WITHOUT LOGIN;
CREATE USER [ExecuteAsTest_User_TargetOf_User_CanControlDbUser] WITHOUT LOGIN;
GRANT CONTROL ON USER::[ExecuteAsTest_User_TargetOf_User_CanControlDbUser] TO [ExecuteAsTest_User_CanControlDbUser];

-- =====================================================
-- DATABASE LEVEL: DatabaseRole -> DatabaseUser
-- =====================================================

-- DatabaseRole with IMPERSONATE permission on database user
CREATE ROLE [ExecuteAsTest_DbRole_CanImpersonateDbUser];
CREATE USER [ExecuteAsTest_User_TargetOf_DbRole_CanImpersonateDbUser] WITHOUT LOGIN;
GRANT IMPERSONATE ON USER::[ExecuteAsTest_User_TargetOf_DbRole_CanImpersonateDbUser] TO [ExecuteAsTest_DbRole_CanImpersonateDbUser];

-- DatabaseRole with CONTROL permission on database user
CREATE ROLE [ExecuteAsTest_DbRole_CanControlDbUser];
CREATE USER [ExecuteAsTest_User_TargetOf_DbRole_CanControlDbUser] WITHOUT LOGIN;
GRANT CONTROL ON USER::[ExecuteAsTest_User_TargetOf_DbRole_CanControlDbUser] TO [ExecuteAsTest_DbRole_CanControlDbUser];

-- =====================================================
-- DATABASE LEVEL: ApplicationRole -> DatabaseUser
-- =====================================================

-- ApplicationRole with IMPERSONATE permission on database user
CREATE APPLICATION ROLE [ExecuteAsTest_AppRole_CanImpersonateDbUser] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE USER [ExecuteAsTest_User_TargetOf_AppRole_CanImpersonateDbUser] WITHOUT LOGIN;
GRANT IMPERSONATE ON USER::[ExecuteAsTest_User_TargetOf_AppRole_CanImpersonateDbUser] TO [ExecuteAsTest_AppRole_CanImpersonateDbUser];

-- ApplicationRole with CONTROL permission on database user
CREATE APPLICATION ROLE [ExecuteAsTest_AppRole_CanControlDbUser] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE USER [ExecuteAsTest_User_TargetOf_AppRole_CanControlDbUser] WITHOUT LOGIN;
GRANT CONTROL ON USER::[ExecuteAsTest_User_TargetOf_AppRole_CanControlDbUser] TO [ExecuteAsTest_AppRole_CanControlDbUser];

USE master;
GO

PRINT 'MSSQL_ExecuteAs test setup completed';
'@

$script:SetupSQL_ExecuteAsOwner = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_ExecuteAsOwner EDGE TESTING
-- =====================================================
-- This creates all objects needed to test TRUSTWORTHY databases
-- with owners having various high privileges
-- Source node type: MSSQL_Database
-- Target node type: MSSQL_Server

-- =====================================================
-- Create logins with different privilege levels
-- =====================================================

-- Login with sysadmin role
CREATE LOGIN [ExecuteAsOwnerTest_Login_Sysadmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [sysadmin] ADD MEMBER [ExecuteAsOwnerTest_Login_Sysadmin];

-- Can't nest roles in sysadmin

-- Login with securityadmin role
CREATE LOGIN [ExecuteAsOwnerTest_Login_Securityadmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [securityadmin] ADD MEMBER [ExecuteAsOwnerTest_Login_Securityadmin];

-- Role nested in securityadmin role
CREATE SERVER ROLE [ExecuteAsOwnerTest_ServerRole_NestedInSecurityadmin];
ALTER SERVER ROLE [securityadmin] ADD MEMBER [ExecuteAsOwnerTest_ServerRole_NestedInSecurityadmin];

-- Login with role nested in securityadmin role
CREATE LOGIN [ExecuteAsOwnerTest_Login_NestedRoleInSecurityadmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [ExecuteAsOwnerTest_ServerRole_NestedInSecurityadmin] ADD MEMBER [ExecuteAsOwnerTest_Login_NestedRoleInSecurityadmin];

-- Login with CONTROL SERVER permission
CREATE LOGIN [ExecuteAsOwnerTest_Login_ControlServer] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL SERVER TO [ExecuteAsOwnerTest_Login_ControlServer];

-- Login with role with CONTROL SERVER permission
CREATE SERVER ROLE [ExecuteAsOwnerTest_ServerRole_HasControlServer];
GRANT CONTROL SERVER TO [ExecuteAsOwnerTest_ServerRole_HasControlServer];
CREATE LOGIN [ExecuteAsOwnerTest_Login_HasRoleWithControlServer] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [ExecuteAsOwnerTest_ServerRole_HasControlServer] ADD MEMBER [ExecuteAsOwnerTest_Login_HasRoleWithControlServer];

-- Login with IMPERSONATE ANY LOGIN permission
CREATE LOGIN [ExecuteAsOwnerTest_Login_ImpersonateAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ANY LOGIN TO [ExecuteAsOwnerTest_Login_ImpersonateAnyLogin];

-- Login with role with IMPERSONATE ANY LOGIN permission
CREATE SERVER ROLE [ExecuteAsOwnerTest_ServerRole_HasImpersonateAnyLogin];
GRANT IMPERSONATE ANY LOGIN TO [ExecuteAsOwnerTest_ServerRole_HasImpersonateAnyLogin];
CREATE LOGIN [ExecuteAsOwnerTest_Login_HasRoleWithImpersonateAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [ExecuteAsOwnerTest_ServerRole_HasImpersonateAnyLogin] ADD MEMBER [ExecuteAsOwnerTest_Login_HasRoleWithImpersonateAnyLogin];

-- Login without high privileges
CREATE LOGIN [ExecuteAsOwnerTest_Login_NoHighPrivileges] WITH PASSWORD = 'EdgeTestP@ss123!';

-- =====================================================
-- Create TRUSTWORTHY databases with different owners
-- =====================================================

-- Database owned by login with sysadmin (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin] TO [ExecuteAsOwnerTest_Login_Sysadmin];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin] SET TRUSTWORTHY ON;

-- Database owned by login with securityadmin (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin] TO [ExecuteAsOwnerTest_Login_Securityadmin];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin] SET TRUSTWORTHY ON;

-- Database owned by login with role with securityadmin (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithNestedRoleInSecurityadmin];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithNestedRoleInSecurityadmin] TO [ExecuteAsOwnerTest_Login_NestedRoleInSecurityadmin];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithNestedRoleInSecurityadmin] SET TRUSTWORTHY ON;

-- Database owned by login with CONTROL SERVER (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithControlServer];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithControlServer] TO [ExecuteAsOwnerTest_Login_ControlServer];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithControlServer] SET TRUSTWORTHY ON;

-- Database owned by login with role with CONTROL SERVER (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithControlServer];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithControlServer] TO [ExecuteAsOwnerTest_Login_HasRoleWithControlServer];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithControlServer] SET TRUSTWORTHY ON;

-- Database owned by login with IMPERSONATE ANY LOGIN (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithImpersonateAnyLogin];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithImpersonateAnyLogin] TO [ExecuteAsOwnerTest_Login_ImpersonateAnyLogin];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithImpersonateAnyLogin] SET TRUSTWORTHY ON;

-- Database owned by login with role with IMPERSONATE ANY LOGIN (should create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithImpersonateAnyLogin];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithImpersonateAnyLogin] TO [ExecuteAsOwnerTest_Login_HasRoleWithImpersonateAnyLogin];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithImpersonateAnyLogin] SET TRUSTWORTHY ON;

-- Database owned by login without high privileges (should NOT create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges] TO [ExecuteAsOwnerTest_Login_NoHighPrivileges];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges] SET TRUSTWORTHY ON;

-- Database with TRUSTWORTHY OFF owned by sysadmin (should NOT create edge)
CREATE DATABASE [EdgeTest_ExecuteAsOwner_NotTrustworthy];
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_ExecuteAsOwner_NotTrustworthy] TO [ExecuteAsOwnerTest_Login_Sysadmin];
ALTER DATABASE [EdgeTest_ExecuteAsOwner_NotTrustworthy] SET TRUSTWORTHY OFF;

PRINT 'MSSQL_ExecuteAsOwner test setup completed';
'@

$script:SetupSQL_GetTGS = @"
USE master;
GO

-- =====================================================
-- SETUP FOR MSSQL_GetTGS and MSSQL_GetAdminTGS EDGE TESTING
-- =====================================================
-- These edges are created from SQL service accounts to domain principals
-- GetTGS: Service account -> Domain principals with SQL login
-- GetAdminTGS: Service account -> SQL Server (when domain principal has sysadmin)

-- Note: The test assumes domain users were created during setup
-- Create Windows logins for domain users (if they don't exist)

-- Domain user with regular SQL access
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser1')
    CREATE LOGIN [$Domain\EdgeTestDomainUser1] FROM WINDOWS;

-- Domain user with sysadmin (triggers GetAdminTGS)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestSysadmin')
BEGIN
    CREATE LOGIN [$Domain\EdgeTestSysadmin] FROM WINDOWS;
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$Domain\EdgeTestSysadmin];
END

-- Domain group with SQL access
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainGroup')
    CREATE LOGIN [$Domain\EdgeTestDomainGroup] FROM WINDOWS;

-- Another domain user without sysadmin
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser2')
    CREATE LOGIN [$Domain\EdgeTestDomainUser2] FROM WINDOWS;

-- Verify service account configuration
SELECT 
    servicename,
    service_account,
    CASE 
        WHEN service_account LIKE '%\%' AND service_account NOT LIKE 'NT SERVICE\%' 
             AND service_account NOT LIKE 'NT AUTHORITY\%' 
        THEN 'Domain Account'
        ELSE 'Local/Built-in Account'
    END as account_type
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server%';

PRINT 'MSSQL_GetTGS and MSSQL_GetAdminTGS test setup completed';
"@

$script:SetupSQL_GrantAnyDBPermission = @'
-- =====================================================
-- SETUP FOR MSSQL_GrantAnyDBPermission EDGE TESTING
-- =====================================================
USE master;
GO

-- Create test databases
CREATE DATABASE [EdgeTest_GrantAnyDBPermission];
GO

CREATE DATABASE [EdgeTest_GrantAnyDBPermission_Second];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseRole -> Database
-- =====================================================

USE [EdgeTest_GrantAnyDBPermission];
GO

-- Create test users to be members of db_securityadmin
CREATE USER [GrantAnyDBPermissionTest_User_InDbSecurityAdmin] WITHOUT LOGIN;
ALTER ROLE db_securityadmin ADD MEMBER [GrantAnyDBPermissionTest_User_InDbSecurityAdmin];

-- Create another user not in db_securityadmin (negative test)
CREATE USER [GrantAnyDBPermissionTest_User_NotInDbSecurityAdmin] WITHOUT LOGIN;

-- Create a custom role that has ALTER ANY ROLE permission (negative test - should not create edge)
CREATE ROLE [GrantAnyDBPermissionTest_CustomRole_HasAlterAnyRole];
GRANT ALTER ANY ROLE TO [GrantAnyDBPermissionTest_CustomRole_HasAlterAnyRole];

-- Create test objects that db_securityadmin can control via permissions
CREATE ROLE [GrantAnyDBPermissionTest_TargetRole1];
CREATE ROLE [GrantAnyDBPermissionTest_TargetRole2];
CREATE USER [GrantAnyDBPermissionTest_TargetUser] WITHOUT LOGIN;

USE [EdgeTest_GrantAnyDBPermission_Second];
GO

-- Create another db_securityadmin member in second database
CREATE USER [GrantAnyDBPermissionTest_User_InDbSecurityAdmin_DB2] WITHOUT LOGIN;
ALTER ROLE db_securityadmin ADD MEMBER [GrantAnyDBPermissionTest_User_InDbSecurityAdmin_DB2];

USE master;
GO

PRINT 'MSSQL_GrantAnyDBPermission test setup completed';
'@

$script:SetupSQL_GrantAnyPermission = @'
-- =====================================================
-- SETUP FOR MSSQL_GrantAnyPermission EDGE TESTING
-- =====================================================
USE master;
GO

-- The securityadmin fixed role exists by default, no setup needed

-- Create test logins to demonstrate the power of securityadmin
CREATE LOGIN [GrantAnyPermissionTest_Login_Target1] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [GrantAnyPermissionTest_Login_Target2] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create a login that is a member of securityadmin (for negative test)
CREATE LOGIN [GrantAnyPermissionTest_Login_InSecurityAdmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [securityadmin] ADD MEMBER [GrantAnyPermissionTest_Login_InSecurityAdmin];

-- Create a custom server role with ALTER ANY LOGIN (negative test - should not create edge)
CREATE SERVER ROLE [GrantAnyPermissionTest_CustomRole_HasAlterAnyLogin];
GRANT ALTER ANY LOGIN TO [GrantAnyPermissionTest_CustomRole_HasAlterAnyLogin];

-- Create login without special permissions
CREATE LOGIN [GrantAnyPermissionTest_Login_NoSpecialPerms] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create database to verify edge is server-level only
CREATE DATABASE [EdgeTest_GrantAnyPermission];
GO

PRINT 'MSSQL_GrantAnyPermission test setup completed';
'@

$script:SetupSQL_HasDBScopedCred = @'
-- =====================================================
-- SETUP FOR MSSQL_HasDBScopedCred EDGE TESTING
-- =====================================================
USE master;
GO

-- Create test databases
CREATE DATABASE [EdgeTest_HasDBScopedCred];
GO

-- =====================================================
-- DATABASE LEVEL: Database -> Base (Domain Account)
-- =====================================================

USE [EdgeTest_HasDBScopedCred];
GO

-- Create database master key (required for database-scoped credentials)
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MasterKeyP@ss123!';
GO

-- Note: Database-scoped credentials require SQL Server 2016 or later
-- Create database-scoped credentials for domain accounts
-- These credentials authenticate as domain users when accessing external resources

-- Credential for domain user (will create edge if user exists)
IF EXISTS (SELECT * FROM sys.database_scoped_credentials WHERE name = 'HasDBScopedCredTest_DomainUser1')
    DROP DATABASE SCOPED CREDENTIAL [HasDBScopedCredTest_DomainUser1];
CREATE DATABASE SCOPED CREDENTIAL [HasDBScopedCredTest_DomainUser1]
    WITH IDENTITY = 'MAYYHEM\EdgeTestDomainUser1',
    SECRET = 'EdgeTestP@ss123!';

-- Non-domain credential (negative test - should not create edge)
IF EXISTS (SELECT * FROM sys.database_scoped_credentials WHERE name = 'HasDBScopedCredTest_NonDomain')
    DROP DATABASE SCOPED CREDENTIAL [HasDBScopedCredTest_NonDomain];
CREATE DATABASE SCOPED CREDENTIAL [HasDBScopedCredTest_NonDomain]
    WITH IDENTITY = 'https://mystorageaccount.blob.core.windows.net/',
    SECRET = 'SAS_TOKEN_HERE';

-- Local account credential (negative test - should not create edge)
IF EXISTS (SELECT * FROM sys.database_scoped_credentials WHERE name = 'HasDBScopedCredTest_LocalAccount')
    DROP DATABASE SCOPED CREDENTIAL [HasDBScopedCredTest_LocalAccount];
CREATE DATABASE SCOPED CREDENTIAL [HasDBScopedCredTest_LocalAccount]
    WITH IDENTITY = 'LocalUser',
    SECRET = 'LocalP@ss123!';

USE master;
GO

PRINT 'MSSQL_HasDBScopedCred test setup completed';
'@

$script:SetupSQL_HasLogin = @'
-- =====================================================
-- SETUP FOR MSSQL_HasLogin EDGE TESTING
-- =====================================================
USE master;
GO

-- Create domain logins with CONNECT SQL permission (enabled by default)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\EdgeTestDomainUser1')
    CREATE LOGIN [MAYYHEM\EdgeTestDomainUser1] FROM WINDOWS;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\EdgeTestDomainUser2')
    CREATE LOGIN [MAYYHEM\EdgeTestDomainUser2] FROM WINDOWS;

-- Create domain group login
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\EdgeTestDomainGroup')
    CREATE LOGIN [MAYYHEM\EdgeTestDomainGroup] FROM WINDOWS;

-- Create computer account login
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\TestComputer$')
    CREATE LOGIN [MAYYHEM\TestComputer$] FROM WINDOWS;

-- Create disabled domain login (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\EdgeTestDisabledUser')
    CREATE LOGIN [MAYYHEM\EdgeTestDisabledUser] FROM WINDOWS;
ALTER LOGIN [MAYYHEM\EdgeTestDisabledUser] DISABLE;

-- Create domain login with CONNECT SQL denied (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MAYYHEM\EdgeTestNoConnect')
    CREATE LOGIN [MAYYHEM\EdgeTestNoConnect] FROM WINDOWS;
DENY CONNECT SQL TO [MAYYHEM\EdgeTestNoConnect];

-- Create local group and add it as login
-- Note: This requires the group to exist on the SQL Server host
-- The test framework should handle creation of BUILTIN groups
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'BUILTIN\Remote Desktop Users')
    CREATE LOGIN [BUILTIN\Remote Desktop Users] FROM WINDOWS;

-- Create SQL login (negative test - not a domain account)
CREATE LOGIN [HasLoginTest_SQLLogin] WITH PASSWORD = 'EdgeTestP@ss123!';

PRINT 'MSSQL_HasLogin test setup completed';
'@

$script:SetupSQL_HasMappedCred = @"
-- =====================================================
-- SETUP FOR MSSQL_HasMappedCred EDGE TESTING
-- =====================================================
USE master;
GO

-- Dynamic domain handling
DECLARE @Domain NVARCHAR(128) = '$Domain';
DECLARE @sql NVARCHAR(MAX);
DECLARE @identity NVARCHAR(256);

-- Create server-level credentials for domain accounts
-- Note: CREATE CREDENTIAL requires CONTROL SERVER or ALTER ANY CREDENTIAL permission

-- Credential for domain user 1
SET @identity = @Domain + '\EdgeTestDomainUser1';
SET @sql = 'IF EXISTS (SELECT * FROM sys.credentials WHERE name = ''HasMappedCredTest_DomainUser1'')
    DROP CREDENTIAL [HasMappedCredTest_DomainUser1]';
EXEC sp_executesql @sql;

SET @sql = 'CREATE CREDENTIAL [HasMappedCredTest_DomainUser1]
    WITH IDENTITY = ''' + @identity + ''',
    SECRET = ''EdgeTestP@ss123!''';
EXEC sp_executesql @sql;

-- Credential for domain user 2
SET @identity = @Domain + '\EdgeTestDomainUser2';
SET @sql = 'IF EXISTS (SELECT * FROM sys.credentials WHERE name = ''HasMappedCredTest_DomainUser2'')
    DROP CREDENTIAL [HasMappedCredTest_DomainUser2]';
EXEC sp_executesql @sql;

SET @sql = 'CREATE CREDENTIAL [HasMappedCredTest_DomainUser2]
    WITH IDENTITY = ''' + @identity + ''',
    SECRET = ''EdgeTestP@ss123!''';
EXEC sp_executesql @sql;

-- Credential for computer account
SET @identity = @Domain + '\TestComputer`$';
SET @sql = 'IF EXISTS (SELECT * FROM sys.credentials WHERE name = ''HasMappedCredTest_ComputerAccount'')
    DROP CREDENTIAL [HasMappedCredTest_ComputerAccount]';
EXEC sp_executesql @sql;

SET @sql = 'CREATE CREDENTIAL [HasMappedCredTest_ComputerAccount]
    WITH IDENTITY = ''' + @identity + ''',
    SECRET = ''ComputerP@ss123!''';
EXEC sp_executesql @sql;

-- Non-domain credential for Azure storage (negative test)
IF EXISTS (SELECT * FROM sys.credentials WHERE name = 'HasMappedCredTest_AzureStorage')
    DROP CREDENTIAL [HasMappedCredTest_AzureStorage];
CREATE CREDENTIAL [HasMappedCredTest_AzureStorage]
    WITH IDENTITY = 'https://mystorageaccount.blob.core.windows.net/',
    SECRET = 'SAS_TOKEN_HERE';

-- Local account credential (negative test)
IF EXISTS (SELECT * FROM sys.credentials WHERE name = 'HasMappedCredTest_LocalAdmin')
    DROP CREDENTIAL [HasMappedCredTest_LocalAdmin];
CREATE CREDENTIAL [HasMappedCredTest_LocalAdmin]
    WITH IDENTITY = 'LocalAdmin',
    SECRET = 'LocalP@ss123!';

-- =====================================================
-- Create SQL logins that map to these credentials
-- =====================================================

-- SQL login mapped to DomainUser1
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasMappedCredTest_SQLLogin_MappedToDomainUser1')
    CREATE LOGIN [HasMappedCredTest_SQLLogin_MappedToDomainUser1] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER LOGIN [HasMappedCredTest_SQLLogin_MappedToDomainUser1] WITH CREDENTIAL = [HasMappedCredTest_DomainUser1];

-- SQL login mapped to DomainUser2
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasMappedCredTest_SQLLogin_MappedToDomainUser2')
    CREATE LOGIN [HasMappedCredTest_SQLLogin_MappedToDomainUser2] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER LOGIN [HasMappedCredTest_SQLLogin_MappedToDomainUser2] WITH CREDENTIAL = [HasMappedCredTest_DomainUser2];

-- SQL login mapped to computer account
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasMappedCredTest_SQLLogin_MappedToComputerAccount')
    CREATE LOGIN [HasMappedCredTest_SQLLogin_MappedToComputerAccount] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER LOGIN [HasMappedCredTest_SQLLogin_MappedToComputerAccount] WITH CREDENTIAL = [HasMappedCredTest_ComputerAccount];

-- SQL login without mapped credential (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasMappedCredTest_SQLLogin_NoCredential')
    CREATE LOGIN [HasMappedCredTest_SQLLogin_NoCredential] WITH PASSWORD = 'EdgeTestP@ss123!';

-- =====================================================
-- Create Windows login and map credential to it
-- =====================================================

-- Create Windows login if it doesn't exist
SET @sql = 'IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = ''' + @Domain + '\EdgeTestDomainUser1'')
BEGIN
    CREATE LOGIN [' + @Domain + '\EdgeTestDomainUser1] FROM WINDOWS
    PRINT ''Created Windows login: ' + @Domain + '\EdgeTestDomainUser1''
END';
EXEC sp_executesql @sql;

-- Map credential to the Windows login (user1 login gets user2 credential)
SET @sql = 'ALTER LOGIN [' + @Domain + '\EdgeTestDomainUser1] WITH CREDENTIAL = [HasMappedCredTest_DomainUser2]';
EXEC sp_executesql @sql;
PRINT 'Mapped credential HasMappedCredTest_DomainUser2 to Windows login ' + @Domain + '\EdgeTestDomainUser1';

-- =====================================================
-- Verify credential mappings
-- =====================================================
PRINT '';
PRINT 'Credential mappings created:';
SELECT 
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    c.name AS CredentialName,
    c.credential_identity AS CredentialIdentity
FROM sys.server_principals sp
LEFT JOIN sys.credentials c ON sp.credential_id = c.credential_id
WHERE (sp.name LIKE 'HasMappedCredTest_%' OR sp.credential_id IS NOT NULL)
    AND sp.name NOT LIKE '##%'  -- Exclude system logins
ORDER BY sp.name;

PRINT '';
PRINT 'MSSQL_HasMappedCred test setup completed';
"@

$script:SetupSQL_HasProxyCred = @"
-- =====================================================
-- SETUP FOR MSSQL_HasProxyCred EDGE TESTING
-- =====================================================
USE master;
GO

-- Create server-level credentials for proxy accounts
-- Credential for domain user (ETL operations)
IF EXISTS (SELECT * FROM sys.credentials WHERE name = 'HasProxyCredTest_ETLUserCred')
    DROP CREDENTIAL [HasProxyCredTest_ETLUserCred];
CREATE CREDENTIAL [HasProxyCredTest_ETLUserCred]
    WITH IDENTITY = '$Domain\EdgeTestDomainUser1',
    SECRET = 'EdgeTestP@ss123!';

-- Credential for service account (backup operations)
IF EXISTS (SELECT * FROM sys.credentials WHERE name = 'HasProxyCredTest_BackupServiceCred')
    DROP CREDENTIAL [HasProxyCredTest_BackupServiceCred];
CREATE CREDENTIAL [HasProxyCredTest_BackupServiceCred]
    WITH IDENTITY = '$Domain\EdgeTestDomainUser2',
    SECRET = 'EdgeTestP@ss123!';

-- Credential for computer account
IF EXISTS (SELECT * FROM sys.credentials WHERE name = 'HasProxyCredTest_ComputerCred')
    DROP CREDENTIAL [HasProxyCredTest_ComputerCred];
CREATE CREDENTIAL [HasProxyCredTest_ComputerCred]
    WITH IDENTITY = '$Domain\TestComputer$',
    SECRET = 'ComputerP@ss123!';

-- Non-domain credential (negative test)
IF EXISTS (SELECT * FROM sys.credentials WHERE name = 'HasProxyCredTest_LocalCred')
    DROP CREDENTIAL [HasProxyCredTest_LocalCred];
CREATE CREDENTIAL [HasProxyCredTest_LocalCred]
    WITH IDENTITY = 'NT AUTHORITY\LOCAL SERVICE',
    SECRET = 'LocalP@ss123!';

-- =====================================================
-- Create SQL Agent proxies
-- =====================================================
USE msdb;
GO

-- ETL Proxy (authorized to SQL login and server role)
IF EXISTS (SELECT * FROM dbo.sysproxies WHERE name = 'HasProxyCredTest_ETLProxy')
    EXEC dbo.sp_delete_proxy @proxy_name = 'HasProxyCredTest_ETLProxy';

EXEC dbo.sp_add_proxy 
    @proxy_name = 'HasProxyCredTest_ETLProxy',
    @credential_name = 'HasProxyCredTest_ETLUserCred',
    @enabled = 1,
    @description = 'Proxy for ETL operations';

-- Grant proxy to CmdExec and PowerShell subsystems
EXEC dbo.sp_grant_proxy_to_subsystem 
    @proxy_name = 'HasProxyCredTest_ETLProxy',
    @subsystem_name = 'CmdExec';

EXEC dbo.sp_grant_proxy_to_subsystem 
    @proxy_name = 'HasProxyCredTest_ETLProxy',
    @subsystem_name = 'PowerShell';

-- Backup Proxy (authorized to different principals)
IF EXISTS (SELECT * FROM dbo.sysproxies WHERE name = 'HasProxyCredTest_BackupProxy')
    EXEC dbo.sp_delete_proxy @proxy_name = 'HasProxyCredTest_BackupProxy';

EXEC dbo.sp_add_proxy 
    @proxy_name = 'HasProxyCredTest_BackupProxy',
    @credential_name = 'HasProxyCredTest_BackupServiceCred',
    @enabled = 1,
    @description = 'Proxy for backup operations';

-- Grant proxy to CmdExec subsystem only
EXEC dbo.sp_grant_proxy_to_subsystem 
    @proxy_name = 'HasProxyCredTest_BackupProxy',
    @subsystem_name = 'CmdExec';

-- Disabled proxy (negative test)
IF EXISTS (SELECT * FROM dbo.sysproxies WHERE name = 'HasProxyCredTest_DisabledProxy')
    EXEC dbo.sp_delete_proxy @proxy_name = 'HasProxyCredTest_DisabledProxy';

EXEC dbo.sp_add_proxy 
    @proxy_name = 'HasProxyCredTest_DisabledProxy',
    @credential_name = 'HasProxyCredTest_ComputerCred',
    @enabled = 0,  -- Disabled
    @description = 'Disabled proxy for testing';

-- Grant subsystem but proxy is disabled
EXEC dbo.sp_grant_proxy_to_subsystem 
    @proxy_name = 'HasProxyCredTest_DisabledProxy',
    @subsystem_name = 'CmdExec';

-- Local credential proxy (negative test - non-domain)
IF EXISTS (SELECT * FROM dbo.sysproxies WHERE name = 'HasProxyCredTest_LocalProxy')
    EXEC dbo.sp_delete_proxy @proxy_name = 'HasProxyCredTest_LocalProxy';

EXEC dbo.sp_add_proxy 
    @proxy_name = 'HasProxyCredTest_LocalProxy',
    @credential_name = 'HasProxyCredTest_LocalCred',
    @enabled = 1,
    @description = 'Proxy with local credential';

USE master;
GO

-- =====================================================
-- Create logins and grant proxy access
-- =====================================================

-- SQL login authorized to use ETL proxy
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasProxyCredTest_ETLOperator')
    CREATE LOGIN [HasProxyCredTest_ETLOperator] WITH PASSWORD = 'EdgeTestP@ss123!';

-- SQL login authorized to use backup proxy
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasProxyCredTest_BackupOperator')
    CREATE LOGIN [HasProxyCredTest_BackupOperator] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Server role authorized to use proxies
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasProxyCredTest_ProxyUsers' AND type = 'R')
    CREATE SERVER ROLE [HasProxyCredTest_ProxyUsers];

-- SQL login not authorized to any proxy (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'HasProxyCredTest_NoProxyAccess')
    CREATE LOGIN [HasProxyCredTest_NoProxyAccess] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Windows login to test
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser1')
    CREATE LOGIN [$Domain\EdgeTestDomainUser1] FROM WINDOWS;

-- =====================================================
-- Grant proxy access to principals
-- =====================================================
USE msdb;
GO

-- Grant ETL proxy to SQL login
EXEC dbo.sp_grant_login_to_proxy 
    @login_name = 'HasProxyCredTest_ETLOperator',
    @proxy_name = 'HasProxyCredTest_ETLProxy';

-- Grant ETL proxy to server role
EXEC dbo.sp_grant_login_to_proxy 
    @login_name = 'HasProxyCredTest_ProxyUsers',
    @proxy_name = 'HasProxyCredTest_ETLProxy';

-- Grant backup proxy to different login
EXEC dbo.sp_grant_login_to_proxy 
    @login_name = 'HasProxyCredTest_BackupOperator',
    @proxy_name = 'HasProxyCredTest_BackupProxy';

-- Grant disabled proxy to login (still creates edge but proxy is disabled)
EXEC dbo.sp_grant_login_to_proxy 
    @login_name = 'HasProxyCredTest_ETLOperator',
    @proxy_name = 'HasProxyCredTest_DisabledProxy';

-- Grant proxy to Windows login
EXEC dbo.sp_grant_login_to_proxy 
    @login_name = '$Domain\EdgeTestDomainUser1',
    @proxy_name = 'HasProxyCredTest_BackupProxy';

USE master;
GO

-- =====================================================
-- Verify proxy configurations
-- =====================================================
PRINT '';
PRINT 'SQL Agent Proxy configurations:';
SELECT 
    p.name AS ProxyName,
    c.credential_identity AS RunsAs,
    p.enabled AS IsEnabled,
    STUFF((
        SELECT ', ' + SUSER_SNAME(pl.sid)
        FROM msdb.dbo.sysproxylogin pl
        WHERE pl.proxy_id = p.proxy_id
        FOR XML PATH('')
    ), 1, 2, '') AS AuthorizedPrincipals,
    STUFF((
        SELECT ', ' + s.subsystem
        FROM msdb.dbo.sysproxysubsystem ps
        INNER JOIN msdb.dbo.syssubsystems s ON ps.subsystem_id = s.subsystem_id
        WHERE ps.proxy_id = p.proxy_id
        FOR XML PATH('')
    ), 1, 2, '') AS Subsystems
FROM msdb.dbo.sysproxies p
INNER JOIN sys.credentials c ON p.credential_id = c.credential_id
WHERE p.name LIKE 'HasProxyCredTest_%'
ORDER BY p.name;

PRINT '';
PRINT 'MSSQL_HasProxyCred test setup completed';
"@

# Define setup SQL for MSSQL_Impersonate
$script:SetupSQL_Impersonate = @'
USE master;
GO

-- =====================================================
-- COMPLETE SETUP FOR MSSQL_Impersonate EDGE TESTING
-- =====================================================
-- This creates all objects needed to test every source/target 
-- combination for MSSQL_Impersonate edges (offensive, non-traversable)

-- Create test database if it doesn't exist
CREATE DATABASE [EdgeTest_Impersonate];
GO

-- =====================================================
-- SERVER LEVEL: Login/ServerRole -> Login
-- =====================================================

-- Login with IMPERSONATE permission on another login
CREATE LOGIN [ImpersonateTest_Login_CanImpersonateLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
CREATE LOGIN [ImpersonateTest_Login_TargetOf_Login_CanImpersonateLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ON LOGIN::[ImpersonateTest_Login_TargetOf_Login_CanImpersonateLogin] TO [ImpersonateTest_Login_CanImpersonateLogin];

-- ServerRole with IMPERSONATE permission on login
CREATE SERVER ROLE [ImpersonateTest_ServerRole_CanImpersonateLogin];
CREATE LOGIN [ImpersonateTest_Login_TargetOf_ServerRole_CanImpersonateLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ON LOGIN::[ImpersonateTest_Login_TargetOf_ServerRole_CanImpersonateLogin] TO [ImpersonateTest_ServerRole_CanImpersonateLogin];

-- =====================================================
-- DATABASE LEVEL SETUP
-- =====================================================

USE [EdgeTest_Impersonate];
GO

-- =====================================================
-- DATABASE LEVEL: DatabaseUser -> DatabaseUser
-- =====================================================

-- DatabaseUser with IMPERSONATE permission on another database user
CREATE USER [ImpersonateTest_User_CanImpersonateDbUser] WITHOUT LOGIN;
CREATE USER [ImpersonateTest_User_TargetOf_User_CanImpersonateDbUser] WITHOUT LOGIN;
GRANT IMPERSONATE ON USER::[ImpersonateTest_User_TargetOf_User_CanImpersonateDbUser] TO [ImpersonateTest_User_CanImpersonateDbUser];

-- =====================================================
-- DATABASE LEVEL: DatabaseRole -> DatabaseUser
-- =====================================================

-- DatabaseRole with IMPERSONATE permission on database user
CREATE ROLE [ImpersonateTest_DbRole_CanImpersonateDbUser];
CREATE USER [ImpersonateTest_User_TargetOf_DbRole_CanImpersonateDbUser] WITHOUT LOGIN;
GRANT IMPERSONATE ON USER::[ImpersonateTest_User_TargetOf_DbRole_CanImpersonateDbUser] TO [ImpersonateTest_DbRole_CanImpersonateDbUser];

-- =====================================================
-- DATABASE LEVEL: ApplicationRole -> DatabaseUser
-- =====================================================

-- ApplicationRole with IMPERSONATE permission on database user
CREATE APPLICATION ROLE [ImpersonateTest_AppRole_CanImpersonateDbUser] WITH PASSWORD = 'AppRoleP@ss123!';
CREATE USER [ImpersonateTest_User_TargetOf_AppRole_CanImpersonateDbUser] WITHOUT LOGIN;
GRANT IMPERSONATE ON USER::[ImpersonateTest_User_TargetOf_AppRole_CanImpersonateDbUser] TO [ImpersonateTest_AppRole_CanImpersonateDbUser];

USE master;
GO

PRINT 'MSSQL_Impersonate test setup completed';
'@

$script:SetupSQL_ImpersonateAnyLogin = @"
-- =====================================================
-- SETUP FOR MSSQL_ImpersonateAnyLogin EDGE TESTING
-- =====================================================
USE master;
GO

-- Create logins with IMPERSONATE ANY LOGIN permission
-- SQL login with IMPERSONATE ANY LOGIN
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ImpersonateAnyLoginTest_Login_Direct')
    CREATE LOGIN [ImpersonateAnyLoginTest_Login_Direct] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ANY LOGIN TO [ImpersonateAnyLoginTest_Login_Direct];

-- Server role with IMPERSONATE ANY LOGIN
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ImpersonateAnyLoginTest_Role_HasPermission' AND type = 'R')
    CREATE SERVER ROLE [ImpersonateAnyLoginTest_Role_HasPermission];
GRANT IMPERSONATE ANY LOGIN TO [ImpersonateAnyLoginTest_Role_HasPermission];

-- Login member of role with IMPERSONATE ANY LOGIN
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ImpersonateAnyLoginTest_Login_ViaRole')
    CREATE LOGIN [ImpersonateAnyLoginTest_Login_ViaRole] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [ImpersonateAnyLoginTest_Role_HasPermission] ADD MEMBER [ImpersonateAnyLoginTest_Login_ViaRole];

-- Windows login with IMPERSONATE ANY LOGIN
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser1')
    CREATE LOGIN [$Domain\EdgeTestDomainUser1] FROM WINDOWS;
GRANT IMPERSONATE ANY LOGIN TO [$Domain\EdgeTestDomainUser1];

-- Create test targets to impersonate
-- High privilege login (sysadmin)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ImpersonateAnyLoginTest_Target_Sysadmin')
    CREATE LOGIN [ImpersonateAnyLoginTest_Target_Sysadmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [sysadmin] ADD MEMBER [ImpersonateAnyLoginTest_Target_Sysadmin];

-- Regular login
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ImpersonateAnyLoginTest_Target_Regular')
    CREATE LOGIN [ImpersonateAnyLoginTest_Target_Regular] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Login without IMPERSONATE ANY LOGIN (negative test)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'ImpersonateAnyLoginTest_Login_NoPermission')
    CREATE LOGIN [ImpersonateAnyLoginTest_Login_NoPermission] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Verify permissions
PRINT '';
PRINT 'Principals with IMPERSONATE ANY LOGIN permission:';
SELECT 
    p.name AS PrincipalName,
    p.type_desc AS PrincipalType,
    sp.permission_name,
    sp.state_desc
FROM sys.server_permissions sp
INNER JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id
WHERE sp.permission_name = 'IMPERSONATE ANY LOGIN'
    AND sp.state IN ('GRANT', 'GRANT_WITH_GRANT_OPTION')
ORDER BY p.name;

PRINT '';
PRINT 'MSSQL_ImpersonateAnyLogin test setup completed';
"@

$script:SetupSQL_IsMappedTo = @"
-- =====================================================
-- SETUP FOR MSSQL_IsMappedTo EDGE TESTING
-- =====================================================
USE master;
GO

-- Create SQL logins
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'IsMappedToTest_SQLLogin_WithDBUser')
    CREATE LOGIN [IsMappedToTest_SQLLogin_WithDBUser] WITH PASSWORD = 'EdgeTestP@ss123!';

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'IsMappedToTest_SQLLogin_NoDBUser')
    CREATE LOGIN [IsMappedToTest_SQLLogin_NoDBUser] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create Windows logins
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser1')
    CREATE LOGIN [$Domain\EdgeTestDomainUser1] FROM WINDOWS;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser2')
    CREATE LOGIN [$Domain\EdgeTestDomainUser2] FROM WINDOWS;

-- Create test databases
CREATE DATABASE [EdgeTest_IsMappedTo_Primary];
GO

CREATE DATABASE [EdgeTest_IsMappedTo_Secondary];
GO

-- =====================================================
-- PRIMARY DATABASE - Create mapped users
-- =====================================================
USE [EdgeTest_IsMappedTo_Primary];
GO

-- SQL user mapped to SQL login
CREATE USER [IsMappedToTest_SQLLogin_WithDBUser] FOR LOGIN [IsMappedToTest_SQLLogin_WithDBUser];

-- Windows user mapped to Windows login
CREATE USER [$Domain\EdgeTestDomainUser1] FOR LOGIN [$Domain\EdgeTestDomainUser1];

-- User without login (orphaned - negative test)
CREATE USER [IsMappedToTest_OrphanedUser] WITHOUT LOGIN;

-- =====================================================
-- SECONDARY DATABASE - Different mappings
-- =====================================================
USE [EdgeTest_IsMappedTo_Secondary];
GO

-- Same SQL login mapped to different user name
CREATE USER [IsMappedToTest_DifferentUserName] FOR LOGIN [IsMappedToTest_SQLLogin_WithDBUser];

-- Windows user 2 mapped
CREATE USER [$Domain\EdgeTestDomainUser2] FOR LOGIN [$Domain\EdgeTestDomainUser2];

-- Create master key for certificate operations
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'EdgeTestMasterKey123!';
GO

-- Certificate mapped user (if testing certificate mappings)
CREATE CERTIFICATE IsMappedToTest_Cert WITH SUBJECT = 'Test Certificate';
CREATE USER [IsMappedToTest_CertUser] FOR CERTIFICATE IsMappedToTest_Cert;

USE master;
GO

-- Verify mappings
PRINT '';
PRINT 'Login to Database User mappings:';
SELECT 
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    DB_NAME() + '\' + dp.name AS DatabaseUser,
    dp.type_desc AS UserType
FROM sys.server_principals sp
INNER JOIN sys.database_principals dp ON sp.sid = dp.sid
WHERE sp.name LIKE '%IsMappedToTest_%' OR sp.name LIKE '%EdgeTest%'
ORDER BY sp.name, DB_NAME();

PRINT '';
PRINT 'MSSQL_IsMappedTo test setup completed';
"@

$script:SetupSQL_LinkedTo = @"
-- =====================================================
-- SETUP FOR MSSQL_LinkedTo and MSSQL_LinkedAsAdmin EDGE TESTING
-- =====================================================
USE master;
GO

-- =====================================================
-- 1. REGULAR SQL LOGIN - No admin privileges
-- Expected: Creates LinkedTo but NOT LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_Regular')
    CREATE LOGIN [LinkedToTest_SQLLogin_Regular] WITH PASSWORD = 'EdgeTestP@ss123!';

-- =====================================================
-- 2. SYSADMIN SQL LOGIN - Direct sysadmin membership
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_Sysadmin')
    CREATE LOGIN [LinkedToTest_SQLLogin_Sysadmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [sysadmin] ADD MEMBER [LinkedToTest_SQLLogin_Sysadmin];

-- =====================================================
-- 3. SECURITYADMIN SQL LOGIN - Direct securityadmin membership
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_SecurityAdmin')
    CREATE LOGIN [LinkedToTest_SQLLogin_SecurityAdmin] WITH PASSWORD = 'EdgeTestP@ss123!';
ALTER SERVER ROLE [securityadmin] ADD MEMBER [LinkedToTest_SQLLogin_SecurityAdmin];

-- =====================================================
-- 4. CONTROL SERVER SQL LOGIN - Direct CONTROL SERVER permission
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_ControlServer')
    CREATE LOGIN [LinkedToTest_SQLLogin_ControlServer] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT CONTROL SERVER TO [LinkedToTest_SQLLogin_ControlServer];

-- =====================================================
-- 5. IMPERSONATE ANY LOGIN SQL LOGIN - Direct IMPERSONATE ANY LOGIN permission
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_ImpersonateAnyLogin')
    CREATE LOGIN [LinkedToTest_SQLLogin_ImpersonateAnyLogin] WITH PASSWORD = 'EdgeTestP@ss123!';
GRANT IMPERSONATE ANY LOGIN TO [LinkedToTest_SQLLogin_ImpersonateAnyLogin];

-- =====================================================
-- 6. SQL LOGIN WITH 1-LEVEL NESTED ADMIN ROLE
-- Login -> Role (with CONTROL SERVER)
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_WithAdminRole')
    CREATE LOGIN [LinkedToTest_SQLLogin_WithAdminRole] WITH PASSWORD = 'EdgeTestP@ss123!';

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_CustomAdminRole' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_CustomAdminRole];
GRANT CONTROL SERVER TO [LinkedToTest_CustomAdminRole];
ALTER SERVER ROLE [LinkedToTest_CustomAdminRole] ADD MEMBER [LinkedToTest_SQLLogin_WithAdminRole];

-- =====================================================
-- 7. SQL LOGIN WITH 3-LEVEL NESTED SECURITYADMIN
-- Login -> Role1 -> Role2 -> Role3 -> securityadmin
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_NestedSecurityAdmin')
    CREATE LOGIN [LinkedToTest_SQLLogin_NestedSecurityAdmin] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create nested role hierarchy
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_Level1' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_Level1];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_Level2' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_Level2];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_Level3' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_Level3];

-- Build the hierarchy: Login -> Level1 -> Level2 -> Level3 -> securityadmin
ALTER SERVER ROLE [LinkedToTest_Role_Level1] ADD MEMBER [LinkedToTest_SQLLogin_NestedSecurityAdmin];
ALTER SERVER ROLE [LinkedToTest_Role_Level2] ADD MEMBER [LinkedToTest_Role_Level1];
ALTER SERVER ROLE [LinkedToTest_Role_Level3] ADD MEMBER [LinkedToTest_Role_Level2];
ALTER SERVER ROLE [securityadmin] ADD MEMBER [LinkedToTest_Role_Level3];

-- =====================================================
-- 8. SQL LOGIN WITH 3-LEVEL NESTED CONTROL SERVER
-- Login -> RoleA -> RoleB -> RoleC (with CONTROL SERVER)
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_NestedControlServer')
    CREATE LOGIN [LinkedToTest_SQLLogin_NestedControlServer] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create nested role hierarchy
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_LevelA' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_LevelA];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_LevelB' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_LevelB];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_LevelC' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_LevelC];

-- Build the hierarchy: Login -> LevelA -> LevelB -> LevelC (grant CONTROL SERVER to LevelC)
ALTER SERVER ROLE [LinkedToTest_Role_LevelA] ADD MEMBER [LinkedToTest_SQLLogin_NestedControlServer];
ALTER SERVER ROLE [LinkedToTest_Role_LevelB] ADD MEMBER [LinkedToTest_Role_LevelA];
ALTER SERVER ROLE [LinkedToTest_Role_LevelC] ADD MEMBER [LinkedToTest_Role_LevelB];
GRANT CONTROL SERVER TO [LinkedToTest_Role_LevelC];

-- =====================================================
-- 9. SQL LOGIN WITH 3-LEVEL NESTED IMPERSONATE ANY LOGIN
-- Login -> RoleX -> RoleY -> RoleZ (with IMPERSONATE ANY LOGIN)
-- Expected: Creates both LinkedTo and LinkedAsAdmin
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_SQLLogin_NestedImpersonate')
    CREATE LOGIN [LinkedToTest_SQLLogin_NestedImpersonate] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create nested role hierarchy
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_LevelX' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_LevelX];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_LevelY' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_LevelY];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'LinkedToTest_Role_LevelZ' AND type = 'R')
    CREATE SERVER ROLE [LinkedToTest_Role_LevelZ];

-- Build the hierarchy: Login -> LevelX -> LevelY -> LevelZ (grant IMPERSONATE ANY LOGIN to LevelZ)
ALTER SERVER ROLE [LinkedToTest_Role_LevelX] ADD MEMBER [LinkedToTest_SQLLogin_NestedImpersonate];
ALTER SERVER ROLE [LinkedToTest_Role_LevelY] ADD MEMBER [LinkedToTest_Role_LevelX];
ALTER SERVER ROLE [LinkedToTest_Role_LevelZ] ADD MEMBER [LinkedToTest_Role_LevelY];
GRANT IMPERSONATE ANY LOGIN TO [LinkedToTest_Role_LevelZ];

-- =====================================================
-- 10. WINDOWS AUTHENTICATION LOGIN
-- Expected: Creates LinkedTo but NOT LinkedAsAdmin (not a SQL login)
-- =====================================================
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser1')
    CREATE LOGIN [$Domain\EdgeTestDomainUser1] FROM WINDOWS;

-- =====================================================
-- DROP AND RECREATE LINKED SERVERS
-- =====================================================
-- Drop existing linked servers if they exist
DECLARE @dropCmd NVARCHAR(MAX) = '';
SELECT @dropCmd = @dropCmd + 
    'IF EXISTS (SELECT * FROM sys.servers WHERE name = ''' + name + ''')
        EXEC sp_dropserver ''' + name + ''', ''droplogins'';'
FROM sys.servers 
WHERE name LIKE 'TESTLINKEDTO_LOOPBACK_%';
EXEC(@dropCmd);

-- Create loopback linked servers with different authentication methods
DECLARE @ServerName NVARCHAR(128) = @@SERVERNAME;

-- 1. Regular SQL login (no admin)
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_REGULAR',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_REGULAR',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_Regular',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 2. Direct sysadmin
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_SYSADMIN',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_SYSADMIN',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_Sysadmin',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 3. Direct securityadmin
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_SECURITYADMIN',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_SECURITYADMIN',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_SecurityAdmin',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 4. Direct CONTROL SERVER
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_CONTROLSERVER',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_CONTROLSERVER',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_ControlServer',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 5. Direct IMPERSONATE ANY LOGIN
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_IMPERSONATE',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_IMPERSONATE',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_ImpersonateAnyLogin',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 6. 1-level nested admin role
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_ADMINROLE',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_ADMINROLE',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_WithAdminRole',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 7. 3-level nested securityadmin
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_NESTED_SECADMIN',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_NESTED_SECADMIN',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_NestedSecurityAdmin',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 8. 3-level nested CONTROL SERVER
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_NESTED_CONTROL',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_NESTED_CONTROL',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_NestedControlServer',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 9. 3-level nested IMPERSONATE ANY LOGIN
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_NESTED_IMPERSONATE',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_NESTED_IMPERSONATE',
    @useself = 'FALSE',
    @rmtuser = 'LinkedToTest_SQLLogin_NestedImpersonate',
    @rmtpassword = 'EdgeTestP@ss123!';

-- 10. Windows authentication
EXEC sp_addlinkedserver 
    @server = 'TESTLINKEDTO_LOOPBACK_WINDOWS',
    @srvproduct = '',
    @provider = 'SQLNCLI',
    @datasrc = @ServerName;

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'TESTLINKEDTO_LOOPBACK_WINDOWS',
    @useself = 'TRUE';  -- Use Windows authentication

-- =====================================================
-- VERIFICATION QUERIES
-- =====================================================
PRINT '';
PRINT 'Created linked servers:';
SELECT 
    s.name AS LinkedServerName,
    s.data_source AS DataSource,
    ll.remote_name AS RemoteLogin,
    ll.uses_self_credential AS UsesWindowsAuth
FROM sys.servers s
INNER JOIN sys.linked_logins ll ON s.server_id = ll.server_id
WHERE s.is_linked = 1 AND s.name LIKE 'TESTLINKEDTO_LOOPBACK_%'
ORDER BY s.name;

PRINT '';
PRINT 'Role hierarchy verification:';
-- Show the nested role memberships
WITH RoleHierarchy AS (
    SELECT 
        p.name AS principal_name,
        p.type_desc AS principal_type,
        r.name AS role_name,
        0 AS level,
        CAST(p.name AS NVARCHAR(MAX)) AS hierarchy_path
    FROM sys.server_role_members rm
    INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
    INNER JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
    WHERE p.name LIKE 'LinkedToTest_%'
    
    UNION ALL
    
    SELECT 
        rh.principal_name,
        rh.principal_type,
        r.name AS role_name,
        rh.level + 1,
        rh.hierarchy_path + ' -> ' + r.name
    FROM RoleHierarchy rh
    INNER JOIN sys.server_role_members rm ON rm.member_principal_id = 
        (SELECT principal_id FROM sys.server_principals WHERE name = rh.role_name)
    INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
    WHERE rh.level < 5
)
SELECT 
    principal_name AS Login,
    hierarchy_path + ' -> ' + role_name AS RoleHierarchy,
    level AS NestingLevel
FROM RoleHierarchy
WHERE principal_type = 'SQL_LOGIN'
ORDER BY principal_name, level;

PRINT '';
PRINT 'Authentication mode:';
SELECT 
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication Only - LinkedAsAdmin edges will NOT be created'
        WHEN 0 THEN 'Mixed Mode Authentication - LinkedAsAdmin edges WILL be created for admin SQL logins'
    END AS AuthenticationMode;

PRINT '';
PRINT 'MSSQL_LinkedTo and MSSQL_LinkedAsAdmin test setup completed';
"@

$script:SetupSQL_MemberOf = @"
-- =====================================================
-- SETUP FOR MSSQL_MemberOf EDGE TESTING
-- =====================================================
USE master;
GO

-- =====================================================
-- SERVER LEVEL: Create logins and server roles
-- =====================================================

-- Create SQL logins
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MemberOfTest_Login1')
    CREATE LOGIN [MemberOfTest_Login1] WITH PASSWORD = 'EdgeTestP@ss123!';

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MemberOfTest_Login2')
    CREATE LOGIN [MemberOfTest_Login2] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create Windows login
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = '$Domain\EdgeTestDomainUser1')
    CREATE LOGIN [$Domain\EdgeTestDomainUser1] FROM WINDOWS;

-- Create custom server roles
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MemberOfTest_ServerRole1' AND type = 'R')
    CREATE SERVER ROLE [MemberOfTest_ServerRole1];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'MemberOfTest_ServerRole2' AND type = 'R')
    CREATE SERVER ROLE [MemberOfTest_ServerRole2];

-- =====================================================
-- SERVER LEVEL: Create role memberships
-- =====================================================

-- Login -> Fixed server role
ALTER SERVER ROLE [processadmin] ADD MEMBER [MemberOfTest_Login1];

-- Login -> Custom server role
ALTER SERVER ROLE [MemberOfTest_ServerRole1] ADD MEMBER [MemberOfTest_Login2];

-- Windows login -> Fixed server role
ALTER SERVER ROLE [diskadmin] ADD MEMBER [$Domain\EdgeTestDomainUser1];

-- Server role -> Server role
ALTER SERVER ROLE [MemberOfTest_ServerRole2] ADD MEMBER [MemberOfTest_ServerRole1];

-- Server role -> Fixed server role (NOT sysadmin - that's restricted)
ALTER SERVER ROLE [securityadmin] ADD MEMBER [MemberOfTest_ServerRole2];

-- =====================================================
-- DATABASE LEVEL: Create database and principals
-- =====================================================

CREATE DATABASE [EdgeTest_MemberOf];
GO

USE [EdgeTest_MemberOf];
GO

-- Create database users
CREATE USER [MemberOfTest_User1] FOR LOGIN [MemberOfTest_Login1];
CREATE USER [MemberOfTest_User2] FOR LOGIN [MemberOfTest_Login2];
CREATE USER [$Domain\EdgeTestDomainUser1] FOR LOGIN [$Domain\EdgeTestDomainUser1];

-- Create database user without login
CREATE USER [MemberOfTest_UserNoLogin] WITHOUT LOGIN;

-- Create custom database roles
CREATE ROLE [MemberOfTest_DbRole1];
CREATE ROLE [MemberOfTest_DbRole2];

-- Create application role
CREATE APPLICATION ROLE [MemberOfTest_AppRole] 
    WITH PASSWORD = 'AppRoleP@ss123!';

-- =====================================================
-- DATABASE LEVEL: Create role memberships
-- =====================================================

-- User -> Fixed database role
ALTER ROLE [db_datareader] ADD MEMBER [MemberOfTest_User1];

-- User -> Custom database role
ALTER ROLE [MemberOfTest_DbRole1] ADD MEMBER [MemberOfTest_User2];

-- Windows user -> Fixed database role
ALTER ROLE [db_datawriter] ADD MEMBER [$Domain\EdgeTestDomainUser1];

-- User without login -> database role
ALTER ROLE [MemberOfTest_DbRole1] ADD MEMBER [MemberOfTest_UserNoLogin];

-- Database role -> Database role
ALTER ROLE [MemberOfTest_DbRole2] ADD MEMBER [MemberOfTest_DbRole1];

-- Database role -> Fixed database role
ALTER ROLE [db_owner] ADD MEMBER [MemberOfTest_DbRole2];

-- Application role -> Database role (using sp_addrolemember as per edge generator comment)
EXEC sp_addrolemember @rolename = 'MemberOfTest_DbRole1', @membername = 'MemberOfTest_AppRole';

USE master;
GO

-- =====================================================
-- VERIFICATION
-- =====================================================
PRINT '';
PRINT 'Server-level role memberships:';
SELECT 
    m.name AS MemberName,
    m.type_desc AS MemberType,
    r.name AS RoleName,
    r.type_desc AS RoleType
FROM sys.server_role_members rm
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
INNER JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
WHERE m.name LIKE 'MemberOfTest_%' OR m.name LIKE '%EdgeTest%'
ORDER BY m.name, r.name;

PRINT '';
PRINT 'Database-level role memberships:';
USE [EdgeTest_MemberOf];
SELECT 
    m.name AS MemberName,
    m.type_desc AS MemberType,
    r.name AS RoleName,
    r.type_desc AS RoleType
FROM sys.database_role_members rm
INNER JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
INNER JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
WHERE m.name LIKE 'MemberOfTest_%' OR m.name LIKE '%EdgeTest%'
ORDER BY m.name, r.name;

USE master;
GO

PRINT '';
PRINT 'MSSQL_MemberOf test setup completed';
"@

$script:SetupSQL_Owns = @"
-- =====================================================
-- SETUP FOR MSSQL_Owns EDGE TESTING
-- =====================================================
USE master;
GO

-- =====================================================
-- SERVER LEVEL: Create logins and server roles
-- =====================================================

-- Create SQL logins
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'OwnsTest_Login_DbOwner')
    CREATE LOGIN [OwnsTest_Login_DbOwner] WITH PASSWORD = 'EdgeTestP@ss123!';

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'OwnsTest_Login_RoleOwner')
    CREATE LOGIN [OwnsTest_Login_RoleOwner] WITH PASSWORD = 'EdgeTestP@ss123!';

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'OwnsTest_Login_NoOwnership')
    CREATE LOGIN [OwnsTest_Login_NoOwnership] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create custom server roles
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'OwnsTest_ServerRole_Owned' AND type = 'R')
    CREATE SERVER ROLE [OwnsTest_ServerRole_Owned];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'OwnsTest_ServerRole_Owner' AND type = 'R')
    CREATE SERVER ROLE [OwnsTest_ServerRole_Owner];

-- =====================================================
-- SERVER LEVEL: Set ownership
-- =====================================================

-- Login owns server role
ALTER AUTHORIZATION ON SERVER ROLE::[OwnsTest_ServerRole_Owned] TO [OwnsTest_Login_RoleOwner];

-- Server role owns another server role
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'OwnsTest_ServerRole_OwnedByRole' AND type = 'R')
    CREATE SERVER ROLE [OwnsTest_ServerRole_OwnedByRole] AUTHORIZATION [OwnsTest_ServerRole_Owner];

-- =====================================================
-- DATABASE LEVEL: Create databases
-- =====================================================

-- Database owned by login
CREATE DATABASE [EdgeTest_Owns_OwnedByLogin];
GO
ALTER AUTHORIZATION ON DATABASE::[EdgeTest_Owns_OwnedByLogin] TO [OwnsTest_Login_DbOwner];
GO

-- Database for role ownership tests
CREATE DATABASE [EdgeTest_Owns_RoleTests];
GO

USE [EdgeTest_Owns_RoleTests];
GO

-- Create database users
CREATE USER [OwnsTest_User_RoleOwner] FOR LOGIN [OwnsTest_Login_RoleOwner];
CREATE USER [OwnsTest_User_NoOwnership] FOR LOGIN [OwnsTest_Login_NoOwnership];

-- Create user without login
CREATE USER [OwnsTest_User_NoLogin] WITHOUT LOGIN;

-- Create custom database roles
CREATE ROLE [OwnsTest_DbRole_Owned];
CREATE ROLE [OwnsTest_DbRole_Owner];
CREATE ROLE [OwnsTest_DbRole_OwnedByRole];

-- Create application roles (they always own themselves and can't be changed)
CREATE APPLICATION ROLE [OwnsTest_AppRole_Owner] 
    WITH PASSWORD = 'AppRoleP@ss123!';

-- =====================================================
-- DATABASE LEVEL: Set ownership
-- =====================================================

-- DatabaseUser owns DatabaseRole
ALTER AUTHORIZATION ON ROLE::[OwnsTest_DbRole_Owned] TO [OwnsTest_User_RoleOwner];

-- DatabaseRole owns DatabaseRole
ALTER AUTHORIZATION ON ROLE::[OwnsTest_DbRole_OwnedByRole] TO [OwnsTest_DbRole_Owner];

-- ApplicationRole owns DatabaseRole (create with AUTHORIZATION)
CREATE ROLE [OwnsTest_DbRole_OwnedByAppRole] AUTHORIZATION [OwnsTest_AppRole_Owner];

USE master;
GO

-- =====================================================
-- VERIFICATION
-- =====================================================
PRINT '';
PRINT 'Database ownership:';
SELECT 
    d.name AS DatabaseName,
    sp.name AS OwnerName,
    sp.type_desc AS OwnerType
FROM sys.databases d
INNER JOIN sys.server_principals sp ON d.owner_sid = sp.sid
WHERE d.name LIKE 'EdgeTest_Owns_%'
ORDER BY d.name;

PRINT '';
PRINT 'Server role ownership:';
SELECT 
    r.name AS RoleName,
    o.name AS OwnerName,
    o.type_desc AS OwnerType
FROM sys.server_principals r
INNER JOIN sys.server_principals o ON r.owning_principal_id = o.principal_id
WHERE r.type = 'R' 
    AND r.name LIKE 'OwnsTest_%'
ORDER BY r.name;

PRINT '';
PRINT 'Database role ownership:';
USE [EdgeTest_Owns_RoleTests];
SELECT 
    r.name AS RoleName,
    r.type_desc AS RoleType,
    o.name AS OwnerName,
    o.type_desc AS OwnerType
FROM sys.database_principals r
INNER JOIN sys.database_principals o ON r.owning_principal_id = o.principal_id
WHERE r.type IN ('R', 'A')  -- Database roles and application roles
    AND r.name LIKE 'OwnsTest_%'
ORDER BY r.name;

USE master;
GO

PRINT '';
PRINT 'MSSQL_Owns test setup completed';
"@


$script:SetupSQL_TakeOwnership = @"
-- =====================================================
-- SETUP FOR MSSQL_TakeOwnership EDGE TESTING
-- =====================================================
USE master;
GO

-- =====================================================
-- SERVER LEVEL: Create logins and server roles
-- =====================================================

-- Create SQL logins
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'TakeOwnershipTest_Login_CanTakeServerRole')
    CREATE LOGIN [TakeOwnershipTest_Login_CanTakeServerRole] WITH PASSWORD = 'EdgeTestP@ss123!';

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'TakeOwnershipTest_Login_NoPermission')
    CREATE LOGIN [TakeOwnershipTest_Login_NoPermission] WITH PASSWORD = 'EdgeTestP@ss123!';

-- Create custom server roles (user-defined only, SQL 2012+)
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'TakeOwnershipTest_ServerRole_Target' AND type = 'R')
    CREATE SERVER ROLE [TakeOwnershipTest_ServerRole_Target];

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'TakeOwnershipTest_ServerRole_Source' AND type = 'R')
    CREATE SERVER ROLE [TakeOwnershipTest_ServerRole_Source];

-- =====================================================
-- SERVER LEVEL: Grant TAKE OWNERSHIP permissions
-- =====================================================

-- Login can take ownership of server role
GRANT TAKE OWNERSHIP ON SERVER ROLE::[TakeOwnershipTest_ServerRole_Target] TO [TakeOwnershipTest_Login_CanTakeServerRole];

-- Server role can take ownership of another server role
GRANT TAKE OWNERSHIP ON SERVER ROLE::[TakeOwnershipTest_ServerRole_Target] TO [TakeOwnershipTest_ServerRole_Source];

-- =====================================================
-- DATABASE LEVEL: Create database and principals
-- =====================================================

CREATE DATABASE [EdgeTest_TakeOwnership];
GO

USE [EdgeTest_TakeOwnership];
GO

-- Create database users
CREATE USER [TakeOwnershipTest_User_CanTakeDb] FOR LOGIN [TakeOwnershipTest_Login_CanTakeServerRole];
CREATE USER [TakeOwnershipTest_User_CanTakeRole] FOR LOGIN [TakeOwnershipTest_Login_NoPermission];
CREATE USER [TakeOwnershipTest_User_NoPermission] WITHOUT LOGIN;

-- Create custom database roles
CREATE ROLE [TakeOwnershipTest_DbRole_Target];
CREATE ROLE [TakeOwnershipTest_DbRole_Source];
CREATE ROLE [TakeOwnershipTest_DbRole_CanTakeDb];

-- Create application roles
CREATE APPLICATION ROLE [TakeOwnershipTest_AppRole_CanTakeRole] 
    WITH PASSWORD = 'AppRoleP@ss123!';

CREATE APPLICATION ROLE [TakeOwnershipTest_AppRole_CanTakeDb] 
    WITH PASSWORD = 'AppRoleP@ss123!';

-- =====================================================
-- DATABASE LEVEL: Grant TAKE OWNERSHIP permissions
-- =====================================================

-- User can take ownership of database
GRANT TAKE OWNERSHIP ON DATABASE::[EdgeTest_TakeOwnership] TO [TakeOwnershipTest_User_CanTakeDb];

-- User can take ownership of database role
GRANT TAKE OWNERSHIP ON ROLE::[TakeOwnershipTest_DbRole_Target] TO [TakeOwnershipTest_User_CanTakeRole];

-- Database role can take ownership of another database role
GRANT TAKE OWNERSHIP ON ROLE::[TakeOwnershipTest_DbRole_Target] TO [TakeOwnershipTest_DbRole_Source];

-- Database role can take ownership of database
GRANT TAKE OWNERSHIP ON DATABASE::[EdgeTest_TakeOwnership] TO [TakeOwnershipTest_DbRole_CanTakeDb];

-- Application role can take ownership of database role
GRANT TAKE OWNERSHIP ON ROLE::[TakeOwnershipTest_DbRole_Target] TO [TakeOwnershipTest_AppRole_CanTakeRole];

-- Application role can take ownership of database
GRANT TAKE OWNERSHIP ON DATABASE::[EdgeTest_TakeOwnership] TO [TakeOwnershipTest_AppRole_CanTakeDb];

USE master;
GO

-- =====================================================
-- VERIFICATION
-- =====================================================
PRINT '';
PRINT 'Server-level TAKE OWNERSHIP permissions:';
SELECT 
    p.state_desc,
    p.permission_name,
    p.class_desc,
    pr.name AS principal_name,
    pr.type_desc AS principal_type,
    CASE 
        WHEN p.major_id > 0 THEN (SELECT name FROM sys.server_principals WHERE principal_id = p.major_id)
        ELSE 'N/A'
    END AS target_object
FROM sys.server_permissions p
INNER JOIN sys.server_principals pr ON p.grantee_principal_id = pr.principal_id
WHERE p.permission_name = 'TAKE OWNERSHIP'
    AND pr.name LIKE 'TakeOwnershipTest_%'
ORDER BY pr.name;

PRINT '';
PRINT 'Database-level TAKE OWNERSHIP permissions:';
USE [EdgeTest_TakeOwnership];
SELECT 
    p.state_desc,
    p.permission_name,
    p.class_desc,
    pr.name AS principal_name,
    pr.type_desc AS principal_type,
    CASE 
        WHEN p.class = 0 THEN 'DATABASE'
        WHEN p.class = 4 THEN (SELECT name FROM sys.database_principals WHERE principal_id = p.major_id)
        ELSE 'Unknown'
    END AS target_object
FROM sys.database_permissions p
INNER JOIN sys.database_principals pr ON p.grantee_principal_id = pr.principal_id
WHERE p.permission_name = 'TAKE OWNERSHIP'
    AND pr.name LIKE 'TakeOwnershipTest_%'
ORDER BY pr.name;

USE master;
GO

PRINT '';
PRINT 'MSSQL_TakeOwnership test setup completed';
"@

function Invoke-TestSetup {
    Write-TestLog "=" * 60 -Level Info
    Write-TestLog "Setting up test environment" -Level Info
    Write-TestLog "=" * 60 -Level Info
    
    try {
        # Clean up any existing test objects first
        Write-TestLog "Cleaning up any existing test objects..." -Level Info
        try {
            Invoke-TestSQL -ServerInstance $ServerInstance -Query $script:CleanupSQL -QueryTimeout 120
            Write-TestLog "Cleanup completed" -Level Success
        }
        catch {
            Write-TestLog "Cleanup had warnings (this is normal on first run): $_" -Level Warning
        }
        
        # Create domain users if requested
        if (-not $SkipCreateDomainUsers -and -not $SkipDomainObjects) {
            Write-TestLog "Creating domain test users..." -Level Info
            
            $domainUsers = @(
                "EdgeTestDomainUser1",
                "EdgeTestDomainUser2", 
                "EdgeTestSysadmin",
                "EdgeTestServiceAcct",
                "EdgeTestDisabledUser",
                "EdgeTestNoConnect",
                "EdgeTestCoerce"
            )
            
            foreach ($user in $domainUsers) {
                $null = New-DomainTestUser -Username $user
            }
            
            # Create computer account
            try {
                if (-not (Get-ADComputer -Filter "Name -eq 'TestComputer'" -ErrorAction SilentlyContinue)) {
                    New-ADComputer -Name "TestComputer" `
                                -SAMAccountName "TestComputer$" `
                                -Enabled $true
                    Write-TestLog "Created computer account: $Domain\TestComputer$" -Level Success
                } else {
                    Write-TestLog "Computer account already exists: $Domain\TestComputer$" -Level Warning
                }
            } catch {
                Write-TestLog "Failed to create computer account: $_" -Level Warning
            }        
            
            # Create additional computer accounts for CoerceAndRelayToMSSQL testing
            $coerceTestComputers = @(
                @{Name = "CoerceTestEnabled1"; Description = "Computer account for coerce testing - enabled"},
                @{Name = "CoerceTestEnabled2"; Description = "Computer account for coerce testing - enabled"},
                @{Name = "CoerceTestDisabled"; Description = "Computer account for coerce testing - disabled login"},
                @{Name = "CoerceTestNoConnect"; Description = "Computer account for coerce testing - no connect"}
            )

            foreach ($computer in $coerceTestComputers) {
                try {
                    if (-not (Get-ADComputer -Filter "Name -eq '$($computer.Name)'" -ErrorAction SilentlyContinue)) {
                        New-ADComputer -Name $computer.Name `
                                    -SAMAccountName "$($computer.Name)$" `
                                    -Description $computer.Description `
                                    -Enabled $true
                        Write-TestLog "Created computer account: $Domain\$($computer.Name)$" -Level Success
                    } else {
                        Write-TestLog "Computer account already exists: $Domain\$($computer.Name)$" -Level Warning
                    }
                } catch {
                    Write-TestLog "Failed to create computer account $($computer.Name): $_" -Level Warning
                }
            }

            # Create domain groups
            if (Get-Command New-ADGroup -ErrorAction SilentlyContinue) {
                try {
                    if (-not (Get-ADGroup -Filter "Name -eq 'EdgeTestDomainGroup'" -ErrorAction SilentlyContinue)) {
                        New-ADGroup -Name "EdgeTestDomainGroup" `
                                   -GroupScope Global `
                                   -GroupCategory Security `
                                   -Description "Test group for MSSQL edge enumeration"
                        
                        # Add members to group
                        Add-ADGroupMember -Identity "EdgeTestDomainGroup" -Members "EdgeTestDomainUser1"
                        
                        Write-TestLog "Created domain group: EdgeTestDomainGroup" -Level Success
                    }
                }
                catch {
                    Write-TestLog "Failed to create domain group: $_" -Level Warning
                }
            }
        }
        
        # Get all SetupSQL variables and run them
        $setupVariables = Get-Variable -Scope Script | Where-Object { 
            $_.Name -like "SetupSQL_*" -and $null -ne $_.Value 
        }

        # Skip setup if limiting to edge and edge doesn't match
        if ($LimitToEdge) {
            Write-TestLog "Limiting setup to edge type: $LimitToEdge" -Level Warning
            $shortEdgeName = $LimitToEdge -replace "MSSQL_", ""
            $setupVariables = $setupVariables | Where-Object{ $_.Name -like "*$shortEdgeName" }
        }

        foreach ($setupVar in $setupVariables) {
            # Extract edge type name from variable name (e.g., SetupSQL_AddMember -> AddMember)
            $edgeType = $setupVar.Name -replace '^SetupSQL_', ''
            
            Write-TestLog "Setting up MSSQL_$edgeType test environment..." -Level Info
            try {
                Invoke-TestSQL -ServerInstance $ServerInstance -Query $setupVar.Value -QueryTimeout 60
                Invoke-VerifySetup "MSSQL_$edgeType"
            }
            catch {
                Write-TestLog "Failed to setup MSSQL_${edgeType}: $_" -Level Error
                throw
            }
        }

        Write-TestLog "Test environment setup completed successfully!" -Level Success
        $script:TestResults.SetupSuccess = $true

    }
    catch {
        Write-TestLog "Error during setup: $_" -Level Error
        $script:TestResults.SetupSuccess = $false
        throw
    }
}

function Invoke-VerifySetup {
    param(
        [string]$EdgeType
    )

    # Verify test objects were created
    Write-TestLog "Verifying $EdgeType test objects..." -Level Info

    $EdgeType = $EdgeType -replace "MSSQL_", ""
    
    # Define server-only edge types that don't have databases
    $serverOnlyEdgeTypes = @(
        "AlterAnyLogin",
        "AlterAnyServerRole",
        "ControlServer",
        "ExecuteAsOwner*",       # Supports any ExecuteAsOwner variant
        "*GetTGS",               # GetTGS and GetAdminTGS
        "GrantAnyPermission",
        "HasLogin",
        "HasMappedCred",
        "HasProxyCred",
        "ImpersonateAnyLogin",
        "IsMappedTo",            # Skipping because there are two DBs and I don't feel like coding it separately
        "Linked*",
        "Owns*",                 # Skipping
        "CoerceAndRelayToMSSQL"
    )
    
    # Check if this is a server-only edge type
    $isServerOnly = $false
    foreach ($serverOnlyType in $serverOnlyEdgeTypes) {
        if ($EdgeType -like $serverOnlyType) {
            $isServerOnly = $true
            break
        }
    }

    if ($isServerOnly) {
        # Server-only verification query
        $verifyQuery = @"
-- Check server-level objects
SELECT 
    'Server' as ObjectType,
    name,
    'SERVER' as type_desc,
    NULL as is_disabled
FROM sys.servers 
WHERE server_id = 0  -- Local server
UNION ALL
SELECT 
    'Login' as ObjectType,
    name,
    type_desc,
    is_disabled
FROM sys.server_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type IN ('S', 'U', 'G')  -- SQL Login, Windows Login, Windows Group
UNION ALL
SELECT 
    'ServerRole' as ObjectType,
    name,
    type_desc,
    NULL as is_disabled
FROM sys.server_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type = 'R'
ORDER BY ObjectType, name;
"@
    } else {
        # Full verification query including database checks
        $verifyQuery = @"
-- Check server-level objects
SELECT 
    'Server' as ObjectType,
    name,
    'SERVER' as type_desc,
    NULL as is_disabled
FROM sys.servers 
WHERE server_id = 0  -- Local server
UNION ALL
SELECT 
    'Login' as ObjectType,
    name,
    type_desc,
    is_disabled
FROM sys.server_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type IN ('S', 'U', 'G')  -- SQL Login, Windows Login, Windows Group
UNION ALL
SELECT 
    'ServerRole' as ObjectType,
    name,
    type_desc,
    NULL as is_disabled
FROM sys.server_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type = 'R'
ORDER BY ObjectType, name;

-- Check if database exists
SELECT 
    'Database' as ObjectType,
    name,
    'DATABASE' as type_desc
FROM sys.databases 
WHERE name LIKE 'EdgeTest_$EdgeType';

-- Check database-level objects if database exists
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'EdgeTest_$EdgeType')
BEGIN
    USE [EdgeTest_$EdgeType];
    SELECT 
        'DatabaseUser' as ObjectType,
        name,
        type_desc
    FROM sys.database_principals 
    WHERE name LIKE '$EdgeType`Test_%' AND type IN ('S', 'U', 'G', 'C', 'K')  -- SQL User, Windows User, Windows Group, Certificate User, Asymmetric Key User
    UNION ALL
    SELECT 
        'DatabaseRole' as ObjectType,
        name,
        type_desc
    FROM sys.database_principals 
    WHERE name LIKE '$EdgeType`Test_%' AND type = 'R'
    UNION ALL
    SELECT 
        'ApplicationRole' as ObjectType,
        name,
        type_desc
    FROM sys.database_principals 
    WHERE name LIKE '$EdgeType`Test_%' AND type = 'A';
    USE master;
END
"@
    }

    try {
        Invoke-TestSQL -ServerInstance $ServerInstance -Query $verifyQuery -ShowDebugOutput
    }
    catch {
        Write-TestLog "Failed to verify test objects: $_" -Level Error
    }

    # Rest of the verification code...
    $verifyConnection = New-Object System.Data.SqlClient.SqlConnection
    $verifyConnection.ConnectionString = "Server=$ServerInstance;Database=master;Integrated Security=True"
    $verifyConnection.Open()
    $verifyCommand = $verifyConnection.CreateCommand()

    # Check server-level objects
    $verifyCommand.CommandText = @"
SELECT COUNT(*) as LoginCount 
FROM sys.server_principals 
WHERE name LIKE '%$EdgeType`Test_%' AND type IN ('S', 'U', 'G')
"@
    $loginCount = $verifyCommand.ExecuteScalar()
    Write-TestLog "  Created $loginCount test logins" -Level Info

    $verifyCommand.CommandText = @"
SELECT COUNT(*) as RoleCount 
FROM sys.server_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type = 'R'
"@
    $roleCount = $verifyCommand.ExecuteScalar()
    Write-TestLog "  Created $roleCount test server roles" -Level Info

    # Only check database if it's not a server-only edge type
    if (-not $isServerOnly) {
        # Check database exists
        $verifyCommand.CommandText = @"
SELECT COUNT(*) as DBCount 
FROM sys.databases 
WHERE name = 'EdgeTest_$EdgeType'
"@
        $dbCount = $verifyCommand.ExecuteScalar()
        Write-TestLog "  EdgeTest_$EdgeType database exists: $($dbCount -gt 0)" -Level Info

        # If database exists, check database-level objects
        if ($dbCount -gt 0) {
            # Check database users
            $verifyCommand.CommandText = @"
USE [EdgeTest_$EdgeType];
SELECT COUNT(*) as UserCount 
FROM sys.database_principals 
WHERE name LIKE '%$EdgeType`Test_%' AND type IN ('S', 'U', 'G', 'C', 'K');
USE master;
"@
            $userCount = $verifyCommand.ExecuteScalar()
            Write-TestLog "  Created $userCount test database users" -Level Info

            # Check database roles
            $verifyCommand.CommandText = @"
USE [EdgeTest_$EdgeType];
SELECT COUNT(*) as DbRoleCount 
FROM sys.database_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type = 'R';
USE master;
"@
            $dbRoleCount = $verifyCommand.ExecuteScalar()
            Write-TestLog "  Created $dbRoleCount test database roles" -Level Info

            # Check application roles
            $verifyCommand.CommandText = @"
USE [EdgeTest_$EdgeType];
SELECT COUNT(*) as AppRoleCount 
FROM sys.database_principals 
WHERE name LIKE '$EdgeType`Test_%' AND type = 'A';
USE master;
"@
            $appRoleCount = $verifyCommand.ExecuteScalar()
            Write-TestLog "  Created $appRoleCount test application roles" -Level Info
        }
    } else {
        Write-TestLog "  No database created (server-only edge type)" -Level Info
    }

    $verifyConnection.Close()
}

#endregion

#region Test Functions

function Test-EdgePattern {
    param(
        [Parameter(Mandatory=$true)]
        $Edge,
        [Parameter(Mandatory=$true)]
        $ExpectedPattern,
        [Parameter(Mandatory=$true)]
        $Nodes,
        [switch]$ShowDebugOutput
    )
    
    if ($Edge.kind -ne $ExpectedPattern.EdgeType) { return $false }
    
    # Get the actual source and target values
    $actualSource = $Edge.start.value
    $actualTarget = $Edge.end.value
    
    # Check if patterns contain wildcards
    $sourceHasWildcard = $ExpectedPattern.SourcePattern -like "*[*?]*"
    $targetHasWildcard = $ExpectedPattern.TargetPattern -like "*[*?]*"
    
    # Handle source pattern matching
    $sourceMatch = if ($sourceHasWildcard) {
        # Use -like for wildcard patterns
        $actualSource -like $ExpectedPattern.SourcePattern
    } else {
        # For non-wildcard patterns, check if it contains @
        if ($ExpectedPattern.SourcePattern -like "*@*") {
            # Principal pattern - extract name part
            $sourceNamePattern = $ExpectedPattern.SourcePattern.Split('@')[0]
            $sourceName = if ($actualSource -match '^([^@]+)@') { $matches[1] } else { $actualSource }
            $sourceName -eq $sourceNamePattern
        } else {
            # Direct comparison (for specific server/database patterns)
            $actualSource -eq $ExpectedPattern.SourcePattern
        }
    }
    
    # Handle target pattern matching
    $targetMatch = if ($targetHasWildcard) {
        # Use -like for wildcard patterns
        $actualTarget -like $ExpectedPattern.TargetPattern
    } else {
        # For non-wildcard patterns, check if it contains @
        if ($ExpectedPattern.TargetPattern -like "*@*") {
            # Principal pattern - extract name part
            $targetNamePattern = $ExpectedPattern.TargetPattern.Split('@')[0]
            $targetName = if ($actualTarget -match '^([^@]+)@') { $matches[1] } else { $actualTarget }
            $targetName -eq $targetNamePattern
        } else {
            # Direct comparison (for specific server/database patterns)
            $actualTarget -eq $ExpectedPattern.TargetPattern
        }
    }
    
    # Check node names if specified
    if ($sourceMatch -and $targetMatch) {
        # Check source node name
        if ($ExpectedPattern.SourceName) {
            $sourceNode = $Nodes | Where-Object { $_.id -eq $actualSource } | Select-Object -First 1
            if ($sourceNode) {
                if ($sourceNode.properties.name -notlike $ExpectedPattern.SourceName) {
                    return $false
                }
            } else {
                return $false
            }
        }
        
        # Check target node name
        if ($ExpectedPattern.TargetName) {
            $targetNode = $Nodes | Where-Object { $_.id -eq $actualTarget } | Select-Object -First 1
            if ($targetNode) {
                if ($targetNode.properties.name -notlike $ExpectedPattern.TargetName) {
                    return $false
                }
            } else {
                return $false
            }
        }

        # Check edge properties (e.g., traversable/non-traversable)
        if ($ExpectedPattern.EdgeProperties) {
            foreach ($propName in $ExpectedPattern.EdgeProperties.Keys) {
                $expectedValue = $ExpectedPattern.EdgeProperties[$propName]
                $actualValue = $Edge.properties.$propName
                
                if ($actualValue -ne $expectedValue) {
                    return $false
                }
            }
        }
    }
    
    # Debug pattern matching results
    if ($ShowDebugOutput) {
        Write-TestLog "Target has wildcard: $targetHasWildcard" -Level Debug
        Write-TestLog "Target pattern: '$($ExpectedPattern.TargetPattern)'" -Level Debug
        Write-TestLog "Actual target: '$actualTarget'" -Level Debug
        Write-TestLog "Target match result: $targetMatch" -Level Debug
        Write-TestLog "Source match result: $sourceMatch" -Level Debug
        if ($targetHasWildcard) {
            Write-TestLog "Using -like operator" -Level Debug
            Write-TestLog "'$actualTarget' -like '$($ExpectedPattern.TargetPattern)' = $($actualTarget -like $ExpectedPattern.TargetPattern)" -Level Debug
        }
    }
    
    return ($sourceMatch -and $targetMatch)
}

function Test-EdgeCreation {
    param(
        [string]$TestPerspective,
        [switch]$ShowDebugOutput = $script:ShowDebugOutput
    )
    
    Write-TestLog "Testing edge creation for $TestPerspective perspective..." -Level Test
    
    # Define expected edges based on our setup
    $script:expectedEdges_AddMember = @(

        # Fixed role permissions
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "db_securityadmin can add members to user-defined database roles"
            SourcePattern = "db_securityadmin@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*"
            Perspective = "offensive"
        },
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "db_securityadmin has ALTER ANY ROLE but cannot add members to fixed roles"
            SourcePattern = "db_securityadmin@*\EdgeTest_AddMember"
            TargetPattern = "ddladmin@*"
            Negative = $true
            Reason = "Only db_owner can add members to fixed roles"
            Perspective = "offensive"
        },

        # =====================================================
        # SERVER LEVEL: Login -> ServerRole
        # =====================================================

        # Login with ALTER permission on specific server role
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "Login with ALTER on role can add members"
            SourcePattern = "AddMemberTest_Login_CanAlterServerRole@*"
            TargetPattern = "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*"
            Perspective = "offensive"
        },
        
        # Login with CONTROL permission on specific server role
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "Login with CONTROL on role can add members"
            SourcePattern = "AddMemberTest_Login_CanControlServerRole@*"
            TargetPattern = "AddMemberTest_ServerRole_TargetOf_Login_CanControlServerRole@*"
            Perspective = "offensive"
        },
        
        # Login with ALTER ANY SERVER ROLE permission (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "Login with ALTER ANY SERVER ROLE can add to user-defined roles"
            SourcePattern = "AddMemberTest_Login_CanAlterAnyServerRole@*"
            TargetPattern = "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*"
            Perspective = "offensive"
        },
        
        # Login member of processadmin can add to processadmin
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "Login member of processadmin can add to processadmin"
            SourcePattern = "AddMemberTest_Login_CanAlterAnyServerRole@*"
            TargetPattern = "processadmin@*"
            Perspective = "offensive"
        },
        
        # Negative test - cannot add to sysadmin
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "Login with ALTER ANY SERVER ROLE CANNOT add to sysadmin"
            SourcePattern = "AddMemberTest_Login_CanAlterAnyServerRole@*"
            TargetPattern = "sysadmin@*"
            Negative = $true
            Reason = "sysadmin role does not accept new members via ALTER ANY SERVER ROLE"
            Perspective = "offensive"
        },

        # =====================================================
        # SERVER LEVEL: ServerRole -> ServerRole
        # =====================================================
        
        # ServerRole with ALTER permission on another role
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ServerRole with ALTER on role can add members"
            SourcePattern = "AddMemberTest_ServerRole_CanAlterServerRole@*"
            TargetPattern = "AddMemberTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole@*"
            Perspective = "offensive"
        },
        
        # ServerRole with CONTROL permission on another role
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ServerRole with CONTROL on role can add members"
            SourcePattern = "AddMemberTest_ServerRole_CanControlServerRole@*"
            TargetPattern = "AddMemberTest_ServerRole_TargetOf_ServerRole_CanControlServerRole@*"
            Perspective = "offensive"
        },
        
        # ServerRole with ALTER ANY SERVER ROLE (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ServerRole with ALTER ANY SERVER ROLE can add to user-defined roles"
            SourcePattern = "AddMemberTest_ServerRole_CanAlterAnyServerRole@*"
            TargetPattern = "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*"
            Perspective = "offensive"
        },
        
        # ServerRole member of processadmin can add to processadmin
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ServerRole member of processadmin can add to processadmin"
            SourcePattern = "AddMemberTest_ServerRole_CanAlterAnyServerRole@*"
            TargetPattern = "processadmin@*"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser -> DatabaseRole
        # =====================================================
        
        # DatabaseUser with ALTER on specific role
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseUser with ALTER on role can add members"
            SourcePattern = "AddMemberTest_User_CanAlterDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # DatabaseUser with ALTER ANY ROLE (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseUser with ALTER ANY ROLE can add to user-defined roles"
            SourcePattern = "AddMemberTest_User_CanAlterAnyDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # DatabaseUser with ALTER on database (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseUser with ALTER on database can add to user-defined roles"
            SourcePattern = "AddMemberTest_User_CanAlterDb@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_User_CanAlterDb@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseRole -> DatabaseRole
        # =====================================================
        
        # DatabaseRole with ALTER on role can add members
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseRole with ALTER on role can add members"
            SourcePattern = "AddMemberTest_DbRole_CanAlterDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # DatabaseRole with CONTROL on role can add members
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseRole with CONTROL on role can add members"
            SourcePattern = "AddMemberTest_DbRole_CanControlDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_DbRole_CanControlDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # DatabaseRole with ALTER ANY ROLE (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseRole with ALTER ANY ROLE can add to user-defined roles"
            SourcePattern = "AddMemberTest_DbRole_CanAlterAnyDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # DatabaseRole with ALTER on database (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "DatabaseRole with ALTER on database can add to user-defined roles"
            SourcePattern = "AddMemberTest_DbRole_CanAlterDb@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDb@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # =====================================================
        # DATABASE LEVEL: ApplicationRole -> DatabaseRole
        # =====================================================
        
        # ApplicationRole with ALTER on role can add members
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ApplicationRole with ALTER on role can add members"
            SourcePattern = "AddMemberTest_AppRole_CanAlterDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # ApplicationRole with CONTROL on role can add members
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ApplicationRole with CONTROL on role can add members"
            SourcePattern = "AddMemberTest_AppRole_CanControlDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_AppRole_CanControlDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # ApplicationRole with ALTER ANY ROLE (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ApplicationRole with ALTER ANY ROLE can add to user-defined roles"
            SourcePattern = "AddMemberTest_AppRole_CanAlterAnyDbRole@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\EdgeTest_AddMember"
            Perspective = "offensive"
        },
        
        # ApplicationRole with ALTER on database (just one example edge)
        @{
            EdgeType = "MSSQL_AddMember"
            Description = "ApplicationRole with ALTER on database can add to user-defined roles"
            SourcePattern = "AddMemberTest_AppRole_CanAlterDb@*\EdgeTest_AddMember"
            TargetPattern = "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDb@*\EdgeTest_AddMember"
            Perspective = "offensive"
        }
    )

    $script:expectedEdges_Alter = @(
            
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> ServerRole
        # =====================================================
        # Note: No direct ALTER on server

        # Login with ALTER on server login
        @{
            EdgeType = "MSSQL_Alter"
            Description = "Login with ALTER on login"
            SourcePattern = "AlterTest_Login_CanAlterLogin@*"
            TargetPattern = "AlterTest_Login_TargetOf_Login_CanAlterLogin@*"
            Perspective = "offensive"
        },       

        # Login with ALTER on server role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "Login with ALTER on role can alter role"
            SourcePattern = "AlterTest_Login_CanAlterServerRole@*"
            TargetPattern = "AlterTest_ServerRole_TargetOf_Login_CanAlterServerRole@*"
            Perspective = "offensive"
        },

        # ServerRole with ALTER on server login
        @{
            EdgeType = "MSSQL_Alter"
            Description = "ServerRole with ALTER on login"
            SourcePattern = "AlterTest_ServerRole_CanAlterLogin@*"
            TargetPattern = "AlterTest_Login_TargetOf_ServerRole_CanAlterLogin@*"
            Perspective = "offensive"
        },

        # ServerRole with ALTER on server role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "ServerRole with ALTER on role can alter role"
            SourcePattern = "AlterTest_ServerRole_CanAlterServerRole@*"
            TargetPattern = "AlterTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole@*"
            Perspective = "offensive"
        }

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> Database
        # =====================================================

        # DatabaseUser with ALTER on database
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseUser with ALTER on database can alter database"
            SourcePattern = "AlterTest_User_CanAlterDb@*\EdgeTest_Alter"
            TargetPattern = "*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # DatabaseRole with ALTER on database
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseRole with ALTER on database can alter database"
            SourcePattern = "AlterTest_DbRole_CanAlterDb@*\EdgeTest_Alter"
            TargetPattern = "*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # ApplicationRole with ALTER on database
        @{
            EdgeType = "MSSQL_Alter"
            Description = "ApplicationRole with ALTER on database can alter database"
            SourcePattern = "AlterTest_AppRole_CanAlterDb@*\EdgeTest_Alter"
            TargetPattern = "*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseUser
        # =====================================================

        # DatabaseUser with ALTER on database user
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseUser with ALTER on user"
            SourcePattern = "AlterTest_User_CanAlterDbUser@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_User_TargetOf_User_CanAlterDbUser@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # DatabaseRole with ALTER on database user
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseRole with ALTER on user"
            SourcePattern = "AlterTest_DbRole_CanAlterDbUser@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_User_TargetOf_DbRole_CanAlterDbUser@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # ApplicationRole with ALTER on database user
        @{
            EdgeType = "MSSQL_Alter"
            Description = "ApplicationRole with ALTER on user"
            SourcePattern = "AlterTest_AppRole_CanAlterDbUser@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_User_TargetOf_AppRole_CanAlterDbUser@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
        # =====================================================

        # DatabaseUser with ALTER on database role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseUser with ALTER on role can alter role"
            SourcePattern = "AlterTest_User_CanAlterDbRole@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_DbRole_TargetOf_User_CanAlterDbRole@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # DatabaseRole with ALTER on database role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseRole with ALTER on role can alter role"
            SourcePattern = "AlterTest_DbRole_CanAlterDbRole@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_DbRole_TargetOf_DbRole_CanAlterDbRole@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # ApplicationRole with ALTER on database role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "ApplicationRole with ALTER on role can alter role"
            SourcePattern = "AlterTest_AppRole_CanAlterDbRole@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_DbRole_TargetOf_AppRole_CanAlterDbRole@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
        # =====================================================

        # DatabaseUser with ALTER on database role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseUser with ALTER on app role"
            SourcePattern = "AlterTest_User_CanAlterAppRole@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_AppRole_TargetOf_User_CanAlterAppRole@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # DatabaseRole with ALTER on database role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "DatabaseRole with ALTER on app role"
            SourcePattern = "AlterTest_DbRole_CanAlterAppRole@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_AppRole_TargetOf_DbRole_CanAlterAppRole@*\EdgeTest_Alter"
            Perspective = "offensive"
        },

        # ApplicationRole with ALTER on database role
        @{
            EdgeType = "MSSQL_Alter"
            Description = "ApplicationRole with ALTER on role can alter role"
            SourcePattern = "AlterTest_AppRole_CanAlterAppRole@*\EdgeTest_Alter"
            TargetPattern = "AlterTest_AppRole_TargetOf_AppRole_CanAlterAppRole@*\EdgeTest_Alter"
            Perspective = "offensive"
        }
    )

    $script:expectedEdges_AlterAnyAppRole = @(
    
        # =====================================================
        # OFFENSIVE PERSPECTIVE: Source -> Database
        # =====================================================
        
        # DatabaseUser with ALTER ANY APPLICATION ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "DatabaseUser with ALTER ANY APPLICATION ROLE targets database"
            SourcePattern = "AlterAnyAppRoleTest_User_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "*\EdgeTest_AlterAnyAppRole"
            Perspective = "offensive"
        },
        
        # DatabaseRole with ALTER ANY APPLICATION ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "DatabaseRole with ALTER ANY APPLICATION ROLE targets database"
            SourcePattern = "AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "*\EdgeTest_AlterAnyAppRole"
            Perspective = "offensive"
        },
        
        # ApplicationRole with ALTER ANY APPLICATION ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "ApplicationRole with ALTER ANY APPLICATION ROLE targets database"
            SourcePattern = "AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "*\EdgeTest_AlterAnyAppRole"
            Perspective = "offensive"
        },
        
        # db_securityadmin has ALTER ANY APPLICATION ROLE by default
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "db_securityadmin targets database"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "*\EdgeTest_AlterAnyAppRole"
            Perspective = "offensive"
        },
        
        # =====================================================
        # DEFENSIVE PERSPECTIVE: Source -> ApplicationRoles
        # =====================================================
        
        # DatabaseUser with ALTER ANY APPLICATION ROLE -> each application role
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "DatabaseUser with ALTER ANY APPLICATION ROLE targets app role 1"
            SourcePattern = "AlterAnyAppRoleTest_User_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole1@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "DatabaseUser with ALTER ANY APPLICATION ROLE targets app role 2"
            SourcePattern = "AlterAnyAppRoleTest_User_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole2@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },

        # DatabaseRole with ALTER ANY APPLICATION ROLE -> each application role
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "DatabaseRole with ALTER ANY APPLICATION ROLE targets app role 1"
            SourcePattern = "AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole1@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "DatabaseRole with ALTER ANY APPLICATION ROLE targets app role 2"
            SourcePattern = "AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole2@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },
        
        # ApplicationRole with ALTER ANY APPLICATION ROLE -> each application role
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "ApplicationRole with ALTER ANY APPLICATION ROLE targets app role 1"
            SourcePattern = "AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole1@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "ApplicationRole with ALTER ANY APPLICATION ROLE targets app role 2"
            SourcePattern = "AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole2@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },
        
        # db_securityadmin -> each application role
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "db_securityadmin targets app role 1"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole1@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyAppRole"
            Description = "db_securityadmin targets app role 2"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyAppRole"
            TargetPattern = "AlterAnyAppRoleTest_TargetAppRole2@*\EdgeTest_AlterAnyAppRole"
            Perspective = "defensive"
        }
    )

    $script:expectedEdges_AlterAnyDBRole = @(
    
        # =====================================================
        # OFFENSIVE PERSPECTIVE: Source -> Database
        # =====================================================
        
        # DatabaseUser with ALTER ANY ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "DatabaseUser with ALTER ANY ROLE targets database"
            SourcePattern = "AlterAnyDBRoleTest_User_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "*\EdgeTest_AlterAnyDBRole"
            Perspective = "offensive"
        },
        
        # DatabaseRole with ALTER ANY ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "DatabaseRole with ALTER ANY ROLE targets database"
            SourcePattern = "AlterAnyDBRoleTest_DbRole_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "*\EdgeTest_AlterAnyDBRole"
            Perspective = "offensive"
        },
        
        # ApplicationRole with ALTER ANY ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "ApplicationRole with ALTER ANY ROLE targets database"
            SourcePattern = "AlterAnyDBRoleTest_AppRole_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "*\EdgeTest_AlterAnyDBRole"
            Perspective = "offensive"
        },
        
        # db_securityadmin (has ALTER ANY ROLE by default)
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "db_securityadmin targets database"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "*\EdgeTest_AlterAnyDBRole"
            Perspective = "offensive"
        },
        
        # db_owner member (has effective ALTER ANY ROLE)
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "db_owner targets database"
            SourcePattern = "db_owner@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "*\EdgeTest_AlterAnyDBRole"
            Perspective = "offensive"
            Negative = $true
            Reason = "db_owner is not drawing edge, included under ControlDB"
        },
        
        # =====================================================
        # DEFENSIVE PERSPECTIVE: Source -> DatabaseRoles
        # =====================================================
        
        # DatabaseUser with ALTER ANY ROLE -> user-defined roles
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "DatabaseUser with ALTER ANY ROLE targets user-defined role 1"
            SourcePattern = "AlterAnyDBRoleTest_User_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole1@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "DatabaseUser with ALTER ANY ROLE targets user-defined role 2"
            SourcePattern = "AlterAnyDBRoleTest_User_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole2@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        
        # DatabaseRole with ALTER ANY ROLE -> user-defined roles
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "DatabaseRole with ALTER ANY ROLE targets user-defined role 1"
            SourcePattern = "AlterAnyDBRoleTest_DbRole_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole1@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "DatabaseRole with ALTER ANY ROLE targets user-defined role 2"
            SourcePattern = "AlterAnyDBRoleTest_DbRole_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole2@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        
        # ApplicationRole with ALTER ANY ROLE -> user-defined roles
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "ApplicationRole with ALTER ANY ROLE targets user-defined role 1"
            SourcePattern = "AlterAnyDBRoleTest_AppRole_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole1@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "ApplicationRole with ALTER ANY ROLE targets user-defined role 2"
            SourcePattern = "AlterAnyDBRoleTest_AppRole_HasAlterAnyRole@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole2@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        
        # db_securityadmin -> user-defined roles (can only alter user-defined roles)
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "db_securityadmin targets user-defined role 1"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole1@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "db_securityadmin member targets user-defined role 2"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole2@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
        },
        
        # Negative test: db_securityadmin cannot alter fixed roles
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "db_securityadmin cannot alter fixed role db_datareader"
            SourcePattern = "db_securityadmin@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "db_datareader@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
            Negative = $true
            Reason = "db_securityadmin can only alter user-defined roles, not fixed roles"
        },
        
        # db_owner is excluded (handled by ControlDB edges)
        @{
            EdgeType = "MSSQL_AlterAnyDBRole"
            Description = "db_owner member should not have AlterAnyDBRole edge to roles"
            SourcePattern = "db_owner@*\EdgeTest_AlterAnyDBRole"
            TargetPattern = "AlterAnyDBRoleTest_TargetRole1@*\EdgeTest_AlterAnyDBRole"
            Perspective = "defensive"
            Negative = $true
            Reason = "db_owner is not drawing edge, included under ControlDB -> Contains[DBRole]"
        }
    )

    $script:expectedEdges_AlterAnyLogin = @(
    
        # =====================================================
        # OFFENSIVE PERSPECTIVE: Source -> Server
        # =====================================================
        
        # Login with ALTER ANY LOGIN permission
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Login with ALTER ANY LOGIN targets server"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "offensive"
        },
        
        # ServerRole with ALTER ANY LOGIN permission
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "ServerRole with ALTER ANY LOGIN targets server"
            SourcePattern = "AlterAnyLoginTest_ServerRole_HasAlterAnyLogin@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "offensive"
        },
        
        # securityadmin fixed role (has ALTER ANY LOGIN by default)
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "securityadmin role targets server"
            SourcePattern = "securityadmin@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "offensive"
        },
        
        # =====================================================
        # DEFENSIVE PERSPECTIVE: Source -> SQL Logins
        # =====================================================
        
        # Login with ALTER ANY LOGIN -> SQL logins
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Login with ALTER ANY LOGIN targets SQL login 1"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin1@*"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Login with ALTER ANY LOGIN targets SQL login 2"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin2@*"
            Perspective = "defensive"
        },

        # ServerRole with ALTER ANY LOGIN -> SQL logins
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "ServerRole with ALTER ANY LOGIN targets SQL login 1"
            SourcePattern = "AlterAnyLoginTest_ServerRole_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin1@*"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "ServerRole with ALTER ANY LOGIN targets SQL login 2"
            SourcePattern = "AlterAnyLoginTest_ServerRole_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin2@*"
            Perspective = "defensive"
        },
        
        # securityadmin fixed role -> SQL logins
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "securityadmin role targets SQL login 1"
            SourcePattern = "securityadmin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin1@*"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "securityadmin role targets SQL login 2"
            SourcePattern = "securityadmin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin2@*"
            Perspective = "defensive"
        },
        
        # =====================================================
        # NEGATIVE TESTS
        # =====================================================
        
        # Cannot target sa login
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Cannot target sa login"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "sa@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "sa login cannot be targeted"
        },
        
        # Cannot target login with sysadmin without CONTROL SERVER
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Cannot target login with sysadmin"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin_WithSysadmin@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Target has sysadmin and source lacks CONTROL SERVER"
        },
        
        # Cannot target login with CONTROL SERVER
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Cannot target login with CONTROL SERVER"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin_WithControlServer@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Target has CONTROL SERVER and source lacks CONTROL SERVER"
        },
        
        # securityadmin also cannot target privileged logins
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "securityadmin cannot target login with sysadmin"
            SourcePattern = "securityadmin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin_WithSysadmin@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Target has sysadmin and securityadmin lacks CONTROL SERVER"
        },
        
        # Cannot target login with nested CONTROL SERVER (through user-defined role)
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "Cannot target login with nested CONTROL SERVER"
            SourcePattern = "AlterAnyLoginTest_Login_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin_NestedControlServer@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Target has CONTROL SERVER through role membership and source lacks CONTROL SERVER"
        },
        
        # securityadmin also cannot target nested privileged logins
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "securityadmin cannot target login with nested sysadmin"
            SourcePattern = "securityadmin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin_NestedSysadmin@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Target has sysadmin through role membership and securityadmin lacks CONTROL SERVER"
        },
        
        # ServerRole with ALTER ANY LOGIN also cannot target nested privileged logins
        @{
            EdgeType = "MSSQL_AlterAnyLogin"
            Description = "ServerRole with ALTER ANY LOGIN cannot target nested CONTROL SERVER"
            SourcePattern = "AlterAnyLoginTest_ServerRole_HasAlterAnyLogin@*"
            TargetPattern = "AlterAnyLoginTest_TargetLogin_NestedControlServer@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Target has CONTROL SERVER through role membership and source lacks CONTROL SERVER"
        }
    )   
    
    $script:expectedEdges_AlterAnyServerRole = @(
    
        # =====================================================
        # OFFENSIVE PERSPECTIVE: Source -> Server
        # =====================================================
        
        # Login with ALTER ANY SERVER ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "Login with ALTER ANY SERVER ROLE targets server"
            SourcePattern = "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*"
            TargetPattern = "S-1-5-21-*"  # Server SID pattern
            Perspective = "offensive"
        },
        
        # ServerRole with ALTER ANY SERVER ROLE permission
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "ServerRole with ALTER ANY SERVER ROLE targets server"
            SourcePattern = "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole@*"
            TargetPattern = "S-1-5-21-*"  # Server SID pattern
            Perspective = "offensive"
        },

        # Negative: sysadmin -> server (covered by MSSQL_ControlServer)
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "sysadmin does not have AlterAnyServerRole edge drawn (covered by ControlServer)"
            SourcePattern = "sysadmin@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "offensive"
            Negative = $true
        },
        
        # =====================================================
        # DEFENSIVE PERSPECTIVE: Source -> ServerRoles
        # =====================================================
        
        # Login -> User-defined roles (no membership required)
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "Login with ALTER ANY SERVER ROLE targets user-defined role 1"
            SourcePattern = "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*"
            TargetPattern = "AlterAnyServerRoleTest_TargetRole1@*"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "Login with ALTER ANY SERVER ROLE targets user-defined role 2"
            SourcePattern = "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*"
            TargetPattern = "AlterAnyServerRoleTest_TargetRole2@*"
            Perspective = "defensive"
        },
        
        # Login -> Fixed role it's a member of (processadmin)
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "Login member of processadmin can alter processadmin"
            SourcePattern = "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*"
            TargetPattern = "processadmin@*"
            Perspective = "defensive"
        },
        
        # Negative: Login -> Fixed role it's NOT a member of
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "Login cannot alter bulkadmin (not a member)"
            SourcePattern = "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*"
            TargetPattern = "bulkadmin@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Can only alter fixed roles if member of that role"
        },
        
        # Negative: Login -> sysadmin (special case)
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "Login cannot alter sysadmin even if member"
            SourcePattern = "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*"
            TargetPattern = "sysadmin@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "sysadmin doesn't accept members via ALTER ANY SERVER ROLE"
        },
        
        # ServerRole -> User-defined roles
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "ServerRole with ALTER ANY SERVER ROLE targets user-defined role 1"
            SourcePattern = "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole@*"
            TargetPattern = "AlterAnyServerRoleTest_TargetRole1@*"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "ServerRole with ALTER ANY SERVER ROLE targets user-defined role 2"
            SourcePattern = "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole@*"
            TargetPattern = "AlterAnyServerRoleTest_TargetRole2@*"
            Perspective = "defensive"
        },
        
        # ServerRole -> Fixed role it's a member of (bulkadmin)
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "ServerRole member of bulkadmin can alter bulkadmin"
            SourcePattern = "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole@*"
            TargetPattern = "bulkadmin@*"
            Perspective = "defensive"
        },
        
        # Negative: ServerRole -> Fixed role it's NOT a member of
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "ServerRole cannot alter processadmin (not a member)"
            SourcePattern = "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole@*"
            TargetPattern = "processadmin@*"
            Perspective = "defensive"
            Negative = $true
            Reason = "Can only alter fixed roles if member of that role"
        },

        # Negative: sysadmin -> role (covered by MSSQL_ControlServer)
        @{
            EdgeType = "MSSQL_AlterAnyServerRole"
            Description = "sysadmin does not have AlterAnyServerRole edge drawn (covered by ControlServer)"
            SourcePattern = "sysadmin@*"
            TargetPattern = "AlterAnyServerRoleTest_TargetRole1@*"
            Perspective = "defensive"
            Negative = $true
        }
    )    

    # Define expected edges for MSSQL_ChangeOwner
    $script:expectedEdges_ChangeOwner = @(
            
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> ServerRole
        # =====================================================

        # Login with TAKE OWNERSHIP on server role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "Login with TAKE OWNERSHIP on server role"
            SourcePattern = "ChangeOwnerTest_Login_CanTakeOwnershipServerRole@*"
            TargetPattern = "ChangeOwnerTest_ServerRole_TargetOf_Login@*"
            Perspective = "offensive"
        },

        # Login with CONTROL on server role (grants TAKE OWNERSHIP)
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "Login with CONTROL on server role"
            SourcePattern = "ChangeOwnerTest_Login_CanControlServerRole@*"
            TargetPattern = "ChangeOwnerTest_ServerRole_TargetOf_Login_CanControlServerRole@*"
            Perspective = "offensive"
        },

        # ServerRole with TAKE OWNERSHIP on another server role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "ServerRole with TAKE OWNERSHIP on server role"
            SourcePattern = "ChangeOwnerTest_ServerRole_CanTakeOwnershipServerRole@*"
            TargetPattern = "ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanTakeOwnershipServerRole@*"
            Perspective = "offensive"
        },

        # ServerRole with CONTROL on another server role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "ServerRole with CONTROL on server role"
            SourcePattern = "ChangeOwnerTest_ServerRole_CanControlServerRole@*"
            TargetPattern = "ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanControlServerRole@*"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
        # =====================================================

        # NOTE: TAKE OWNERSHIP/CONTROL on database also creates edges to ALL database roles

        # DatabaseUser with TAKE OWNERSHIP on database creates edges to target roles
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "DatabaseUser with TAKE OWNERSHIP on database -> roles"
            SourcePattern = "ChangeOwnerTest_User_CanTakeOwnershipDb@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDb@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # DatabaseUser with CONTROL on database just gets MSSQL_ControlDB, no edge here

        # DatabaseRole with TAKE OWNERSHIP on database creates edges to target roles
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "DatabaseRole with TAKE OWNERSHIP on database -> roles"
            SourcePattern = "ChangeOwnerTest_DbRole_CanTakeOwnershipDb@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDb@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # DatabaseRole with CONTROL on database just gets MSSQL_ControlDB, no edge here

        # ApplicationRole with TAKE OWNERSHIP on database creates edges to target roles
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "ApplicationRole with TAKE OWNERSHIP on database -> roles"
            SourcePattern = "ChangeOwnerTest_AppRole_CanTakeOwnershipDb@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDb@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # ApplicationRole with CONTROL on database just gets MSSQL_ControlDB, no edge here

        # DatabaseUser with TAKE OWNERSHIP on specific role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "DatabaseUser with TAKE OWNERSHIP on specific role"
            SourcePattern = "ChangeOwnerTest_User_CanTakeOwnershipDbRole@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDbRole@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # DatabaseUser with CONTROL on specific role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "DatabaseUser with CONTROL on specific role"
            SourcePattern = "ChangeOwnerTest_User_CanControlDbRole@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_User_CanControlDbRole@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # DatabaseRole with TAKE OWNERSHIP on another role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "DatabaseRole with TAKE OWNERSHIP on specific role"
            SourcePattern = "ChangeOwnerTest_DbRole_CanTakeOwnershipDbRole@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDbRole@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # DatabaseRole with CONTROL on another role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "DatabaseRole with CONTROL on specific role"
            SourcePattern = "ChangeOwnerTest_DbRole_CanControlDbRole@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanControlDbRole@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # ApplicationRole with TAKE OWNERSHIP on role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "ApplicationRole with TAKE OWNERSHIP on specific role"
            SourcePattern = "ChangeOwnerTest_AppRole_CanTakeOwnershipDbRole@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDbRole@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        },

        # ApplicationRole with CONTROL on role
        @{
            EdgeType = "MSSQL_ChangeOwner"
            Description = "ApplicationRole with CONTROL on specific role"
            SourcePattern = "ChangeOwnerTest_AppRole_CanControlDbRole@*\EdgeTest_ChangeOwner"
            TargetPattern = "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanControlDbRole@*\EdgeTest_ChangeOwner"
            Perspective = "offensive"
        }
    )    

    # Define expected edges for MSSQL_ChangePassword
    $script:expectedEdges_ChangePassword = @(
            
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> Login
        # =====================================================

        # Login with ALTER ANY LOGIN -> SQL Login (not sa)
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "Login with ALTER ANY LOGIN can change password of SQL login"
            SourcePattern = "ChangePasswordTest_Login_CanAlterAnyLogin@*"
            TargetPattern = "ChangePasswordTest_Login_TargetOf_Login_CanAlterAnyLogin@*"
            Perspective = "offensive"
        },

        # ServerRole with ALTER ANY LOGIN -> SQL Login
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "ServerRole with ALTER ANY LOGIN can change password of SQL login"
            SourcePattern = "ChangePasswordTest_ServerRole_CanAlterAnyLogin@*"
            TargetPattern = "ChangePasswordTest_Login_TargetOf_ServerRole_CanAlterAnyLogin@*"
            Perspective = "offensive"
        },

        # Fixed role: securityadmin -> SQL Login
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "securityadmin can change password of SQL login"
            SourcePattern = "securityadmin@*"
            TargetPattern = "ChangePasswordTest_Login_TargetOf_SecurityAdmin@*"
            Perspective = "offensive"
        },

        # Negative test: Cannot change password of login with sysadmin without CONTROL SERVER
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "Cannot change password of login with sysadmin without CONTROL SERVER"
            SourcePattern = "ChangePasswordTest_Login_CanAlterAnyLogin@*"
            TargetPattern = "ChangePasswordTest_Login_WithSysadmin@*"
            Negative = $true
            Reason = "Target has sysadmin and source lacks CONTROL SERVER"
            Perspective = "offensive"
        },

        # Negative test: Cannot change password of login with CONTROL SERVER without CONTROL SERVER
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "Cannot change password of login with CONTROL SERVER"
            SourcePattern = "ChangePasswordTest_Login_CanAlterAnyLogin@*"
            TargetPattern = "ChangePasswordTest_Login_WithControlServer@*"
            Negative = $true
            Reason = "Target has CONTROL SERVER and source lacks CONTROL SERVER"
            Perspective = "offensive"
        },

        # Negative test: Cannot change password of sa login
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "Cannot change password of sa login"
            SourcePattern = "ChangePasswordTest_Login_CanAlterAnyLogin@*"
            TargetPattern = "sa@*"
            Negative = $true
            Reason = "sa login password cannot be changed via ALTER ANY LOGIN"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> ApplicationRole
        # =====================================================

        # DatabaseUser with ALTER ANY APPLICATION ROLE -> ApplicationRole
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "DatabaseUser with ALTER ANY APPLICATION ROLE can change app role password"
            SourcePattern = "ChangePasswordTest_User_CanAlterAnyAppRole@*\EdgeTest_ChangePassword"
            TargetPattern = "ChangePasswordTest_AppRole_TargetOf_User_CanAlterAnyAppRole@*\EdgeTest_ChangePassword"
            Perspective = "offensive"
        },

        # DatabaseRole with ALTER ANY APPLICATION ROLE -> ApplicationRole
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "DatabaseRole with ALTER ANY APPLICATION ROLE can change app role password"
            SourcePattern = "ChangePasswordTest_DbRole_CanAlterAnyAppRole@*\EdgeTest_ChangePassword"
            TargetPattern = "ChangePasswordTest_AppRole_TargetOf_DbRole_CanAlterAnyAppRole@*\EdgeTest_ChangePassword"
            Perspective = "offensive"
        },

        # ApplicationRole with ALTER ANY APPLICATION ROLE -> ApplicationRole
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "ApplicationRole with ALTER ANY APPLICATION ROLE can change app role password"
            SourcePattern = "ChangePasswordTest_AppRole_CanAlterAnyAppRole@*\EdgeTest_ChangePassword"
            TargetPattern = "ChangePasswordTest_AppRole_TargetOf_AppRole_CanAlterAnyAppRole@*\EdgeTest_ChangePassword"
            Perspective = "offensive"
        },

        # Fixed role: db_securityadmin -> ApplicationRole
        @{
            EdgeType = "MSSQL_ChangePassword"
            Description = "db_securityadmin can change app role password"
            SourcePattern = "db_securityadmin@*\EdgeTest_ChangePassword"
            TargetPattern = "ChangePasswordTest_AppRole_TargetOf_DbSecurityAdmin@*\EdgeTest_ChangePassword"
            Perspective = "offensive"
        }
    )    

    $script:expectedEdges_CoerceAndRelayToMSSQL = @(
        # =====================================================
        # POSITIVE TESTS - Authenticated Users -> SQL logins for computer accounts
        # =====================================================
        
        # Authenticated Users -> login with default CONNECT SQL permission
        @{
            EdgeType = "CoerceAndRelayToMSSQL"
            Description = "Authenticated Users can coerce and relay to computer with SQL login"
            SourcePattern = "*S-1-5-11"      # Authenticated Users
            TargetPattern = "*CoerceTestEnabled1*"    # Computer SID
            Perspective = "both"
        },
        
        # Authenticated Users -> Another computer account with SQL login
        @{
            EdgeType = "CoerceAndRelayToMSSQL"
            Description = "Authenticated Users can coerce and relay to second computer with SQL login"
            SourcePattern = "*S-1-5-11"
            TargetPattern = "*CoerceTestEnabled2*"
            Perspective = "both"
        },
        
        # =====================================================
        # NEGATIVE TESTS - Should NOT create edges
        # =====================================================
        
        # No edge to disabled computer account login
        @{
            EdgeType = "CoerceAndRelayToMSSQL"
            Description = "No edge to computer with disabled SQL login"
            SourcePattern = "*S-1-5-11"
            TargetPattern = "*CoerceTestDisabled*" 
            Negative = $true
            Reason = "Computer's SQL login is disabled"
            Perspective = "both"
        },
        
        # No edge to computer account with CONNECT SQL denied
        @{
            EdgeType = "CoerceAndRelayToMSSQL"
            Description = "No edge to computer with CONNECT SQL denied"
            SourcePattern = "*S-1-5-11"
            TargetPattern = "*CoerceTestNoConnect*" 
            Negative = $true
            Reason = "Computer's SQL login has CONNECT SQL denied"
            Perspective = "both"
        },
        
        # No edge for regular user account (not computer)
        @{
            EdgeType = "CoerceAndRelayToMSSQL"
            Description = "No edge for regular user account"
            SourcePattern = "*S-1-5-11"
            TargetPattern = "*CoerceTestUser*" 
            TargetName = "CoerceTestUser"
            Negative = $true
            Reason = "Target is not a computer account"
            Perspective = "both"
        },
        
        # No edge for SQL login (not Windows login)
        @{
            EdgeType = "CoerceAndRelayToMSSQL"
            Description = "No edge for SQL login"
            SourcePattern = "*S-1-5-11"
            TargetPattern = "*CoerceTestSQLLogin*" 
            TargetName = "CoerceTestSQLLogin"
            Negative = $true
            Reason = "Target is not a Windows login"
            Perspective = "both"
        }
        
        # Test that no edges exist if Extended Protection is enabled
        # Note: This test requires server configuration and cannot be easily tested
        # in the same test run. It would require:
        # 1. Running enumeration with Extended Protection = Off
        # 2. Changing server config to Extended Protection = Required
        # 3. Re-running enumeration and verifying no edges exist
    )

    $script:expectedEdges_Connect = @(
        # Server level - positive tests
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Login with CONNECT SQL permission"
            SourcePattern = "ConnectTest_Login_HasConnectSQL@*"
            TargetPattern = "S-1-5-21-*" # Server ObjectIdentifier
            TargetType = "MSSQL_Server"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Server role with CONNECT SQL permission"
            SourcePattern = "ConnectTest_ServerRole_HasConnectSQL@*"
            TargetPattern = "S-1-5-21-*" # Server ObjectIdentifier
            TargetType = "MSSQL_Server"
            Perspective = "both"
        },
        
        # Server level - negative tests
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Login with CONNECT SQL denied"
            SourcePattern = "ConnectTest_Login_NoConnectSQL@*"
            TargetPattern = "S-1-5-21-*"
            TargetType = "MSSQL_Server"
            Negative = $true
            Reason = "CONNECT SQL is denied"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Disabled login should not have Connect edge"
            SourcePattern = "ConnectTest_Login_Disabled@*"
            TargetPattern = "S-1-5-21-*"
            TargetType = "MSSQL_Server"
            Negative = $true
            Reason = "Login is disabled"
            Perspective = "both"
        },
        
        # Database level - positive tests
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Database user with CONNECT permission"
            SourcePattern = "ConnectTest_User_HasConnect@*\EdgeTest_Connect"
            TargetPattern = "*\EdgeTest_Connect"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Database role with CONNECT permission"
            SourcePattern = "ConnectTest_DbRole_HasConnect@*\EdgeTest_Connect"
            TargetPattern = "*\EdgeTest_Connect"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        },
        
        # Database level - negative tests
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Database user with CONNECT denied"
            SourcePattern = "ConnectTest_User_NoConnect@*\EdgeTest_Connect"
            TargetPattern = "*\EdgeTest_Connect"
            TargetType = "MSSQL_Database"
            Negative = $true
            Reason = "CONNECT is denied"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Connect"
            Description = "Application role cannot have CONNECT permission"
            SourcePattern = "ConnectTest_AppRole@*\EdgeTest_Connect"
            TargetPattern = "*\EdgeTest_Connect"
            TargetType = "MSSQL_Database"
            Negative = $true
            Reason = "Application roles cannot be assigned CONNECT permission"
            Perspective = "both"
        }
    )   
    
    $script:expectedEdges_ConnectAnyDatabase = @(
        # Server level - positive tests
        @{
            EdgeType = "MSSQL_ConnectAnyDatabase"
            Description = "Login with CONNECT ANY DATABASE permission"
            SourcePattern = "ConnectAnyDatabaseTest_Login_HasConnectAnyDatabase@*"
            TargetPattern = "S-1-5-21-*" # Server ObjectIdentifier
            TargetType = "MSSQL_Server"
            Perspective = "offensive"
        },
        @{
            EdgeType = "MSSQL_ConnectAnyDatabase"
            Description = "Server role with CONNECT ANY DATABASE permission"
            SourcePattern = "ConnectAnyDatabaseTest_ServerRole_HasConnectAnyDatabase@*"
            TargetPattern = "S-1-5-21-*" # Server ObjectIdentifier
            TargetType = "MSSQL_Server"
            Perspective = "offensive"
        },
        @{
            EdgeType = "MSSQL_ConnectAnyDatabase"
            Description = "##MS_DatabaseConnector## has CONNECT ANY DATABASE permission"
            SourcePattern = "##MS_DatabaseConnector##@*"
            TargetPattern = "S-1-5-21-*" # Server ObjectIdentifier
            TargetType = "MSSQL_Server"
            Perspective = "offensive"
        },
        @{
            EdgeType = "MSSQL_ConnectAnyDatabase"
            Description = "Login with CONNECT ANY DATABASE permission"
            SourcePattern = "ConnectAnyDatabaseTest_Login_HasConnectAnyDatabase@*"
            TargetPattern = "*master"
            TargetType = "MSSQL_Database"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_ConnectAnyDatabase"
            Description = "Server role with CONNECT ANY DATABASE permission"
            SourcePattern = "ConnectAnyDatabaseTest_ServerRole_HasConnectAnyDatabase@*"
            TargetPattern = "*master"
            TargetType = "MSSQL_Database"
            Perspective = "defensive"
        },
        @{
            EdgeType = "MSSQL_ConnectAnyDatabase"
            Description = "##MS_DatabaseConnector## has CONNECT ANY DATABASE permission"
            SourcePattern = "##MS_DatabaseConnector##@*"
            TargetPattern = "*master"
            TargetType = "MSSQL_Database"
            Perspective = "defensive"
        }
    )   

    $script:expectedEdges_Contains = @(
        # Server contains databases
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Server contains database"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "S-1-5-21-*\EdgeTest_Contains"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        },
        
        # Server contains logins
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Server contains login"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "ContainsTest_Login1@*"
            TargetType = "MSSQL_Login"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Server contains login"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "ContainsTest_Login2@*"
            TargetType = "MSSQL_Login"
            Perspective = "both"
        },
        
        # Server contains server roles
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Server contains server role"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "ContainsTest_ServerRole1@*"
            TargetType = "MSSQL_ServerRole"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Server contains server role"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "ContainsTest_ServerRole2@*"
            TargetType = "MSSQL_ServerRole"
            Perspective = "both"
        },
        
        # Database contains database users
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Database contains database user"
            SourcePattern = "*\EdgeTest_Contains"
            TargetPattern = "ContainsTest_User1@*\EdgeTest_Contains"
            TargetType = "MSSQL_DatabaseUser"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Database contains database user"
            SourcePattern = "*\EdgeTest_Contains"
            TargetPattern = "ContainsTest_User2@*\EdgeTest_Contains"
            TargetType = "MSSQL_DatabaseUser"
            Perspective = "both"
        },
        
        # Database contains database roles
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Database contains database role"
            SourcePattern = "*\EdgeTest_Contains"
            TargetPattern = "ContainsTest_DbRole1@*\EdgeTest_Contains"
            TargetType = "MSSQL_DatabaseRole"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Database contains database role"
            SourcePattern = "*\EdgeTest_Contains"
            TargetPattern = "ContainsTest_DbRole2@*\EdgeTest_Contains"
            TargetType = "MSSQL_DatabaseRole"
            Perspective = "both"
        },
        
        # Database contains application roles
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Database contains application role"
            SourcePattern = "*\EdgeTest_Contains"
            TargetPattern = "ContainsTest_AppRole1@*\EdgeTest_Contains"
            TargetType = "MSSQL_ApplicationRole"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_Contains"
            Description = "Database contains application role"
            SourcePattern = "*\EdgeTest_Contains"
            TargetPattern = "ContainsTest_AppRole2@*\EdgeTest_Contains"
            TargetType = "MSSQL_ApplicationRole"
            Perspective = "both"
        }
    )

    $script:expectedEdges_Control = @(
            
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> ServerRole
        # =====================================================
        # Note: No direct CONTROL on server

        # Login with CONTROL on server login
        @{
            EdgeType = "MSSQL_Control"
            Description = "Login with CONTROL on login"
            SourcePattern = "ControlTest_Login_CanControlLogin@*"
            TargetPattern = "ControlTest_Login_TargetOf_Login_CanControlLogin@*"
            Perspective = "offensive"
        },       

        # Login with CONTROL on server role
        @{
            EdgeType = "MSSQL_Control"
            Description = "Login with CONTROL on role can alter role"
            SourcePattern = "ControlTest_Login_CanControlServerRole@*"
            TargetPattern = "ControlTest_ServerRole_TargetOf_Login_CanControlServerRole@*"
            Perspective = "offensive"
        },

        # ServerRole with CONTROL on server login
        @{
            EdgeType = "MSSQL_Control"
            Description = "ServerRole with CONTROL on login"
            SourcePattern = "ControlTest_ServerRole_CanControlLogin@*"
            TargetPattern = "ControlTest_Login_TargetOf_ServerRole_CanControlLogin@*"
            Perspective = "offensive"
        },

        # ServerRole with CONTROL on server role
        @{
            EdgeType = "MSSQL_Control"
            Description = "ServerRole with CONTROL on role can alter role"
            SourcePattern = "ControlTest_ServerRole_CanControlServerRole@*"
            TargetPattern = "ControlTest_ServerRole_TargetOf_ServerRole_CanControlServerRole@*"
            Perspective = "offensive"
        }

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> Database
        # =====================================================

        # DatabaseUser with CONTROL on database
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseUser with CONTROL on database can alter database"
            SourcePattern = "ControlTest_User_CanControlDb@*\EdgeTest_Control"
            TargetPattern = "*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # DatabaseRole with CONTROL on database
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseRole with CONTROL on database can alter database"
            SourcePattern = "ControlTest_DbRole_CanControlDb@*\EdgeTest_Control"
            TargetPattern = "*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # ApplicationRole with CONTROL on database
        @{
            EdgeType = "MSSQL_Control"
            Description = "ApplicationRole with CONTROL on database can alter database"
            SourcePattern = "ControlTest_AppRole_CanControlDb@*\EdgeTest_Control"
            TargetPattern = "*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseUser
        # =====================================================

        # DatabaseUser with CONTROL on database user
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseUser with CONTROL on user"
            SourcePattern = "ControlTest_User_CanControlDbUser@*\EdgeTest_Control"
            TargetPattern = "ControlTest_User_TargetOf_User_CanControlDbUser@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # DatabaseRole with CONTROL on database user
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseRole with CONTROL on user"
            SourcePattern = "ControlTest_DbRole_CanControlDbUser@*\EdgeTest_Control"
            TargetPattern = "ControlTest_User_TargetOf_DbRole_CanControlDbUser@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # ApplicationRole with CONTROL on database user
        @{
            EdgeType = "MSSQL_Control"
            Description = "ApplicationRole with CONTROL on user"
            SourcePattern = "ControlTest_AppRole_CanControlDbUser@*\EdgeTest_Control"
            TargetPattern = "ControlTest_User_TargetOf_AppRole_CanControlDbUser@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
        # =====================================================

        # DatabaseUser with CONTROL on database role
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseUser with CONTROL on role can alter role"
            SourcePattern = "ControlTest_User_CanControlDbRole@*\EdgeTest_Control"
            TargetPattern = "ControlTest_DbRole_TargetOf_User_CanControlDbRole@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # DatabaseRole with CONTROL on database role
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseRole with CONTROL on role can alter role"
            SourcePattern = "ControlTest_DbRole_CanControlDbRole@*\EdgeTest_Control"
            TargetPattern = "ControlTest_DbRole_TargetOf_DbRole_CanControlDbRole@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # ApplicationRole with CONTROL on database role
        @{
            EdgeType = "MSSQL_Control"
            Description = "ApplicationRole with CONTROL on role can alter role"
            SourcePattern = "ControlTest_AppRole_CanControlDbRole@*\EdgeTest_Control"
            TargetPattern = "ControlTest_DbRole_TargetOf_AppRole_CanControlDbRole@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseRole
        # =====================================================

        # DatabaseUser with CONTROL on database role
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseUser with CONTROL on app role"
            SourcePattern = "ControlTest_User_CanControlAppRole@*\EdgeTest_Control"
            TargetPattern = "ControlTest_AppRole_TargetOf_User_CanControlAppRole@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # DatabaseRole with CONTROL on database role
        @{
            EdgeType = "MSSQL_Control"
            Description = "DatabaseRole with CONTROL on app role"
            SourcePattern = "ControlTest_DbRole_CanControlAppRole@*\EdgeTest_Control"
            TargetPattern = "ControlTest_AppRole_TargetOf_DbRole_CanControlAppRole@*\EdgeTest_Control"
            Perspective = "offensive"
        },

        # ApplicationRole with CONTROL on database role
        @{
            EdgeType = "MSSQL_Control"
            Description = "ApplicationRole with CONTROL on role can alter role"
            SourcePattern = "ControlTest_AppRole_CanControlAppRole@*\EdgeTest_Control"
            TargetPattern = "ControlTest_AppRole_TargetOf_AppRole_CanControlAppRole@*\EdgeTest_Control"
            Perspective = "offensive"
        }
    )

    $script:expectedEdges_ControlDB = @(
        # Positive tests - explicit CONTROL permission
        @{
            EdgeType = "MSSQL_ControlDB"
            Description = "DatabaseUser with CONTROL on database"
            SourcePattern = "ControlDBTest_User_HasControlOnDb@*\EdgeTest_ControlDB"
            TargetPattern = "*\EdgeTest_ControlDB"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_ControlDB"
            Description = "DatabaseRole with CONTROL on database"
            SourcePattern = "ControlDBTest_DbRole_HasControlOnDb@*\EdgeTest_ControlDB"
            TargetPattern = "*\EdgeTest_ControlDB"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        },
        @{
            EdgeType = "MSSQL_ControlDB"
            Description = "ApplicationRole with CONTROL on database"
            SourcePattern = "ControlDBTest_AppRole_HasControlOnDb@*\EdgeTest_ControlDB"
            TargetPattern = "*\EdgeTest_ControlDB"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        },
        
        # db_owner (implicit CONTROL)
        @{
            EdgeType = "MSSQL_ControlDB"
            Description = "db_owner has implicit CONTROL of databases"
            SourcePattern = "db_owner@*\EdgeTest_ControlDB"
            TargetPattern = "*\EdgeTest_ControlDB"
            TargetType = "MSSQL_Database"
            Perspective = "both"
        }
    )

    $script:expectedEdges_ControlServer = @(
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> Server
        # =====================================================
        
        # Login with CONTROL SERVER permission
        @{
            EdgeType = "MSSQL_ControlServer"
            Description = "Login with CONTROL SERVER permission"
            SourcePattern = "ControlServerTest_Login_HasControlServer@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # ServerRole with CONTROL SERVER permission
        @{
            EdgeType = "MSSQL_ControlServer"
            Description = "ServerRole with CONTROL SERVER permission"
            SourcePattern = "ControlServerTest_ServerRole_HasControlServer@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # sysadmin fixed role has CONTROL SERVER by default
        @{
            EdgeType = "MSSQL_ControlServer"
            Description = "sysadmin fixed role has CONTROL SERVER by default"
            SourcePattern = "sysadmin@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        }
    )    

    $script:expectedEdges_ExecuteAs = @(
    
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> Login
        # =====================================================
        
        # Login with IMPERSONATE on another login
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "Login with IMPERSONATE on login can execute as"
            SourcePattern = "ExecuteAsTest_Login_CanImpersonateLogin@*"
            TargetPattern = "ExecuteAsTest_Login_TargetOf_Login_CanImpersonateLogin@*"
            Perspective = "offensive"
        },
        
        # Login with CONTROL on another login
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "Login with CONTROL on login can execute as"
            SourcePattern = "ExecuteAsTest_Login_CanControlLogin@*"
            TargetPattern = "ExecuteAsTest_Login_TargetOf_Login_CanControlLogin@*"
            Perspective = "offensive"
        },
        
        # ServerRole with IMPERSONATE on login
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "ServerRole with IMPERSONATE on login can execute as"
            SourcePattern = "ExecuteAsTest_ServerRole_CanImpersonateLogin@*"
            TargetPattern = "ExecuteAsTest_Login_TargetOf_ServerRole_CanImpersonateLogin@*"
            Perspective = "offensive"
        },
        
        # ServerRole with CONTROL on login
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "ServerRole with CONTROL on login can execute as"
            SourcePattern = "ExecuteAsTest_ServerRole_CanControlLogin@*"
            TargetPattern = "ExecuteAsTest_Login_TargetOf_ServerRole_CanControlLogin@*"
            Perspective = "offensive"
        },
        
        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseUser
        # =====================================================
        
        # DatabaseUser with IMPERSONATE on database user
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "DatabaseUser with IMPERSONATE on user can execute as"
            SourcePattern = "ExecuteAsTest_User_CanImpersonateDbUser@*\EdgeTest_ExecuteAs"
            TargetPattern = "ExecuteAsTest_User_TargetOf_User_CanImpersonateDbUser@*\EdgeTest_ExecuteAs"
            Perspective = "offensive"
        },
        
        # DatabaseUser with CONTROL on database user
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "DatabaseUser with CONTROL on user can execute as"
            SourcePattern = "ExecuteAsTest_User_CanControlDbUser@*\EdgeTest_ExecuteAs"
            TargetPattern = "ExecuteAsTest_User_TargetOf_User_CanControlDbUser@*\EdgeTest_ExecuteAs"
            Perspective = "offensive"
        },
        
        # DatabaseRole with IMPERSONATE on database user
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "DatabaseRole with IMPERSONATE on user can execute as"
            SourcePattern = "ExecuteAsTest_DbRole_CanImpersonateDbUser@*\EdgeTest_ExecuteAs"
            TargetPattern = "ExecuteAsTest_User_TargetOf_DbRole_CanImpersonateDbUser@*\EdgeTest_ExecuteAs"
            Perspective = "offensive"
        },
        
        # DatabaseRole with CONTROL on database user
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "DatabaseRole with CONTROL on user can execute as"
            SourcePattern = "ExecuteAsTest_DbRole_CanControlDbUser@*\EdgeTest_ExecuteAs"
            TargetPattern = "ExecuteAsTest_User_TargetOf_DbRole_CanControlDbUser@*\EdgeTest_ExecuteAs"
            Perspective = "offensive"
        },
        
        # ApplicationRole with IMPERSONATE on database user
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "ApplicationRole with IMPERSONATE on user can execute as"
            SourcePattern = "ExecuteAsTest_AppRole_CanImpersonateDbUser@*\EdgeTest_ExecuteAs"
            TargetPattern = "ExecuteAsTest_User_TargetOf_AppRole_CanImpersonateDbUser@*\EdgeTest_ExecuteAs"
            Perspective = "offensive"
        },
        
        # ApplicationRole with CONTROL on database user
        @{
            EdgeType = "MSSQL_ExecuteAs"
            Description = "ApplicationRole with CONTROL on user can execute as"
            SourcePattern = "ExecuteAsTest_AppRole_CanControlDbUser@*\EdgeTest_ExecuteAs"
            TargetPattern = "ExecuteAsTest_User_TargetOf_AppRole_CanControlDbUser@*\EdgeTest_ExecuteAs"
            Perspective = "offensive"
        }
    )

    $script:expectedEdges_ExecuteAsOwner = @(
        # =====================================================
        # POSITIVE TESTS: Database -> Server edges
        # =====================================================
        
        # Database owned by login with sysadmin
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with sysadmin"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # Database owned by login with securityadmin
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with securityadmin"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # Database owned by login with nested role in securityadmin
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with nested role in securityadmin"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithNestedRoleInSecurityadmin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # Database owned by login with CONTROL SERVER
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with CONTROL SERVER"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithControlServer"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # Database owned by login with role with CONTROL SERVER
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with role with CONTROL SERVER"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithControlServer"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # Database owned by login with IMPERSONATE ANY LOGIN
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with IMPERSONATE ANY LOGIN"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithImpersonateAnyLogin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # Database owned by login with role with IMPERSONATE ANY LOGIN
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login with role with IMPERSONATE ANY LOGIN"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithImpersonateAnyLogin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # =====================================================
        # NEGATIVE TESTS: No edges should be created
        # =====================================================
        
        # Database owned by login without high privileges
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "TRUSTWORTHY database owned by login without high privileges"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Database owner does not have high privileges"
            Perspective = "both"
        },
        
        # Database with TRUSTWORTHY OFF owned by sysadmin
        @{
            EdgeType = "MSSQL_ExecuteAsOwner"
            Description = "Non-TRUSTWORTHY database owned by sysadmin"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_NotTrustworthy"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Database is not TRUSTWORTHY"
            Perspective = "both"
        },
        
        # =====================================================
        # COMPANION EDGE: MSSQL_IsTrustedBy
        # =====================================================
        
        # All TRUSTWORTHY databases should have IsTrustedBy edge
        @{
            EdgeType = "MSSQL_IsTrustedBy"
            Description = "TRUSTWORTHY database creates IsTrustedBy edge (sysadmin owner)"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        @{
            EdgeType = "MSSQL_IsTrustedBy"
            Description = "TRUSTWORTHY database creates IsTrustedBy edge (securityadmin owner)"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        @{
            EdgeType = "MSSQL_IsTrustedBy"
            Description = "TRUSTWORTHY database creates IsTrustedBy edge (no high privileges owner)"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        @{
            EdgeType = "MSSQL_IsTrustedBy"
            Description = "Non-TRUSTWORTHY database should not have IsTrustedBy edge"
            SourcePattern = "*\EdgeTest_ExecuteAsOwner_NotTrustworthy"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Database is not TRUSTWORTHY"
            Perspective = "both"
        }
    )    

    $script:expectedEdges_ExecuteOnHost = @(
        # =====================================================
        # SERVER -> COMPUTER EDGE
        # =====================================================
        
        # Every SQL Server has ExecuteOnHost edge to its computer
        @{
            EdgeType = "MSSQL_ExecuteOnHost"
            Description = "SQL Server has ExecuteOnHost edge to its host computer"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "S-1-5-21-*"  # Computer object identifier
            Perspective = "both"
        }
        
        # =====================================================
        # COMPANION EDGE: MSSQL_HostFor
        # =====================================================
        
        # Computer has HostFor edge to SQL Server
        @{
            EdgeType = "MSSQL_HostFor"
            Description = "Computer has HostFor edge to SQL Server"
            SourcePattern = "S-1-5-21-*"  # Computer object identifier
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        }
    )

    $script:expectedEdges_GrantAnyDBPermission = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # db_securityadmin fixed role -> Database (first database)
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "db_securityadmin role targets its database"
            SourcePattern = "db_securityadmin@*\EdgeTest_GrantAnyDBPermission"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission"
            Perspective = "both"
        },
        
        # db_securityadmin fixed role -> Database (second database)
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "db_securityadmin role targets its database (second DB)"
            SourcePattern = "db_securityadmin@*\EdgeTest_GrantAnyDBPermission_Second"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission_Second"
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # User member of db_securityadmin should not have direct edge
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "User member of db_securityadmin does not create edge"
            SourcePattern = "GrantAnyDBPermissionTest_User_InDbSecurityAdmin@*"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission"
            Negative = $true
            Reason = "Only the db_securityadmin role itself creates the edge, not its members"
            Perspective = "both"
        },
        
        # Custom role with ALTER ANY ROLE should not create edge
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "Custom role with ALTER ANY ROLE does not create edge"
            SourcePattern = "GrantAnyDBPermissionTest_CustomRole_HasAlterAnyRole@*"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission"
            Negative = $true
            Reason = "Only db_securityadmin fixed role creates this edge"
            Perspective = "both"
        },
        
        # db_owner should not create this edge
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "db_owner does not create GrantAnyDBPermission edge"
            SourcePattern = "db_owner@*\EdgeTest_GrantAnyDBPermission"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission"
            Negative = $true
            Reason = "db_owner uses MSSQL_ControlDB edge instead"
            Perspective = "both"
        },
        
        # Cross-database edge should not exist
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "db_securityadmin cannot grant permissions in other databases"
            SourcePattern = "db_securityadmin@*\EdgeTest_GrantAnyDBPermission"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission_Second"
            Negative = $true
            Reason = "db_securityadmin only affects its own database"
            Perspective = "both"
        },
        
        # Regular user should not create edge
        @{
            EdgeType = "MSSQL_GrantAnyDBPermission"
            Description = "Regular user does not create edge"
            SourcePattern = "GrantAnyDBPermissionTest_User_NotInDbSecurityAdmin@*"
            TargetPattern = "*\EdgeTest_GrantAnyDBPermission"
            Negative = $true
            Reason = "User is not db_securityadmin"
            Perspective = "both"
        }
    )    

    $script:expectedEdges_GrantAnyPermission = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # securityadmin fixed role -> Server
        @{
            EdgeType = "MSSQL_GrantAnyPermission"
            Description = "securityadmin role targets the server"
            SourcePattern = "securityadmin@*"
            TargetPattern = "S-1-5-21-*"
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Login member of securityadmin should not have direct edge
        @{
            EdgeType = "MSSQL_GrantAnyPermission"
            Description = "Login member of securityadmin does not create edge"
            SourcePattern = "GrantAnyPermissionTest_Login_InSecurityAdmin@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Only the securityadmin role itself creates the edge, not its members"
            Perspective = "both"
        },
        
        # sysadmin should not create this edge
        @{
            EdgeType = "MSSQL_GrantAnyPermission"
            Description = "sysadmin does not create GrantAnyPermission edge"
            SourcePattern = "sysadmin@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "sysadmin uses MSSQL_ControlServer edge instead"
            Perspective = "both"
        },
        
        # Regular login should not create edge
        @{
            EdgeType = "MSSQL_GrantAnyPermission"
            Description = "Regular login does not create edge"
            SourcePattern = "GrantAnyPermissionTest_Login_NoSpecialPerms@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Login has no special permissions"
            Perspective = "both"
        },
        
        # Edge should not exist to database
        @{
            EdgeType = "MSSQL_GrantAnyPermission"
            Description = "securityadmin cannot grant permissions at database level"
            SourcePattern = "securityadmin@*"
            TargetPattern = "*\EdgeTest_GrantAnyPermission"
            Negative = $true
            Reason = "GrantAnyPermission is server-level only"
            Perspective = "both"
        },
        
        # db_securityadmin should not create this edge
        @{
            EdgeType = "MSSQL_GrantAnyPermission"
            Description = "db_securityadmin does not create GrantAnyPermission edge"
            SourcePattern = "db_securityadmin@*\EdgeTest_GrantAnyPermission"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "db_securityadmin uses MSSQL_GrantAnyDBPermission edge at database level"
            Perspective = "both"
        }
    )    

    $script:expectedEdges_HasDBScopedCred = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # Database -> Domain User 
        @{
            EdgeType = "MSSQL_HasDBScopedCred"
            Description = "Database has scoped credential for domain user"
            SourcePattern = "*\EdgeTest_HasDBScopedCred"
            TargetPattern = "S-1-5-21-*"  # Will match the SID of EdgeTestDomainUser1
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Database without credentials should not create edge
        @{
            EdgeType = "MSSQL_HasDBScopedCred"
            Description = "Database without credentials does not create edge"
            SourcePattern = "*\master"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "master database has no database-scoped credentials"
            Perspective = "both"
        }
    )

    $script:expectedEdges_HasLogin = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # Domain User 1 -> Login
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Domain user has SQL login"
            SourcePattern = "S-1-5-21*"  # SID of MAYYHEM\EdgeTestDomainUser1
            TargetPattern = "*\EdgeTestDomainUser1@*"
            Perspective = "both"
        },
        
        # Domain User 2 -> Login
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Second domain user has SQL login"
            SourcePattern = "S-1-5-21*"  # SID of MAYYHEM\EdgeTestDomainUser2
            TargetPattern = "*\EdgeTestDomainUser2@*"
            Perspective = "both"
        },
        
        # Domain Group -> Login
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Domain group has SQL login"
            SourcePattern = "S-1-5-21*"  # SID of MAYYHEM\EdgeTestDomainGroup
            TargetPattern = "*\EdgeTestDomainGroup@*"
            Perspective = "both"
        },
        
        # Computer Account -> Login
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Computer account has SQL login"
            SourcePattern = "S-1-5-21-*"  # SID of MAYYHEM\TestComputer$
            TargetPattern = "*\TestComputer$@*"
            Perspective = "both"
        },
        
        # Local Group -> Login
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Local group has SQL login"
            SourcePattern = "*-S-1-5-32-555"  # SID for BUILTIN\Remote Desktop Users
            TargetPattern = "BUILTIN\Remote Desktop Users@*"
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Disabled login should not create edge
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Disabled login does not create edge"
            SourcePattern = "S-1-5-21-*"  # Would be SID of EdgeTestDisabledUser
            TargetPattern = "*\EdgeTestDisabledUser@*"
            Negative = $true
            Reason = "Login is disabled"
            Perspective = "both"
        },
        
        # Login with CONNECT SQL denied should not create edge
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Login with CONNECT SQL denied does not create edge"
            SourcePattern = "S-1-5-21-*"  # Would be SID of EdgeTestNoConnect
            TargetPattern = "*\EdgeTestNoConnect@*"
            Negative = $true
            Reason = "CONNECT SQL permission is denied"
            Perspective = "both"
        },
        
        # SQL login should not create edge (not a domain account)
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "SQL login does not create HasLogin edge"
            SourcePattern = "*"
            TargetPattern = "HasLoginTest_SQLLogin@*"
            Negative = $true
            Reason = "SQL logins don't create HasLogin edges (only Windows logins)"
            Perspective = "both"
        },
        
        # Non-existent domain account should not have edge
        @{
            EdgeType = "MSSQL_HasLogin"
            Description = "Non-existent domain account has no edge"
            SourcePattern = "S-1-5-21-*"
            TargetPattern = "*\NonExistentUser@*"
            Negative = $true
            Reason = "No login exists for this account"
            Perspective = "both"
        }
    )

    $script:expectedEdges_HasMappedCred = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # SQL Login mapped to Domain User 1
        @{
            EdgeType = "MSSQL_HasMappedCred"
            Description = "SQL login has mapped credential for domain user 1"
            SourcePattern = "HasMappedCredTest_SQLLogin_MappedToDomainUser1@*"
            TargetPattern = "S-1-5-21-*"  # SID of EdgeTestDomainUser1
            Perspective = "both"
        },
        
        # SQL Login mapped to Domain User 2
        @{
            EdgeType = "MSSQL_HasMappedCred"
            Description = "SQL login has mapped credential for domain user 2"
            SourcePattern = "HasMappedCredTest_SQLLogin_MappedToDomainUser2@*"
            TargetPattern = "S-1-5-21-*"  # SID of EdgeTestDomainUser2
            Perspective = "both"
        },
        
        # SQL Login mapped to Computer Account
        @{
            EdgeType = "MSSQL_HasMappedCred"
            Description = "SQL login has mapped credential for computer account"
            SourcePattern = "HasMappedCredTest_SQLLogin_MappedToComputerAccount@*"
            TargetPattern = "S-1-5-21-*"  # SID of TestComputer$
            Perspective = "both"
        },
        
        # Windows Login mapped to different credential
        @{
            EdgeType = "MSSQL_HasMappedCred"
            Description = "Windows login has mapped credential for different user"
            SourcePattern = "*\EdgeTestDomainUser1@*"
            TargetPattern = "S-1-5-21-*"  # SID of EdgeTeMSSQL+stDomainUser2 (mapped to different user)
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # SQL login without mapped credential
        @{
            EdgeType = "MSSQL_HasMappedCred"
            Description = "SQL login without mapped credential has no edge"
            SourcePattern = "HasMappedCredTest_SQLLogin_NoCredential@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Login has no mapped credential"
            Perspective = "both"
        }
    )

    $script:expectedEdges_HasProxyCred = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # SQL Login -> Domain User 1 (via ETL proxy)
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "SQL login authorized to use ETL proxy for domain user 1"
            SourcePattern = "HasProxyCredTest_ETLOperator@*"
            TargetPattern = "S-1-5-21-*"  # SID of EdgeTestDomainUser1
            Perspective = "both"
        },
        
        # Server Role -> Domain User 1 (via ETL proxy)
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "Server role authorized to use ETL proxy for domain user 1"
            SourcePattern = "HasProxyCredTest_ProxyUsers@*"
            TargetPattern = "S-1-5-21-*"  # SID of EdgeTestDomainUser1
            Perspective = "both"
        },
        
        # SQL Login -> Domain User 2 (via backup proxy)
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "SQL login authorized to use backup proxy for domain user 2"
            SourcePattern = "HasProxyCredTest_BackupOperator@*"
            TargetPattern = "S-1-5-21-*"  # SID of EdgeTestDomainUser2
            Perspective = "both"
        },
        
        # Windows Login -> Domain User 2 (via backup proxy) - Case-insensitive version
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "Windows login authorized to use backup proxy"
            SourcePattern = "*\EdgeTestDomainUser1@*"  # Any case domain
            TargetPattern = "S-1-5-21-*"  # Target is EdgeTestDomainUser2 (what the proxy runs as)
            Perspective = "both"
        }
        
        # SQL Login -> Computer Account (via disabled proxy - still creates edge)
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "SQL login authorized to disabled proxy (edge still created)"
            SourcePattern = "HasProxyCredTest_ETLOperator@*"
            TargetPattern = "S-1-5-21-*"  # SID of TestComputer$
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Login without proxy access
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "Login without proxy access has no edge"
            SourcePattern = "HasProxyCredTest_NoProxyAccess@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Login is not authorized to use any proxy"
            Perspective = "both"
        },
        
        # Non-domain credential proxy should not create edges
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "Proxy with local credential does not create edge"
            SourcePattern = "*"
            TargetPattern = "*LocalService*"
            Negative = $true
            Reason = "Only domain credentials create HasProxyCred edges"
            Perspective = "both"
        },
        
        # Database principals cannot have proxy access
        @{
            EdgeType = "MSSQL_HasProxyCred"
            Description = "Database users cannot have proxy access"
            SourcePattern = "*@*\*"  # Database principal pattern
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Only server-level principals can use SQL Agent proxies"
            Perspective = "both"
        }
    )    

    $script:expectedEdges_Impersonate = @(
        
        # =====================================================
        # SERVER LEVEL: Login/ServerRole -> Login
        # =====================================================
        
        # Login with IMPERSONATE on another login
        @{
            EdgeType = "MSSQL_Impersonate"
            Description = "Login with IMPERSONATE on login can impersonate"
            SourcePattern = "ImpersonateTest_Login_CanImpersonateLogin@*"
            TargetPattern = "ImpersonateTest_Login_TargetOf_Login_CanImpersonateLogin@*"
            Perspective = "offensive"
        },
        
        # ServerRole with IMPERSONATE on login
        @{
            EdgeType = "MSSQL_Impersonate"
            Description = "ServerRole with IMPERSONATE on login can impersonate"
            SourcePattern = "ImpersonateTest_ServerRole_CanImpersonateLogin@*"
            TargetPattern = "ImpersonateTest_Login_TargetOf_ServerRole_CanImpersonateLogin@*"
            Perspective = "offensive"
        },
        
        # =====================================================
        # DATABASE LEVEL: DatabaseUser/DatabaseRole/ApplicationRole -> DatabaseUser
        # =====================================================
        
        # DatabaseUser with IMPERSONATE on database user
        @{
            EdgeType = "MSSQL_Impersonate"
            Description = "DatabaseUser with IMPERSONATE on user can impersonate"
            SourcePattern = "ImpersonateTest_User_CanImpersonateDbUser@*\EdgeTest_Impersonate"
            TargetPattern = "ImpersonateTest_User_TargetOf_User_CanImpersonateDbUser@*\EdgeTest_Impersonate"
            Perspective = "offensive"
        },
        
        # DatabaseRole with IMPERSONATE on database user
        @{
            EdgeType = "MSSQL_Impersonate"
            Description = "DatabaseRole with IMPERSONATE on user can impersonate"
            SourcePattern = "ImpersonateTest_DbRole_CanImpersonateDbUser@*\EdgeTest_Impersonate"
            TargetPattern = "ImpersonateTest_User_TargetOf_DbRole_CanImpersonateDbUser@*\EdgeTest_Impersonate"
            Perspective = "offensive"
        },
        
        # ApplicationRole with IMPERSONATE on database user
        @{
            EdgeType = "MSSQL_Impersonate"
            Description = "ApplicationRole with IMPERSONATE on user can impersonate"
            SourcePattern = "ImpersonateTest_AppRole_CanImpersonateDbUser@*\EdgeTest_Impersonate"
            TargetPattern = "ImpersonateTest_User_TargetOf_AppRole_CanImpersonateDbUser@*\EdgeTest_Impersonate"
            Perspective = "offensive"
        }
    )

    $script:expectedEdges_ImpersonateAnyLogin = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # SQL Login with direct permission -> Server
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "SQL login with IMPERSONATE ANY LOGIN targets server"
            SourcePattern = "ImpersonateAnyLoginTest_Login_Direct@*"
            TargetPattern = "S-1-5-21-*"  # Server identifier
            Perspective = "both" 
        },
        
        # Server Role with permission -> Server
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "Server role with IMPERSONATE ANY LOGIN targets server"
            SourcePattern = "ImpersonateAnyLoginTest_Role_HasPermission@*"
            TargetPattern = "S-1-5-21-*"  # Server identifier
            Perspective = "both" 
        },
        
        # Windows Login with permission -> Server
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "Windows login with IMPERSONATE ANY LOGIN targets server"
            SourcePattern = "*\EdgeTestDomainUser1@*"
            TargetPattern = "S-1-5-21-*"  # Server identifier
            Perspective = "both" 
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Login without permission
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "Login without IMPERSONATE ANY LOGIN has no edge"
            SourcePattern = "ImpersonateAnyLoginTest_Login_NoPermission@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Login does not have IMPERSONATE ANY LOGIN permission"
            Perspective = "both" 
        },
        
        # Login member of role (only the role itself should have edge)
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "Login member of role does not have direct edge"
            SourcePattern = "ImpersonateAnyLoginTest_Login_ViaRole@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "Only the role with the permission has the edge, not its members"
            Perspective = "both" 
        },
        
        # sysadmin should not have this edge
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "sysadmin does not create ImpersonateAnyLogin edge"
            SourcePattern = "sysadmin@*"
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "sysadmin uses ControlServer edge instead"
            Perspective = "both" 
        },
        
        # Database principals cannot have this edge
        @{
            EdgeType = "MSSQL_ImpersonateAnyLogin"
            Description = "Database users cannot have IMPERSONATE ANY LOGIN"
            SourcePattern = "*@*\*"  # Database principal pattern
            TargetPattern = "S-1-5-21-*"
            Negative = $true
            Reason = "IMPERSONATE ANY LOGIN is a server-level permission"
            Perspective = "both" 
        }
    )

    $script:expectedEdges_IsMappedTo = @(
        # =====================================================
        # Positive Tests - Edges that should exist
        # =====================================================
        
        # SQL Login -> SQL User in Primary DB
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "SQL login mapped to database user in primary database"
            SourcePattern = "IsMappedToTest_SQLLogin_WithDBUser@*"
            TargetPattern = "IsMappedToTest_SQLLogin_WithDBUser@*\EdgeTest_IsMappedTo_Primary"
            Perspective = "both"
        },
        
        # Windows Login -> Windows User in Primary DB
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "Windows login mapped to database user in primary database"
            SourcePattern = "*\EdgeTestDomainUser1@*"
            TargetPattern = "*\EdgeTestDomainUser1@*\EdgeTest_IsMappedTo_Primary"
            Perspective = "both"
        },
        
        # SQL Login -> Different Named User in Secondary DB
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "SQL login mapped to differently named user in secondary database"
            SourcePattern = "IsMappedToTest_SQLLogin_WithDBUser@*"
            TargetPattern = "IsMappedToTest_DifferentUserName@*\EdgeTest_IsMappedTo_Secondary"
            Perspective = "both"
        },
        
        # Windows Login 2 -> Windows User 2 in Secondary DB
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "Windows login 2 mapped to database user in secondary database"
            SourcePattern = "*\EdgeTestDomainUser2@*"
            TargetPattern = "*\EdgeTestDomainUser2@*\EdgeTest_IsMappedTo_Secondary"
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Login without database user
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "Login without database user has no mapping"
            SourcePattern = "IsMappedToTest_SQLLogin_NoDBUser@*"
            TargetPattern = "*"
            Negative = $true
            Reason = "Login has no corresponding database user"
            Perspective = "both"
        },
        
        # Orphaned user has no mapping
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "Orphaned database user has no login mapping"
            SourcePattern = "*"
            TargetPattern = "IsMappedToTest_OrphanedUser@*\EdgeTest_IsMappedTo_Primary"
            Negative = $true
            Reason = "Database user was created WITHOUT LOGIN"
            Perspective = "both"
        },
        
        # Cross-database mappings don't exist
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "Login is not mapped to users in databases where it doesn't exist"
            SourcePattern = "*\EdgeTestDomainUser1@*"
            TargetPattern = "*\EdgeTest_IsMappedTo_Secondary"
            Negative = $true
            Reason = "Windows login 1 has no user in secondary database"
            Perspective = "both"
        },
        
        # Server roles don't have database mappings
        @{
            EdgeType = "MSSQL_IsMappedTo"
            Description = "Server roles cannot be mapped to database users"
            SourcePattern = "sysadmin@*"
            TargetPattern = "*"
            Negative = $true
            Reason = "Only logins can be mapped to database users"
            Perspective = "both"
        }
    )

    $script:expectedEdges_GetTGS = @(
        # =====================================================
        # Service Account -> Domain Principals with SQL Login
        # =====================================================
        
        # Service account to domain user 1
        @{
            EdgeType = "MSSQL_GetTGS"
            Description = "Service account can get TGS for domain user with SQL login"
            SourcePattern = "*"  # Service account (varies by environment)
            TargetPattern = "*\EdgeTestDomainUser1@*"
            Perspective = "both"
        },
        
        # Service account to domain user 2
        @{
            EdgeType = "MSSQL_GetTGS"
            Description = "Service account can get TGS for second domain user"
            SourcePattern = "*"  # Service account
            TargetPattern = "*\EdgeTestDomainUser2@*"
            Perspective = "both"
        },
        
        # Service account to domain group
        @{
            EdgeType = "MSSQL_GetTGS"
            Description = "Service account can get TGS for domain group with SQL login"
            SourcePattern = "*"  # Service account
            TargetPattern = "*\EdgeTestDomainGroup@*"
            Perspective = "both"
        },
        
        # Service account to domain user with sysadmin
        @{
            EdgeType = "MSSQL_GetTGS"
            Description = "Service account can get TGS for domain user with sysadmin"
            SourcePattern = "*"  # Service account
            TargetPattern = "*\EdgeTestSysadmin@*"
            Perspective = "both"
        }
    )

    $script:expectedEdges_GetAdminTGS = @(
        # =====================================================
        # Service Account -> SQL Server (when domain principal has sysadmin)
        # =====================================================
        
        # Service account to SQL Server (because EdgeTestSysadmin has sysadmin)
        @{
            EdgeType = "MSSQL_GetAdminTGS"
            Description = "Service account can get admin TGS (domain principal has sysadmin)"
            SourcePattern = "*"  # Service account
            TargetPattern = "S-1-5-21-*"  # SQL Server
            Perspective = "both"
        }
    )

    $script:expectedEdges_LinkedTo = @(
        # =====================================================
        # Positive Tests - All linked servers create LinkedTo
        # =====================================================
        
        # All 10 loopback linked servers will create LinkedTo edges
        @{
            EdgeType = "MSSQL_LinkedTo"
            Description = "All 10 loopback linked servers create LinkedTo edges"
            SourcePattern = "S-1-5-21-*"  # Current server SID
            TargetPattern = "S-1-5-21-*"  # Same server SID (loopback)
            Perspective = "both"
            ExpectedCount = 11  # All 10 linked servers
        }
    )
    
    $script:expectedEdges_LinkedAsAdmin = @(
        # =====================================================
        # Positive Tests - Admin SQL logins create LinkedAsAdmin
        # =====================================================
        
        # 9 SQL logins with admin privileges (excluding regular and Windows auth)
        @{
            EdgeType = "MSSQL_LinkedAsAdmin"
            Description = "Admin SQL login linked servers create LinkedAsAdmin edges (including nested roles)"
            SourcePattern = "S-1-5-21-*"  # Current server SID
            TargetPattern = "S-1-5-21-*"  # Same server SID (loopback)
            Perspective = "both"
            ExpectedCount = 8  # All admin SQL logins including deeply nested ones
        }
    )

    $script:expectedEdges_MemberOf = @(
        # =====================================================
        # SERVER LEVEL: Login -> ServerRole
        # =====================================================
        
        # SQL Login -> Fixed server role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "SQL login member of processadmin"
            SourcePattern = "MemberOfTest_Login1@*"
            TargetPattern = "processadmin@*"
            Perspective = "both"
        },
        
        # SQL Login -> Custom server role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "SQL login member of custom server role"
            SourcePattern = "MemberOfTest_Login2@*"
            TargetPattern = "MemberOfTest_ServerRole1@*"
            Perspective = "both"
        },
        
        # Windows Login -> Fixed server role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Windows login member of diskadmin"
            SourcePattern = "*\EdgeTestDomainUser1@*"
            TargetPattern = "diskadmin@*"
            Perspective = "both"
        },
        
        # =====================================================
        # SERVER LEVEL: ServerRole -> ServerRole
        # =====================================================
        
        # Custom role -> Custom role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Server role member of another server role"
            SourcePattern = "MemberOfTest_ServerRole1@*"
            TargetPattern = "MemberOfTest_ServerRole2@*"
            Perspective = "both"
        },
        
        # Server role -> Fixed server role (securityadmin, not sysadmin)
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Custom server role member of securityadmin"
            SourcePattern = "MemberOfTest_ServerRole2@*"
            TargetPattern = "securityadmin@*"
            Perspective = "both"
        },
        
        # =====================================================
        # DATABASE LEVEL: DatabaseUser -> DatabaseRole
        # =====================================================
        
        # SQL User -> Fixed database role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Database user member of db_datareader"
            SourcePattern = "MemberOfTest_User1@*\EdgeTest_MemberOf"
            TargetPattern = "db_datareader@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # SQL User -> Custom database role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Database user member of custom database role"
            SourcePattern = "MemberOfTest_User2@*\EdgeTest_MemberOf"
            TargetPattern = "MemberOfTest_DbRole1@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # Windows User -> Fixed database role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Windows database user member of db_datawriter"
            SourcePattern = "*\EdgeTestDomainUser1@*\EdgeTest_MemberOf"
            TargetPattern = "db_datawriter@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # User without login -> Database role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Database user without login member of role"
            SourcePattern = "MemberOfTest_UserNoLogin@*\EdgeTest_MemberOf"
            TargetPattern = "MemberOfTest_DbRole1@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # =====================================================
        # DATABASE LEVEL: DatabaseRole -> DatabaseRole
        # =====================================================
        
        # Custom role -> Custom role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Database role member of another database role"
            SourcePattern = "MemberOfTest_DbRole1@*\EdgeTest_MemberOf"
            TargetPattern = "MemberOfTest_DbRole2@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # Database role -> Fixed database role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Custom database role member of db_owner"
            SourcePattern = "MemberOfTest_DbRole2@*\EdgeTest_MemberOf"
            TargetPattern = "db_owner@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # =====================================================
        # DATABASE LEVEL: ApplicationRole -> DatabaseRole
        # =====================================================
        
        # Application role -> Custom database role
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Application role member of database role"
            SourcePattern = "MemberOfTest_AppRole@*\EdgeTest_MemberOf"
            TargetPattern = "MemberOfTest_DbRole1@*\EdgeTest_MemberOf"
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Server roles cannot be members of sysadmin
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Server roles cannot be added to sysadmin"
            SourcePattern = "MemberOfTest_ServerRole*@*"
            TargetPattern = "sysadmin@*"
            Negative = $true
            Reason = "Server roles cannot be added as members of sysadmin"
            Perspective = "both"
        },
        
        # No cross-database memberships
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "No cross-database role memberships"
            SourcePattern = "*@*\EdgeTest_MemberOf"
            TargetPattern = "*@*\master"
            Negative = $true
            Reason = "Role memberships don't cross database boundaries"
            Perspective = "both"
        },
        
        # Server principals not members of database roles
        @{
            EdgeType = "MSSQL_MemberOf"
            Description = "Server login not directly member of database role"
            SourcePattern = "MemberOfTest_Login1@*"
            TargetPattern = "*@*\EdgeTest_MemberOf"
            Negative = $true
            Reason = "Server principals must be mapped to database users first"
            Perspective = "both"
        }
    )

    $script:expectedEdges_Owns = @(
        # =====================================================
        # SERVER LEVEL
        # =====================================================
        
        # Login -> Database
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Login owns database"
            SourcePattern = "OwnsTest_Login_DbOwner@*"
            TargetPattern = "*\EdgeTest_Owns_OwnedByLogin"
            Perspective = "both"
        },
        
        # Login -> ServerRole
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Login owns server role"
            SourcePattern = "OwnsTest_Login_RoleOwner@*"
            TargetPattern = "OwnsTest_ServerRole_Owned@*"
            Perspective = "both"
        },
        
        # ServerRole -> ServerRole
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Server role owns another server role"
            SourcePattern = "OwnsTest_ServerRole_Owner@*"
            TargetPattern = "OwnsTest_ServerRole_OwnedByRole@*"
            Perspective = "both"
        },
        
        # =====================================================
        # DATABASE LEVEL
        # =====================================================
        
        # DatabaseUser -> DatabaseRole
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Database user owns database role"
            SourcePattern = "OwnsTest_User_RoleOwner@*\EdgeTest_Owns_RoleTests"
            TargetPattern = "OwnsTest_DbRole_Owned@*\EdgeTest_Owns_RoleTests"
            Perspective = "both"
        },
        
        # DatabaseRole -> DatabaseRole
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Database role owns another database role"
            SourcePattern = "OwnsTest_DbRole_Owner@*\EdgeTest_Owns_RoleTests"
            TargetPattern = "OwnsTest_DbRole_OwnedByRole@*\EdgeTest_Owns_RoleTests"
            Perspective = "both"
        },
        
        # ApplicationRole -> DatabaseRole
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Application role owns database role"
            SourcePattern = "OwnsTest_AppRole_Owner@*\EdgeTest_Owns_RoleTests"
            TargetPattern = "OwnsTest_DbRole_OwnedByAppRole@*\EdgeTest_Owns_RoleTests"
            Perspective = "both"
        },
        
        # =====================================================
        # Negative Tests - Edges that should NOT exist
        # =====================================================
        
        # Login without ownership
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Login without ownership has no Owns edges"
            SourcePattern = "OwnsTest_Login_NoOwnership@*"
            TargetPattern = "*"
            Negative = $true
            Reason = "Login doesn't own any objects"
            Perspective = "both"
        },
        
        # Database user without ownership
        @{
            EdgeType = "MSSQL_Owns"
            Description = "Database user without ownership has no Owns edges"
            SourcePattern = "OwnsTest_User_NoOwnership@*"
            TargetPattern = "*"
            Negative = $true
            Reason = "User doesn't own any objects"
            Perspective = "both"
        },
        
        # Cross-database ownership doesn't exist
        @{
            EdgeType = "MSSQL_Owns"
            Description = "No cross-database ownership edges"
            SourcePattern = "*@*\EdgeTest_Owns_RoleTests"
            TargetPattern = "*@*\EdgeTest_Owns_OwnedByLogin"
            Negative = $true
            Reason = "Ownership doesn't cross database boundaries"
            Perspective = "both"
        }
    )

    $script:expectedEdges_ServiceAccountFor = @(
        # =====================================================
        # Service Account -> SQL Server Instance
        # =====================================================
        
        # The service account (domain account, local account, or machine account) 
        # should have an edge to the SQL Server instance
        @{
            EdgeType = "MSSQL_ServiceAccountFor"
            Description = "Service account for SQL Server instance"
            SourcePattern = "S-1-5-21-*"  # Service account SID (varies by environment)
            TargetPattern = "S-1-5-21-*"  # SQL Server instance ID
            SourceName = "sccmsqlsvc"     # Hardcoded, not test data
            Perspective = "both"
            ExpectedCount = 1  # Exactly one service account per instance
        },

        # =====================================================
        # HasSession edges - Computer -> Service Account (Base)
        # =====================================================

        # HasSession edge for domain service account
        @{
            EdgeType = "HasSession"
            Description = "Computer has session for domain service account"
            SourcePattern = "S-1-5-21-*"  # Computer SID
            TargetPattern = "S-1-5-21-*"  # Domain service account
            TargetName = "sccmsqlsvc"
            Perspective = "both"
        },

        # Negative test - No HasSession for local service accounts
        @{
            EdgeType = "HasSession"
            Description = "No HasSession edge for LocalSystem account"
            SourcePattern = "S-1-5-21-*"  # Computer SID
            TargetName = "NT AUTHORITY\SYSTEM"
            Negative = $true
            Reason = "Local system accounts don't get HasSession edges"
            Perspective = "both"
        },

        # Negative test - No HasSession for NETWORK SERVICE
        @{
            EdgeType = "HasSession"
            Description = "No HasSession edge for NETWORK SERVICE account"
            SourcePattern = "S-1-5-21-*"  # Computer SID
            TargetName = "NT AUTHORITY\NETWORK SERVICE"
            Negative = $true
            Reason = "Built-in service accounts don't get HasSession edges"
            Perspective = "both"
        },

        # Negative test - No HasSession for LOCAL SERVICE
        @{
            EdgeType = "HasSession"
            Description = "No HasSession edge for LOCAL SERVICE account"
            SourcePattern = "S-1-5-21-*"  # Computer SID
            TargetName = "NT AUTHORITY\LOCAL SERVICE"
            Negative = $true
            Reason = "Built-in service accounts don't get HasSession edges"
            Perspective = "both"
        },

        # Negative test - No HasSession for computer account itself
        @{
            EdgeType = "HasSession"
            Description = "No HasSession edge for computer account itself"
            SourcePattern = "S-1-5-21-*"  # Computer SID
            TargetName = "*$"  # Computer account (ends with $)
            Negative = $true
            Reason = "Computer accounts don't get HasSession edges to themselves"
            Perspective = "both"
        }
    )

    $script:expectedEdges_TakeOwnership = @(
        # =====================================================
        # SERVER LEVEL - OFFENSIVE PERSPECTIVE (Non-traversable)
        # =====================================================
        
        # Login -> ServerRole
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Login can take ownership of server role (offensive)"
            SourcePattern = "TakeOwnershipTest_Login_CanTakeServerRole@*"
            TargetPattern = "TakeOwnershipTest_ServerRole_Target@*"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # ServerRole -> ServerRole
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Server role can take ownership of another server role (offensive)"
            SourcePattern = "TakeOwnershipTest_ServerRole_Source@*"
            TargetPattern = "TakeOwnershipTest_ServerRole_Target@*"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # =====================================================
        # SERVER LEVEL - DEFENSIVE PERSPECTIVE (Traversable)
        # =====================================================
        
        # Login -> ServerRole (defensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Login can take ownership of server role (defensive)"
            SourcePattern = "TakeOwnershipTest_Login_CanTakeServerRole@*"
            TargetPattern = "TakeOwnershipTest_ServerRole_Target@*"
            Perspective = "defensive"
            EdgeProperties = @{
                traversable = $true
            }
        },
        
        # ServerRole -> ServerRole (defensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Server role can take ownership of another server role (defensive)"
            SourcePattern = "TakeOwnershipTest_ServerRole_Source@*"
            TargetPattern = "TakeOwnershipTest_ServerRole_Target@*"
            Perspective = "defensive"
            EdgeProperties = @{
                traversable = $true
            }
        },
        
        # =====================================================
        # DATABASE LEVEL - OFFENSIVE PERSPECTIVE (Database target)
        # =====================================================
        
        # DatabaseUser -> Database (offensive only)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Database user can take ownership of database (offensive)"
            SourcePattern = "TakeOwnershipTest_User_CanTakeDb@*\EdgeTest_TakeOwnership"
            TargetPattern = "*\EdgeTest_TakeOwnership"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # DatabaseRole -> Database (offensive only)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Database role can take ownership of database (offensive)"
            SourcePattern = "TakeOwnershipTest_DbRole_CanTakeDb@*\EdgeTest_TakeOwnership"
            TargetPattern = "*\EdgeTest_TakeOwnership"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # ApplicationRole -> Database (offensive only)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Application role can take ownership of database (offensive)"
            SourcePattern = "TakeOwnershipTest_AppRole_CanTakeDb@*\EdgeTest_TakeOwnership"
            TargetPattern = "*\EdgeTest_TakeOwnership"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # =====================================================
        # DATABASE LEVEL - BOTH PERSPECTIVES (DatabaseRole target)
        # =====================================================
        
        # DatabaseUser -> DatabaseRole (offensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Database user can take ownership of database role (offensive)"
            SourcePattern = "TakeOwnershipTest_User_CanTakeRole@*\EdgeTest_TakeOwnership"
            TargetPattern = "TakeOwnershipTest_DbRole_Target@*\EdgeTest_TakeOwnership"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # DatabaseUser -> DatabaseRole (defensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Database user can take ownership of database role (defensive)"
            SourcePattern = "TakeOwnershipTest_User_CanTakeRole@*\EdgeTest_TakeOwnership"
            TargetPattern = "TakeOwnershipTest_DbRole_Target@*\EdgeTest_TakeOwnership"
            Perspective = "defensive"
            EdgeProperties = @{
                traversable = $true
            }
        },
        
        # DatabaseRole -> DatabaseRole (offensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Database role can take ownership of another database role (offensive)"
            SourcePattern = "TakeOwnershipTest_DbRole_Source@*\EdgeTest_TakeOwnership"
            TargetPattern = "TakeOwnershipTest_DbRole_Target@*\EdgeTest_TakeOwnership"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # DatabaseRole -> DatabaseRole (defensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Database role can take ownership of another database role (defensive)"
            SourcePattern = "TakeOwnershipTest_DbRole_Source@*\EdgeTest_TakeOwnership"
            TargetPattern = "TakeOwnershipTest_DbRole_Target@*\EdgeTest_TakeOwnership"
            Perspective = "defensive"
            EdgeProperties = @{
                traversable = $true
            }
        },
        
        # ApplicationRole -> DatabaseRole (offensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Application role can take ownership of database role (offensive)"
            SourcePattern = "TakeOwnershipTest_AppRole_CanTakeRole@*\EdgeTest_TakeOwnership"
            TargetPattern = "TakeOwnershipTest_DbRole_Target@*\EdgeTest_TakeOwnership"
            Perspective = "offensive"
            EdgeProperties = @{
                traversable = $false
            }
        },
        
        # ApplicationRole -> DatabaseRole (defensive)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Application role can take ownership of database role (defensive)"
            SourcePattern = "TakeOwnershipTest_AppRole_CanTakeRole@*\EdgeTest_TakeOwnership"
            TargetPattern = "TakeOwnershipTest_DbRole_Target@*\EdgeTest_TakeOwnership"
            Perspective = "defensive"
            EdgeProperties = @{
                traversable = $true
            }
        },
        
        # =====================================================
        # Negative Tests
        # =====================================================
        
        # No edges to Database itself in defensive perspective (database roles still get edges)
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "No database ownership edges in defensive perspective"
            SourcePattern = "*"
            TargetPattern = "S-1-5-21-*\EdgeTest_TakeOwnership"  # Database target pattern
            Negative = $true
            Reason = "Database ownership is handled by MSSQL_DBTakeOwnership in defensive"
            Perspective = "defensive"
        },
        
        # Cannot take ownership of fixed server roles
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Cannot take ownership of fixed server roles"
            SourcePattern = "*"
            TargetPattern = "sysadmin@*"
            Negative = $true
            Reason = "Fixed server roles cannot have ownership changed"
            Perspective = "both"
        },
        
        # Cannot take ownership of fixed database roles
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Cannot take ownership of fixed database roles"
            SourcePattern = "*"
            TargetPattern = "db_owner@*\*"
            Negative = $true
            Reason = "Fixed database roles cannot have ownership changed"
            Perspective = "both"
        },
        
        # Login without permission
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "Login without TAKE OWNERSHIP permission has no edge"
            SourcePattern = "TakeOwnershipTest_Login_NoPermission@*"
            TargetPattern = "*"
            Negative = $true
            Reason = "No TAKE OWNERSHIP permission granted"
            Perspective = "both"
        },
        
        # User without permission
        @{
            EdgeType = "MSSQL_TakeOwnership"
            Description = "User without TAKE OWNERSHIP permission has no edge"
            SourcePattern = "TakeOwnershipTest_User_NoPermission@*"
            TargetPattern = "*"
            Negative = $true
            Reason = "No TAKE OWNERSHIP permission granted"
            Perspective = "both"
        }
    )

    # Combine all edge arrays into one
    $expectedEdges = @()

    # Dynamically find and append all variables starting with $expectedEdges_
    Get-Variable -Scope Script -Name "expectedEdges_*" | ForEach-Object {
        $expectedEdges += $_.Value
    }

        
    if ($LimitToEdge) {
        $expectedEdges = $expectedEdges | Where-Object { $_.EdgeType -eq $LimitToEdge }
    }

    # Determine which edges to expect based on perspective
    $edgesToTest = @()
    $negativeCasesToTest = @()
    $expectedEdgeTypes = @()

    if ($TestPerspective -eq "offensive") {
        $expectedEdgeTypes = $script:OffensiveOnlyEdges + $script:BothPerspectivesEdges
    } elseif ($TestPerspective -eq "defensive") {
        $expectedEdgeTypes = $script:DefensiveOnlyEdges + $script:BothPerspectivesEdges
    }
    
    # Filter expected edges based on perspective and separate positive/negative
    foreach ($edge in $expectedEdges) {
        
        # Debug logging
        if ($null -ne $edge.Perspective -and $ShowDebugOutput) {
            Write-TestLog "$($edge.Name) has Perspective: $($edge.Perspective), TestPerspective: $TestPerspective" -Level Debug
        }
        
        # Check if edge matches current perspective
        if ($null -eq $edge.Perspective -or 
            $edge.Perspective -eq $TestPerspective -or 
            $edge.Perspective -eq "both") {
            
            if ($edge.EdgeType -in $expectedEdgeTypes) {
                if ($edge.Negative) {
                    $negativeCasesToTest += $edge
                } else {
                    $edgesToTest += $edge
                }
            }
        } else {
            if ($ShowDebugOutput) {
                Write-TestLog "Skipping edge due to perspective mismatch: $($edge.Description)" -Level Warning
            }
        }
    }
    
    Write-TestLog "Expecting to test $($edgesToTest.Count) positive cases and $($negativeCasesToTest.Count) negative cases" -Level Info

    # Check if we should skip enumeration and load from a file instead
    if ($InputFile) {
        Write-TestLog "Skipping enumeration, loading from specified file: $InputFile" -Level Info

        # Load output from the specified file
        $output = Get-MSSQLOutputFromZip -SpecificFile $InputFile
    }
    else {
        # Run enumeration
        Write-TestLog "Running enumeration..." -Level Info
        Write-TestLog "Script path: $EnumerationScript" -Level Info

        # Verify script exists
        if (-not (Test-Path $EnumerationScript)) {
            Write-TestLog "Enumeration script not found at: $EnumerationScript" -Level Error
            $edges = @()
            $nodes = @()
            return
        }

        Write-TestLog "Running enumeration with full error capture..." -Level Info

        # Run with full output capture
        $error.Clear()

        try {

            # Run the script - it will create mssql.json files for each server and zip them
            $scriptOutput = & $EnumerationScript `
            -ServerInstance $ServerInstance `
            -OutputFormat "BloodHound" `
            -IncludeNontraversableEdges $true `
            -UserID "lowpriv" `
            -Password "password" `
            2>&1

            if ($ShowDebugOutput) {
                # Save all output
                $scriptOutput | Out-File -FilePath $debugFile -Encoding UTF8
                Write-TestLog "Script output saved to: $debugFile" -Level Info
            }

            # Wait a moment for file to be written
            Start-Sleep -Milliseconds 1000

            # The new script creates a ZIP file with the output
            $output = Get-MSSQLOutputFromZip

        if (-not $output) {
            # Fallback to check for direct JSON files
            $outputFiles = Get-ChildItem -Path . -Filter "mssql*.json" | Sort-Object LastWriteTime -Descending
            
            if ($outputFiles -and $outputFiles.Count -gt 0) {
                $latestFile = $outputFiles[0].FullName
                Write-TestLog "Found output file: $latestFile" -Level Info
                
                # Read the JSON content
                $jsonContent = Get-Content $latestFile -Raw
                $output = $jsonContent | ConvertFrom-Json
                Write-TestLog "Successfully parsed JSON from $latestFile" -Level Info
                
                # Clean up the file after reading
                Remove-Item $latestFile -Force
                Write-TestLog "Cleaned up output file: $latestFile" -Level Info
            } else {
                Write-TestLog "No output files found" -Level Error
            }
        }
        }
        catch {
            Write-TestLog "Error running enumeration script: $_" -Level Error
            $_.Exception | Out-File -FilePath "$debugFile.error" -Encoding UTF8
        }

        # Check for any errors
        if ($error.Count -gt 0) {
            Write-TestLog "Errors occurred during enumeration:" -Level Error
            $error | ForEach-Object { Write-TestLog "  $_" -Level Error }
        }
    }

    # Process output
    if ($output) {
        # Copy to clipboard
        $output | ConvertTo-Json -Depth 10 -Compress | Set-Clipboard
        Write-TestLog "BloodHound output copied to clipboard" -Level Info
        
        # Check structure
        if ($output.graph -and $output.graph.nodes -and $output.graph.edges) {
            $edges = $output.graph.edges
            $nodes = $output.graph.nodes

        } else {
            Write-TestLog "Output structure unexpected. Properties: $($output.PSObject.Properties.Name -join ', ')" -Level Error
            Write-TestLog "Output type: $($output.GetType().Name)" -Level Error
            if ($output -is [System.Collections.Hashtable]) {
                Write-TestLog "Output keys: $($output.Keys -join ', ')" -Level Error
            }
            $edges = @()
            $nodes = @()
        }
    } else {
        Write-TestLog "No output received from enumeration script" -Level Error
        $edges = @()
        $nodes = @()
    }
    
    Write-TestLog "Found $($edges.Count) edges and $($nodes.Count) nodes" -Level Info
        
    # Test run tracking
    $testRun = @{
        Perspective = $TestPerspective
        Timestamp = Get-Date
        ExpectedEdgeCount = 0      # Expected number of edges
        ActualEdgeCount = 0        # Actual number of edges found
        PassedPositiveTests = 0    # Number of positive tests that passed
        PassedNegativeTests = 0    # Number of negative tests that passed
        MissingEdges = @()         # Tests that failed to find expected edges
        ExtraEdges = @()           # Unexpected edges found
        FailedNegativeTests = @()  # Negative tests that failed (edge existed)
        TotalTests = 0             # Total number of tests run
        PassedTests = 0            # Total number of tests passed
        Edges = @()                # All edges found during enumeration
        Nodes = @()                # All nodes found during enumeration
        Results = @()              # Detailed results for each test
    }
    
    # Calculate expected edge count (sum of all expected edges including ExpectedCount values)
    $expectedEdgeCount = 0
    foreach ($test in $edgesToTest) {
        if ($test.ExpectedCount) {
            $expectedEdgeCount += $test.ExpectedCount
        } else {
            $expectedEdgeCount += 1
        }
    }
    $testRun.ExpectedEdgeCount = $expectedEdgeCount
    
    # Check positive test cases (edges that should exist)
    Write-TestLog "Running positive tests" -Level Test

    # Track which tests have already passed to avoid double-counting
    $passedTests = @{}

    # Helper function to count matching edges
    function Get-MatchingEdgeCount {
        param(
            $ExpectedEdge,
            $Edges,
            $Nodes,
            [switch]$ShowDebugOutput
        )
        
        if ($ExpectedEdge.SourcePattern -or $ExpectedEdge.TargetPattern) {
            # Pattern-based matching
            $matchingEdges = @($Edges | Where-Object {
                $_.kind -eq $ExpectedEdge.EdgeType -and
                (Test-EdgePattern -Edge $_ -ExpectedPattern $ExpectedEdge -Nodes $Nodes -ShowDebugOutput:$ShowDebugOutput)
            })
            return $matchingEdges.Count
        } else {
            # Simple edge type matching
            return @($Edges | Where-Object { $_.kind -eq $ExpectedEdge.EdgeType }).Count
        }
    }

    # Process each expected edge test
    foreach ($expectedEdge in $edgesToTest) {
        # Handle ExpectedCount tests (tests that expect a specific number of edges)
        if ($expectedEdge.ExpectedCount) {
            $actualCount = Get-MatchingEdgeCount -ExpectedEdge $expectedEdge -Edges $edges -Nodes $nodes -ShowDebugOutput:$ShowDebugOutput

            # Debug output for pattern matching
            if ($ShowDebugOutput -and $expectedEdge.SourceName) {
                Write-TestLog "Pattern matching details" -Level Debug
                Write-TestLog "  Expected SourceName: $($expectedEdge.SourceName)" -Level Debug
                Write-TestLog "  Expected SourcePattern: $($expectedEdge.SourcePattern)" -Level Debug
                Write-TestLog "  Expected TargetPattern: $($expectedEdge.TargetPattern)" -Level Debug
                
                # Check if we have any nodes with the expected name
                $nodesWithExpectedName = @($nodes | Where-Object { $_.properties.name -eq $expectedEdge.SourceName })
                Write-TestLog "  Nodes with expected name: $($nodesWithExpectedName.Count)" -Level Warning
            }
            
            $testPassed = $actualCount -eq $expectedEdge.ExpectedCount
            $testResult = @{
                EdgeType = $expectedEdge.EdgeType
                Description = $expectedEdge.Description
                SourcePattern = $expectedEdge.SourcePattern
                TargetPattern = $expectedEdge.TargetPattern
                Passed = $testPassed
                ExpectedCount = $expectedEdge.ExpectedCount
                ActualCount = $actualCount
            }
            
            if ($testPassed) {
                $testRun.PassedPositiveTests++
                $testRun.ActualEdgeCount += $actualCount  # Add to total edge count
                Write-TestLog "$($expectedEdge.EdgeType): $($expectedEdge.Description)" -Level Success
                Write-TestLog "        Expected count: $($expectedEdge.ExpectedCount), Actual: $actualCount" -Level Success
            } else {
                $testRun.MissingEdges += $expectedEdge
                Write-TestLog "$($expectedEdge.EdgeType): $($expectedEdge.Description)" -Level Error
                Write-TestLog "        Expected count: $($expectedEdge.ExpectedCount), Actual: $actualCount" -Level Error
            }
            
            $testRun.Results += $testResult
            continue  # Skip regular pattern matching for ExpectedCount tests
        }

        # Handle regular pattern tests (tests that expect exactly one edge)
        # Create a unique key for this test to avoid double-counting
        $testKey = "$($expectedEdge.EdgeType)|$($expectedEdge.SourcePattern)|$($expectedEdge.TargetPattern)|$($expectedEdge.Description)"
        
        # Skip if we've already counted this test as passed
        if ($passedTests.ContainsKey($testKey)) {
            Write-TestLog "Skipping duplicate test key: $testKey (already passed)" -Level Warning   
            continue
        }

        # Find the first matching edge
        $found = $edges | Where-Object {
            Test-EdgePattern -Edge $_ -ExpectedPattern $expectedEdge -Nodes $nodes -ShowDebugOutput:$ShowDebugOutput
        } | Select-Object -First 1
        
        # Record test result
        $testPassed = $null -ne $found
        $testResult = @{
            EdgeType = $expectedEdge.EdgeType
            Description = $expectedEdge.Description
            SourcePattern = $expectedEdge.SourcePattern
            TargetPattern = $expectedEdge.TargetPattern
            Passed = $testPassed
        }
        
        if ($testPassed) {
            $passedTests[$testKey] = $true  # Mark as passed to avoid double-counting
            $testRun.PassedPositiveTests++
            $testRun.ActualEdgeCount++  # Regular tests count as 1 edge
            Write-TestLog "$($expectedEdge.EdgeType): $($expectedEdge.Description)" -Level Success
            Write-TestLog "        Actual: $($found.start.value) -> $($found.end.value)" -Level Success
        } else {
            $testRun.MissingEdges += $expectedEdge
            Write-TestLog "$($expectedEdge.EdgeType): $($expectedEdge.Description)" -Level Error
            Write-TestLog "          Expected: $($expectedEdge.SourcePattern) -> $($expectedEdge.TargetPattern)" -Level Error
        }
        
        $testRun.Results += $testResult
    }
        
    # Check negative test cases (edges that should NOT exist)
    Write-TestLog "Running negative tests" -Level Test

    foreach ($negativeCase in $negativeCasesToTest) {
        # Look for edges that match the negative test pattern
        $found = $edges | Where-Object {
            Test-EdgePattern -Edge $_ -ExpectedPattern $negativeCase -Nodes $nodes -ShowDebugOutput:$ShowDebugOutput
        } | Select-Object -First 1
        
        # Record negative test result
        $testPassed = $null -eq $found  # Pass if edge NOT found
        $negativeTestResult = @{
            EdgeType = $negativeCase.EdgeType
            Description = $negativeCase.Description
            SourcePattern = $negativeCase.SourcePattern
            TargetPattern = $negativeCase.TargetPattern
            Passed = $testPassed
        }
        
        if ($testPassed) {
            $testRun.PassedNegativeTests++
            Write-TestLog "$($negativeCase.EdgeType): $($negativeCase.Description)" -Level Success
            Write-TestLog "        Actual: No edge found (as expected)" -Level Success
        } else {
            $testRun.FailedNegativeTests += @{
                TestCase = $negativeCase
                FoundEdge = $found
            }
            Write-TestLog "$($negativeCase.EdgeType): $($negativeCase.Description)" -Level Error
            Write-TestLog "          Expected: No edge should exist" -Level Error
            Write-TestLog "          Found: $($found.start.value) -> $($found.end.value)" -Level Error
        }
        
        # Add to results for reporting
        $testRun.Results += $negativeTestResult
    }

    # Additional debug output for ExpectedCount tests with patterns
    if ($ShowDebugOutput) {
        $expectedCountTests = $edgesToTest | Where-Object { $_.ExpectedCount }
        foreach ($test in $expectedCountTests) {
            if ($test.SourcePattern -and $test.TargetPattern) {
                # Count edges matching specific patterns for debug output
                $matchingEdges = @($edges | Where-Object {
                    Test-EdgePattern -Edge $_ -ExpectedPattern $test -Nodes $nodes
                })
                $actualForPattern = $matchingEdges.Count
                
                if ($actualForPattern -ne $test.ExpectedCount) {
                    Write-TestLog "ExpectedCount pattern test: $($test.EdgeType)" -Level Debug
                    Write-TestLog "  Expected: $($test.ExpectedCount) edges matching pattern" -Level Debug
                    Write-TestLog "  Actual: $actualForPattern edges found" -Level Debug
                    foreach ($edge in $matchingEdges) {
                        Write-TestLog "    - $($edge.start.value) -> $($edge.end.value)" -Level Debug
                    }
                }
            }
        }
    }
    
    # Helper function to extract principal name from ID
    function Get-PrincipalName {
        param($Value)
        if ($Value -match '^([^@]+)@') { return $matches[1] } else { return $Value }
    }
    
    if ($ShowDebugOutput) {
        # Check for extra edges (edges that don't match any expected pattern)
        $allExpectedPatterns = $edgesToTest + $negativeCasesToTest
        foreach ($edge in $edges) {
            $isExpected = $false
            
            # Check if this edge matches any expected pattern
            foreach ($pattern in $allExpectedPatterns) {
                if (Test-EdgePattern -Edge $edge -ExpectedPattern $pattern -Nodes $nodes) {
                    $isExpected = $true
                    break
                }
            }
            
            # For ExpectedCount tests, also check if it's the right type
            if (-not $isExpected) {
                $expectedCountTests = $edgesToTest | Where-Object { $_.ExpectedCount }
                $expectedCountTest = $expectedCountTests | Where-Object { $_.EdgeType -eq $edge.kind } | Select-Object -First 1
                if ($expectedCountTest) {
                    $isExpected = $true
                }
            }
            
            # Check by extracting name patterns for known test edges
            if (-not $isExpected) {
                $sourceName = Get-PrincipalName -Value $edge.start.value
                $targetName = Get-PrincipalName -Value $edge.end.value
                
                # Check if it matches test patterns by name
                foreach ($pattern in $allExpectedPatterns) {
                    $sourceNamePattern = Get-PrincipalName -Value $pattern.SourcePattern
                    $targetNamePattern = Get-PrincipalName -Value $pattern.TargetPattern
                    
                    if ($sourceName -eq $sourceNamePattern -and $targetName -eq $targetNamePattern) {
                        $isExpected = $true
                        break
                    }
                }
            }
            
            # Track unexpected test-related edges
            if (-not $isExpected -and ($edge.start.value -like "*Test*" -or $edge.end.value -like "*Test*")) {
                $testRun.ExtraEdges += $edge
                if ($ShowDebugOutput) {
                    Write-TestLog "[EXTRA] $($edge.kind): $($edge.start.value) -> $($edge.end.value)" -Level Warning
                }
            }
        }
    }
    
    # Output test summary
    Write-TestLog "=" * 60 -Level Info
    Write-TestLog "Test Summary for $TestPerspective perspective:" -Level Info
    Write-TestLog "Positive test cases:" -Level Info
    Write-TestLog "  Expected edges: $($testRun.ExpectedEdgeCount)" -Level Info
    Write-TestLog "  Found edges: $($testRun.ActualEdgeCount)" -Level Info
    $missingEdgeCount = $testRun.ExpectedEdgeCount - $testRun.ActualEdgeCount
    Write-TestLog "  Missing edges: $missingEdgeCount" -Level $(if ($missingEdgeCount -eq 0) { "Success" } else { "Error" })
    Write-TestLog "Negative test cases:" -Level Info
    Write-TestLog "  Passed (no edge): $($testRun.PassedNegativeTests)" -Level Success
    Write-TestLog "  Failed (edge exists): $($testRun.FailedNegativeTests.Count)" -Level $(if ($testRun.FailedNegativeTests.Count -eq 0) { "Success" } else { "Error" })
    
    # Show details of missing edges if any
    if ($testRun.MissingEdges.Count -gt 0) {
        Write-TestLog "" -Level Info
        Write-TestLog "Failed tests (missing edges):" -Level Error
        foreach ($missingEdge in $testRun.MissingEdges) {
            Write-TestLog "  - $($missingEdge.EdgeType): $($missingEdge.Description)" -Level Error
            if ($missingEdge.ExpectedCount) {
                # For ExpectedCount tests, show the count discrepancy
                $actualFound = $testRun.Results | Where-Object { 
                    $_.EdgeType -eq $missingEdge.EdgeType -and 
                    $_.SourcePattern -eq $missingEdge.SourcePattern -and 
                    $_.TargetPattern -eq $missingEdge.TargetPattern 
                } | Select-Object -First 1
                
                if ($actualFound) {
                    $edgeDeficit = $missingEdge.ExpectedCount - $actualFound.ActualCount
                    Write-TestLog "    Expected: $($missingEdge.ExpectedCount), Found: $($actualFound.ActualCount) (missing $edgeDeficit edges)" -Level Error
                }
            } else {
                Write-TestLog "    Expected: $($missingEdge.SourcePattern) -> $($missingEdge.TargetPattern)" -Level Error
            }
        }
    }

    # Store the edges and nodes for later analysis
    $testRun.Edges = $edges
    $testRun.Nodes = $nodes

    # Calculate total tests and passed tests
    $testRun.TotalTests = $edgesToTest.Count + $negativeCasesToTest.Count
    $testRun.PassedTests = $testRun.PassedPositiveTests + $testRun.PassedNegativeTests

    # Store test run results
    $script:TestResults.TestRuns += $testRun

    # Display clean summary for this perspective
    Write-CleanTestSummary -TestRun $testRun
        
    # Update edge type coverage tracking
    foreach ($edgeType in $expectedEdgeTypes) {
        if (-not $script:TestResults.Coverage.ContainsKey($edgeType)) {
            $script:TestResults.Coverage[$edgeType] = @{
                Tested = $false
                Perspectives = @()
            }
        }
        $script:TestResults.Coverage[$edgeType].Tested = $true
        $script:TestResults.Coverage[$edgeType].Perspectives += $TestPerspective
    }
}

#endregion

#region Coverage Functions

function Get-EdgeCoverage {
    param(
        [switch]$ShowDebugOutput = $script:ShowDebugOutput
    )
    
    Write-TestLog "Analyzing edge type coverage..." -Level Info

    if ($ShowDebugOutput) {
        # Debug output
        Write-TestLog "DEBUG: TestRuns count: $($script:TestResults.TestRuns.Count)" -Level Warning
        foreach ($run in $script:TestResults.TestRuns) {
            $edgeCount = if ($run.Edges) { $run.Edges.Count } else { 0 }
            Write-TestLog "DEBUG: $($run.Perspective) has $edgeCount edges stored" -Level Warning
        }
    }        
    
    $coverage = @{
        offensive = @()
        defensive = @()
    }
    
    # Use stored edges from test results
    if ($script:TestResults.TestRuns.Count -gt 0) {
        Write-TestLog "Using stored edges from test results for coverage analysis" -Level Info
        
        foreach ($testRun in $script:TestResults.TestRuns) {
            $perspective = $testRun.Perspective
            if ($testRun.Edges) {
                $uniqueEdgeTypes = $testRun.Edges | ForEach-Object { $_.kind } | Select-Object -Unique
                $coverage[$perspective] = @($uniqueEdgeTypes)  # Convert to array
                Write-TestLog "Found $($uniqueEdgeTypes.Count) unique edge types in $perspective (from stored results)" -Level Info
                
                # Check for unexpected edges in both perspectives
                if ($perspective -eq "offensive") {
                    $expectedOffensive = $script:OffensiveOnlyEdges + $script:BothPerspectivesEdges
                    $unexpectedInOffensive = $uniqueEdgeTypes | Where-Object { $_ -notin $expectedOffensive }
                    if ($unexpectedInOffensive) {
                        Write-TestLog "WARNING: Found unexpected edges in Offensive perspective:" -Level Warning
                        $unexpectedInOffensive | ForEach-Object {
                            Write-TestLog "  - $_ (should be Defensive only)" -Level Warning
                        }
                    }
                }
                elseif ($perspective -eq "defensive") {
                    $expectedDefensive = $script:DefensiveOnlyEdges + $script:BothPerspectivesEdges
                    $unexpectedInDefensive = $uniqueEdgeTypes | Where-Object { $_ -notin $expectedDefensive }
                    if ($unexpectedInDefensive) {
                        Write-TestLog "WARNING: Found unexpected edges in Defensive perspective:" -Level Warning
                        $unexpectedInDefensive | ForEach-Object {
                            Write-TestLog "  - $_ (should be Offensive only)" -Level Warning
                        }
                    }
                }
                
                # Also check for missing expected edges
                if ($perspective -eq "offensive") {
                    $expectedOffensive = $script:OffensiveOnlyEdges + $script:BothPerspectivesEdges
                    $missingFromOffensive = $expectedOffensive | Where-Object { $_ -notin $uniqueEdgeTypes }
                    if ($missingFromOffensive) {
                        Write-TestLog "WARNING: Missing expected edges in Offensive perspective:" -Level Warning
                        $missingFromOffensive | ForEach-Object {
                            Write-TestLog "  - $_" -Level Warning
                        }
                    }
                }
                elseif ($perspective -eq "defensive") {
                    $expectedDefensive = $script:DefensiveOnlyEdges + $script:BothPerspectivesEdges
                    $missingFromDefensive = $expectedDefensive | Where-Object { $_ -notin $uniqueEdgeTypes }
                    if ($missingFromDefensive) {
                        Write-TestLog "WARNING: Missing expected edges in Defensive perspective:" -Level Warning
                        $missingFromDefensive | ForEach-Object {
                            Write-TestLog "  - $_" -Level Warning
                        }
                    }
                }
            } else {
                Write-TestLog "No edges stored for $perspective perspective" -Level Warning
            }
        }
    } else {
        Write-TestLog "No test results found with stored edges" -Level Error
        return @()
    }
    
    # Analyze coverage
    Write-TestLog "Edge Type Coverage Analysis:" -Level Info
    Write-TestLog "=" * 60 -Level Info
    
    $coverageReport = @()
    foreach ($edgeType in $script:AllEdgeTypes | Sort-Object) {
        $inOffensive = $edgeType -in $coverage.offensive
        $inDefensive = $edgeType -in $coverage.defensive     
        
        # Adjust status based on what perspectives were actually tested
        $testedOffensive = $script:TestResults.TestRuns | Where-Object { $_.Perspective -eq "offensive" }
        $testedDefensive = $script:TestResults.TestRuns | Where-Object { $_.Perspective -eq "defensive" }

        $status = if ($edgeType -in $script:OffensiveOnlyEdges) {
            # Offensive-only edge
            if ($testedOffensive) {
                if ($inOffensive) { "Offensive Only (Expected)" } else { "MISSING" }
            } else {
                "N/A - Offensive Only"
            }
        } elseif ($edgeType -in $script:DefensiveOnlyEdges) {
            # Defensive-only edge
            if ($testedDefensive) {
                if ($inDefensive) { "Defensive Only (Expected)" } else { "MISSING" }
            } else {
                "N/A - Defensive Only"
            }
        } else {
            # Should be in both perspectives
            if ($testedOffensive -and $testedDefensive) {
                # Both perspectives were tested
                if ($inOffensive -and $inDefensive) { "Both" }
                elseif ($inOffensive) { "Partial (Missing Defensive)" }
                elseif ($inDefensive) { "Partial (Missing Offensive)" }
                else { "MISSING" }
            } elseif ($testedOffensive) {
                # Only offensive was tested
                if ($inOffensive) { "Found in Offensive" } else { "MISSING" }
            } elseif ($testedDefensive) {
                # Only defensive was tested
                if ($inDefensive) { "Found in Defensive" } else { "MISSING" }
            } else {
                "Not Tested"
            }
        }
        
        $report = [PSCustomObject]@{
            EdgeType = $edgeType
            Offensive = $inOffensive
            Defensive = $inDefensive
            Status = $status
        }
        
        $coverageReport += $report
        
        $color = switch -Wildcard ($status) {
            "Both" { "Success" }
            "*Expected*" { "Success" }
            "Found in*" { "Success" }
            "MISSING" { "Error" }
            "N/A*" { "Info" }
            "Partial*" { "Warning" }
            default { "Warning" }
        }
        
        Write-TestLog "$edgeType : $status" -Level $color
    }
    
    $script:TestResults.Coverage = @{
        Report = $coverageReport
        OffensiveCount = $coverage.offensive.Count
        DefensiveCount = $coverage.defensive.Count
        TotalPossible = $script:AllEdgeTypes.Count
    }
    
    # Summary
    $missingCount = ($coverageReport | Where-Object { $_.Status -eq "MISSING" }).Count

    Write-TestLog "Coverage Summary:" -Level Info
    Write-TestLog "Total Edge Types: $($script:AllEdgeTypes.Count)" -Level Info
    Write-TestLog "Expected in Offensive: $($script:OffensiveOnlyEdges.Count + $script:BothPerspectivesEdges.Count)" -Level Info
    Write-TestLog "Expected in Defensive: $($script:DefensiveOnlyEdges.Count + $script:BothPerspectivesEdges.Count)" -Level Info
    Write-TestLog "Actually found in Offensive: $($coverage.offensive.Count)" -Level Info
    Write-TestLog "Actually found in Defensive: $($coverage.defensive.Count)" -Level Info
    Write-TestLog "Missing: $missingCount" -Level $(if ($missingCount -eq 0) { "Success" } else { "Warning" })

    # Additional breakdown if both perspectives were tested
    if ($script:TestResults.TestRuns.Count -eq 2) {
        $bothCount = ($coverageReport | Where-Object { $_.Status -eq "Both" }).Count
        Write-TestLog "Covered in Both Perspectives: $bothCount" -Level Success
    }
    
    return $coverageReport
}

function Get-MissingTests {
    param(
        [switch]$ShowDetails = $false
    )
    
    Write-TestLog "Checking for edge types without test cases..." -Level Info
    Write-TestLog "=" * 60 -Level Info
    
    # Get all variables that start with $expectedEdges_
    $testVariables = Get-Variable -Scope Script | Where-Object { 
        $_.Name -like "expectedEdges_*" 
    }
    
    # Extract edge types that have tests by looking at actual test cases
    $edgeTypesWithTests = @()
    foreach ($testVar in $testVariables) {
        # Get unique edge types from the test cases
        $uniqueEdgeTypes = $testVar.Value | 
            Where-Object { $_.EdgeType } | 
            ForEach-Object { $_.EdgeType } |
            Select-Object -Unique
        
        foreach ($edgeType in $uniqueEdgeTypes) {
            if ($edgeType -notin $edgeTypesWithTests) {
                $edgeTypesWithTests += $edgeType
            }
        }
    }
    
    # Find edge types without tests
    $edgeTypesWithoutTests = $script:AllEdgeTypes | Where-Object { 
        $_ -notin $edgeTypesWithTests 
    }
    
    # Display results
    if ($edgeTypesWithoutTests.Count -eq 0) {
        Write-TestLog "All edge types have test cases defined!" -Level Success
    } else {
        Write-TestLog "Edge types WITHOUT test cases ($($edgeTypesWithoutTests.Count)):" -Level Warning
        foreach ($edgeType in $edgeTypesWithoutTests | Sort-Object) {
            Write-TestLog "  - $edgeType" -Level Warning
            
            if ($ShowDetails) {
                # Show which perspective this edge should be in
                if ($edgeType -in $script:OffensiveOnlyEdges) {
                    Write-TestLog "    (Offensive only)" -Level Info
                } elseif ($edgeType -in $script:DefensiveOnlyEdges) {
                    Write-TestLog "    (Defensive only)" -Level Info
                } elseif ($edgeType -in $script:BothPerspectivesEdges) {
                    Write-TestLog "    (Both perspectives)" -Level Info
                } else {
                    Write-TestLog "    (Unknown perspective - not categorized!)" -Level Error
                }
            }
        }
    }
    
    # Summary
    Write-TestLog "`nSummary:" -Level Info
    Write-TestLog "Total edge types: $($script:AllEdgeTypes.Count)" -Level Info
    Write-TestLog "Edge types with tests: $($edgeTypesWithTests.Count)" -Level Success
    Write-TestLog "Edge types without tests: $($edgeTypesWithoutTests.Count)" -Level $(if ($edgeTypesWithoutTests.Count -eq 0) { "Success" } else { "Warning" })
    
    # Check for test edge types that aren't in the known edge types list
    $unknownEdgeTypes = @()
    foreach ($edgeType in $edgeTypesWithTests) {
        if ($edgeType -notin $script:AllEdgeTypes) {
            $unknownEdgeTypes += $edgeType
        }
    }
    
    if ($unknownEdgeTypes.Count -gt 0) {
        Write-TestLog "`nWARNING: Found tests for unknown edge types:" -Level Warning
        foreach ($unknownEdge in $unknownEdgeTypes) {
            Write-TestLog "  - $unknownEdge" -Level Warning
        }
    }
    
    # Optional: Show which test variables contain which edge types
    if ($ShowDetails) {
        Write-TestLog "`nTest variable breakdown:" -Level Info
        foreach ($testVar in $testVariables) {
            $uniqueEdgeTypes = $testVar.Value | 
                Where-Object { $_.EdgeType } | 
                ForEach-Object { $_.EdgeType } |
                Select-Object -Unique
            
            if ($uniqueEdgeTypes.Count -gt 0) {
                Write-TestLog "  $($testVar.Name):" -Level Info
                foreach ($edgeType in $uniqueEdgeTypes | Sort-Object) {
                    $testCount = ($testVar.Value | Where-Object { $_.EdgeType -eq $edgeType }).Count
                    Write-TestLog "    - $edgeType ($testCount tests)" -Level Info
                }
            }
        }
    }
    
    return [PSCustomObject]@{
        EdgeTypesWithTests = $edgeTypesWithTests | Sort-Object
        EdgeTypesWithoutTests = $edgeTypesWithoutTests | Sort-Object
        UnknownEdgeTypes = $unknownEdgeTypes | Sort-Object
    }
}

function Write-CleanTestSummary {
    param(
        [Parameter(Mandatory=$true)]
        $TestRun
    )
    
    # Separate positive and negative test results
    $positiveTests = @($TestRun.Results | Where-Object { 
        $_.EdgeType -and $_.EdgeType -ne "Negative" 
    })
    $negativeTests = @($TestRun.Results | Where-Object { 
        $_.EdgeType -eq "Negative" -or $_.SourcePattern -match "NEGATIVE:" 
    })
    
    # Count positive test results
    $positiveTestsPassed = @($positiveTests | Where-Object { $_.Passed }).Count
    $positiveTestsFailed = $positiveTests.Count - $positiveTestsPassed
    
    # Count negative test results  
    $negativeTestsPassed = @($negativeTests | Where-Object { $_.Passed }).Count
    $negativeTestsFailed = $negativeTests.Count - $negativeTestsPassed
    
    # Calculate edge counts for positive tests
    $expectedEdges = $TestRun.ExpectedEdgeCount
    $foundEdges = $TestRun.ActualEdgeCount
    $missingEdges = $TestRun.MissingEdges.Count
    
    # Display per-perspective summary
    Write-TestLog "`n$($TestRun.Perspective.ToUpper()) Perspective Summary:" -Level Info
    Write-TestLog "* Positive test cases: $($positiveTests.Count)" -Level Info
    Write-TestLog "*     Passed: $positiveTestsPassed" -Level Success
    Write-TestLog "*     Failed: $positiveTestsFailed" -Level Error
    Write-TestLog "*     Expected edges: $expectedEdges" -Level Info
    Write-TestLog "*     Found edges: $foundEdges" -Level Info
    Write-TestLog "*     Missing edges: $missingEdges" -Level Warning
    Write-TestLog "* Negative test cases: $($negativeTests.Count)" -Level Info
    Write-TestLog "*     Passed (no edge): $negativeTestsPassed" -Level Success
    Write-TestLog "*     Failed (edge exists): $negativeTestsFailed" -Level Error
}

function Write-OverallTestSummary {
    param()
    
    if (-not $script:TestResults -or -not $script:TestResults.TestRuns) {
        Write-TestLog "No test results available for summary" -Level Warning
        return
    }
    
    # Initialize counters
    $totalOffensivePositive = 0
    $totalOffensivePositivePassed = 0
    $totalOffensiveNegative = 0
    $totalOffensiveNegativePassed = 0
    
    $totalDefensivePositive = 0
    $totalDefensivePositivePassed = 0
    $totalDefensiveNegative = 0
    $totalDefensiveNegativePassed = 0
    
    # Process each test run
    foreach ($run in $script:TestResults.TestRuns) {
        # Separate positive and negative tests
        $positiveTests = @($run.Results | Where-Object { 
            $_.EdgeType -and $_.EdgeType -ne "Negative" 
        })
        $negativeTests = @($run.Results | Where-Object { 
            $_.EdgeType -eq "Negative" -or $_.SourcePattern -match "NEGATIVE:" 
        })
        
        $positiveTestsPassed = @($positiveTests | Where-Object { $_.Passed }).Count
        $negativeTestsPassed = @($negativeTests | Where-Object { $_.Passed }).Count
        
        if ($run.Perspective -eq "offensive") {
            $totalOffensivePositive += $positiveTests.Count
            $totalOffensivePositivePassed += $positiveTestsPassed
            $totalOffensiveNegative += $negativeTests.Count
            $totalOffensiveNegativePassed += $negativeTestsPassed
        }
        elseif ($run.Perspective -eq "defensive") {
            $totalDefensivePositive += $positiveTests.Count
            $totalDefensivePositivePassed += $positiveTestsPassed
            $totalDefensiveNegative += $negativeTests.Count
            $totalDefensiveNegativePassed += $negativeTestsPassed
        }
    }
    
    # Calculate totals
    $totalOffensive = $totalOffensivePositive + $totalOffensiveNegative
    $totalOffensivePassed = $totalOffensivePositivePassed + $totalOffensiveNegativePassed
    $offensivePassRate = if ($totalOffensive -gt 0) {
        [math]::Round(($totalOffensivePassed / $totalOffensive) * 100, 2)
    } else { 0 }
    
    $totalDefensive = $totalDefensivePositive + $totalDefensiveNegative
    $totalDefensivePassed = $totalDefensivePositivePassed + $totalDefensiveNegativePassed
    $defensivePassRate = if ($totalDefensive -gt 0) {
        [math]::Round(($totalDefensivePassed / $totalDefensive) * 100, 2)
    } else { 0 }
    
    $totalTests = $totalOffensive + $totalDefensive
    $totalPassed = $totalOffensivePassed + $totalDefensivePassed
    $overallPassRate = if ($totalTests -gt 0) {
        [math]::Round(($totalPassed / $totalTests) * 100, 2)
    } else { 0 }
    
    # Display overall summary
    Write-TestLog "`nTotal (both perspectives):" -Level Info
    Write-TestLog "* Offensive test cases: $totalOffensive" -Level Info
    Write-TestLog "*     Passed: $totalOffensivePassed" -Level Success
    Write-TestLog "*     Failed: $($totalOffensive - $totalOffensivePassed)" -Level Error
    Write-TestLog "*     Pass %: $offensivePassRate%" -Level $(
        if ($offensivePassRate -ge 90) { "Success" }
        elseif ($offensivePassRate -ge 70) { "Warning" }
        else { "Error" }
    )
    Write-TestLog "* Defensive test cases: $totalDefensive" -Level Info
    Write-TestLog "*     Passed: $totalDefensivePassed" -Level Success
    Write-TestLog "*     Failed: $($totalDefensive - $totalDefensivePassed)" -Level Error
    Write-TestLog "*     Pass %: $defensivePassRate%" -Level $(
        if ($defensivePassRate -ge 90) { "Success" }
        elseif ($defensivePassRate -ge 70) { "Warning" }
        else { "Error" }
    )
    Write-TestLog "* Total tests run: $totalTests" -Level Info
    Write-TestLog "*     Passed: $totalPassed" -Level Success
    Write-TestLog "*     Failed: $($totalTests - $totalPassed)" -Level Error
    Write-TestLog "*     Pass %: $overallPassRate%" -Level $(
        if ($overallPassRate -ge 90) { "Success" }
        elseif ($overallPassRate -ge 70) { "Warning" }
        else { "Error" }
    )
}

#endregion

#region Report Functions

function New-TestReport {
    Write-TestLog "Generating test report..." -Level Info
    
    $report = @{
        Summary = @{
            Timestamp = $script:TestResults.Timestamp
            ServerInstance = $ServerInstance
            Domain = $Domain
            SetupSuccess = $script:TestResults.SetupSuccess
            TotalTestsRun = 0
            TotalPassed = 0
            TotalFailed = 0
            OverallPassRate = 0
        }
        TestRuns = $script:TestResults.TestRuns
        Coverage = $script:TestResults.Coverage
    }
    
    # Calculate totals
    foreach ($run in $script:TestResults.TestRuns) {
        $report.Summary.TotalTestsRun += $run.TotalTests
        $report.Summary.TotalPassed += $run.PassedTests
    }
    $report.Summary.TotalFailed = $report.Summary.TotalTestsRun - $report.Summary.TotalPassed
    $report.Summary.OverallPassRate = if ($report.Summary.TotalTestsRun -gt 0) {
        [math]::Round(($report.Summary.TotalPassed / $report.Summary.TotalTestsRun) * 100, 2)
    } else { 0 }
    
    # Save JSON report
    $jsonFile = "MSSQLEnumerationTestReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $jsonFile
    Write-TestLog "JSON report saved to: $jsonFile" -Level Success
    
    # Generate HTML report if requested
    if (-not $SkipHTMLReport) {
        $htmlFile = "MSSQLEnumerationTestReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $html = Generate-HTMLReport -Report $report
        $html | Out-File $htmlFile -Encoding UTF8
        Write-TestLog "HTML report saved to: $htmlFile" -Level Success
    }
    
    # Display clean overall summary
    Write-TestLog "`n" + ("=" * 60) -Level Info
    Write-TestLog "Test Execution Summary" -Level Info  
    Write-TestLog ("=" * 60) -Level Info
    Write-OverallTestSummary
    Write-TestLog ("=" * 60) -Level Info
}

function Generate-HTMLReport {
    param($Report)
    
    return @"
<!DOCTYPE html>
<html>
<head>
    <title>MSSQL Enumeration Test Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 0; 
            background-color: #f0f2f5; 
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background-color: white; 
            box-shadow: 0 0 20px rgba(0,0,0,0.1); 
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header .subtitle {
            margin-top: 10px;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        .card h3 {
            margin: 0 0 10px 0;
            color: #555;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .card.success .value { color: #28a745; }
        .card.warning .value { color: #ffc107; }
        .card.danger .value { color: #dc3545; }
        .card.info .value { color: #17a2b8; }
        
        .progress-bar {
            width: 100%;
            height: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            transition: width 0.3s;
        }
        .progress-fill.good { background-color: #28a745; }
        .progress-fill.warning { background-color: #ffc107; }
        .progress-fill.bad { background-color: #dc3545; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        th {
            background-color: #f8f9fa;
            color: #333;
            font-weight: 600;
            text-align: left;
            padding: 15px;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        .failed-test {
            background-color: #f8d7da !important;
        }
        .failed-test:hover {
            background-color: #f5c6cb !important;
        }
        
        .section {
            margin: 40px 0;
        }
        .section h2 {
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .edge-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            margin: 20px 0;
        }
        .edge-card {
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            font-size: 0.9em;
            border: 2px solid;
            transition: all 0.2s;
        }
        .edge-card:hover {
            transform: scale(1.05);
        }
        .edge-card.both {
            background-color: #d4edda;
            border-color: #28a745;
            color: #155724;
        }
        .edge-card.offensive {
            background-color: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        .edge-card.defensive {
            background-color: #cce5ff;
            border-color: #004085;
            color: #004085;
        }
        .edge-card.missing {
            background-color: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        .footer {
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
        
        code {
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MSSQL Enumeration Test Report</h1>
            <div class="subtitle">
                Server: $($Report.Summary.ServerInstance) | 
                Domain: $($Report.Summary.Domain) | 
                Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            </div>
        </div>
        
        <div class="content">
            <div class="summary-cards">
                <div class="card info">
                    <h3>Total Tests</h3>
                    <div class="value">$($Report.Summary.TotalTestsRun)</div>
                </div>
                <div class="card success">
                    <h3>Passed</h3>
                    <div class="value">$($Report.Summary.TotalPassed)</div>
                </div>
                <div class="card danger">
                    <h3>Failed</h3>
                    <div class="value">$($Report.Summary.TotalFailed)</div>
                </div>
                <div class="card $(if ($Report.Summary.OverallPassRate -ge 90) { 'success' } elseif ($Report.Summary.OverallPassRate -ge 70) { 'warning' } else { 'danger' })">
                    <h3>Pass Rate</h3>
                    <div class="value">$($Report.Summary.OverallPassRate)%</div>
                    <div class="progress-bar">
                        <div class="progress-fill $(if ($Report.Summary.OverallPassRate -ge 90) { 'good' } elseif ($Report.Summary.OverallPassRate -ge 70) { 'warning' } else { 'bad' })" 
                             style="width: $($Report.Summary.OverallPassRate)%"></div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Test Results by Perspective</h2>
$(
    foreach ($run in $Report.TestRuns) {
        $passRate = if ($run.TotalTests -gt 0) { 
            [math]::Round(($run.PassedTests / $run.TotalTests) * 100, 2) 
        } else { 0 }
        
        @"
                <h3>$($run.Perspective.ToUpper()) Perspective</h3>
                <p>Tests: $($run.TotalTests) | Passed: $($run.PassedTests) | Failed: $($run.TotalTests - $run.PassedTests) | Pass Rate: $passRate%</p>
                
                <table>
                    <tr>
                        <th>Edge Type</th>
                        <th>Description</th>
                        <th>Result</th>
                        <th>Source</th>
                        <th>Target</th>
                    </tr>
$(
    foreach ($test in $run.Results) {
        $rowClass = if (-not $test.Passed) { 'class="failed-test"' } else { '' }
        $resultIcon = if ($test.Passed) { 'Y' } else { 'N' }
        $resultColor = if ($test.Passed) { 'color: #28a745;' } else { 'color: #dc3545;' }
        
        @"
                    <tr $rowClass>
                        <td><strong>$($test.EdgeType)</strong></td>
                        <td>$($test.Description)</td>
                        <td style="$resultColor font-weight: bold;">$resultIcon</td>
                        <td><code>$($test.SourcePattern)</code></td>
                        <td><code>$($test.TargetPattern)</code></td>
                    </tr>
"@
    }
)
                </table>
"@
    }
)
            </div>
            
            <div class="section">
                <h2>Edge Type Coverage</h2>
                <p>Total possible edge types: $($Report.Coverage.TotalPossible)</p>
                <p>Coverage in Offensive: $($Report.Coverage.OffensiveCount) | Coverage in Defensive: $($Report.Coverage.DefensiveCount)</p>
                
                <div class="edge-grid">
$(
    foreach ($edge in $Report.Coverage.Report | Sort-Object EdgeType) {
        $class = switch -Wildcard ($edge.Status) {
            "Both" { "both" }
            "*Offensive Only*" { "offensive" }
            "*Defensive Only*" { "defensive" }
            "MISSING" { "missing" }
            default { "missing" }
        }
        
        @"
                    <div class="edge-card $class">
                        <strong>$($edge.EdgeType)</strong><br>
                        <small>$($edge.Status)</small>
                    </div>
"@
    }
)
                </div>
            </div>
            
            <div class="section">
                <h2>Test Objects Created</h2>
                <p>The following SQL Server objects were created with descriptive names to test specific edge types:</p>
                
                <h3>Server-Level Objects</h3>
                <ul>
                    <li><strong>Logins:</strong> CanAlterLogin_Login, CanAlterAnyLogin_Login, CanControlLogin_Login, CanImpersonateLogin_Login, etc.</li>
                    <li><strong>Server Roles:</strong> CanAddMember_ServerRole, CanTakeOwnership_ServerRole, OwnedBy_UserRole, etc.</li>
                    <li><strong>Credentials:</strong> EdgeTest_DomainCredential, EdgeTest_LocalCredential</li>
                    <li><strong>Linked Server:</strong> LinkedTo_AdminServer</li>
                </ul>
                
                <h3>Database-Level Objects</h3>
                <ul>
                    <li><strong>Databases:</strong> EdgeTest_RegularDB, EdgeTest_TrustworthyDB, EdgeTest_PermissionDB</li>
                    <li><strong>DB Users:</strong> CanAlterRole_DBUser, CanControlUser_DBUser, DBOwner_Member, etc.</li>
                    <li><strong>DB Roles:</strong> CanAddMember_DBRole, CanTakeOwnership_DBRole, OwnedBy_UserRole, etc.</li>
                    <li><strong>App Roles:</strong> CanChangePassword_AppRole, ControlTarget_AppRole</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>MSSQL Enumeration Test Suite v1.0 | Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
</body>
</html>
"@
}

#endregion

#region Teardown Functions

function Invoke-TestTeardown {
    Write-TestLog "Cleaning up test environment..." -Level Info
    
    try {
        Invoke-TestSQL -ServerInstance $ServerInstance -Query $script:CleanupSQL -QueryTimeout 120
        
        # Clean up domain objects if requested
        if (-not $SkipCreateDomainUsers -and -not $SkipDomainObjects) {
            Write-TestLog "Cleaning up domain objects..." -Level Info
            
            if (Get-Command Remove-ADUser -ErrorAction SilentlyContinue) {
                $domainUsers = @(
                    "EdgeTestDomainUser1",
                    "EdgeTestDomainUser2",
                    "EdgeTestSysadmin",
                    "EdgeTestServiceAcct",
                    "EdgeTestDisabledUser",
                    "EdgeTestNoConnect",
                    "EdgeTestCoerce"
                )
                
                foreach ($user in $domainUsers) {
                    try {
                        Remove-ADUser -Identity $user -Confirm:$false -ErrorAction SilentlyContinue
                        Write-TestLog "Removed domain user: $user" -Level Success
                    }
                    catch {
                        # User might not exist
                    }
                }
                
                # Remove computer account
                try {
                    if (Get-ADComputer -Filter "Name -eq 'TestComputer'" -ErrorAction SilentlyContinue) {
                        Remove-ADComputer -Identity "TestComputer" -Confirm:$false
                        Write-TestLog "Removed computer account: $Domain\TestComputer$" -Level Success
                    }
                } catch {
                    Write-Warning "Failed to remove computer account: $_"
                }

                # Remove CoerceAndRelayToMSSQL test computer accounts
                $coerceTestComputers = @("CoerceTestEnabled1", "CoerceTestEnabled2", "CoerceTestDisabled", "CoerceTestNoConnect")
                foreach ($computerName in $coerceTestComputers) {
                    try {
                        if (Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction SilentlyContinue) {
                            Remove-ADComputer -Identity $computerName -Confirm:$false
                            Write-TestLog "Removed computer account: $Domain\$computerName$" -Level Success
                        }
                    } catch {
                        Write-Warning "Failed to remove computer account $computerName : $_"
                    }
                }                
                
                try {
                    Remove-ADGroup -Identity "EdgeTestDomainGroup" -Confirm:$false -ErrorAction SilentlyContinue
                    Write-TestLog "Removed domain group: EdgeTestDomainGroup" -Level Success
                }
                catch {
                    # Group might not exist
                }
            }
        }
        
        Write-TestLog "Test environment cleanup completed!" -Level Success
    }
    catch {
        Write-TestLog "Error during cleanup: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

Write-TestLog "MSSQL Enumeration Test Suite" -Level Info
Write-TestLog "=" * 60 -Level Info

switch ($Action) {
    "Setup" {
        Invoke-TestSetup
    }
    
    "Test" {
        if ($Perspective -eq "both") {
            Test-EdgeCreation -TestPerspective "offensive"
            Test-EdgeCreation -TestPerspective "defensive"
        }
        else {
            Test-EdgeCreation -TestPerspective $Perspective
        }
    }
    
    "Coverage" {
        Get-EdgeCoverage
        # Display coverage table
        Write-TestLog "Edge Type Coverage Summary:" -Level Info
        $coverageReport | Format-Table -AutoSize
    }

    "MissingTests" {
        Get-MissingTests -ShowDetails
    }    
    
    "Report" {
        New-TestReport
    }
    
    "Teardown" {
        Invoke-TestTeardown
    }
    
    "All" {
        try {
            # Setup
            Invoke-TestSetup

            if ($script:TestResults.SetupSuccess) {
                # Test based on Perspective parameter
                if ($Perspective -eq "both") {
                    Test-EdgeCreation -TestPerspective "offensive"
                    Test-EdgeCreation -TestPerspective "defensive"
                }
                else {
                    Test-EdgeCreation -TestPerspective $Perspective
                }
                
                # Get coverage
                Get-EdgeCoverage

                # Check for missing tests
                Write-TestLog "`n" + ("=" * 60) -Level Info
                Get-MissingTests                
                
                # Generate report
                New-TestReport

                # Display coverage table
                Write-TestLog "Edge Type Coverage Summary:" -Level Info
                $coverageReport | Format-Table -AutoSize
            }
            else {
                Write-TestLog "Skipping tests due to setup failure" -Level Error
            }
        }
        finally {
            # Always try to cleanup
            Write-TestLog "Do you want to clean up the test environment? (Y/N)" -Level Warning
            $response = Read-Host
            if ($response -eq 'Y' -or $response -eq 'y') {
                Invoke-TestTeardown
            }
        }
    }
}

Write-TestLog "Test suite execution completed!" -Level Success

#endregion