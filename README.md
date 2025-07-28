# MSSQLHound
PowerShell collector for adding MSSQL attack paths to BloodHound with OpenGraph, by Chris Thompson (@_Mayyhem) at SpecterOps

# Overview
Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual temporary files, then zips them in the current directory
  - Example: mssql-bloodhound-20250724-115610.zip
      
## System Requirements:
  - PowerShell 4.0 or higher
  - Target is running SQL Server 2005 or higher

## Minimum Permissions:
### Windows Level:
  - Active Directory domain context with line of sight to a domain controller
### MSSQL Server Level:
  - **CONNECT SQL** (default for new logins)
  - **VIEW ANY DATABASE** (default for new logins)

## Recommended Permissions:
### MSSQL Server Level:
  - **VIEW ANY DEFINITION** permission or ##MS_DefinitionReader role membership (available in versions 2022+)
      - Needed to read server principals and their permissions
      - Without one of these permissions, there will be false negatives (invisible server principals)
  - **VIEW SERVER PERFORMANCE STATE** permission or ##MSS_ServerPerformanceStateReader## role membership (available in versions 2022+) or local Administrators group privileges on the target (fallback for WMI collection)
      - Only used for service account collection

### MSSQL Database Level:
  - **CONNECT ANY DATABASE** server permission (available in versions 2014+) or ##MS_DatabaseConnector## role membership (available in versions 2022+) or login maps to a database user with CONNECT on individual databases
      - Needed to read database principals and their permissions
  - Login maps to **msdb database user with db_datareader** role or with SELECT permission on:
       - msdb.dbo.sysproxies
       - msdb.dbo.sysproxylogin
       - msdb.dbo.sysproxysubsystem
       - msdb.dbo.syssubsystems
       - Only used for proxy account collection

# Command Line Options
For the latest and most reliable information, please execute MSSQLHound with the `-Help` flag.

| Option | Values |
|--------|--------|
| **-Help** `<switch>` | • Display usage information |
| **-OutputFormat** `<string>` | • **BloodHound**: OpenGraph implementation that collects data in separate files for each MSSQL server, then zips them up and deletes the originals. The zip can be uploaded to BloodHound by navigating to `Administration` > `File Ingest`<br>• **BloodHound-customnodes**: Generate JSON to POST to `custom-nodes` API endpoint<br>• **BloodHound-customnode**: Generate JSON for DELETE on `custom-nodes` API endpoint<br>• **BHGeneric**: Work in progress to make script compatible with [BHOperator](https://github.com/SadProcessor/BloodHoundOperator) |
| **-ServerInstance** `<string>` | • A specific MSSQL instance to collect from:<br>&nbsp;&nbsp;• **Null**: Query the domain for SPNs and collect from each server found<br>&nbsp;&nbsp;• **Name/FQDN**: `<host>`<br>&nbsp;&nbsp;• **Instance**: `<host>[:<port>\|:<instance_name>]`<br>&nbsp;&nbsp;• **SPN**: `<service class>/<host>[:<port>\|:<instance_name>]` |
| **-ServerListFile** `<string>` | • Specify the path to a file containing multiple server instances to collect from in the ServerInstance formats above |
| **-ServerList** `<string>` | • Specify a comma-separated list of server instances to collect from in the ServerInstance formats above |
| **-TempDir** `<string>` | • Specify the path to a temporary directory where .json files will be stored before being zipped<br>Default: new directory created with `[System.IO.Path]::GetTempPath()` |
| **-ZipDir** `<string>` | • Specify the path to a directory where the final .zip file will be stored<br>• Default: current directory |
| **-MemoryThresholdPercent** `<uint>` | • Maximum memory allocation limit, after which the script will exit to prevent availability issues<br>• Default: `90` |
| **-UserID** `<string>` | • Specify a **login** to connect to the remote server(s) |
| **-Password** `<string>` | • Specify a **password** to connect to the remote server(s) |
| **-Domain** `<string>` | • Specify a **domain** to use for name and SID resolution |
| **-IncludeNontraversableEdges** (switch) | • **On**: • Collect both **traversable and non-traversable edges**<br>• **Off (default)**: Collect **only traversable edges** (good for offensive engagements until Pathfinding supports OpenGraph edges) |
| **-MakeInterestingEdgesTraversable** (switch) | • **On**: Make the following edges traversable (useful for offensive engagements but prone to false positive edges that may not be abusable):<br>&nbsp;&nbsp;• **MSSQL_HasDBScopedCred**<br>&nbsp;&nbsp;• **MSSQL_HasMappedCred**<br>&nbsp;&nbsp;• **MSSQL_HasProxyCred**<br>&nbsp;&nbsp;• **MSSQL_IsTrustedBy**<br>&nbsp;&nbsp;• **MSSQL_LinkedTo**<br>&nbsp;&nbsp;• **MSSQL_ServiceAccountFor**<br>• **Off (default)**: The edges above are non-traversable |
| **-CollectFromLinkedServers** (switch) | • **On**: If linked servers are found, try and perform a full MSSQL collection against each server<br>• **Off (default)**: If linked servers are found, **don't** try and perform a full MSSQL collection against each server |
| **-DomainEnumOnly** (switch) | • **On**: If SPNs are found, **don't** try and perform a full MSSQL collection against each server<br>• **Off (default)**: If SPNs are found, try and perform a full MSSQL collection against each server |
| **-InstallADModule** (switch) | • **On**: Try to install the ActiveDirectory module for PowerShell if it is not already installed<br>• **Off (default)**: Do not try to install the ActiveDirectory module for PowerShell if it is not already installed. Rely on DirectoryServices, ADSISearcher, DirectorySearcher, and NTAccount.Translate() for object resolution. |
| **-LinkedServerTimeout** `<uint>` | • Give up enumerating linked servers after `X` seconds<br>• Default: `300` seconds (5 minutes) |
| **-FileSizeLimit** `<string>` | • Stop enumeration after all collected files exceed this size on disk<br> • Supports MB, GB<br> • Default: `1GB` |
| **-FileSizeUpdateInterval** `<uint>` | • Receive periodic size updates as files are being written for each server<br>• Default: `5` seconds |
