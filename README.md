# MSSQLHound
PowerShell collector for adding MSSQL attack paths to BloodHound with OpenGraph, by Chris Thompson (@_Mayyhem) at SpecterOps

# Overview
Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual files, then zips them
  - Example: mssql-bloodhound-20250724-115610.zip
      
## System Requirements:
  - PowerShell 4.0 or higher
  - Active Directory module (or connectivity to download/import/install it)
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

Please refer to the wiki for detailed information on new nodes, edges, and their properties.
