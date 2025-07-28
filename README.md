# MSSQLHound
PowerShell collector for adding MSSQL attack paths to [BloodHound](https://github.com/SpecterOps/BloodHound) with OpenGraph, by Chris Thompson ([@_Mayyhem](https://x.com/_Mayyhem)) at [SpecterOps](https://x.com/SpecterOps)

# Table of Contents

- [Overview](#overview)
  - [System Requirements](#system-requirements)
  - [Minimum Permissions](#minimum-permissions)
  - [Recommended Permissions](#recommended-permissions)
- [Command Line Options](#command-line-options)
- [Limitations](#limitations)
- [Future Development](#future-development)
- [MSSQL Nodes Reference](#mssql-nodes-reference)
- [MSSQL Edges Reference](#mssql-edges-reference)

# Overview
Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual temporary files, then zips them in the current directory
  - Example: `mssql-bloodhound-20250724-115610.zip`
      
## System Requirements:
  - PowerShell 4.0 or higher
  - Target is running SQL Server 2005 or higher

## Minimum Permissions:
### Windows Level:
  - Active Directory domain context with line of sight to a domain controller
### MSSQL Server Level:
  - **`CONNECT SQL`** (default for new logins)
  - **`VIEW ANY DATABASE`** (default for new logins)

## Recommended Permissions:
### MSSQL Server Level:
  - **`VIEW ANY DEFINITION`** permission or `##MS_DefinitionReader##` role membership (available in versions 2022+)
      - Needed to read server principals and their permissions
      - Without one of these permissions, there will be false negatives (invisible server principals)
  - **`VIEW SERVER PERFORMANCE STATE`** permission or `##MSS_ServerPerformanceStateReader##` role membership (available in versions 2022+) or local `Administrators` group privileges on the target (fallback for WMI collection)
      - Only used for service account collection

### MSSQL Database Level:
  - **`CONNECT ANY DATABASE`** server permission (available in versions 2014+) or `##MS_DatabaseConnector##` role membership (available in versions 2022+) or login maps to a database user with `CONNECT` on individual databases
      - Needed to read database principals and their permissions
  - Login maps to **`msdb`** database user with **`db_datareader`** role or with `SELECT` permission on:
       - `msdb.dbo.sysproxies`
       - `msdb.dbo.sysproxylogin`
       - `msdb.dbo.sysproxysubsystem`
       - `msdb.dbo.syssubsystems`
       - Only used for proxy account collection

# Command Line Options
For the latest and most reliable information, please execute MSSQLHound with the `-Help` flag.

| Option<br>______________________________________________ | Values<br>_______________________________________________________________________________________________ |
|--------|--------|
| **-Help** `<switch>` | • Display usage information |
| **-OutputFormat** `<string>` | • **BloodHound**: OpenGraph implementation that collects data in separate files for each MSSQL server, then zips them up and deletes the originals. The zip can be uploaded to BloodHound by navigating to `Administration` > `File Ingest`<br>• **BloodHound-customnodes**: Generate JSON to POST to `custom-nodes` API endpoint<br>• **BloodHound-customnode**: Generate JSON for DELETE on `custom-nodes` API endpoint<br>• **BHGeneric**: Work in progress to make script compatible with [BHOperator](https://github.com/SadProcessor/BloodHoundOperator) |
| **-ServerInstance** `<string>` | • A specific MSSQL instance to collect from:<br>&nbsp;&nbsp;&nbsp;&nbsp;• **Null**: Query the domain for SPNs and collect from each server found<br>&nbsp;&nbsp;&nbsp;&nbsp;• **Name/FQDN**: `<host>`<br>&nbsp;&nbsp;&nbsp;&nbsp;• **Instance**: `<host>[:<port>\|:<instance_name>]`<br>&nbsp;&nbsp;&nbsp;&nbsp;• **SPN**: `<service class>/<host>[:<port>\|:<instance_name>]` |
| **-ServerListFile** `<string>` | • Specify the path to a file containing multiple server instances to collect from in the ServerInstance formats above |
| **-ServerList** `<string>` | • Specify a comma-separated list of server instances to collect from in the ServerInstance formats above |
| **-TempDir** `<string>` | • Specify the path to a temporary directory where .json files will be stored before being zipped<br>Default: new directory created with `[System.IO.Path]::GetTempPath()` |
| **-ZipDir** `<string>` | • Specify the path to a directory where the final .zip file will be stored<br>• Default: current directory |
| **-MemoryThresholdPercent** `<uint>` | • Maximum memory allocation limit, after which the script will exit to prevent availability issues<br>• Default: `90` |
| **-UserID** `<string>` | • Specify a **login** to connect to the remote server(s) |
| **-Password** `<string>` | • Specify a **password** to connect to the remote server(s) |
| **-Domain** `<string>` | • Specify a **domain** to use for name and SID resolution |
| **-IncludeNontraversableEdges** (switch) | • **On**: • Collect both **traversable and non-traversable edges**<br>• **Off (default)**: Collect **only traversable edges** (good for offensive engagements until Pathfinding supports OpenGraph edges) |
| **-MakeInterestingEdgesTraversable** (switch) | • **On**: Make the following edges traversable (useful for offensive engagements but prone to false positive edges that may not be abusable):<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_HasDBScopedCred**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_HasMappedCred**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_HasProxyCred**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_IsTrustedBy**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_LinkedTo**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_ServiceAccountFor**<br>• **Off (default)**: The edges above are non-traversable |
| **-CollectFromLinkedServers** (switch) | • **On**: If linked servers are found, try and perform a full MSSQL collection against each server<br>• **Off (default)**: If linked servers are found, **don't** try and perform a full MSSQL collection against each server |
| **-DomainEnumOnly** (switch) | • **On**: If SPNs are found, **don't** try and perform a full MSSQL collection against each server<br>• **Off (default)**: If SPNs are found, try and perform a full MSSQL collection against each server |
| **-InstallADModule** (switch) | • **On**: Try to install the ActiveDirectory module for PowerShell if it is not already installed<br>• **Off (default)**: Do not try to install the ActiveDirectory module for PowerShell if it is not already installed. Rely on DirectoryServices, ADSISearcher, DirectorySearcher, and NTAccount.Translate() for object resolution. |
| **-LinkedServerTimeout** `<uint>` | • Give up enumerating linked servers after `X` seconds<br>• Default: `300` seconds (5 minutes) |
| **-FileSizeLimit** `<string>` | • Stop enumeration after all collected files exceed this size on disk<br> • Supports MB, GB<br> • Default: `1GB` |
| **-FileSizeUpdateInterval** `<uint>` | • Receive periodic size updates as files are being written for each server<br>• Default: `5` seconds |

# Limitations
- MSSQLHound can’t currently collect nodes and edges from linked servers over the link, although I’d like to add more linked server collection functionality in the future.
- MSSQLHound doesn’t check DENY permissions. Because permissions are denied by default unless explicitly granted, it is assumed that use of DENY permissions is rare. One exception is the CONNECT SQL permission, for which the DENY permission is checked to see if the principal can remotely log in to the MSSQL instance at all. 
- MSSQLHound stops enumerating at the database level. It could be modified to go deeper (to the table/stored procedure or even column level), but that would degrade performance, especially when merging with the AD graph.
- EPA enumeration without a login or Remote Registry access is not yet supported (but will be soon)
- Separate collections in domains that can’t reach each other for principal SID resolution may not merge correctly when they are ingested (i.e., more than one MSSQL_Server node may represent the same server, one labelled with the SID, one with the name).

# Future Development:
- Unprivileged EPA collection (in the works)
- Collection from linked servers
- Collect across domains and trusts
- Azure extension for SQL Server
- AZUser/Groups for server logins / database users
- Cross database ownership chaining
- DENY permissions
- EXECUTE permission on xp_cmdshell
- UNSAFE/EXTERNAL_ACCESS permission on assembly (impacted by TRUSTWORTHY)
- Add this to CoerceAndRelayToMSSQL:
    - Domain principal has CONNECT SQL (and EXECUTE on xp_dirtree or other stored procedures that will authenticate to a remote host)
    - Service account/Computer has a server login that is enabled on another SQL instance
    - EPA is not required on remote SQL instance

# MSSQL Nodes Reference
## Server Level
### Server Instance (`MSSQL_Server` node)
The entire installation of the MSSQL Server database management system (DBMS) that contains multiple databases and server-level objects

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>[:<port>\|:<instance_name>]`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SQL.MAYYHEM.COM` (default port and instance name)<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SQL.MAYYHEM.COM:SQL2012` (named instance) |
| **Object ID**: string | • Format: `<computer_domain_sid>:<port\|instance_name>`<br>• Example: `S-1-5-21-843997178-3776366836-1907643539-1108:1433`<br>• Port or instance name should be a part of the identifier in case there are multiple MSSQL Server instances on the same host.<br>• Two or more accounts are permitted to have identical SPNs in Active Directory (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn), and two or more names may resolve to the same host (e.g., `MSSQLSvc/ps1-db:1433` and `MSSQLSvc/ps1-db.mayyhem.com:1433`) so we will use the domain SID instead of the host portion of the SPN, when available.<br>• MSSQLSvc SPNs may contain an instance name instead of the port, in which case the SQL Browser service (`UDP/1434`) is used to determine the listening port for the MSSQL server. In other cases the port is dynamically chosen and the SPN updated when the service [re]starts. The `ObjectIdentifier` must be capable of storing either value in case there is an instance name in the SPN and the SQL Browser service is not reachable, and prefer instance over port.<br>• The script currently falls back to using the FQDN instead of the SID if the server can't be resolved to a domain object (for example, if it is resolved via DNS or reachable via the MSSQL port but can't be resolved to a principal in another domain).<br>&nbsp;&nbsp;&nbsp;&nbsp;• This format complicates things when trying to merge objects from collections taken from different domains, with different privileges, or when servers are discovered via SQL links. For example, when collecting from `hostA.domain1.local`, a link to `hostB.domain2.local:1433` is discovered. The collector can't resolve principals in `domain2`, so its `ObjectIdentifier` is the `hostname:port` instead. However, `hostB.domain2.local` is reachable on port `1433` and after connecting, the collector determines that its instance name is `SQLHOSTB`. Later, a collection is done on `HostB` from within `domain2`, so its `ObjectIdentifier` is either `sid:port` or `sid:instanceName`, depending on what's in the SPNs.|
| **Databases**: List\<string\> | • Names of databases contained in the SQL Server instance |
| **Extended Protection**: string<br>(`Off` \| `Allowed` \| `Required` \| `Allowed/Required`) |• Allowed and required both prevent authentication relay to MSSQL (using service binding if Force Encryption is `No`, using channel binding if Force Encryption is `Yes`). |
| **Force Encryption**: string<br>(`No` \| `Yes`) | • Does the server require clients to encrypt communications? |
| **Has Links From Servers**: List\<string\> | • SQL Server instances that have a link to this SQL Server instance<br>• There is no way to view this using SSMS or other native tools on the target of a link. |
| **Instance Name**: string | • SQL Server instances are identified using either a port or an instance name.<br>• Default: `MSSQLSERVER` |
| **Is Any Domain Principal Sysadmin**: bool | • If a domain principal is a member of the sysadmin server role or has equivalent permissions (`securityadmin`, `CONTROL SERVER`, or `IMPERSONATE ANY LOGIN`), the domain service account running MSSQL can impersonate such a principal to gain control of the server via S4U2Silver. See the `MSSQL_GetAdminTGS` edge for more information. |
| **Is Linked Server Target**: bool | • Does any SQL Server instance have a link to this SQL Server instance?<br>• There is no way to view this using SSMS or other native tools on the target of a link. |
| **Is Mixed Mode Auth Enabled**: bool | • **True**: both Windows and SQL logins are permitted to access the server remotely<br>• **False**: only Windows logins are permitted to access the server remotely |
| **Linked To Servers**: List\<string\> | • SQL Server instances that this SQL Server instance is linked to |
| **Port**: uint |• SQL Server instances are identified using either a port or an instance name. <br>• Default: `1433` |
| **Service Account**: string | • The Windows account running the SQL Server instance |
| **Service Principal Names**: List\<string\> | • SPNs associated with this SQL Server instance |
| **Version**: string | • Result of `SELECT @@VERSION`

### Server Login (`MSSQL_Login` node)
A type of server principal that can be assigned permissions to access server-level objects, such as the ability to connect to the instance or modify server role membership. These principals can be local to the instance (SQL logins) or mapped to a domain user, computer, or group (Windows logins). Server logins can be added as members of server roles to inherit the permissions assigned to the role.

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>`<br>• Example: `MAYYHEM\sqladmin` |
| **Object ID**: string | • Format: `<name>@<mssqlserver_object_id>`<br>• Example: `MAYYHEM\sqladmin@S-1-5-21-843997178-3776366836-1907643539-1108:1433` |
| **Active Directory Principal**: string | • Name of the AD principal this login is mapped to |
| **Active Directory SID**: string | • SID of the AD principal this login is mapped to |
| **Create Date**: datetime | • When the login was created |
| **Database Users**: List\<string\> | • Names of each database user this login is mapped to |
| **Default Database**: string | • The default database used when the login connects to the server |
| **Disabled**: bool | • Is the account disabled? |
| **Explicit Permissions**: List\<string\> | • Server level permissions assigned directly to this login<br>• Does not include all effective permissions such as those granted through role membership |
| **Is Active Directory Principal**: bool | • If a domain principal has a login, the domain service account running MSSQL can impersonate such a principal to gain control of the login via S4U2Silver. |
| **Member of Roles**: List\<string\> | • Names of roles this principal is a direct member of<br>• Does not include nested memberships |
| **Modify Date**: datetime | • When the principal was last modified |
| **Principal Id**: uint | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **SQL Server**: string | • Name of the SQL Server where this object is a principal |
| **Type**: string | • **ASYMMETRIC_KEY_MAPPED_LOGIN**: Used to sign modules within the database, such as stored procedures, functions, triggers, or assemblies and can't be used to connect to the server remotely. I haven't messed with these much but they can be assigned permissions and impersonated.<br>• **CERTIFICATE_MAPPED_LOGIN**: Used to sign modules within the database, such as stored procedures, functions, triggers, or assemblies and can't be used to connect to the server remotely. I haven't messed with these much but they can be assigned permissions and impersonated.<br>• **SQL_LOGIN**: This login is local to the SQL Server instance and mixed-mode authentication must be enabled to connect with it<br>• **WINDOWS_LOGIN**: A Windows account is mapped to this login<br>• **WINDOWS_GROUP**: A Windows group is mapped to this login |

### Server Role (`MSSQL_ServerRole` node)
A type of server principal that can be assigned permissions to access server-level objects, such as the ability to connect to the instance or modify server role membership. Server logins and user-defined server roles can be added as members of server roles, inheriting the role's permissions.

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>`<br>• Example: `processadmin` |
| **Object ID**: string | • Format: `<name>@<mssqlserver_object_id>`<br>• Example: `processadmin@S-1-5-21-843997178-3776366836-1907643539-1108:1433` |
| **Create Date**: datetime | • When the role was created |
| **Explicit Permissions**: List\<string\> | • Server level permissions assigned directly to this login<br>• Does not include all effective permissions such as those granted through role membership |
| **Is Fixed Role**: bool | • Whether or not the role is built-in (i.e., ships with MSSQL and can't be removed) |
| **Member of Roles**: List\<string\> | • Names of roles this principal is a direct member of<br>• Does not include nested memberships |
| **Members**: List\<string\> | • Names of each principal that is a direct member of this role |
| **Modify Date**: datetime | • When the principal was last modified |
| **Principal Id**: uint | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **SQL Server**: string | • Name of the SQL Server where this object is a principal |

## Database Level

### Database (`MSSQL_Database` node)
A collection of database principals (e.g., users and roles) as well as object groups called schemas, each of which contains securable database objects such as tables, views, and stored procedures.

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>`<br>• Example: `master` |
| **Object ID**: string | • Format: `<mssqlserver_object_id>\<name>`<br>• Example: `S-1-5-21-843997178-3776366836-1907643539-1108:1433\master` |
| **Is Trustworthy**: bool | • Is the `Trustworthy` property of this database set to `True`?<br>• When `Trustworthy` is `True`, principals with control of the database are permitted to execute server level actions in the context of the database's owner, allowing server compromise if the owner has administrative privileges.<br>• Example: If `sa` owns the `CM_PS1` database and the database's `Trustworthy` property is `True`, then a user in the database with sufficient privileges could create a stored procedure with the `EXECUTE AS OWNER` statement and leverage the `sa` account's permissions to execute SQL statements on the server. See the `MSSQL_ExecuteAsOwner` edge for more information. |
| **Owner Login Name**: string | • Example: `MAYYHEM\cthompson` |
| **Owner Principal ID**: uint | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **SQL Server**: string | • Name of the SQL Server where this object is a principal |

### Database User (`MSSQL_DatabaseUser` node)
A user that has access to the specific database it is contained in. Users may be mapped to a login or may be created without a login. Users can be assigned permissions to access database-level objects, such as the ability to connect to the database, access tables, modify database role membership, or execute stored procedures. Users and user-defined database roles can be added as members of database roles, inheriting the role's permissions.

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>@<databasename>`<br>• Example: `MAYYHEM\LOWPRIV@CM_CAS` |
| **Object ID**: string | • Format: `<name>@<database_object_id>`<br>• `Example: MAYYHEM\LOWPRIV@S-1-5-21-843997178-3776366836-1907643539-1117:1433\CM_CAS` |
| **Create Date**: datetime | • When the user was created |
| **Database**: string | • Name of the database where this user is a principal |
| **Default Schema**: string | • The default schema used when the user connects to the database |
| **Explicit Permissions**: List\<string\> | • Database level permissions assigned directly to this principal<br>• Does not include all effective permissions such as those granted through role membership |
| **Member of Roles**: List\<string\> | • Names of roles this principal is a direct member of<br>• Does not include nested memberships |
| **Modify Date**: datetime | • When the principal was last modified |
| **Principal Id**: uint | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **Server Login**: string | • Name of the login this user is mapped to |
| **SQL Server**: string | • Name of the SQL Server where this object is a principal |
| **Type**: string | • **ASYMMETRIC_KEY_MAPPED_USER**: Used to sign modules within the database, such as stored procedures, functions, triggers, or assemblies and can't be used to connect to the server remotely. I haven't messed with these much but they can be assigned permissions and impersonated.<br>• **CERTIFICATE_MAPPED_USER**: Used to sign modules within the database, such as stored procedures, functions, triggers, or assemblies and can't be used to connect to the server remotely. I haven't messed with these much but they can be assigned permissions and impersonated.<br>• **SQL_USER**: This user is local to the SQL Server instance and mixed-mode authentication must be enabled to connect with it<br>• **WINDOWS_USER**: A Windows account is mapped to this user<br>• **WINDOWS_GROUP**: A Windows group is mapped to this user |

### Database Role (`MSSQL_DatabaseRole` node)
A type of database principal that can be assigned permissions to access database-level objects, such as the ability to connect to the database, access tables, modify database role membership, or execute stored procedures. Database users, user-defined database roles, and application roles can be added as members of database roles, inheriting the role's permissions.

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>@<databasename>`<br>• Example: `db_owner@CM_CAS` |
| **Object ID**: string | • Format: `<name>@<database_object_id>`<br>• Example: `db_owner@S-1-5-21-843997178-3776366836-1907643539-1117:1433\CM_CAS` |
| **Create Date**: datetime | • When the role was created |
| **Database**: string | • Name of the database where this role is a principal |
| **Explicit Permissions**: List\<string\> | • Database level permissions assigned directly to this principal<br>• Does not include all effective permissions such as those granted through role membership |
| **Member of Roles**: List\<string\> | • Names of roles this principal is a direct member of<br>• Does not include nested memberships |
| **Members**: List\<string\> | • Names of each principal that is a direct member of this role |
| **Modify Date**: datetime | • When the principal was last modified |
| **Principal Id**: uint | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **SQL Server**: string | • Name of the SQL Server where this object is a principal |

### Application Role (`MSSQL_ApplicationRole` node)
A type of database principal that is not associated with a user but instead is activated by an application using a password so it can interact with the database using the role's permissions.

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Label**: string | • Format: `<name>@<databasename>`<br>• Example: `TESTAPPROLE@TESTDATABASE` |
| **Object ID**: string | • Format: `<name>@<database_object_id>`<br>• Example: `TESTAPPROLE@S-1-5-21-843997178-3776366836-1907643539-1108:1433\TESTDATABASE` |
| **Create Date**: datetime | • When the principal was created |
| **Database**: string | • Name of the database where this object is a principal |
| **Default Schema**: string | • The default schema used when the principal connects to the database |
| **Explicit Permissions**: List\<string\> | • Database level permissions assigned directly to this principal<br>• Does not include all effective permissions such as those granted through role membership |
| **Member of Roles**: List\<string\> | • Names of roles this principal is a direct member of<br>• Does not include nested memberships |
| **Modify Date**: datetime | • When the principal was last modified |
| **Principal Id**: uint | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **SQL Server**: string | • Name of the SQL Server where this object is a principal |


# MSSQL Edges Reference
This section includes explanations for edges that have their own unique properties. Please refer to the `$script:EdgePropertyGenerators` variable in `MSSQLHound.ps1` for the following details:
- Source and target node classes (all combinations)
- Requirements
- Default fixed roles with the permission
- Traversability
- Entity panel details (dynamically-generated)
    - General
    - Windows Abuse
    - Linux Abuse
    - OPSEC
    - References
    - Composition Cypher (where applicable)

## Edge Classes and Properties

### `MSSQL_ExecuteAsOwner`
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **Database**: string                          | • Name of the target database where the source can execute SQL statements as the server-level owning principal |
| **Database Is Trustworthy**: bool            | • **True**: Database principals that can execute `EXECUTE AS OWNER` statements can execute actions in the context of the server principal that owns the database<br>• **False**: The database isn't allowed to access resources beyond the scope of the database |
| **Owner Has Control Server**: bool           | • **True**: The server principal that owns the database has the `CONTROL SERVER` permission, allowing complete control of the MSSQL server instance. |
| **Owner Has Impersonate Any Login**: bool    | • **True**: The server principal that owns the database has the `IMPERSONATE ANY LOGIN` permission, allowing complete control of the MSSQL server instance. |
| **Owner Has Securityadmin**: bool            | • **True**: The server principal that owns the database is a member of the `securityadmin` server role, allowing complete control of the MSSQL server instance. |
| **Owner Has Sysadmin**: bool                 | • **True**: The server principal that owns the database is a member of the `sysadmin` server role, allowing complete control of the MSSQL server instance. |
| **Owner Login Name**: string                 | • The name of the server login that owns the database<br>• Example: `MAYYHEM\cthompson` |
| **Owner Object Identifier**: string          | • The object identifier of the server login that owns the database |
| **Owner Principal ID**: uint                 | • The identifier the SQL Server instance uses to associate permissions and other objects with this principal |
| **SQL Server**: string                       | • Name of the SQL Server where this object is a principal |

### `MSSQL_GetAdminTGS`
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **Domain Principals with ControlServer**: List<string> | • Domain principals with logins that have the `CONTROL SERVER` effective permission, allowing complete control of the MSSQL server instance. |
| **Domain Principals with ImpersonateAnyLogin**: List<string> | • Domain principals with logins that have the `IMPERSONATE ANY LOGIN` effective permission, allowing complete control of the MSSQL server instance. |
| **Domain Principals with Securityadmin**: List<string> | • Domain principals with membership in the `securityadmin` server role, allowing complete control of the MSSQL server instance. |
| **Domain Principals with Sysadmin**: List<string> | • Domain principals with membership in the `sysadmin` server role, allowing complete control of the MSSQL server instance. |

### `MSSQL_HasDBScopedCred`
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **Credential ID**: string                     | • The identifier the SQL Server instance uses to associate other objects with this principal |
| **Credential Identity**: string               | • The domain principal this credential uses to authenticate to resources |
| **Credential Name**: string                   | • The name used to identify this credential in the SQL Server instance |
| **Create Date**: datetime                     | • When the credential was created |
| **Database**: string                          | • Name of the database where this object is a credential |
| **Modify Date**: datetime                     | • When the credential was last modified |
| **Resolved SID**: string                      | • The domain SID for the credential identity |

### `MSSQL_HasMappedCred`
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **Credential ID**: uint                       | • The identifier the SQL Server instance uses to associate other objects with this principal |
| **Credential Identity**: string               | • The domain principal this credential uses to authenticate to resources |
| **Credential Name**: string                   | • The name used to identify this credential in the SQL Server instance |
| **Create Date**: datetime                     | • When the credential was created |
| **Modify Date**: datetime                     | • When the credential was last modified |
| **Resolved SID**: string                      | • The domain SID for the credential identity |

### `MSSQL_HasProxyCred`
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **Authorized Principals**: List<string>       | • Principals that are authorized to use this proxy credential |
| **Credential ID**: string                     | • The identifier the SQL Server instance uses to associate other objects with this principal |
| **Credential Identity**: string               | • The domain principal this credential uses to authenticate to resources |
| **Credential Name**: string                   | • The name used to identify this credential in the SQL Server instance |
| **Description**: string                       | • User-provided description of the proxy that uses this credential |
| **Is Enabled**: bool                          | • Is the proxy that uses this credential enabled? |
| **Proxy ID**: uint                            | • The identifier the SQL Server instance uses to associate other objects with this proxy |
| **Proxy Name**: string                        | • The name used to identify this proxy in the SQL Server instance |
| **Resolved SID**: string                      | • The domain SID for the credential identity |
| **Resolved Type**: string                     | • The class of domain principal for the credential identity |
| **Subsystems**: List<string>                  | • Subsystems this proxy is configured with (e.g., `CmdExec`, `PowerShell`) |

### `MSSQL_LinkedAsAdmin`
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **Data Access**: bool                         | • **True (enabled)**:<br>&nbsp;&nbsp;&nbsp;&nbsp;• The linked server can be used in distributed queries<br>&nbsp;&nbsp;&nbsp;&nbsp;• You can `SELECT`, `INSERT`, `UPDATE`, `DELETE` data through the linked server<br>&nbsp;&nbsp;&nbsp;&nbsp;• Four-part naming queries work: `[LinkedServer].[Database].[Schema].[Table]`<br>&nbsp;&nbsp;&nbsp;&nbsp;• `OPENQUERY()` statements work against this linked server<br>• **False (disabled)**:<br>&nbsp;&nbsp;&nbsp;&nbsp;• The linked server connection still exists but cannot be used for data queries<br>&nbsp;&nbsp;&nbsp;&nbsp;• Attempts to query through it will fail with an error<br>&nbsp;&nbsp;• The linked server can still be used for other purposes like RPC calls (if RPC is enabled) |
| **Data Source**: string                       | • Format: `<linked_server_hostname>[\instancename]`<br>• Examples: `SITE-DB` or `CAS-PSS\CAS` |
| **Local Login**: List<string>                 | • The login(s) on the source that can use the link and connect to the linked server using the Remote Login |
| **Path**: string                              | • The link used to collect the information needed to create this edge |
| **Product**: string                           | • A user-defined name of the product used by the remote server<br>• Examples: `SQL Server`, `Oracle`, `Access` |
| **Provider**: string                          | • The driver or interface that SQL Server uses to communicate with the remote data source |
| **Remote Current Login**: string              | • Displays the login context that is actually used on the remote linked server based on the results of the `SELECT SYSTEM_USER` SQL statement on the remote linked server<br>• If impersonation is used, it is likely that this value will be the login used for collection<br>• If not, this should match Remote Login |
| **Remote Has Control Server**: bool           | • Does the login context on the remote server have the `CONTROL SERVER` permission? |
| **Remote Has Impersonate Any Login**: bool    | • Does the login context on the remote server have the `IMPERSONATE ANY LOGIN` permission? |
| **Remote Is Mixed Mode**: bool                | • Is mixed mode authentication (for both Windows and SQL logins) enabled on the remote server? |
| **Remote Is Securityadmin**: bool             | • Is the login context on the remote server a member of the `securityadmin` server role? |
| **Remote Is Sysadmin**: bool                  | • Is the login context on the remote server a member of the `sysadmin` server role? |
| **Remote Login**: string                      | • The SQL Server authentication login that exists on the remote server that connections over this link are mapped to<br>• The password for this login must be saved on the source server<br>• Will be null if impersonation is used, in which case the login context being used on the source server is used to connect to the remote linked server |
| **Remote Server Roles**: List<string>         | • Server roles the remote login context is a member of |
| **RPC Out**: bool                             | • Can the source server call stored procedures on remote server? |
| **Uses Impersonation**: bool                  | • Does the linked server attempt to use the current user's Windows credentials to authenticate to the remote server?<br>• For SQL Server authentication, a login with the exact same name and password must exist on the remote server.<br>• For Windows logins, the login must be a valid login on the linked server.<br>• This requires Kerberos delegation to be properly configured<br>• The user's actual Windows identity is passed through to the remote server |

### Remaining Edges
| Edge Class<br>______________________________________________ | Properties<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
| **`CoerceAndRelayToMSSQL`**                     | • No unique edge properties |
| **`MSSQL_AddMember`**                           | • No unique edge properties |
| **`MSSQL_Alter`**                               | • No unique edge properties |
| **`MSSQL_AlterAnyAppRole`**                     | • No unique edge properties |
| **`MSSQL_AlterAnyDBRole`**                      | • No unique edge properties |
| **`MSSQL_AlterAnyLogin`**                       | • No unique edge properties |
| **`MSSQL_AlterAnyServerRole`**                  | • No unique edge properties |
| **`MSSQL_ChangeOwner`**                         | • No unique edge properties |
| **`MSSQL_ChangePassword`**                      | • No unique edge properties |
| **`MSSQL_Connect`**                             | • No unique edge properties |
| **`MSSQL_ConnectAnyDatabase`**                  | • No unique edge properties |
| **`MSSQL_Contains`**                            | • No unique edge properties |
| **`MSSQL_Control`**                             | • No unique edge properties |
| **`MSSQL_ControlDB`**                           | • No unique edge properties |
| **`MSSQL_ControlServer`**                       | • No unique edge properties |
| **`MSSQL_ExecuteAs`**                           | • No unique edge properties |
| **`MSSQL_ExecuteOnHost`**                       | • No unique edge properties |
| **`MSSQL_GetTGS`**                              | • No unique edge properties |
| **`MSSQL_GrantAnyDBPermission`**                | • No unique edge properties |
| **`MSSQL_GrantAnyPermission`**                  | • No unique edge properties |
| **`MSSQL_HasLogin`**                            | • No unique edge properties |
| **`MSSQL_HostFor`**                             | • No unique edge properties |
| **`MSSQL_Impersonate`**                         | • No unique edge properties |
| **`MSSQL_ImpersonateAnyLogin`**                 | • No unique edge properties |
| **`MSSQL_IsMappedTo`**                          | • No unique edge properties |
| **`MSSQL_IsTrustedBy`**                         | • No unique edge properties |
| **`MSSQL_LinkedTo`**                            | • Edge properties are the same as `MSSQL_LinkedAsAdmin` |
| **`MSSQL_MemberOf`**                            | • No unique edge properties |
| **`MSSQL_Owns`**                                | • No unique edge properties |
| **`MSSQL_ServiceAccountFor`**                   | • No unique edge properties |
| **`MSSQL_TakeOwnership`**                       | • No unique edge properties |
