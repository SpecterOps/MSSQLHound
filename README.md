# MSSQLHound
<img width="3147" height="711" alt="image" src="https://github.com/user-attachments/assets/476babac-c265-4d2b-bc03-f893fdb7bc1f" />

A collector for adding MSSQL attack paths to [BloodHound](https://github.com/SpecterOps/BloodHound) with [OpenGraph](https://specterops.io/opengraph) by Chris Thompson at [SpecterOps](https://x.com/SpecterOps). Available as both a PowerShell script and a cross-platform Go binary (with concurrent collection, SOCKS5 proxy support, and streaming output).

Introductory blog posts:
- https://specterops.io/blog/2025/08/04/adding-mssql-to-bloodhound-with-opengraph/
- https://specterops.io/blog/2026/01/20/updates-to-the-mssqlhound-opengraph-collector-for-bloodhound/

Please hit me up on the [BloodHound Slack](http://ghst.ly/BHSlack) (@Mayyhem), Twitter ([@_Mayyhem](https://x.com/_Mayyhem)), or open an issue if you have any questions I can help with!

# Table of Contents

- [Overview](#overview)
  - [System Requirements](#system-requirements)
  - [Minimum Permissions](#minimum-permissions)
  - [Recommended Permissions](#recommended-permissions)
- [OPSEC](#opsec)
  - [Network Connections](#network-connections)
  - [Authentication Events](#authentication-events)
  - [Subprocesses Executed](#subprocesses-executed)
  - [SQL Queries Executed on Targets](#sql-queries-executed-on-targets)
  - [Files Created](#files-created)
- [Go Version](#go-version)
  - [Why a Go Port?](#why-a-go-port)
  - [Building](#building)
  - [Go Usage](#go-usage)
    - [Basic Usage](#basic-usage)
    - [Multiple Servers](#multiple-servers)
    - [Full Domain Enumeration](#full-domain-enumeration)
    - [DNS and Domain Controller Configuration](#dns-and-domain-controller-configuration)
    - [SOCKS5 Proxy Support](#socks5-proxy-support)
    - [Credential Fallback](#credential-fallback)
    - [Kerberos Authentication](#kerberos-authentication)
    - [Pass-the-Hash](#pass-the-hash)
    - [Domain Enum Only (Reconnaissance)](#domain-enum-only-reconnaissance)
    - [Output and Storage Options](#output-and-storage-options)
    - [BloodHound Upload](#bloodhound-upload)
    - [Interesting Edge Options](#interesting-edge-options)
    - [Linked Server Options](#linked-server-options)
    - [test-epa-matrix Subcommand](#test-epa-matrix-subcommand)
    - [Shell Completion](#shell-completion)
  - [Go Command Line Options](#go-command-line-options)
  - [Key Differences from PowerShell Version](#key-differences-from-powershell-version)
  - [CVE Detection](#cve-detection)
  - [Known Limitations and Issues (Go)](#known-limitations-and-issues-go)
  - [Troubleshooting (Go)](#troubleshooting-go)
- [PowerShell Usage](#powershell-usage)
- [PowerShell Command Line Options](#powershell-command-line-options)
- [Limitations](#limitations)
- [Future Development](#future-development)
- [Credits](#credits)
- [MSSQL Graph Model](#mssql-graph-model)
- [MSSQL Nodes Reference](#mssql-nodes-reference)
   - [Server Level](#server-level)
     - [`MSSQL_Server`](#server-instance-mssql_server-node)
     - [`MSSQL_Login`](#server-login-mssql_login-node)
     - [`MSSQL_ServerRole`](#server-role-mssql_serverrole-node)
   - [Database Level](#database-level)
     - [`MSSQL_Database`](#database-mssql_database-node)
     - [`MSSQL_DatabaseUser`](#database-user-mssql_databaseuser-node)
     - [`MSSQL_DatabaseRole`](#database-role-mssql_databaserole-node)
     - [`MSSQL_ApplicationRole`](#application-role-mssql_applicationrole-node)
- [MSSQL Edges Reference](#mssql-edges-reference)
   - [Edge Classes and Properties](#edge-classes-and-properties)
     - [`CoerceAndRelayToMSSQL`](#coerceandrelaytomssql)
     - [`MSSQL_AddMember`](#mssql_addmember)
     - [`MSSQL_Alter`](#mssql_alter)
     - [`MSSQL_AlterAnyAppRole`](#mssql_alteranyapprole)
     - [`MSSQL_AlterAnyDBRole`](#mssql_alteranydbrole)
     - [`MSSQL_AlterAnyLogin`](#mssql_alteranylogin)
     - [`MSSQL_AlterAnyServerRole`](#mssql_alteranyserverrole)
     - [`MSSQL_ChangeOwner`](#mssql_changeowner)
     - [`MSSQL_ChangePassword`](#mssql_changepassword)
     - [`MSSQL_Connect`](#mssql_connect)
     - [`MSSQL_ConnectAnyDatabase`](#mssql_connectanydatabase)
     - [`MSSQL_Contains`](#mssql_contains)
     - [`MSSQL_Control`](#mssql_control)
     - [`MSSQL_ControlDB`](#mssql_controldb)
     - [`MSSQL_ControlServer`](#mssql_controlserver)
     - [`MSSQL_ExecuteAs`](#mssql_executeas)
     - [`MSSQL_ExecuteAsOwner`](#mssql_executeasowner)
     - [`MSSQL_ExecuteOnHost`](#mssql_executeonhost)
     - [`MSSQL_GetAdminTGS`](#mssql_getadmintgs)
     - [`MSSQL_GetTGS`](#mssql_gettgs)
     - [`MSSQL_GrantAnyDBPermission`](#mssql_grantanydbpermission)
     - [`MSSQL_GrantAnyPermission`](#mssql_grantanypermission)
     - [`MSSQL_HasDBScopedCred`](#mssql_hasdbscopedcred)
     - [`MSSQL_HasLogin`](#mssql_haslogin)
     - [`MSSQL_HasMappedCred`](#mssql_hasmappedcred)
     - [`MSSQL_HasProxyCred`](#mssql_hasproxycred)
     - [`MSSQL_HostFor`](#mssql_hostfor)
     - [`MSSQL_Impersonate`](#mssql_impersonate)
     - [`MSSQL_ImpersonateAnyLogin`](#mssql_impersonateanylogin)
     - [`MSSQL_IsMappedTo`](#mssql_ismappedto)
     - [`MSSQL_IsTrustedBy`](#mssql_istrustedby)
     - [`MSSQL_LinkedAsAdmin`](#mssql_linkedasadmin)
     - [`MSSQL_LinkedTo`](#mssql_linkedto)
     - [`MSSQL_MemberOf`](#mssql_memberof)
     - [`MSSQL_Owns`](#mssql_owns)
     - [`MSSQL_ServiceAccountFor`](#mssql_serviceaccountfor)
     - [`MSSQL_TakeOwnership`](#mssql_takeownership)

# Overview
Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual temporary files, then zips them in the current directory
  - Example: `mssql-bloodhound-20250724-115610.zip`
      
## System Requirements:
  - PowerShell 4.0 or higher
  - Target is running SQL Server 2005 or higher
  - BloodHound v8.0.0+ with Postgres backend (to use prebuilt Cypher queries): https://bloodhound.specterops.io/get-started/custom-installation#postgresql
  - **For Kerberos authentication (`-k`):** `krb5-user` package on Linux (`sudo apt install krb5-user`)

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

# OPSEC

This section documents every network connection, authentication event, subprocess, query, and file artifact produced by MSSQLHound so operators can make informed decisions about detection risk.

## Network Connections

All TCP connections support SOCKS5 proxy tunneling (`--proxy`). TLS connections use `InsecureSkipVerify=true` and cap at TLS 1.2.

| Protocol | Port | Transport | Target | Purpose | Conditions |
|----------|------|-----------|--------|---------|------------|
| TDS (SQL Server) | 1433/tcp (default, configurable) | TCP with optional TLS | Each SQL Server being enumerated | SQL authentication and query execution | Always (core functionality) |
| SQL Browser | 1434/udp | UDP | SQL Server host | Named instance port resolution | Only for named instances without an explicit port. **Not proxied through SOCKS5.** |
| LDAPS | 636/tcp | TLS | Domain controller | SPN enumeration, principal/SID resolution, computer enumeration | First LDAP method attempted |
| LDAP + StartTLS | 389/tcp | TCP upgraded to TLS | Domain controller | Same as LDAPS | Fallback if LDAPS fails |
| Plain LDAP | 389/tcp | TCP (unencrypted) | Domain controller | Same as LDAPS | Final LDAP fallback |
| DNS | 53/udp | UDP | `--dns-resolver` or `--dc` | SRV records (`_ldap._tcp.<domain>`), A records, reverse DNS (PTR) | When domain resolution is needed |
| WinRM | 5985/tcp (HTTP) or 5986/tcp (HTTPS) | HTTP/HTTPS | SQL Server host | Remote PowerShell for EPA configuration | **Only `test-epa-matrix` subcommand** |
| WMI/DCOM | 135/tcp + dynamic RPC | TCP | SQL Server host | Enumerate local group members (`Win32_GroupUser`) | **Windows only.** Fails gracefully on other platforms. |

### TDS Encryption Modes

| Mode | Description |
|------|-------------|
| TDS 8.0 (strict) | Full TLS before any TDS traffic. Uses ALPN `tds/8.0`. |
| TLS-in-TDS | TLS negotiated inside the TDS PRELOGIN handshake. |
| Force Encryption | Server-mandated encryption after PRELOGIN exchange. |

### LDAP Queries Issued

| Filter | Purpose |
|--------|---------|
| `(servicePrincipalName=MSSQLSvc/*)` | Find all MSSQL SPNs in the domain |
| `(servicePrincipalName=MSSQLSvc/<host>*)` (short + FQDN) | Look up SPNs for a specific server |
| `(&(objectCategory=computer)(objectClass=computer))` | Enumerate all domain computers (`--scan-all-computers`) |
| `(objectSid=<sid>)` | Resolve a SID to an AD principal |
| `(sAMAccountName=<name>)` | Resolve an account name to an AD principal |
| `(&(objectClass=computer)(sAMAccountName=<name>$))` | Resolve a computer account by name |

All LDAP searches use subtree scope with 1000-result paging.

## Authentication Events

Each authentication below generates log entries on the target system.

| Event | Target | Method | Details | Conditions |
|-------|--------|--------|---------|------------|
| SQL Server login | SQL Server | SQL auth (username/password in TDS LOGIN7) | Logged as a login event in SQL Server audit logs | When `-u`/`-p` supplied |
| SQL Server login | SQL Server | Windows auth (NTLM SSPI in TDS LOGIN7: Negotiate → Challenge → Authenticate) | Includes Channel Binding Token (CBT) when TLS is active. Logged as a login event in SQL Server audit logs. | When using domain credentials |
| LDAP bind | Domain controller | GSSAPI/SSPI (Kerberos) | Uses current user's Windows security context | Windows only, when no explicit LDAP credentials |
| LDAP bind | Domain controller | NTLM or Simple bind (UPN, DN, or DOMAIN\user) | Logged as an authentication event on the DC | When `--ldap-user`/`--ldap-password` supplied or SQL credentials reused |
| WinRM login | SQL Server host | NTLM or Basic auth | Logged as a Windows authentication event | **Only `test-epa-matrix` subcommand** |
| WMI/DCOM login | SQL Server host | Current user's Windows credentials | Logged as a DCOM authentication event | **Windows only**, during local group enumeration |

## Subprocesses Executed

MSSQLHound spawns local `powershell.exe` processes as fallbacks when native Go clients fail. All subprocesses run on the **operator's machine**, not on targets (except WinRM remote execution).

| Executable | Arguments | Purpose | Conditions |
|------------|-----------|---------|------------|
| `powershell.exe` | `-NoProfile -NonInteractive -Command <script>` | SQL query execution via `System.Data.SqlClient` | Windows only. Fallback when Go TDS driver fails with "untrusted domain" error. **Not used when `--proxy` is set.** |
| `powershell.exe` | `-NoProfile -NonInteractive -Command <script>` | SPN enumeration via `[adsisearcher]` (ADSI) | Windows only. Fallback when Go LDAP client fails. |
| `powershell.exe` | `-NoProfile -NonInteractive -Command <script>` | Domain computer enumeration via `[adsisearcher]` (ADSI) | Windows only. Fallback when Go LDAP client fails. |
| `powershell.exe` | `-NoProfile -NonInteractive -Command <script>` | SPN lookup by hostname via `[adsisearcher]` (ADSI) | Windows only. Fallback when Go LDAP client fails. |
| `powershell.exe` | `-NoProfile -NonInteractive -EncodedCommand <base64>` | Remote PowerShell via WinRM: EPA registry configuration and SQL service restart on target host | **Only `test-epa-matrix` subcommand.** Executes on the remote target via WinRM. |

## SQL Queries Executed on Targets

All queries are **read-only**. No data is written to any target server.

### Server Metadata

| Query | Purpose |
|-------|---------|
| `SELECT SERVERPROPERTY('ServerName'), SERVERPROPERTY('MachineName'), SERVERPROPERTY('InstanceName'), SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('Edition'), ...` | Server name, version, edition |
| `SELECT @@VERSION` | Full version string |
| `SERVERPROPERTY('IsIntegratedSecurityOnly')` | Authentication mode (Windows-only vs mixed) |

### Server Principals and Permissions

| Query | Purpose |
|-------|---------|
| `SELECT ... FROM sys.server_principals` | Enumerate logins and server roles |
| `SELECT ... FROM sys.server_role_members JOIN sys.server_principals` | Map server role membership |
| `SELECT ... FROM sys.server_permissions` | Enumerate server-level permissions (GRANT, DENY) |

### Databases

| Query | Purpose |
|-------|---------|
| `SELECT ... FROM sys.databases` | List databases with owner SID, trustworthy flag, state |

### Database Principals and Permissions (per database)

| Query | Purpose |
|-------|---------|
| `SELECT ... FROM [db].sys.database_principals` | Enumerate users and roles per database |
| `SELECT ... FROM [db].sys.database_role_members` | Map database role membership |
| `SELECT ... FROM [db].sys.database_permissions` | Enumerate database-level permissions |

### Service Accounts

| Query | Purpose |
|-------|---------|
| `SELECT ... FROM sys.dm_server_services` | Discover SQL Server service accounts (SQL 2008 R2+) |
| `EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SYSTEM\CurrentControlSet\Services\...', N'ObjectName'` | Fallback: read service account from registry |

### Encryption and EPA Settings

| Query | Purpose |
|-------|---------|
| `EXEC master.dbo.xp_instance_regread ... 'SuperSocketNetLib', 'ForceEncryption'` | Check Force Encryption setting |
| `EXEC master.dbo.xp_instance_regread ... 'SuperSocketNetLib', 'ExtendedProtection'` | Check Extended Protection (EPA) setting |

### Credentials and Proxies

| Query | Purpose |
|-------|---------|
| `SELECT ... FROM sys.credentials` | Enumerate server-level credentials |
| `SELECT ... FROM [db].sys.database_scoped_credentials` | Enumerate database-scoped credentials |
| `SELECT ... FROM sys.server_principal_credentials` | Map login-to-credential relationships |
| `SELECT ... FROM msdb.dbo.sysproxies` | Enumerate SQL Agent proxy accounts |
| `SELECT ... FROM msdb.dbo.sysproxylogin` | Map proxy-to-login authorization |
| `SELECT ... FROM msdb.dbo.sysproxysubsystem` | Map proxy-to-subsystem relationships |

### Linked Servers

| Query | Purpose |
|-------|---------|
| `SELECT ... FROM sys.servers JOIN sys.linked_logins` | Enumerate linked servers and login mappings |
| `SELECT ... FROM OPENQUERY([LinkedServer], '...')` | Recursive linked server traversal (up to 10 levels deep) |

## Files Created

**No files are written to any target server.** All artifacts are created on the operator's machine.

### Directory Structure

```
{system temp or --temp-dir}/
  mssql-bloodhound-YYYYMMDD-HHMMSS/
    mssql-{hostname}.json                    Per-server BloodHound data (default port/instance)
    mssql-{hostname}_{port}.json             Non-default port
    mssql-{hostname}_{port}_{instance}.json  Named instance
    mssql-{hostname}.log                     Per-server log (only if per-target logging enabled)
    computers.json                           AD computer nodes (unless --skip-ad-nodes)
    users.json                               AD user nodes (unless --skip-ad-nodes)
    groups.json                              AD group nodes (unless --skip-ad-nodes)

{current directory or --zip-dir}/
  mssql-bloodhound-YYYYMMDD-HHMMSS.zip      Final output (contains all JSON files above)
  mssql-logs-YYYYMMDD-HHMMSS.zip            Log archive (only if per-target logging enabled)
```

### Naming Conventions

| Component | Rule |
|-----------|------|
| Default port (1433) | Omitted from filename |
| Default instance (`MSSQLSERVER`) | Omitted from filename |
| Separator | Underscore (`_`) between hostname, port, instance |
| Special characters | `\ / : * ? " < > \|` replaced with `_` |

### Cleanup

The temporary directory is removed after the zip file is created. The only persistent artifacts are the zip file(s) in `--zip-dir` (default: current directory).

# Go Version

## Why a Go Port?

The original MSSQLHound PowerShell script is an excellent tool for SQL Server security analysis, but has some limitations that motivated this Go port:

### Evasion
- **Proxying**: PowerShell execution is easily detected. The Go version allows network traffic to be sent into the target environment through a SOCKS proxy to maintain stealth during offensive operations.

### Performance
- **Concurrent Processing**: The Go version processes multiple SQL servers simultaneously using worker pools, significantly reducing total enumeration time in large environments
- **Streaming Output**: Memory-efficient JSON streaming prevents memory exhaustion when collecting from servers with thousands of principals
- **Compiled Binary**: No PowerShell interpreter overhead, faster startup and execution

### Portability
- **Cross-Platform**: Runs on Windows, Linux, and macOS (Windows authentication requires Windows)
- **Single Binary**: No dependencies, easy to deploy and run
- **No PowerShell Required**: Can run on systems without PowerShell installed

### Compatibility
- **PowerShell Fallback**: When the native Go SQL driver fails (e.g., certain SSPI configurations), automatically falls back to PowerShell's `System.Data.SqlClient` for maximum compatibility
- **Full Feature Parity**: Produces identical BloodHound-compatible output

### Maintainability
- **Strongly Typed**: Go's type system catches errors at compile time
- **Unit Testable**: Comprehensive test coverage for edge generation logic
- **Modular Architecture**: Clean separation between collection, graph generation, and output

## Features

- **SQL Server Collection**: Enumerates server principals (logins, server roles), databases, database principals (users, roles), permissions, and role memberships
- **Linked Server Discovery**: Maps SQL Server linked server relationships
- **Active Directory Integration**: Resolves Windows logins to domain principals via LDAP
- **BloodHound Output**: Produces OpenGraph JSON format compatible with BloodHound CE
- **Streaming Output**: Memory-efficient streaming JSON writer for large environments
- **Automatic Fallback**: Falls back to PowerShell for servers with SSPI issues
- **LDAP Paging**: Handles large domains with thousands of computers/SPNs

## Building

```bash
go build -o mssqlhound.exe ./cmd/mssqlhound
```

## Go Usage

### Basic Usage

Collect from a single SQL Server:
```bash
# Windows integrated authentication
./mssqlhound -t sql.contoso.com

# SQL authentication
./mssqlhound -t sql.contoso.com -u sa -p password

# Inline credentials (equivalent to the above)
./mssqlhound -t 'sa:password@sql.contoso.com'

# Named instance
./mssqlhound -t 'sql.contoso.com\INSTANCE'

# Custom port
./mssqlhound -t 'sql.contoso.com:1434'

# Inline credentials with named instance
./mssqlhound -t 'sa:password@sql.contoso.com\INSTANCE'

# Inline credentials with SPN format
./mssqlhound -t 'CONTOSO\admin:password@MSSQLSvc/sql.contoso.com:1433'
```

### Multiple Servers

```bash
# Comma-separated list
./mssqlhound -t 'server1,server2,server3' -u sa -p password

# Comma-separated with inline credentials
./mssqlhound -t 'sa:password@server1,sa:password@server2,sa:password@server3'

# From file (one server per line, supports user:pass@host per line)
./mssqlhound -t servers.txt

# With concurrent workers
./mssqlhound -t servers.txt -w 20
```

### Full Domain Enumeration

```bash
# Scan all computers in the domain (not just those with SQL SPNs)
./mssqlhound --scan-all-computers

# With explicit LDAP credentials (recommended for large domains)
./mssqlhound --scan-all-computers --ldap-user "DOMAIN\username" --ldap-password "password"

# Specifying domain controller IP (also used as DNS resolver)
./mssqlhound --scan-all-computers --dc 10.0.0.1 --ldap-user "DOMAIN\username" --ldap-password "password"
```

### DNS and Domain Controller Configuration

```bash
# Use a specific DNS resolver for domain lookups
./mssqlhound --scan-all-computers --dns-resolver 10.0.0.1

# Specify DC IP (automatically used as DNS resolver if --dns-resolver is not set)
./mssqlhound --scan-all-computers --dc 10.0.0.1

# Use separate DNS resolver and DC
./mssqlhound --scan-all-computers --dc 10.0.0.1 --dns-resolver 10.0.0.2
```

### SOCKS5 Proxy Support

All network traffic (SQL connections, LDAP queries, EPA tests) can be tunneled through a SOCKS5 proxy:

```bash
# Basic SOCKS5 proxy
./mssqlhound -t sql.contoso.com --proxy 127.0.0.1:1080

# With proxy authentication
./mssqlhound -t sql.contoso.com --proxy "socks5://user:pass@127.0.0.1:1080"

# Combined with domain enumeration
./mssqlhound --scan-all-computers --proxy 127.0.0.1:1080 --dc 10.0.0.1
```

**Note:** SQL Browser (UDP) resolution is not supported through SOCKS5 proxies. Named instances must include explicit ports (e.g., `sql.contoso.com\INSTANCE:1433`).

### Credential Fallback

When `--ldap-user` and `--ldap-password` are not specified, the tool automatically reuses SQL credentials for LDAP authentication if the `--user` value contains a domain delimiter (`\` or `@`):

```bash
# These domain credentials are used for both SQL and LDAP
./mssqlhound --scan-all-computers -u "DOMAIN\admin" -p "password"
```

### Kerberos Authentication

```bash
# Use ccache from KRB5CCNAME env var
./mssqlhound -t sql.contoso.com -k

# Explicit ccache file
./mssqlhound -t sql.contoso.com -k --krb5-credcachefile /tmp/krb5cc_1000

# Use a keytab file
./mssqlhound -t sql.contoso.com -k \
  --user "CONTOSO\svc_mssqlhound" \
  --krb5-keytabfile /etc/mssqlhound.keytab \
  --krb5-realm CONTOSO.COM

# Custom krb5.conf
./mssqlhound -t sql.contoso.com -k --krb5-configfile /etc/krb5_custom.conf
```

### Pass-the-Hash

```bash
# Authenticate with an NT hash instead of a plaintext password
./mssqlhound -t sql.contoso.com -u "CONTOSO\admin" --nt-hash aad3b435b51404eeaad3b435b51404ee

# Combined with domain enumeration
./mssqlhound --scan-all-computers --dc 10.0.0.1 \
  -u "CONTOSO\admin" --nt-hash aad3b435b51404eeaad3b435b51404ee
```

### Domain Enum Only (Reconnaissance)

```bash
# List SQL servers discovered via SPNs without connecting to them
./mssqlhound --domain-enum-only --dc 10.0.0.1 \
  --ldap-user "CONTOSO\user" --ldap-password "password"

# List all domain computers (not just SPN holders)
./mssqlhound --domain-enum-only --scan-all-computers --dc 10.0.0.1
```

### Output and Storage Options

```bash
# Save zip file to a specific directory
./mssqlhound -t sql.contoso.com --zip-dir /data/collections/

# Use a custom temporary directory for intermediate files
./mssqlhound -t servers.txt --temp-dir /tmp/mssqlhound

# Stop collecting after 500MB of data
./mssqlhound -t servers.txt --file-size-limit 500MB

# Save per-target log files in a separate zip archive (useful for debugging)
./mssqlhound -t servers.txt --log-per-target
```

### BloodHound Upload

```bash
# Shorthand: collect and upload schema + results in one shot
./mssqlhound -t 'sa:password@sql.contoso.com' \
  -B '<token-id>:<token-key>@https://bloodhound.contoso.com'

# Shorthand with inline target credentials and domain enumeration
./mssqlhound -t 'CONTOSO\admin:password@sql.contoso.com' -d contoso.com \
  -B '<token-id>:<token-key>@https://bloodhound.contoso.com'

# Via environment variables
export BLOODHOUND_URL=https://bloodhound.contoso.com
export BLOODHOUND_TOKEN_ID=<token-id>
export BLOODHOUND_TOKEN_KEY=<token-key>
./mssqlhound -t sql.contoso.com -u sa -p password --upload-results

# Explicit long flags
./mssqlhound -t sql.contoso.com -u sa -p password \
  --bloodhound-url https://bloodhound.contoso.com \
  --token-id <id> --token-key <key> \
  --upload-results

# Upload the MSSQL schema once to register edge/node types in BloodHound
./mssqlhound \
  --bloodhound-url https://bloodhound.contoso.com \
  --token-id <id> --token-key <key> \
  --upload-schema
```

### Interesting Edge Options

```bash
# Include non-traversable edges (shows all permission paths, not just attack paths)
./mssqlhound -t sql.contoso.com --include-nontraversable

# Make interesting edges traversable (more aggressive pathfinding, may have false positives)
./mssqlhound -t sql.contoso.com --make-interesting-traversable

# Skip AD node creation (collect only MSSQL nodes, no User/Group/Computer nodes)
./mssqlhound -t sql.contoso.com --skip-ad-nodes
```

### Linked Server Options

```bash
# Skip linked server enumeration (faster, less noisy)
./mssqlhound -t sql.contoso.com --skip-linked-servers

# Perform full collection on each discovered linked server
./mssqlhound -t sql.contoso.com --collect-from-linked

# Reduce linked server timeout from the default 300s
./mssqlhound -t sql.contoso.com --linked-timeout 60
```

### test-epa-matrix Subcommand

Tests all combinations of Force Encryption, Force Strict Encryption, and Extended Protection by modifying registry settings via WinRM and restarting the SQL Server service. Requires WinRM access and domain credentials.

```bash
# Test all EPA setting combinations (12 combinations for SQL Server 2022+)
./mssqlhound test-epa-matrix -t sql.contoso.com -u "CONTOSO\admin" -p "password"

# Named instance, skip strict encryption combos (for pre-SQL Server 2022)
./mssqlhound test-epa-matrix -t "sql.contoso.com\INST" \
  --sql-instance-name INST --skip-strict \
  -u "CONTOSO\admin" -p "password"

# Use HTTPS for WinRM
./mssqlhound test-epa-matrix -t sql.contoso.com --winrm-https \
  -u "CONTOSO\admin" -p "password"
```

### Shell Completion

```bash
# Bash
source <(mssqlhound completion bash)

# Zsh
source <(mssqlhound completion zsh)

# Fish
mssqlhound completion fish | source

# PowerShell
mssqlhound completion powershell | Out-String | Invoke-Expression
```

## Go Command Line Options

### Authentication

| Flag | Description |
|------|-------------|
| `-t, --targets` | SQL Server targets: `[user:pass@]host`, `host:port`, `host\instance`, `MSSQLSvc/host:port`, comma-separated list, or file path (default: enumerate domain MSSQLSvc SPNs) |
| `-u, --user` | SQL login username |
| `-p, --password` | SQL login password |
| `--nt-hash` | NT hash (32 hex chars) for pass-the-hash authentication (mutually exclusive with `--password`) |
| `-k, --kerberos` | Use Kerberos authentication (reads ccache from `KRB5CCNAME` env var or `--krb5-credcachefile`) |
| `--krb5-configfile` | Path to `krb5.conf` (default: `/etc/krb5.conf` or `KRB5_CONFIG` env var) |
| `--krb5-credcachefile` | Path to Kerberos credential cache file (overrides `KRB5CCNAME` env var) |
| `--krb5-keytabfile` | Path to Kerberos keytab file |
| `--krb5-realm` | Kerberos realm (default: derived from domain or `krb5.conf`) |

### Domain / LDAP

| Flag | Description |
|------|-------------|
| `-d, --domain` | Domain to use for name and SID resolution |
| `--dc` | Domain controller hostname or IP (auto-resolved from `--domain` if omitted; used for LDAP and as DNS resolver if `--dns-resolver` not specified) |
| `--dns-resolver` | DNS resolver IP address for domain lookups |
| `--ldap-user` | LDAP user (`DOMAIN\user` or `user@domain`) for GSSAPI/Kerberos bind |
| `--ldap-password` | LDAP password for GSSAPI/Kerberos bind |

### Target Selection

| Flag | Description |
|------|-------------|
| `-t, --targets` | Targets (see Authentication above): single, comma-separated, or file path |
| `-A, --scan-all-computers` | Scan all domain computers, not just those with SQL SPNs |
| `--skip-private-address` | Skip private IP check when resolving domain computer addresses |

### Collection

| Flag | Default | Description |
|------|---------|-------------|
| `--domain-enum-only` | false | Only enumerate SPNs/computers, skip MSSQL collection |
| `--skip-linked-servers` | false | Don't enumerate linked servers |
| `--collect-from-linked` | false | Perform full collection on discovered linked servers |
| `--linked-timeout` | 300 | Linked server enumeration timeout (seconds) |
| `--skip-ad-nodes` | false | Skip creating `User`, `Group`, `Computer` nodes |
| `--include-nontraversable` | false | Include non-traversable edges |
| `--make-interesting-traversable` | true | Make interesting edges traversable |
| `-w, --workers` | 0 | Number of concurrent workers (0 = sequential processing) |

### Output / Storage

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output-format` | `BloodHound` | Output format: `BloodHound`, `BHGeneric` |
| `--temp-dir` | system temp | Temporary directory for output files |
| `--zip-dir` | `.` | Directory for the final zip file |
| `--file-size-limit` | `1GB` | Stop enumeration after output files exceed this size |
| `--log-per-target` | false | Save per-target log files in a separate zip archive |
| `--memory-threshold` | 90 | Stop when memory usage exceeds this percentage |
| `--size-update-interval` | 5 | Interval for file size updates (seconds) |

### BloodHound Upload

| Flag | Env Var | Description |
|------|---------|-------------|
| `-B, --bloodhound` | | Upload to BloodHound CE: `<token-id>:<token-key>@<bloodhound_url>` (uploads schema + results) |
| `--bloodhound-url` | `BLOODHOUND_URL` | BloodHound CE instance URL |
| `--token-id` | `BLOODHOUND_TOKEN_ID` | BloodHound API token ID |
| `--token-key` | `BLOODHOUND_TOKEN_KEY` | BloodHound API token key |
| `--upload-results` | | Upload collection results to BloodHound after collection |
| `--upload-schema` | | Upload schema definitions (`SCHEMA.json`) to BloodHound |

### Diagnostics

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Enable verbose output showing detailed collection progress |
| `--debug` | Enable debug output (includes EPA/TLS/NTLM diagnostics) |
| `--proxy` | SOCKS5 proxy address for tunneling all traffic (`host:port` or `socks5://[user:pass@]host:port`) |

## Key Differences from PowerShell Version

### Behavioral Differences

| Feature | PowerShell | Go |
|---------|------------|-----|
| **Concurrency** | Single-threaded | Multi-threaded with configurable worker pool |
| **Memory Usage** | Loads all data in memory | Streaming JSON output |
| **Cross-Platform** | Windows only | Windows, Linux, macOS |
| **SSPI Fallback** | N/A (native .NET) | Falls back to PowerShell for problematic servers |
| **LDAP Paging** | Automatic via .NET | Explicit paging implementation |
| **Duplicate Edges** | May emit duplicates | De-duplicates edges |

### Edge Generation Differences

#### `MSSQL_HasLogin` Edges

| Aspect | PowerShell | Go |
|--------|------------|-----|
| **Domain Validation** | Calls `Resolve-DomainPrincipal` to verify the SID exists in Active Directory | Creates edges for all domain SIDs (`S-1-5-21-*`) |
| **Orphaned Logins** | Skips logins where AD account no longer exists | Includes all logins regardless of AD status |
| **Edge Count** | Fewer edges (only verified AD accounts) | More edges (all domain-authenticated logins) |

**Why Go includes more edges**: For security analysis, orphaned SQL logins (where the AD account was deleted but the SQL login remains) still represent valid attack paths. An attacker who can restore or impersonate the deleted account's SID could still authenticate to SQL Server. The Go version captures these potential risks.

#### `HasSession` Edges

| Aspect | PowerShell | Go |
|--------|------------|-----|
| **Self-referencing** | Creates edge when computer runs SQL as itself (LocalSystem) | Skips self-referencing edges |

**Why Go skips self-loops**: A `HasSession` edge from a computer to itself (when SQL Server runs as LocalSystem/the computer account) doesn't provide meaningful attack path information.

#### `MSSQL_AddMember` Edges

| Aspect | PowerShell | Go |
|--------|------------|-----|
| **Duplicates** | May emit duplicate edges | De-duplicates all edges |

**Why Go has fewer edges**: The PowerShell version may emit the same AddMember edge multiple times in certain scenarios. Go ensures each unique edge is only emitted once.

### Connection Handling

The Go version includes automatic PowerShell fallback for servers that fail with the native `go-mssqldb` driver:

```
Native connection: go-mssqldb (fast, cross-platform)
        ↓ fails with "untrusted domain" error
Fallback: PowerShell + System.Data.SqlClient (Windows only, more compatible)
```

This ensures maximum compatibility while maintaining performance for the majority of servers.

### LDAP Connection Methods

The Go version tries multiple LDAP connection methods in order:

1. **LDAPS (port 636)** - TLS encrypted, most secure
2. **LDAP + StartTLS (port 389)** - Upgrade to TLS
3. **Plain LDAP (port 389)** - Unencrypted (may fail if DC requires signing)
4. **PowerShell/ADSI Fallback** - Windows COM-based fallback

## CVE Detection

The Go version includes detection for SQL Server vulnerabilities:

### CVE-2025-49758
Checks if the SQL Server version is vulnerable to CVE-2025-49758 and reports the status:
- `VULNERABLE` - Server is running an affected version
- `NOT vulnerable` - Server has been patched

## Known Limitations and Issues (Go)

### Windows Authentication on Non-Windows Platforms

Windows Integrated Authentication (SSPI/Kerberos) is only available when running on Windows. On Linux/macOS, use SQL authentication instead.

### GSSAPI/Kerberos Authentication Issues

The Go LDAP library's GSSAPI implementation may fail in certain environments with errors like:

```
LDAP Result Code 49 "Invalid Credentials": 80090346: LdapErr: DSID-0C0906CF,
comment: AcceptSecurityContext error, data 80090346
```

**Common causes:**
- Channel binding token (CBT) mismatch between client and server
- Kerberos ticket issues (expired, clock skew, wrong realm)
- Domain controller requires specific LDAP signing/sealing options

**Solutions:**

1. **Use explicit LDAP credentials** (recommended for `--scan-all-computers`):
   ```bash
   ./mssqlhound --scan-all-computers --ldap-user "DOMAIN\username" --ldap-password "password"
   ```

2. **Verify Kerberos tickets**:
   ```bash
   klist  # Check current tickets
   klist purge  # Clear and re-acquire tickets
   ```

3. **Check time synchronization** - Kerberos requires clocks within 5 minutes

### LDAP Size Limits

Active Directory has a default maximum result size of 1000 objects per query. The Go version implements LDAP paging to handle domains with more than 1000 computers or SPNs. If you see "Size Limit Exceeded" errors, ensure you're using the latest version.

### SQL Server SSPI Compatibility

Some SQL Server instances with specific SSPI configurations may fail to connect with the native Go driver.

**Symptom:**
```
Login failed. The login is from an untrusted domain and cannot be used with Windows authentication
```

**Automatic Handling:** The Go version detects this error and automatically retries using PowerShell's `System.Data.SqlClient`, which handles these edge cases more reliably. This fallback requires PowerShell to be available on the system.

### PowerShell Fallback Limitations

The PowerShell fallback for SQL connections and AD enumeration requires:
- Windows operating system
- PowerShell execution not blocked by security policy
- Access to `System.Data.SqlClient` (.NET Framework)

If PowerShell is blocked (e.g., `Access is denied` error), the fallback will not work. In this case:
- For SQL connections: Some servers may not be reachable
- For AD enumeration: Use explicit LDAP credentials instead

### When to Use LDAP Credentials

Use `--ldap-user` and `--ldap-password` when:

1. **Full domain computer enumeration** (`--scan-all-computers`) - GSSAPI often fails with the Go library due to CBT issues
2. **Cross-domain scenarios** - When enumerating from a machine in a different domain
3. **Service account execution** - When running as a service account that may have Kerberos delegation issues
4. **Troubleshooting GSSAPI failures** - As a workaround when implicit authentication fails

**Example:**
```bash
# Recommended for large domain enumeration
./mssqlhound --scan-all-computers \
  --ldap-user "DOMAIN\svc_mssqlhound" \
  --ldap-password "SecurePassword123" \
  -w 50
```

## Troubleshooting (Go)

### Verbose Output

Use `-v` or `--verbose` to see detailed connection attempts and errors:

```bash
./mssqlhound -t sql.contoso.com -u sa -p password -v
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `untrusted domain` | SSPI negotiation failed | Automatic PowerShell fallback; check domain trust |
| `Size Limit Exceeded` | Too many LDAP results | Update to latest version (has paging) |
| `80090346` | GSSAPI/Kerberos failure | Use explicit LDAP credentials |
| `Strong Auth Required` | DC requires LDAP signing | Will automatically try LDAPS/StartTLS |
| `Access is denied` (PowerShell) | Execution policy blocked | Use explicit LDAP credentials instead |

### Debug LDAP Connection

The verbose output shows which LDAP connection methods are attempted:

```
LDAPS:636 GSSAPI: <error>
LDAP:389+StartTLS GSSAPI: <error>
LDAP:389 GSSAPI: <error>
```

This helps identify whether the issue is TLS-related or authentication-related.

# PowerShell Usage
Run MSSQLHound from a box where you aren’t highly concerned about resource consumption. While there are guardrails in place to stop the script if resource consumption is too high, it’s probably a good idea to be careful and run it on a workstation instead of directly on a critical database server, just in case.

If you don't already have a specific target or targets in mind, start by running the script with the `-DomainEnumOnly` flag set to see just how many servers you’re dealing with in Active Directory. Then, use the `-ServerInstance` option to run it again for a single server or add all of the servers that look interesting to a file and run it again with the `-ServerListFile` option. 

If you don't do a dry run first and collect from all SQL servers with SPNs in the domain (the default action), expect the script to take a very long time to finish and eat up a ton of disk space if there ar a lot of servers in the environment. Based on limited testing in client environments, the file size for each server before they are all zipped ranges significantly from 2MB to 50MB+, depending on how many objects are on the server.

To populate the MSSQL node glyphs in BloodHound, execute `MSSQLHound.ps1 -OutputFormat BloodHound-customnodes` (or copy the following) and use the API Explorer page to submit the JSON to the `custom-nodes` endpoint.

```
{
  "custom_types": {
    "MSSQL_DatabaseUser": {
      "icon": {
        "name": "user",
        "color": "#f5ef42",
        "type": "font-awesome"
      }
    },
    "MSSQL_Login": {
      "icon": {
        "name": "user-gear",
        "color": "#dd42f5",
        "type": "font-awesome"
      }
    },
    "MSSQL_DatabaseRole": {
      "icon": {
        "name": "users",
        "color": "#f5a142",
        "type": "font-awesome"
      }
    },
    "MSSQL_Database": {
      "icon": {
        "name": "database",
        "color": "#f54242",
        "type": "font-awesome"
      }
    },
    "MSSQL_ApplicationRole": {
      "icon": {
        "name": "robot",
        "color": "#6ff542",
        "type": "font-awesome"
      }
    },
    "MSSQL_Server": {
      "icon": {
        "name": "server",
        "color": "#42b9f5",
        "type": "font-awesome"
      }
    },
    "MSSQL_ServerRole": {
      "icon": {
        "name": "users-gear",
        "color": "#6942f5",
        "type": "font-awesome"
      }
    }
  }
}
```

There are several new edges that have to be non-traversable because they are not abusable 100% of the time, including when:
- the stored AD credentials might be stale/invalid, but maybe they are!
    - MSSQL_HasMappedCred
    - MSSQL_HasDBScopedCred
    - MSSQL_HasProxyCred
- the server principal that owns the database does not have complete control of the server, but maybe it has other interesting permissions
    - MSSQL_IsTrustedBy
- the server is linked to another server using a principal that does not have complete control of the remote server, but maybe it has other interesting permissions
    - MSSQL_LinkedTo
- the service account can be used to impersonate domain users that have a login to the server, but we don’t have the necessary permissions to check that any domain users have logins
    - MSSQL_ServiceAccountFor
    - It would be unusual, but not impossible, for the MSSQL Server instance to run in the context of a domain service account and have no logins for domain users. If you can infer that certain domain users have access to a particular MSSQL Server instance or discover that information through other means (e.g., naming conventions, OSINT, organizational documentation, internal communications, etc.), you can request service tickets for those users to the MSSQL Server if you have control of the service account (e.g., by cracking weak passwords for Kerberoastable service principals).
      
Want to be a bit more aggressive with your pathfinding queries? You can make these edges traversable using the `-MakeInterestingEdgesTraversable` flag.

I also recommend conducting a collection with the `-IncludeNontraversableEdges` flag enabled at some point if you need to understand what permissions on which objects allow the traversable edges to be created. By default, non-traversable edges are skipped to make querying the data for valid attack paths easier. This is still a work in progress, but look out for the “Composition” item in the edge entity panel for each traversable edges to grab a pastable cypher query to identify the offending permissions.

If the [prebuilt Cypher queries](saved_queries) are returning `failed to translate kinds: unable to map kinds:` errors, upload [seed_data.json](internal/bloodhound/seed_data.json) to populate a single fake instance of each new edge class so they can be queried.

# PowerShell Command Line Options
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
| **-Credential** `<PSCredential>` | • Specify a PSCredential object to connect to the remote server(s) |
| **-UserID** `<string>` | • Specify a **login** to connect to the remote server(s) |
| **-SecureString** `<SecureString>` | • Specify a SecureString object for the login used to connect to the remote server(s) |
| **-Password** `<string>` | • Specify a **password** for the login used to connect to the remote server(s) |
| **-Domain** `<string>` | • Specify a **domain** to use for name and SID resolution |
| **-DomainController** `<string>` | • Specify a **domain controller** FQDN/IP to use for name and SID resolution |
| **-IncludeNontraversableEdges** (switch) | • **On**: • Collect both **traversable and non-traversable edges**<br>• **Off (default)**: Collect **only traversable edges** (good for offensive engagements until Pathfinding supports OpenGraph edges) |
| **-MakeInterestingEdgesTraversable** (switch) | • **On**: Make the following edges traversable (useful for offensive engagements but prone to false positive edges that may not be abusable):<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_HasDBScopedCred**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_HasMappedCred**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_HasProxyCred**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_IsTrustedBy**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_LinkedTo**<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_ServiceAccountFor**<br>• **Off (default)**: The edges above are non-traversable |
| **-SkipLinkedServerEnum** (switch) | • **On**: Don't enumerate linked servers<br>• **Off (default)**: Enumerate linked servers |
| **-CollectFromLinkedServers** (switch) | • **On**: If linked servers are found, try and perform a full MSSQL collection against each server<br>• **Off (default)**: If linked servers are found, **don't** try and perform a full MSSQL collection against each server |
| **-DomainEnumOnly** (switch) | • **On**: If SPNs are found, **don't** try and perform a full MSSQL collection against each server<br>• **Off (default)**: If SPNs are found, try and perform a full MSSQL collection against each server |
| **-InstallADModule** (switch) | • **On**: Try to install the ActiveDirectory module for PowerShell if it is not already installed<br>• **Off (default)**: Do not try to install the ActiveDirectory module for PowerShell if it is not already installed. Rely on DirectoryServices, ADSISearcher, DirectorySearcher, and NTAccount.Translate() for object resolution. |
| **-LinkedServerTimeout** `<uint>` | • Give up enumerating linked servers after `X` seconds<br>• Default: `300` seconds (5 minutes) |
| **-FileSizeLimit** `<string>` | • Stop enumeration after all collected files exceed this size on disk<br> • Supports MB, GB<br> • Default: `1GB` |
| **-FileSizeUpdateInterval** `<uint>` | • Receive periodic size updates as files are being written for each server<br>• Default: `5` seconds |
| **-Version** `<switch>` | • Display version information and exit |

# Limitations
- MSSQLHound can’t currently collect nodes and edges from linked servers over the link, although I’d like to add more linked server collection functionality in the future.
- MSSQLHound doesn’t check DENY permissions. Because permissions are denied by default unless explicitly granted, it is assumed that use of DENY permissions is rare. One exception is the CONNECT SQL permission, for which the DENY permission is checked to see if the principal can remotely log in to the MSSQL instance at all. 
- MSSQLHound stops enumerating at the database level. It could be modified to go deeper (to the table/stored procedure or even column level), but that would degrade performance, especially when merging with the AD graph.
- EPA enumeration without a login or Remote Registry access is not yet supported (but will be soon)
- Separate collections in domains that can’t reach each other for principal SID resolution may not merge correctly when they are ingested (i.e., more than one MSSQL_Server node may represent the same server, one labelled with the SID, one with the name).

# Future Development:
- Unprivileged EPA collection (in the works)
- Option to zip after every server (to save disk space)
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
 
# MSSQL Graph Model
<img width="4562" height="2356" alt="MSSQL Red Green (1)" src="https://github.com/user-attachments/assets/ddf897ef-6531-44e0-8911-73f5adc3dcdd" />

# MSSQL Nodes Reference
## Server Level
### Server Instance (`MSSQL_Server` node)
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/0dc2dc7a-9ae3-4c90-b44d-b3c5142a68e1" /><br>
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
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/6e98a0ed-e2d0-4da6-bcf6-fc4f4843b6c5" /><br>
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
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/3ddfe30c-32d4-485c-9f9c-e424bdc323a5" /><br>
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
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/2a1b0dfe-33ff-42e5-a70a-77f9d59a8a3a" /><br>
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
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/ce11f264-d19f-43a2-80ae-9d81e2a4a8bd" /><br>
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
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/620a59ee-85c1-4183-a1e5-37d3f8016e15" /><br>
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
<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/61a5db37-dbeb-49f8-834e-ba7100c4ca0f" /><br>
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
Please refer to the `$script:EdgePropertyGenerators` variable in `MSSQLHound.ps1` for the following details:
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
 
All edges based on permissions may contain the `With Grant` property, which means the source not only has the permission but can grant it to other principals.

| Edge Class<br>______________________________________________ | Properties<br>_______________________________________________________________________________________________ |
|-----------------------------------------------|------------|
<a id="coerceandrelaytomssql"></a>
| **`CoerceAndRelayToMSSQL`**                     | • No unique edge properties |
<a id="mssql_addmember"></a>
| **`MSSQL_AddMember`**                           | • No unique edge properties |
<a id="mssql_alter"></a>
| **`MSSQL_Alter`**                               | • No unique edge properties |
<a id="mssql_alteranyapprole"></a>
| **`MSSQL_AlterAnyAppRole`**                     | • No unique edge properties |
<a id="mssql_alteranydbrole"></a>
| **`MSSQL_AlterAnyDBRole`**                      | • No unique edge properties |
<a id="mssql_alteranylogin"></a>
| **`MSSQL_AlterAnyLogin`**                       | • No unique edge properties |
<a id="mssql_alteranyserverrole"></a>
| **`MSSQL_AlterAnyServerRole`**                  | • No unique edge properties |
<a id="mssql_changeowner"></a>
| **`MSSQL_ChangeOwner`**                         | • No unique edge properties |
<a id="mssql_changepassword"></a>
| **`MSSQL_ChangePassword`**                      | • No unique edge properties |
<a id="mssql_connect"></a>
| **`MSSQL_Connect`**                             | • No unique edge properties |
<a id="mssql_connectanydatabase"></a>
| **`MSSQL_ConnectAnyDatabase`**                  | • No unique edge properties |
<a id="mssql_contains"></a>
| **`MSSQL_Contains`**                            | • No unique edge properties |
<a id="mssql_control"></a>
| **`MSSQL_Control`**                             | • No unique edge properties |
<a id="mssql_controldb"></a>
| **`MSSQL_ControlDB`**                           | • No unique edge properties |
<a id="mssql_controlserver"></a>
| **`MSSQL_ControlServer`**                       | • No unique edge properties |
<a id="mssql_executeas"></a>
| **`MSSQL_ExecuteAs`**                           | • No unique edge properties |
<a id="mssql_executeonhost"></a>
| **`MSSQL_ExecuteOnHost`**                       | • No unique edge properties |
<a id="mssql_gettgs"></a>
| **`MSSQL_GetTGS`**                              | • No unique edge properties |
<a id="mssql_grantanydbpermission"></a>
| **`MSSQL_GrantAnyDBPermission`**                | • No unique edge properties |
<a id="mssql_grantanypermission"></a>
| **`MSSQL_GrantAnyPermission`**                  | • No unique edge properties |
<a id="mssql_haslogin"></a>
| **`MSSQL_HasLogin`**                            | • No unique edge properties |
<a id="mssql_hostfor"></a>
| **`MSSQL_HostFor`**                             | • No unique edge properties |
<a id="mssql_impersonate"></a>
| **`MSSQL_Impersonate`**                         | • No unique edge properties |
<a id="mssql_impersonateanylogin"></a>
| **`MSSQL_ImpersonateAnyLogin`**                 | • No unique edge properties |
<a id="mssql_ismappedto"></a>
| **`MSSQL_IsMappedTo`**                          | • No unique edge properties |
<a id="mssql_istrustedby"></a>
| **`MSSQL_IsTrustedBy`**                         | • No unique edge properties |
<a id="mssql_linkedto"></a>
| **`MSSQL_LinkedTo`**                            | • Edge properties are the same as `MSSQL_LinkedAsAdmin` |
<a id="mssql_memberof"></a>
| **`MSSQL_MemberOf`**                            | • No unique edge properties |
<a id="mssql_owns"></a>
| **`MSSQL_Owns`**                                | • No unique edge properties |
<a id="mssql_serviceaccountfor"></a>
| **`MSSQL_ServiceAccountFor`**                   | • No unique edge properties |
<a id="mssql_takeownership"></a>
| **`MSSQL_TakeOwnership`**                       | • No unique edge properties |

# Credits

- Original PowerShell version by Chris Thompson (@_Mayyhem) at SpecterOps
- Go port by Javier Azofra at Siemens Healthineers and Chris Thompson
