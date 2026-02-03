# MSSQLHound Go

A Go port of the [MSSQLHound](https://github.com/SpecterOps/MSSQLHound) PowerShell collector for adding MSSQL attack paths to BloodHound.

## Overview

MSSQLHound collects security-relevant information from Microsoft SQL Server instances and produces BloodHound OpenGraph-compatible JSON files. This Go implementation provides the same functionality as the PowerShell version with improved performance and cross-platform support.

## Features

- **SQL Server Collection**: Enumerates server principals (logins, server roles), databases, database principals (users, roles), permissions, and role memberships
- **Linked Server Discovery**: Maps SQL Server linked server relationships
- **Active Directory Integration**: Resolves Windows logins to domain principals via LDAP
- **BloodHound Output**: Produces OpenGraph JSON format compatible with BloodHound CE
- **Streaming Output**: Memory-efficient streaming JSON writer for large environments

## Building

```bash
cd go
go build -o mssqlhound.exe ./cmd/mssqlhound
```

## Usage

### Basic Usage

Collect from a single SQL Server:
```bash
# Windows integrated authentication
./mssqlhound -s sql.contoso.com

# SQL authentication
./mssqlhound -s sql.contoso.com -u sa -p password

# Named instance
./mssqlhound -s "sql.contoso.com\INSTANCE"

# Custom port
./mssqlhound -s "sql.contoso.com:1434"
```

### Multiple Servers

```bash
# From command line
./mssqlhound --server-list "server1,server2,server3"

# From file
./mssqlhound --server-list-file servers.txt
```

### Options

| Flag | Description |
|------|-------------|
| `-s, --server` | SQL Server instance (host, host:port, or host\instance) |
| `-u, --user` | SQL login username |
| `-p, --password` | SQL login password |
| `-d, --domain` | Domain for name/SID resolution |
| `--dc` | Domain controller to use |
| `--skip-linked-servers` | Don't enumerate linked servers |
| `--collect-from-linked` | Full collection on discovered linked servers |
| `--skip-ad-nodes` | Skip creating User, Group, Computer nodes |
| `--include-nontraversable` | Include non-traversable edges |
| `--zip-dir` | Directory for final zip file |
| `--temp-dir` | Temporary directory for output files |

## Output Format

MSSQLHound produces BloodHound OpenGraph JSON files containing:

### Node Types
- `MSSQLServer` - SQL Server instances
- `MSSQLLogin` - Server-level logins
- `MSSQLServerRole` - Server roles (sysadmin, securityadmin, etc.)
- `MSSQLDatabase` - Databases
- `MSSQLDatabaseUser` - Database users
- `MSSQLDatabaseRole` - Database roles (db_owner, db_securityadmin, etc.)

### Edge Types

The Go implementation supports 51 edge kinds with full feature parity to the PowerShell version:

| Edge Kind | Description | Traversable |
|-----------|-------------|-------------|
| `MSSQL_MemberOf` | Principal is a member of a role, inheriting all role permissions | Yes |
| `MSSQL_IsMappedTo` | Login is mapped to a database user, granting automatic database access | Yes |
| `MSSQL_Contains` | Containment relationship showing hierarchy (Server→DB, DB→User, etc.) | Yes |
| `MSSQL_Owns` | Principal owns an object, providing full control | Yes |
| `MSSQL_ControlServer` | Has CONTROL SERVER permission, granting sysadmin-equivalent control | Yes |
| `MSSQL_ControlDB` | Has CONTROL on database, granting db_owner-equivalent permissions | Yes |
| `MSSQL_ControlDBRole` | Has CONTROL on database role, allowing full control including member management | Yes |
| `MSSQL_ControlDBUser` | Has CONTROL on database user, allowing impersonation | Yes |
| `MSSQL_ControlLogin` | Has CONTROL on login, allowing impersonation and password changes | Yes |
| `MSSQL_ControlServerRole` | Has CONTROL on server role, allowing member management | Yes |
| `MSSQL_Impersonate` | Can impersonate target principal | Yes |
| `MSSQL_ImpersonateAnyLogin` | Can impersonate any server login | Yes |
| `MSSQL_ImpersonateDBUser` | Can impersonate specific database user | Yes |
| `MSSQL_ImpersonateLogin` | Can impersonate specific server login | Yes |
| `MSSQL_ChangePassword` | Can change target's password without knowing current password | Yes |
| `MSSQL_AddMember` | Can add members to target role | Yes |
| `MSSQL_Alter` | Has ALTER permission on target object | No |
| `MSSQL_AlterDB` | Has ALTER permission on database | No |
| `MSSQL_AlterDBRole` | Has ALTER permission on database role | No |
| `MSSQL_AlterServerRole` | Has ALTER permission on server role | No |
| `MSSQL_Control` | Has CONTROL permission on target object | No |
| `MSSQL_ChangeOwner` | Can take ownership via TAKE OWNERSHIP permission | Yes |
| `MSSQL_AlterAnyLogin` | Can alter any login on the server | No |
| `MSSQL_AlterAnyServerRole` | Can alter any server role | No |
| `MSSQL_AlterAnyRole` | Can alter any role (generic) | No |
| `MSSQL_AlterAnyDBRole` | Can alter any database role | No |
| `MSSQL_AlterAnyAppRole` | Can alter any application role | No |
| `MSSQL_GrantAnyPermission` | Can grant ANY server permission (securityadmin capability) | Yes |
| `MSSQL_GrantAnyDBPermission` | Can grant ANY database permission (db_securityadmin capability) | Yes |
| `MSSQL_LinkedTo` | Linked server connection to another SQL Server | Yes |
| `MSSQL_LinkedAsAdmin` | Linked server with admin privileges on remote server | Yes |
| `MSSQL_ExecuteAsOwner` | TRUSTWORTHY DB allows privilege escalation via owner permissions | Yes |
| `MSSQL_IsTrustedBy` | Database has TRUSTWORTHY enabled | Yes |
| `MSSQL_HasDBScopedCred` | Database has database-scoped credential for external auth | No |
| `MSSQL_HasMappedCred` | Login has mapped credential | No |
| `MSSQL_HasProxyCred` | Principal can use SQL Agent proxy account | No |
| `MSSQL_ServiceAccountFor` | Domain account is service account for SQL Server | Yes |
| `MSSQL_HostFor` | Computer hosts the SQL Server instance | Yes |
| `MSSQL_ExecuteOnHost` | SQL Server can execute OS commands on host | Yes |
| `MSSQL_TakeOwnership` | Has TAKE OWNERSHIP permission | Yes |
| `MSSQL_DBTakeOwnership` | Has TAKE OWNERSHIP on database | Yes |
| `MSSQL_CanExecuteOnServer` | Can execute code on server | Yes |
| `MSSQL_CanExecuteOnDB` | Can execute code on database | Yes |
| `MSSQL_Connect` | Has CONNECT SQL permission | No |
| `MSSQL_ConnectAnyDatabase` | Can connect to any database | No |
| `MSSQL_ExecuteAs` | Can execute as target (action edge) | Yes |
| `MSSQL_HasLogin` | Domain account has SQL Server login | Yes |
| `MSSQL_GetTGS` | Service account SPN enables Kerberoasting | Yes |
| `MSSQL_GetAdminTGS` | Service account SPN enables Kerberoasting with admin access | Yes |
| `HasSession` | AD account has session on computer | Yes |
| `CoerceAndRelayToMSSQL` | EPA disabled, enables NTLM relay attacks | Yes |

**Note:** Traversable edges represent attack paths that can be directly exploited. Non-traversable edges provide context but may not always be directly abusable (e.g., credentials may be stale).

## Differences from PowerShell Version

| Feature | PowerShell | Go |
|---------|------------|-----|
| Windows Auth | Full support | Full support |
| Kerberos delegation | Supported | Supported via go-mssqldb |
| Performance | Single-threaded | Concurrent capable |
| Memory efficiency | Loads all in memory | Streaming output |
| Cross-platform | Windows only | Windows, Linux, macOS |

## License

MIT License - see LICENSE file.

## Credits

- Original PowerShell version by Chris Thompson (@_Mayyhem) at SpecterOps
- Go port maintains the same functionality and output format
