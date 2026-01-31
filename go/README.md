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
- `MSSQL_MemberOf` - Role membership
- `MSSQL_IsMappedTo` - Login to database user mapping
- `MSSQL_Contains` - Server contains database relationship
- `MSSQL_Owns` - Database ownership
- `MSSQL_ControlServer` - CONTROL SERVER permission
- `MSSQL_ControlDB` - CONTROL permission on database
- `MSSQL_Impersonate` - IMPERSONATE permission
- `MSSQL_ImpersonateAnyLogin` - IMPERSONATE ANY LOGIN permission
- `MSSQL_LinkedTo` - Linked server relationship
- `MSSQL_IsTrustedBy` - Trustworthy database relationship
- And more...

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
