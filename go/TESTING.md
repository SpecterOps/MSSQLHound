# MSSQLHound Go - Testing Guide

This document covers how to run and write tests for the MSSQLHound Go port.

## Quick Start

```bash
cd go

# Run all unit tests
go test ./...

# Verbose output
go test -v ./...

# Run a specific test by name
go test -v -run TestContainsEdges ./internal/collector/...
```

## Test Architecture

Tests are split into two categories separated by Go build tags:

| Category | Build Tag | Requirements |
|----------|-----------|-------------|
| **Unit tests** | _(none)_ | None — runs anywhere with `go test` |
| **Integration tests** | `integration` | Live SQL Server + Active Directory environment |

### File Layout

```
go/internal/collector/
├── collector_test.go              # Core unit tests (node/edge creation, JSON output)
├── cve_test.go                    # CVE version-parsing tests
├── edge_unit_test.go              # Per-edge-type unit tests (data builders + test runners)
├── edge_test_helpers_test.go      # Shared utilities: pattern matching, assertions, edge runner
├── edge_test_data_test.go         # Test case definitions (translated from PS1)
├── integration_sql_test.go        # Embedded SQL setup/cleanup scripts (build:integration)
├── integration_setup_test.go      # Integration environment setup/teardown (build:integration)
├── integration_report_test.go     # Coverage analysis & HTML reporting (build:integration)
└── edge_integration_test.go       # Live edge validation (build:integration)

go/internal/mssql/
└── ntlm_auth_test.go              # NTLM hash & message tests (MS-NLMP spec vectors)
```

## Unit Tests

### Running

```bash
# All unit tests
go test ./...

# Collector package only
go test ./internal/collector/...

# MSSQL/NTLM package only
go test ./internal/mssql/...

# Single test function
go test -v -run TestEdgeCreation ./internal/collector/...

# Pattern match (runs all tests with "MemberOf" in the name)
go test -v -run MemberOf ./internal/collector/...
```

### Edge Unit Tests

The bulk of the unit test suite validates that the correct BloodHound edges are (or are not) created for a given SQL Server configuration. Each edge type has:

1. **A data builder** in `edge_unit_test.go` — constructs a mock `ServerInfo` with the principals, permissions, and role memberships needed to exercise that edge type.
2. **A set of test cases** in `edge_test_data_test.go` — declarative expectations translated 1:1 from the PowerShell test suite (`Invoke-MSSQLHoundUnitTests.ps1`).
3. **A test function** in `edge_unit_test.go` — calls the builder, runs edge creation, then asserts all cases.

Example flow for `MSSQL_AddMember`:

```go
// 1. Builder creates mock server state
func buildAddMemberTestData() *types.ServerInfo {
    info := baseServerInfo()
    addSQLLogin(info, "AddMemberTest_Login_CanAlterServerRole",
        withPermissions(perm("ALTER", "GRANT", "SERVER_ROLE", "AddMemberTest_ServerRole_...")))
    // ...
    return info
}

// 2. Test cases define expectations
var addMemberTestCases = []edgeTestCase{
    {
        EdgeType:      "MSSQL_AddMember",
        Description:   "Login with ALTER on role can add members",
        SourcePattern: "AddMemberTest_Login_CanAlterServerRole@*",
        TargetPattern: "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*",
    },
    {
        EdgeType:    "MSSQL_AddMember",
        Description: "ALTER ANY SERVER ROLE CANNOT add to sysadmin",
        Negative:    true,
        Reason:      "sysadmin role does not accept new members via ALTER ANY SERVER ROLE",
        // ...
    },
}

// 3. Test function ties them together
func TestAddMemberEdges(t *testing.T) {
    info := buildAddMemberTestData()
    result := runEdgeCreation(t, info, true)
    runTestCases(t, result.Edges, addMemberTestCases)
}
```

### Test Case Structure

Each `edgeTestCase` specifies:

| Field | Description |
|-------|-------------|
| `EdgeType` | BloodHound edge kind (e.g. `MSSQL_AddMember`) |
| `Description` | Human-readable explanation |
| `SourcePattern` | Glob pattern for edge source (`*` and `?` wildcards) |
| `TargetPattern` | Glob pattern for edge target |
| `Negative` | If `true`, asserts the edge must **not** exist |
| `Reason` | Explanation for negative test cases |
| `EdgeProperties` | Property assertions (e.g. `"traversable": true`) |
| `ExpectedCount` | Assert exactly N matching edges |

### Data Builder Helpers

Mock data is constructed using a functional options pattern:

```go
// Server-level
addSQLLogin(info, "name", withPermissions(...), withMemberOf(...))
addWindowsLogin(info, "DOMAIN\\user", sid, withMemberOf(...))
addWindowsGroup(info, "DOMAIN\\group", sid)
addServerRole(info, "roleName")
addLinkedServer(info, "remote.server", withLinkedLogin(...))
addCredential(info, "credName", "DOMAIN\\identity")

// Database-level
db := addDatabase(info, "dbName")
addDatabaseUser(db, "userName", withDBPermissions(...))
addWindowsUser(db, "DOMAIN\\user", withDBMemberOf(...))
addDatabaseRole(db, "roleName", isFixedRole)
addAppRole(db, "appRoleName")
addDBScopedCredential(db, "credName", "identity")

// Permission/role helpers
perm("CONTROL SERVER", "GRANT", "SERVER")
roleMembership("sysadmin", serverOID)
```

### Assertion Helpers

The test helpers in `edge_test_helpers_test.go` provide:

- `findEdges(edges, kind, sourcePattern, targetPattern)` — find matching edges using glob patterns
- `assertEdgeExists(t, edges, kind, source, target)` — fail if no match
- `assertEdgeNotExists(t, edges, kind, source, target)` — fail if a match exists
- `assertEdgeCount(t, edges, kind, source, target, n)` — fail if count != n
- `assertEdgeProperty(t, edge, key, expected)` — fail if property doesn't match

### Other Unit Tests

- **`TestEdgeCreation`** (`collector_test.go`) — end-to-end test that builds mock data, creates nodes/edges via the collector, writes JSON output, and verifies the result parses correctly.
- **`TestParseSQLVersion` / `TestCVEVulnerability`** (`cve_test.go`) — table-driven tests for SQL Server version parsing and CVE detection.
- **`TestNTLMv2Hash` / `TestNTProofStr` / `TestCBTComputation`** (`ntlm_auth_test.go`) — validates NTLM authentication against MS-NLMP specification test vectors.

## Integration Tests

Integration tests run against a live SQL Server and Active Directory environment. They are gated behind the `integration` build tag and are **not** included in `go test ./...`.

### Prerequisites

- SQL Server instance with sysadmin access
- Active Directory domain with LDAP write access (for creating test objects)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MSSQL_SERVER` | `ps1-db.mayyhem.com` | SQL Server instance |
| `MSSQL_USER` | _(empty = Windows auth)_ | Sysadmin username |
| `MSSQL_PASSWORD` | | Sysadmin password |
| `MSSQL_DOMAIN` | `$USERDOMAIN` | AD domain name |
| `MSSQL_DC` | _(auto-discover)_ | Domain controller IP |
| `LDAP_USER` | | LDAP username for AD object creation |
| `LDAP_PASSWORD` | | LDAP password |
| `MSSQL_LIMIT_EDGE` | _(all)_ | Limit to a specific edge type |
| `MSSQL_SKIP_DOMAIN` | `false` | Skip AD object creation |
| `MSSQL_ACTION` | `all` | `all`, `setup`, `test`, `teardown`, `coverage` |
| `MSSQL_SKIP_HTML` | `false` | Skip HTML coverage report |
| `MSSQL_ZIP` | | Path to existing .zip to validate |
| `MSSQL_ENUM_USER` | `lowpriv` | Low-privilege enumeration user |
| `MSSQL_ENUM_PASSWORD` | `password` | Enumeration password |

### Environment Setup

Before running integration tests, you need to set up the test environment on your target SQL Server and AD domain. The setup phase creates AD objects (users, groups, computers) via LDAP and executes embedded SQL scripts to build databases, logins, permissions, and role memberships needed by the test suite.

```bash
# Run setup only — creates AD objects and SQL Server test environment
MSSQL_SERVER=sql.example.com \
MSSQL_USER='EXAMPLE\admin' \
MSSQL_PASSWORD='P@ssw0rd' \
MSSQL_DOMAIN=example.com \
MSSQL_DC=10.0.0.1 \
LDAP_USER='EXAMPLE\admin' \
LDAP_PASSWORD='LdapP@ss' \
go test -v -tags integration -timeout 30m -run TestIntegrationSetup ./internal/collector/...

# SQL-only setup (skip AD object creation)
MSSQL_SKIP_DOMAIN=true \
MSSQL_SERVER=sql.example.com \
MSSQL_USER=sa \
MSSQL_PASSWORD='P@ssw0rd' \
go test -v -tags integration -timeout 30m -run TestIntegrationSetup ./internal/collector/...
```

`MSSQL_USER` requires sysadmin privileges on the SQL Server instance. `LDAP_USER` requires write access to create test objects in Active Directory. Both support `DOMAIN\user` format for domain accounts.

Once setup completes, the environment persists until you run the teardown phase, so you can run the test and coverage phases repeatedly without re-running setup.

### Running Integration Tests

```bash
# Full cycle: setup -> test -> coverage -> teardown
MSSQL_SERVER=sql.example.com \
MSSQL_USER='EXAMPLE\admin' \
MSSQL_PASSWORD='P@ssw0rd' \
MSSQL_DOMAIN=example.com \
MSSQL_DC=10.0.0.1 \
LDAP_USER='EXAMPLE\admin' \
LDAP_PASSWORD='LdapP@ss' \
go test -v -tags integration -timeout 30m -run TestIntegrationAll ./internal/collector/...

# Individual phases (set env vars as above)
go test -v -tags integration -run TestIntegrationSetup ./internal/collector/...
go test -v -tags integration -run TestIntegrationEdges ./internal/collector/...
go test -v -tags integration -run TestIntegrationCoverage ./internal/collector/...
go test -v -tags integration -run TestIntegrationTeardown ./internal/collector/...

# Validate an existing MSSQLHound zip output
MSSQL_ZIP=/path/to/output.zip \
go test -v -tags integration -run TestIntegrationValidateZip ./internal/collector/...

# Test a single edge type
MSSQL_LIMIT_EDGE=AddMember \
go test -v -tags integration -run TestIntegrationEdges ./internal/collector/...
```

### Integration Test Flow

1. **Setup** — Uses embedded SQL setup scripts (in `integration_sql_test.go`), creates AD objects (users, groups, computers) via LDAP, and executes SQL batches to build the test environment.
2. **Test** — Runs MSSQLHound against the live server, then validates all expected edges exist (and negative edges do not) using the same `edgeTestCase` definitions as unit tests.
3. **Coverage** — Analyzes which of the 38+ edge types were found and generates an HTML coverage report.
4. **Teardown** — Removes AD objects and drops test databases.

## Adding a New Edge Type Test

1. **Define test cases** in `edge_test_data_test.go`:
   ```go
   var myNewEdgeTestCases = []edgeTestCase{
       {
           EdgeType:      "MSSQL_MyNewEdge",
           Description:   "User with SOME_PERM can do something",
           SourcePattern: "MyNewTest_Login@*",
           TargetPattern: "MyNewTest_Target@*",
       },
       {
           EdgeType:    "MSSQL_MyNewEdge",
           Description: "User without SOME_PERM cannot do something",
           SourcePattern: "MyNewTest_OtherLogin@*",
           TargetPattern: "MyNewTest_Target@*",
           Negative:    true,
           Reason:      "Missing required permission",
       },
   }
   ```

2. **Create a data builder** in `edge_unit_test.go`:
   ```go
   func buildMyNewEdgeTestData() *types.ServerInfo {
       info := baseServerInfo()
       addSQLLogin(info, "MyNewTest_Login",
           withPermissions(perm("SOME_PERM", "GRANT", "SERVER")))
       addSQLLogin(info, "MyNewTest_OtherLogin") // no permissions
       // ... add whatever objects the edge logic needs
       return info
   }
   ```

3. **Add the test function** in `edge_unit_test.go`:
   ```go
   func TestMyNewEdgeEdges(t *testing.T) {
       info := buildMyNewEdgeTestData()
       result := runEdgeCreation(t, info, true)
       runTestCases(t, result.Edges, myNewEdgeTestCases)
   }
   ```

4. **Run the test**:
   ```bash
   go test -v -run TestMyNewEdge ./internal/collector/...
   ```

## Covered Edge Types

The unit test suite covers 38+ edge types including:

| Category | Edge Types |
|----------|-----------|
| **Containment** | Contains |
| **Membership** | MemberOf (including nested roles) |
| **Mapping** | IsMappedTo, HasLogin |
| **Ownership** | Owns, ChangeOwner, TakeOwnership |
| **Control** | ControlServer, ControlDB, Control |
| **Permissions** | Connect, ConnectAnyDatabase, Alter, AlterAnyLogin, AlterAnyServerRole, AlterAnyDBRole, AlterAnyAppRole |
| **Granting** | GrantAnyPermission, GrantAnyDBPermission |
| **Impersonation** | Impersonate, ImpersonateAnyLogin, ExecuteAs |
| **Role Management** | AddMember |
| **Credential** | HasMappedCred, HasProxyCred, HasDBScopedCred |
| **Linked Servers** | LinkedTo, LinkedAsAdmin |
| **Execution** | ExecuteAsOwner, ExecuteOnHost |
| **Service Accounts** | GetTGS, GetAdminTGS, ServiceAccountFor |
| **Security** | CoerceAndRelayToMSSQL, ChangePassword |

Each edge type includes both positive tests (edge is created) and negative tests (edge is NOT created when conditions aren't met).

## EPA Test Matrix

The `test-epa-matrix` subcommand systematically validates EPA (Extended Protection for Authentication) detection by cycling through all combinations of SQL Server encryption/protection registry settings, restarting the service for each combination, and running 5 NTLM authentication variations to detect the effective EPA enforcement level.

### Prerequisites

- SQL Server instance with WinRM (PowerShell Remoting) access
- Domain credentials with admin privileges on the SQL Server host (to modify registry and restart the service)
- The `mssqlhound` binary (`cd go && go build ./cmd/mssqlhound/`)

### Running

```bash
# Basic EPA matrix test
./mssqlhound test-epa-matrix \
  --server sql.example.com \
  --user "EXAMPLE\admin" \
  --password "P@ssw0rd" \
  --domain EXAMPLE.COM

# Named instance with HTTPS WinRM
./mssqlhound test-epa-matrix \
  --server sql.example.com\SQLEXPRESS \
  --user "EXAMPLE\admin" \
  --password "P@ssw0rd" \
  --domain EXAMPLE.COM \
  --sql-instance-name SQLEXPRESS \
  --winrm-https \
  --winrm-port 5986

# SQL Server 2019 or earlier (no strict encryption support)
./mssqlhound test-epa-matrix \
  --server sql.example.com \
  --user "EXAMPLE\admin" \
  --password "P@ssw0rd" \
  --domain EXAMPLE.COM \
  --skip-strict
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | _(required)_ | SQL Server instance |
| `--user` | _(required)_ | Domain credentials (`DOMAIN\user` format) |
| `--password` | _(required)_ | Password |
| `--domain` | _(required)_ | AD domain name |
| `--winrm-host` | _(auto from server)_ | WinRM target host |
| `--winrm-port` | `5985` | WinRM port (`5986` if `--winrm-https`) |
| `--winrm-https` | `false` | Use HTTPS for WinRM |
| `--winrm-basic` | `false` | Use Basic auth instead of NTLM |
| `--sql-instance-name` | `MSSQLSERVER` | SQL Server instance name for registry lookup |
| `--restart-wait` | `60` | Max seconds to wait for service restart |
| `--post-restart-delay` | `5` | Seconds to wait after service reports Running |
| `--skip-strict` | `false` | Skip `ForceStrictEncryption=1` combinations (pre-SQL Server 2022) |

### What If Tests

The matrix tests **12 combinations** (or 6 with `--skip-strict`) of three SQL Server registry settings under `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{Instance}\MSSQLServer\SuperSocketNetLib`:

| Setting | Values |
|---------|--------|
| **ForceEncryption** | 0 (off), 1 (on) |
| **ForceStrictEncryption** | 0 (off), 1 (on) — SQL Server 2022+ only |
| **ExtendedProtection** | 0 (Off), 1 (Allowed), 2 (Required) |

For each combination, it runs **5 EPA test modes** against the server:

| Test Mode | Channel Binding | Service Binding | Purpose |
|-----------|----------------|-----------------|---------|
| **Normal** | Correct CBT | Correct SPN | Baseline — should always succeed |
| **BogusCBT** | Wrong hash | Correct SPN | Fails if EPA is enforced |
| **MissingCBT** | Omitted | Correct SPN | Distinguishes Allowed vs Required |
| **BogusService** | Correct CBT | Wrong SPN (`cifs/`) | Fails if EPA is enforced |
| **MissingService** | Omitted | Omitted | Distinguishes Allowed vs Required |

The detected EPA status (Off / Allowed / Required) is compared against the expected status for each registry combination, and the results are printed as a formatted table with a verdict per row.

### Safety

- Original registry settings are saved before the matrix starts
- Settings are restored on completion and on interrupt (Ctrl+C)
- The service is restarted between each combination and the test waits for TCP readiness
