# Contributing to MSSQLHound

Thanks for your interest in contributing to MSSQLHound! This guide will help you get started.

## Getting in Touch

Before diving into code, feel free to reach out:

- **BloodHound Slack**: [@Mayyhem](http://ghst.ly/BHSlack)
- **Twitter/X**: [@_Mayyhem](https://x.com/_Mayyhem)
- **GitHub Issues**: [Open an issue](https://github.com/SpecterOps/MSSQLHound/issues)

If you're planning a significant change, please open an issue first to discuss the approach.

## Project Structure

```
MSSQLHound/
├── go/                        # Go implementation (active development)
│   ├── cmd/mssqlhound/        # CLI entry point
│   ├── internal/              # Internal packages
│   │   ├── ad/                # Active Directory / LDAP integration
│   │   ├── bloodhound/        # BloodHound output formatting
│   │   ├── collector/         # Core edge/node collection logic
│   │   ├── epamatrix/         # EPA matrix testing
│   │   ├── mssql/             # SQL Server protocol and authentication
│   │   ├── proxydialer/       # SOCKS5 proxy support
│   │   ├── types/             # Shared data structures
│   │   ├── winrmclient/       # WinRM client for EPA testing
│   │   └── wmi/               # WMI service account collection (Windows)
│   ├── TESTING.md             # Comprehensive testing guide
│   └── README.md              # Go-specific documentation
├── saved_queries/             # Pre-built BloodHound Cypher queries
├── util/                      # Utility scripts
│   └── compare_edges.py       # Edge comparison tool (Python 3, no dependencies)
├── powershell_deprecated/     # Original PowerShell implementation (archived)
├── seed_data.json             # BloodHound seed data for custom node types
└── MSSQL Design.json          # Graph model definition
```

## Prerequisites

- **Go 1.24+** (for building and testing)
- **Python 3** (only needed for utility scripts in `util/`)
- **Git**

## Building

```bash
cd go
go build -o mssqlhound ./cmd/mssqlhound
```

The build produces a single standalone binary with no external runtime dependencies. Cross-compilation works for Windows, Linux, and macOS.

## Testing

### Unit Tests

Unit tests run without any external infrastructure:

```bash
cd go
go test ./...
```

Run a specific test or match a pattern:

```bash
go test -v -run TestContainsEdges ./internal/collector/...
go test -v -run MemberOf ./internal/collector/...
```

### Integration Tests

Integration tests require a live SQL Server instance and Active Directory environment. They are gated behind a build tag:

```bash
cd go
MSSQL_SERVER=sql.example.com \
MSSQL_USER=sa \
MSSQL_PASSWORD='P@ssw0rd' \
MSSQL_DOMAIN=example.com \
MSSQL_DC=10.0.0.1 \
LDAP_USER='EXAMPLE\admin' \
LDAP_PASSWORD='LdapP@ss' \
go test -v -tags integration -timeout 30m -run TestIntegrationAll ./internal/collector/...
```

See [go/TESTING.md](go/TESTING.md) for the full testing guide, including:

- All environment variables and their defaults
- Integration test flow (setup, test, coverage, teardown)
- EPA matrix testing
- How to add tests for new edge types

## Development Workflow

1. **Fork and clone** the repository
2. **Create a branch** from `main` for your changes
3. **Make your changes** following the code style conventions below
4. **Write tests** for new functionality (especially new edge types)
5. **Run unit tests** to verify nothing is broken
6. **Open a pull request** against `main`

## Code Style

MSSQLHound follows standard Go conventions:

- **Formatting**: Run `gofmt` (or `goimports`) on all Go files
- **Error handling**: Wrap errors with context using `fmt.Errorf("...: %w", err)`
- **Testing**: Use the standard library `testing` package (no external test frameworks)
- **Naming**: CamelCase for exported symbols, `json:"snake_case"` for struct tags
- **Documentation**: Package-level `// Package <name>` doc comments on each file
- **Receivers**: Single-letter pointer receivers (e.g., `func (c *Collector) ...`)
- **Concurrency**: Protect shared state with `sync.Mutex` / `sync.RWMutex`

### Test Conventions

- Unit test files live alongside the code they test (`*_test.go`, no build tag)
- Integration tests use the `//go:build integration` build tag
- Edge tests use the project's builder pattern and assertion helpers -- see [go/TESTING.md](go/TESTING.md) for details
- Platform-specific code uses build-constrained files (e.g., `wmi_windows.go`, `wmi_stub.go`)

## Adding New Edge Types

If you're adding a new MSSQL edge type, follow the step-by-step guide in [go/TESTING.md](go/TESTING.md#adding-a-new-edge-type-test). The process involves:

1. Defining the edge in the collector
2. Adding unit test cases using the test data builders
3. Adding integration test coverage
4. Documenting the edge in the README

## Reporting Issues

When opening an issue, please include:

- **MSSQLHound version** (from `mssqlhound --version` or the release you downloaded)
- **Operating system** and architecture
- **SQL Server version** you're collecting from
- **Steps to reproduce** the issue
- **Expected vs. actual behavior**
- **Relevant log output** (sanitize any credentials or sensitive hostnames)

## Pull Request Guidelines

- Target the `main` branch
- Keep PRs focused -- one logical change per PR
- Write a clear title and description explaining what changed and why
- Include tests for new edge types or significant logic changes
- Ensure all unit tests pass (`go test ./...`)
- Reference any related GitHub issues in the PR description

## License

MSSQLHound is licensed under the [GNU General Public License v3.0](LICENSE). By contributing, you agree that your contributions will be licensed under the same terms.
