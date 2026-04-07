# Logging Overhaul Plan

## Context
MSSQLHound currently uses raw `fmt.Printf`/`fmt.Println` for all logging (~149 calls across 10 files). Messages have no timestamps, no log levels, and inconsistent formatting. The goal is to add UTC timestamps and log levels to every message using Go's stdlib `log/slog` (available since Go 1.21, project uses Go 1.24).

## Approach: Use `log/slog` from stdlib

No new packages or dependencies. Create a `*slog.Logger` in `main()`, propagate via struct fields.

### Output format
```
INFO    2026-03-30T14:22:01Z Processing 5 SQL Server(s)...
INFO    2026-03-30T14:22:01Z [corp.local] Enumerating MSSQL SPNs from Active Directory...
VERBOSE 2026-03-30T14:22:01Z [corp.local] Found SPNs count=12 host=sql01.corp.local
WARNING 2026-03-30T14:22:02Z [sql01.corp.local] SPN enumeration failed error="connection refused"
DEBUG   2026-03-30T14:22:02Z [sql01.corp.local] EPA TLS handshake complete cipher=0x1301
```

- Custom `slog.Handler` implementation in a new file `internal/logging/handler.go`
- Format: `LEVEL TIMESTAMP [target] message attrs...`
- Level name is left-aligned, right-padded to 7 chars (longest: `WARNING` and `VERBOSE`)
- Output goes to **stderr** (standard for logs; keeps stdout clean for data output like tables)
- Timestamps in UTC RFC3339 format
- **Target context**: when processing a specific server or domain, a `[target]` tag appears after the timestamp. Implemented via `logger.With("target", serverName)` to create sub-loggers. The custom handler renders the `target` attr specially in brackets, separate from other attrs.
- Messages without a target (startup, global config) omit the bracket section

### Colors (ANSI escape codes)
- Auto-detect TTY on stderr (`os.Stderr.Fd()` + `isatty` check or `golang.org/x/term.IsTerminal`). Disable colors when piped.
- **Level colors**:
  - `ERROR` — red (ANSI 31)
  - `WARNING` — yellow (ANSI 33)
  - `INFO` — white/default (no color)
  - `VERBOSE` — dim/gray (ANSI 90)
  - `DEBUG` — magenta (ANSI 35)
- **Timestamp** — light blue (ANSI 94)
- **Target** `[brackets]` — deterministic color per unique target string. Hash the target name to pick from a palette of primary/secondary ANSI colors (red 31, green 32, yellow 33, blue 34, magenta 35, cyan 36). Same target always gets the same color. Use a simple hash (e.g., `fnv32(target) % len(palette)`).
- **Message text** — default/no color
- **Attrs** (`key=value`) — dim (ANSI 2) for the key, default for value

### Custom slog levels
| Name | slog.Level value | Meaning |
|---|---|---|
| `ERROR` | `slog.LevelError` (8) | Error conditions |
| `WARNING` | `slog.LevelWarn` (4) | Warnings |
| `INFO` | `slog.LevelInfo` (0) | Normal status/progress |
| `VERBOSE` | `slog.Level(-2)` | Detailed progress (was `logVerbose`) |
| `DEBUG` | `slog.LevelDebug` (-4) | EPA/TLS/NTLM diagnostics (was `logDebug`/`logf`) |

### Level mapping from current code
| Current pattern | New level |
|---|---|
| `fmt.Printf(...)` (status/progress) | `INFO` |
| `fmt.Printf("Warning: ...")` | `WARNING` |
| `fmt.Printf("ERROR: ...")` | `ERROR` |
| `logVerbose(...)` | `VERBOSE` |
| `logDebug(...)` / `logf(...)` (EPA diagnostics) | `DEBUG` |

### Flag behavior
- No flags: minimum level = INFO
- `--verbose`: minimum level = VERBOSE (shows VERBOSE + INFO + WARNING + ERROR)
- `--debug`: minimum level = DEBUG (shows everything)
- `--debug` additionally sets `debug=true` on subsystems (controls EPA test behavior beyond just logging)

## Implementation Phases

### Phase 0: Custom handler (`internal/logging/`)

**New file: [internal/logging/handler.go](go/internal/logging/handler.go)**
- Implement `slog.Handler` that formats: `LEVEL   TIMESTAMP [target] message attrs...`
- Define custom level constants: `LevelVerbose = slog.Level(-2)`
- Level name mapping: `-2` → `VERBOSE`, `slog.LevelWarn` → `WARNING`
- Left-align level name, right-pad to 7 chars
- Special handling for `target` attr: rendered as `[value]` before the message, not as `key=value`
- Other attrs appended as `key=value` after the message
- Thread-safe writer (mutex around writes)
- `WithAttrs` / `WithGroup` support for creating sub-loggers (e.g., `logger.With("target", server)`)
- ANSI color support: detect TTY via `golang.org/x/term.IsTerminal(int(os.Stderr.Fd()))`
- Color each element per the palette defined above (level, timestamp, target, attrs)
- Target color: `fnv32a(targetString) % 6` maps to one of [blue 34, cyan 36, bright green 92, bright blue 94, bright cyan 96, bright white 97]. These avoid red (ERROR), yellow (WARNING), magenta (DEBUG), and gray (VERBOSE).
- Accept a `NoColor bool` option to force colors off (for tests or `--no-color` flag)

### Phase 1: Logger setup in main (`cmd/mssqlhound/`)

**[main.go](go/cmd/mssqlhound/main.go)**
- Create `slog.LevelVar` and `*slog.Logger` with custom `logging.NewHandler(os.Stderr, ...)` in `main()`
- Add `PersistentPreRunE` to set level from `--verbose`/`--debug` flags
- Pass logger to `run()` and subcommands
- Convert 11 `fmt.Printf`/`fmt.Println` calls to `logger.Info`/`logger.Warn`
- Keep `fmt.Fprintf(os.Stderr, ...)` for cobra error at line 105 (logger may not exist)

**[cmd_test_epa_matrix.go](go/cmd/mssqlhound/cmd_test_epa_matrix.go)**
- Accept logger parameter from main
- Convert 8 `fmt.Printf` calls

### Phase 2: Collector (`internal/collector/`)

**[collector.go](go/internal/collector/collector.go)**
- Add `Logger *slog.Logger` field to `Config` struct
- Convert 75 `fmt.Printf`/`fmt.Println` calls to appropriate slog levels
- Convert 49 `c.logVerbose(...)` calls to `c.config.Logger.Log(ctx, logging.LevelVerbose, ...)`
- Remove `logVerbose` method (line 6128)
- When processing a server, create a sub-logger: `serverLog := c.config.Logger.With("target", server.ConnectionString)` and use it for all per-server messages
- For domain-level operations: `domainLog := c.config.Logger.With("target", domain)`
- Pass logger to `mssql.Client` and `wmi` calls

### Phase 3: MSSQL client (`internal/mssql/`)

**[client.go](go/internal/mssql/client.go)** — 15 fmt calls + 7 logf calls
- Add `logger *slog.Logger` field, `SetLogger` method
- Default to `slog.Default()` in `NewClient`
- Replace `logVerbose`/`logDebug` methods with `c.logger.Debug()`
- Change `epaTLSDialer.logf` and `epaTDSDialer.logf` fields from `func(string, ...interface{})` to `*slog.Logger`
- Update dialer `d.logf(...)` calls to `d.logger.Debug(...)`

**[epa_tester.go](go/internal/mssql/epa_tester.go)** — 69 logf calls + 2 fmt calls
- Add `Logger *slog.Logger` to `EPATestConfig`
- Remove the `logf` closure (line 91-95)
- Convert all 69 `logf(...)` calls to `config.Logger.Debug(...)` with `"component", "epa"` attr
- Convert 2 direct `fmt.Printf` calls

**[epa_auth_provider.go](go/internal/mssql/epa_auth_provider.go)** — 2 fmt calls
- Add `logger *slog.Logger` field
- Convert 2 `fmt.Printf("[EPA-auth] ...")` calls

**[powershell_fallback.go](go/internal/mssql/powershell_fallback.go)** — 1 fmt call
- Add `logger *slog.Logger` field, `SetLogger` method
- Remove `logVerbose` method, convert call to `p.logger.Debug()`

### Phase 4: Supporting packages

**[epamatrix/epamatrix.go](go/internal/epamatrix/epamatrix.go)** — 24 fmt calls
- Add `Logger *slog.Logger` to `MatrixConfig`
- Convert all 24 calls

**[wmi/wmi_windows.go](go/internal/wmi/wmi_windows.go)** — 7 fmt calls
- Change `GetLocalGroupMembers` and `GetLocalGroupMembersWithFallback` signatures: replace `verbose bool` with `logger *slog.Logger`
- Update [wmi/wmi_stub.go](go/internal/wmi/wmi_stub.go) signatures to match
- Update caller in [collector.go:1854](go/internal/collector/collector.go#L1854)

### NOT changed
- **[epamatrix/table.go](go/internal/epamatrix/table.go)** — `PrintResultsTable`/`Summarize` write formatted table data to `io.Writer`. This is data output, not logging.
- All `fmt.Errorf(...)` calls (error construction, not logging)
- All `fmt.Sprintf(...)` calls (string building)

## Verification
1. `go build ./...` compiles cleanly
2. `go vet ./...` passes
3. Run with no flags — only INFO+ messages appear, each with UTC timestamp and level
4. Run with `--verbose` — DEBUG messages appear
5. Run with `--debug` — EPA diagnostic messages appear with `component=epa` attribute
6. Table output (EPA matrix) still renders correctly to stdout without log formatting
