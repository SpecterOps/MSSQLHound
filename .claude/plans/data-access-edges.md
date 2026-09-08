# Plan: Optional Read / Write / Delete database edges

## Context
Today the only edge that terminates on an `MSSQL_Database` node representing
elevated access is `MSSQL_ControlDB` (traversable, created from `CONTROL` on the
database or the `db_owner` fixed role). Meatbag wants to also surface principals
that can **read, write, or delete** data in a database — a weaker but still
security-relevant capability. These new edges must be **non-traversable** (they
are informational, not privilege-escalation paths) and their creation must be
**opt-in** via a new flag so existing output is unchanged by default.

## Decisions (confirmed with user)
- **Three edges**, all `→ MSSQL_Database`, all non-traversable:
  - `MSSQL_ReadDB`   ← `SELECT` on the database
  - `MSSQL_WriteDB`  ← `INSERT` or `UPDATE` on the database
  - `MSSQL_DeleteDB` ← `DELETE` on the database
- **Opt-in flag** `--enable-data-access-edges` (default `false`).
- **Sources**: explicit DB-scoped grants (`sys.database_permissions`, class
  `DATABASE`) **and** the `db_datareader` / `db_datawriter` fixed roles.
  (`db_datareader` → Read; `db_datawriter` → Write **and** Delete.)

## Implementation

### 1. Register the three edge kinds — `internal/bloodhound/writer.go`
- Add `ReadDB`, `WriteDB`, `DeleteDB` fields to the `EdgeKinds` struct and its
  literal, with values `"MSSQL_ReadDB"`, `"MSSQL_WriteDB"`, `"MSSQL_DeleteDB"`.

### 2. Mark them non-traversable + add properties — `internal/bloodhound/edges.go`
- Add the three kinds to the `case` list in `IsTraversableEdge` (return `false`).
- Add three entries to `edgePropertyGenerators` (mirror the `ControlDB` /
  `Connect` generator style: General / WindowsAbuse / LinuxAbuse / Opsec /
  References). Abuse text = connect as `ctx.SourceName` to `ctx.SQLServerName`,
  `USE <db>;` then `SELECT` / `INSERT`+`UPDATE` / `DELETE` example statements.

### 3. Schema + seed data (so BloodHound registers the kinds)
- `internal/bloodhound/schema.json`: add 3 `relationship_kinds` entries with
  `"is_traversable": false` (one per new kind).
- `internal/bloodhound/seed_data.json`: add one self-loop edge per new kind
  (matches the existing one-edge-per-kind convention).

### 4. Config plumbing
- `internal/collector/collector.go` `Config`: add `EnableDataAccessEdges bool`.
- `cmd/mssqlhound/main.go`: add package var `enableDataAccessEdges`, register
  `rootCmd.Flags().BoolVar(... "enable-data-access-edges", false, ...)`, add it
  to the `"Collection"` group annotation slice, and set
  `EnableDataAccessEdges: enableDataAccessEdges` in the `Config` literal in `run`.

### 5. Emit the edges
All new edge creation is guarded by `if c.config.EnableDataAccessEdges`.

- **Explicit grants** — `createDatabasePermissionEdges`
  (`internal/collector/collector.go`, ~line 5910). Add `case "SELECT"`,
  `case "INSERT"`, `case "UPDATE"`, `case "DELETE"` (only when
  `perm.ClassDesc == "DATABASE"`), each creating the corresponding edge from
  `principal.ObjectIdentifier` → `db.ObjectIdentifier` via `c.createEdge`,
  reusing `c.getDatabasePrincipalType(principal.TypeDescription)` for
  `SourceType`. `INSERT` and `UPDATE` both emit `WriteDB` (edge-dedup in the
  writer's `seenEdges` collapses the duplicate when both are granted).
- **Fixed roles** — `createFixedRoleEdges` DB-role loop
  (`internal/collector/collector.go`, ~line 5192). Add `case "db_datareader":`
  (emit `ReadDB`) and `case "db_datawriter":` (emit `WriteDB` + `DeleteDB`),
  using `IsFixedRole: true` in the `EdgeContext`, following the `db_owner`
  pattern.

Because `createEdge` already returns `nil` for non-traversable edges when
`DisableNontraversableEdges` is set, the new edges also correctly disappear
under `--disable-nontraversable-edges`.

### 6. Tests — `internal/collector/edge_unit_test.go` + `edge_test_data_test.go`
- Add `buildDataAccessTestData()` with principals holding `SELECT` / `INSERT` /
  `UPDATE` / `DELETE` DATABASE grants and `db_datareader` / `db_datawriter`
  fixed roles.
- Add `readDBTestCases` / `writeDBTestCases` / `deleteDBTestCases` and a
  `TestDataAccessEdges` that runs `runEdgeCreation`. **Note**: the default test
  config does not set `EnableDataAccessEdges`; add a variant helper (or extend
  `runEdgeCreation`) so the test enables the flag, and add one negative test
  asserting the edges are absent when the flag is off.
- Append the new case slices into the aggregate `all` slice in
  `edge_test_data_test.go` (the `allEdgeTestCases` builder ~line 696).

### 7. Docs — `README.md`
- Add the flag row to the **Collection** flag table (~line 674) and a short
  usage example near **Possible Edge Options** (~line 579).
- Add the three edges to the edge index (~line 100) and the edge-properties
  table (~line 1290) as "No unique edge properties".

## Verification
- `go test ./...` (project rule 10) — new `TestDataAccessEdges` plus existing
  suite must pass.
- `go build ./cmd/mssqlhound` → binary in repo root; run
  `./mssqlhound --help` and confirm `--enable-data-access-edges` appears in the
  Collection group.
- Sanity-check schema validity: the collector's schema-upload path reads
  `bloodhound.SchemaJSON`; a malformed JSON edit would fail `go test`'s
  `json.Unmarshal` in schema-dependent tests.
