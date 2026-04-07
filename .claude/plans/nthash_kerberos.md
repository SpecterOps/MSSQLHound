# Plan: Add NT Hash and Kerberos Authentication Options

## Context

MSSQLHound currently only supports plaintext password authentication (SQL auth or NTLM) and Windows integrated auth (SSPI). Pentesters frequently have NT hashes or Kerberos tickets (from tools like Mimikatz, Rubeus, or impacket) rather than cleartext passwords. Adding pass-the-hash and pass-the-ticket support makes MSSQLHound usable in real-world engagements where passwords aren't available.

**Key discovery:** go-mssqldb already ships a full Kerberos provider (`integratedauth/krb5`) that supports ccache files via `KRB5CCNAME` or `krb5-credcachefile` connection string param. We can leverage this directly rather than building custom Kerberos auth from scratch.

**Key discovery:** go-ldap already has `NTLMBindWithHash(domain, username, hash)` for pass-the-hash LDAP binds.

---

## New CLI Flags

| Flag | Type | Description |
|------|------|-------------|
| `--nt-hash` | `string` | NT hash (32 hex chars) for pass-the-hash authentication |
| `--kerberos` / `-k` | `bool` | Use Kerberos authentication (reads ccache from `KRB5CCNAME` env var) |
| `--krb5-configfile` | `string` | Path to krb5.conf (default: `/etc/krb5.conf` or `KRB5_CONFIG` env var) |
| `--krb5-credcachefile` | `string` | Path to ccache file (overrides `KRB5CCNAME` env var) |
| `--krb5-keytabfile` | `string` | Path to keytab file (alternative to ccache) |
| `--krb5-realm` | `string` | Kerberos realm (default: extracted from username or krb5.conf) |

Validation:
- `--nt-hash` is mutually exclusive with `--password` and `--kerberos`
- `--kerberos` is mutually exclusive with `--password` and `--nt-hash`
- `--nt-hash` must be exactly 32 hex characters
- `--kerberos` without `--krb5-credcachefile` requires `KRB5CCNAME` env var or a keytab

---

## Phase 1: Pass-the-Hash (NT Hash)

### 1.1 Config plumbing

**Files:** `cmd/mssqlhound/main.go`, `internal/collector/collector.go`

- Add `ntHash` var and `--nt-hash` persistent flag in `main.go` (~line 32, ~line 99)
- Add `NTHash string` field to `collector.Config` struct
- Wire `ntHash` into config in `run()` function (~line 179)
- Add validation: if `--nt-hash` set, reject `--password`; validate 32 hex chars

### 1.2 NTLM auth with pre-computed hash

**File:** `internal/mssql/ntlm_auth.go`

- Add `ntHash []byte` field to `ntlmAuth` struct (line 90)
- Add `SetNTHash(hash []byte)` method on `ntlmAuth`
- Modify `computeNTLMv2Hash()` (line 586) to accept an optional pre-computed NT hash:
  - New signature: `computeNTLMv2HashFromNT(ntHash []byte, username, domain string) []byte`
  - Skips the `MD4(UTF16LE(password))` step, uses provided `ntHash` directly
  - Computes `HMAC-MD5(ntHash, UTF16LE(UPPER(username) + domain))` as before
- Update `CreateAuthenticateMessage()` (line 336) to check if `a.ntHash` is set and call the hash-based variant
- Update `ComputeNTLMv2HashHex()` to work with pre-computed hash

### 1.3 MSSQL Client pass-the-hash

**File:** `internal/mssql/client.go`

- Add `ntHash []byte` field to `Client` struct (line 345)
- Add `SetNTHash(hash []byte)` method
- Update `NewClient()`: if ntHash is provided (password empty), set `useWindowsAuth = false` — we'll use NTLM with hash
- Update `buildConnectionStringForStrategy()` (line 860): when ntHash is set, use `trusted_connection=yes` with DOMAIN\user format (triggers integratedauth provider) instead of SQL auth
- Update EPA auth provider path: pass ntHash through to `ntlmAuth` via `newNTLMAuth()`

### 1.4 EPA auth provider with hash support

**File:** `internal/mssql/epa_auth_provider.go`

- Add `ntHash []byte` field to `epaAuthProvider` struct
- Add `SetNTHash(hash []byte)` method
- In `GetIntegratedAuthenticator()` (line 55): if ntHash is set, call `auth.SetNTHash(ntHash)` on the created `ntlmAuth`

### 1.5 EPA tester with hash support

**File:** `internal/mssql/epa_tester.go`

- Add `NTHash []byte` field to `EPATestConfig` struct
- Pass ntHash to `newNTLMAuth()` in the EPA test flow

### 1.6 LDAP pass-the-hash

**File:** `internal/ad/client.go`

- Add `ntHash string` field to AD `Client` struct (hex string for go-ldap compatibility)
- Add `SetNTHash(hash string)` method
- Update `ntlmBind()` (line 324): if `ntHash` is set, call `conn.NTLMBindWithHash(domain, username, ntHash)` instead of `conn.NTLMBind(domain, username, password)`

### 1.7 Collector wiring

**File:** `internal/collector/collector.go`

- Pass `config.NTHash` to both MSSQL client (`SetNTHash`) and AD client (`SetNTHash`)
- Update LDAP credential fallback logic: if ntHash is set with domain-format user, also use for LDAP

---

## Phase 2: Kerberos Authentication

### 2.1 Config plumbing

**Files:** `cmd/mssqlhound/main.go`, `internal/collector/collector.go`

- Add vars: `useKerberos`, `krb5ConfigFile`, `krb5CredCacheFile`, `krb5KeytabFile`, `krb5Realm`
- Add corresponding persistent flags
- Add fields to `collector.Config`: `UseKerberos bool`, `Krb5ConfigFile string`, `Krb5CredCacheFile string`, `Krb5KeytabFile string`, `Krb5Realm string`
- Wire into config in `run()`, validate mutual exclusivity with `--password`/`--nt-hash`

### 2.2 Import go-mssqldb krb5 provider

**File:** `internal/mssql/client.go`

- Add blank import: `_ "github.com/microsoft/go-mssqldb/integratedauth/krb5"` to register the krb5 provider
- This makes the provider available when `authenticator=krb5` is in the connection string

### 2.3 MSSQL Kerberos connection

**File:** `internal/mssql/client.go`

- Add Kerberos fields to `Client` struct: `useKerberos bool`, `krb5ConfigFile string`, `krb5CredCacheFile string`, `krb5KeytabFile string`, `krb5Realm string`
- Add setter methods for these fields
- Update `buildConnectionStringForStrategy()`:
  - When `useKerberos` is true, add `authenticator=krb5` to connection string
  - Add `krb5-credcachefile=<path>` if set
  - Add `krb5-keytabfile=<path>` if set
  - Add `krb5-configfile=<path>` if set
  - Add `krb5-realm=<realm>` if set
  - Set `trusted_connection=yes`
  - Set `ServerSPN=MSSQLSvc/<hostname>:<port>`
  - If user provided `--user`, format as `user id=<user>` (go-mssqldb krb5 uses this)

### 2.4 Kerberos config generation

**File:** `internal/mssql/krb5_config.go` (new)

- When `--kerberos` is used without `--krb5-configfile` and no `/etc/krb5.conf` exists:
  - Auto-generate a minimal krb5.conf from `--domain` and `--dc-ip`:
    ```ini
    [libdefaults]
        default_realm = DOMAIN.COM
        dns_lookup_kdc = true

    [realms]
        DOMAIN.COM = {
            kdc = <dc-ip>
        }
    ```
  - Write to a temp file and pass as `krb5-configfile`
- This eliminates the need for users to manually create krb5.conf when `--domain` and `--dc-ip` are provided

### 2.5 LDAP Kerberos on non-Windows

**File:** `internal/ad/gssapi_nonwindows.go`

- Currently returns error "GSSAPI/Kerberos SSPI is only supported on Windows"
- Implement using `gokrb5` directly:
  - Create `gokrb5` client from ccache/keytab (same logic as go-mssqldb's krb5 provider)
  - Use `github.com/jcmturner/gokrb5/v8/spnego` for SPNEGO/GSSAPI
  - Adapt to go-ldap's `gssapi.Client` interface
- Add Kerberos fields: `useKerberos`, `krb5ConfigFile`, `krb5CredCacheFile`, `krb5KeytabFile`, `krb5Realm` to AD `Client`

### 2.6 Collector wiring

**File:** `internal/collector/collector.go`

- Pass all Kerberos config fields to both MSSQL and AD clients
- When `--kerberos` is set, skip EPA testing (EPA is NTLM-specific, not applicable to Kerberos)
- When `--kerberos` is set without explicit LDAP creds, use Kerberos for LDAP too

---

## Phase 3: EPA Matrix Subcommand

**File:** `cmd/mssqlhound/cmd_test_epa_matrix.go`

- Add `--nt-hash` support to EPA matrix test command (EPA is NTLM-only, no Kerberos needed here)

---

## Files to Modify (ordered)

| File | Changes |
|------|---------|
| `cmd/mssqlhound/main.go` | New flags, validation, config wiring |
| `internal/collector/collector.go` | New Config fields, client setup |
| `internal/mssql/ntlm_auth.go` | NT hash support in NTLM computation |
| `internal/mssql/client.go` | NT hash + Kerberos connection string building, krb5 import |
| `internal/mssql/epa_auth_provider.go` | NT hash passthrough |
| `internal/mssql/epa_tester.go` | NT hash in EPA test config |
| `internal/ad/client.go` | NT hash + Kerberos fields, NTLMBindWithHash |
| `internal/ad/gssapi_nonwindows.go` | gokrb5-based GSSAPI for non-Windows |
| `cmd/mssqlhound/cmd_test_epa_matrix.go` | NT hash flag for EPA matrix |

## New Files

| File | Purpose |
|------|---------|
| `internal/mssql/krb5_config.go` | Auto-generate minimal krb5.conf from --domain/--dc-ip |

## Key Functions to Reuse

- `go-ldap`'s `conn.NTLMBindWithHash()` — already supports pass-the-hash for LDAP
- `go-mssqldb`'s `integratedauth/krb5` package — full Kerberos auth with ccache, keytab, user/pass
- `gokrb5` `credentials.LoadCCache()` — ccache parsing
- `gokrb5` `client.NewFromCCache()` — client from ccache
- Existing `epaAuthProvider`/`epaAuthenticator` pattern — model for Kerberos provider integration

---

## Implementation Order

1. **NT hash (Phase 1)** — smaller scope, self-contained, immediately useful
2. **Kerberos MSSQL (Phase 2.1-2.4)** — leverages existing go-mssqldb krb5 provider
3. **Kerberos LDAP non-Windows (Phase 2.5)** — extends Kerberos to AD enumeration
4. **EPA matrix (Phase 3)** — polish

---

## Verification

1. **NT hash unit test**: Add test in `ntlm_auth_test.go` that computes NTLMv2 hash from a known NT hash and verifies against expected output (MS-NLMP test vectors)
2. **Build verification**: `go build ./...` compiles cleanly
3. **Existing tests pass**: `go test ./...`
4. **CLI help output**: Verify `--help` shows new flags with correct descriptions
5. **Flag validation**: Test mutual exclusivity (`--password` + `--nt-hash` → error, `--password` + `--kerberos` → error)
6. **Integration** (manual): Test against a real MSSQL instance with an NT hash and with a Kerberos ccache
