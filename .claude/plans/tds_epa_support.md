# Summary: TDS 8.0 + EPA Support in MSSQLHound

## Problem

When SQL Server has EPA (Extended Protection for Authentication) set to "Required", NTLM authentication must include channel binding tokens (CBT) that tie the auth to the TLS session. `go-mssqldb`'s built-in NTLM does NOT support EPA. Additionally, Go's `crypto/tls` `VerifyConnection` callback fires before TLS Finished messages, making `TLSUnique` always zero — so even a custom provider can't get the correct CBT through normal go-mssqldb hooks.

## Changes by File (12 files, ~1300 lines added)

### 1. New: `go/internal/mssql/ntlm_auth.go` — Custom NTLMv2 with EPA AV_PAIRs

Full NTLMv2 implementation with controllable AV_PAIRs:
- **MsvAvChannelBindings**: 16-byte MD5 of `SEC_CHANNEL_BINDINGS` structure using `tls-unique:` prefix + TLS Finished bytes
- **MsvAvTargetName**: SPN (e.g. `MSSQLSvc/hostname:1433`) encoded as UTF-16LE
- **MsvAvFlags**: Bit indicating MIC is present
- **MIC**: HMAC-MD5 over Type1+Type2+Type3 messages, keyed by session base key
- Five test modes: Normal, BogusCBT, MissingCBT, BogusService, MissingService
- Three diagnostic flags: `disableMIC`, `useRawTargetInfo`, `useClientTimestamp`
- Key fix: uses user-provided domain (not server's NetBIOS domain) for NTLMv2 hash, matching Windows SSPI/impacket behavior
- Key fix: real LMv2 response (not zeros), server's negotiate flags echoed in Type3

### 2. New: `go/internal/mssql/epa_auth_provider.go` — go-mssqldb Auth Bridge

Implements `integratedauth.Provider` to plug custom NTLM into go-mssqldb:
- `SetCBT(cbt)` — called from TLS dialer after handshake completes
- `SetSPN(spn)` — called before connection
- `GetIntegratedAuthenticator(config)` — creates `ntlmAuth` instance with stored CBT
- Registered as `"epa-ntlm"` via `integratedauth.SetIntegratedAuthenticationProvider`

### 3. `go/internal/mssql/tds_transport.go` — TLS-over-TDS Handshake

- `tlsOverTDSConn`: wraps TLS records inside TDS PRELOGIN packets for the TLS handshake phase
- `switchableConn`: swaps from TDS-wrapped to raw TCP after handshake
- `performTLSHandshake()`: standard TLS-in-TDS for TDS 7.x
- `performDirectTLSHandshake()`: raw TLS on socket for TDS 8.0 strict
- Both capped at TLS 1.2 — SQL Server SChannel does NOT accept `tls-server-end-point` for EPA, only `tls-unique` (which TLS 1.3 removed)

### 4. `go/internal/mssql/epa_tester.go` — EPA Detection Engine

Raw TDS+TLS+NTLM login attempts to determine EPA enforcement:
- `runEPATest()`: standard encryption path (PRELOGIN → TLS-in-TDS → LOGIN7)
- `runEPATestStrict()`: TDS 8.0 strict path (direct TLS → PRELOGIN → LOGIN7)
- Logic: Normal login succeeds? BogusCBT fails? MissingCBT fails? → Required/Allowed/Not Supported
- Auto-diagnostics on failure: raw NTLM baseline, client timestamp test, MIC bypass test
- SOCKS5 proxy support with DNS pre-resolution

### 5. `go/internal/mssql/client.go` — Connection Strategy Overhaul (largest change)

**Two custom dialers solve the TLSUnique problem:**

| Dialer | When Used | How It Works |
|--------|-----------|-------------|
| `epaTLSDialer` | TDS 8.0 strict + EPA | TCP → direct TLS (ALPN `tds/8.0`) → capture TLSUnique → return `*tls.Conn` |
| `epaTDSDialer` | Standard encryption + EPA | TCP → PRELOGIN → TLS-in-TDS → capture TLSUnique → return `preloginFakerConn` |

**`preloginFakerConn`**: intercepts go-mssqldb's PRELOGIN write (discards it), returns fake response with `encryption=NOT_SUP`, then passes through. This prevents double-TLS since go-mssqldb uses `encrypt=disable`.

**Connection strategy order:**
1. EPA+strict-TLS (if strict encryption detected)
2. EPA+TDS-TLS (if EPA required/allowed, non-strict)
3. Regular strategy loop: FQDN+encrypt, FQDN+strict, FQDN+encrypt+SPN, FQDN+no-encrypt, short+encrypt, short+strict, short+no-encrypt
4. PowerShell fallback (Windows only, not available through proxy)

### 6. `go/internal/collector/collector.go` — EPA Pre-Check + Proxy Wiring

- Runs `client.TestEPA(ctx)` **before** `client.Connect(ctx)` so the EPA result is available for dialer selection
- Factory methods `newADClient()` / `newMSSQLClient()` inject proxy dialer uniformly
- `ProxyAddr` field in `Config`

### 7. `go/internal/ad/client.go` — LDAP Through Proxy

- `dialLDAP()` method routes LDAP connections through SOCKS5 proxy
- DNS resolver rebuilt to route TCP DNS queries through proxy
- Replaces all `ldap.DialURL()` calls

### 8. `go/cmd/mssqlhound/main.go` — CLI Flags

- `--proxy` flag: SOCKS5 proxy address
- DNS resolver configured to route through proxy when both specified
- Warning messages about SQL Browser UDP limitation

### 9. New: `go/internal/proxydialer/` — Shared SOCKS5 Dialer

Centralizes SOCKS5 dialer creation, used by mssql, ad, and collector packages.

### 10. New: `go/internal/mssql/ntlm_auth_test.go` — Unit Tests

Tests for NTLMv2 hash, NTProofStr, MIC, CBT hash (both binding types), full exchange, UTF-16LE encoding.

## Key Technical Insight

```
EPA test (raw TLS):     TLSUnique = 49a30ec6880a7f38e6301a77  ← correct, auth succeeds
go-mssqldb VerifyConn:  TLSUnique = 000000000000000000000000  ← all zeros, auth fails
```

Go's `VerifyConnection` fires during `doFullHandshake()` → BEFORE `sendFinished()` sets `firstFinished`. The solution: do TLS ourselves in custom dialers, call `ConnectionState().TLSUnique` after `Handshake()` fully completes.
