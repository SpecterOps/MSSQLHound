# LDAP SSPI Fix Plan

## Goal
Make Windows LDAP enumeration use native SSPI integrated authentication when no explicit LDAP credentials are supplied, matching ShareHound behavior.

## Tasks
1. Inspect MSSQLHound LDAP connection and bind selection logic.
2. Inspect ShareHound Windows LDAP/SSPI implementation for the working pattern.
3. Implement the minimal Windows-specific SSPI path or correct the existing selection logic.
4. Add focused unit coverage where feasible without requiring a live domain controller.
5. Run `go test ./...` and address failures related to this change.

## Follow-up
1. Keep successful Windows ADSI fallback logs concise at info level.
2. Preserve the full Go LDAP failure only at verbose level for troubleshooting.
3. Re-run `go test ./...` and rebuild `mssqlhound.exe`.

## Go ADSI Computer Enumeration
1. Add an in-process Windows ADSI/ADO computer enumeration helper in Go; do not fork PowerShell.
2. Use the same filter and attributes as ShareHound's Go LDAP path: all computer objects, `dNSHostName` first and `name` as fallback.
3. Route `--scan-all-computers` Windows fallback to the Go helper.
4. Add non-Windows stub/tests, run `go test ./...`, and rebuild `mssqlhound.exe`.

## IP Deduplication Progress
1. Resolve unique hostnames concurrently instead of serially resolving every server entry.
2. Emit info-level progress during DNS resolution and final dedupe processing.
3. Preserve existing input-order dedupe preference behavior.
