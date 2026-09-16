package collector

import (
	"testing"

	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// TestDeriveLDAPMachineName covers resolveComputerSIDViaLDAP's machine-name derivation,
// in particular that an IP-literal target (e.g. -t 10.112.0.74) doesn't get chopped up
// as if it were a dotted hostname (which previously produced a bogus one-octet name
// like "10" and made LDAP computer SID resolution fail for IP targets).
func TestDeriveLDAPMachineName(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		fqdn     string
		wantName string
		wantOK   bool
	}{
		{
			name:     "FQDN hostname is split to short name",
			hostname: "ps1-db.mayyhem.com",
			fqdn:     "ps1-db.mayyhem.com",
			wantName: "ps1-db",
			wantOK:   true,
		},
		{
			name:     "short hostname is used as-is",
			hostname: "ps1-db",
			fqdn:     "ps1-db.mayyhem.com",
			wantName: "ps1-db",
			wantOK:   true,
		},
		{
			name:     "IPv4 hostname falls back to resolved FQDN",
			hostname: "10.112.0.74",
			fqdn:     "ps1-db.mayyhem.com",
			wantName: "ps1-db",
			wantOK:   true,
		},
		{
			name:     "IPv4 hostname with no FQDN resolved is unresolvable",
			hostname: "10.112.0.74",
			fqdn:     "",
			wantOK:   false,
		},
		{
			name:     "IPv4 hostname with FQDN falling back to the same IP is unresolvable",
			hostname: "10.112.0.74",
			fqdn:     "10.112.0.74",
			wantOK:   false,
		},
		{
			name:     "IPv6 hostname falls back to resolved FQDN",
			hostname: "::1",
			fqdn:     "localhost.mayyhem.com",
			wantName: "localhost",
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotOK := deriveLDAPMachineName(tt.hostname, tt.fqdn)
			if gotOK != tt.wantOK {
				t.Fatalf("deriveLDAPMachineName(%q, %q) ok = %v, want %v", tt.hostname, tt.fqdn, gotOK, tt.wantOK)
			}
			if gotOK && gotName != tt.wantName {
				t.Fatalf("deriveLDAPMachineName(%q, %q) name = %q, want %q", tt.hostname, tt.fqdn, gotName, tt.wantName)
			}
		})
	}
}

// TestIsLinkedServerSourceCurrentServer covers the linked-server source-identity check that
// backs MSSQL_LinkedTo/MSSQL_LinkedAsAdmin edge sourcing. When a server is targeted by IP
// (e.g. -t 10.112.0.83), serverInfo.Hostname never string-matches SQL Server's own
// self-reported SourceServer name, which previously made the collector treat the server's
// own linked-server entry as if it came from a different (chained) server, sourcing the edge
// from a synthetic "LinkedServer:<name>" placeholder instead of the real MSSQL_Server node.
func TestIsLinkedServerSourceCurrentServer(t *testing.T) {
	tests := []struct {
		name         string
		sourceServer string
		serverInfo   types.ServerInfo
		want         bool
	}{
		{
			name:         "hostname matches directly",
			sourceServer: "ps1-db.mayyhem.com",
			serverInfo:   types.ServerInfo{Hostname: "ps1-db.mayyhem.com"},
			want:         true,
		},
		{
			name:         "IP hostname falls back to FQDN-derived short name",
			sourceServer: "monitor",
			serverInfo:   types.ServerInfo{Hostname: "10.112.0.83", FQDN: "monitor.mayyhem.com"},
			want:         true,
		},
		{
			name:         "IP hostname with no DNS at all falls back to SQL-reported ServerName",
			sourceServer: "monitor",
			serverInfo:   types.ServerInfo{Hostname: "10.112.0.83", FQDN: "10.112.0.83", ServerName: "monitor"},
			want:         true,
		},
		{
			name:         "genuinely different (chained) server",
			sourceServer: "cas-db",
			serverInfo:   types.ServerInfo{Hostname: "10.112.0.83", FQDN: "monitor.mayyhem.com", ServerName: "monitor"},
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLinkedServerSourceCurrentServer(tt.sourceServer, &tt.serverInfo)
			if got != tt.want {
				t.Fatalf("isLinkedServerSourceCurrentServer(%q, %+v) = %v, want %v", tt.sourceServer, tt.serverInfo, got, tt.want)
			}
		})
	}
}
