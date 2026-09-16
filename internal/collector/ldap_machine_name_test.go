package collector

import "testing"

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
