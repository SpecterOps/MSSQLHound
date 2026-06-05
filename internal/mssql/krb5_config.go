// Package mssql - Kerberos configuration helpers.
// Auto-generates a minimal krb5.conf when --domain and --dc are provided
// but no explicit krb5.conf path is given. This avoids requiring users to
// manually create /etc/krb5.conf on systems where it doesn't exist.
package mssql

import (
	"fmt"
	"os"
	"strings"
)

// generateKrb5Config creates a minimal krb5.conf in a temp file and returns its path.
// The caller is responsible for cleaning up the file (e.g. via os.Remove or defer).
func GenerateKrb5Config(domain, kdcAddress string) (string, error) {
	realm := strings.ToUpper(domain)

	content := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    udp_preference_limit = 1

[realms]
    %s = {
        kdc = %s
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, kdcAddress,
		strings.ToLower(domain), realm,
		strings.ToLower(domain), realm)

	f, err := os.CreateTemp("", "mssqlhound-krb5-*.conf")
	if err != nil {
		return "", fmt.Errorf("creating temp krb5.conf: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("writing temp krb5.conf: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("closing temp krb5.conf: %w", err)
	}
	return f.Name(), nil
}
