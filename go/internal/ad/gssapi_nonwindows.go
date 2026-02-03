//go:build !windows
// +build !windows

package ad

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func newGSSAPIClient(domain, user, password string) (ldap.GSSAPIClient, func() error, error) {
	return nil, nil, fmt.Errorf("GSSAPI/Kerberos SSPI is only supported on Windows")
}
