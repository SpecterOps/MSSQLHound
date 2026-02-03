//go:build windows
// +build windows

package ad

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

func newGSSAPIClient(domain, user, password string) (ldap.GSSAPIClient, func() error, error) {
	if user != "" && password != "" {
		// Try multiple credential forms to satisfy SSPI requirements.
		if strings.Contains(user, "@") {
			parts := strings.SplitN(user, "@", 2)
			upnDomain := parts[1]
			upnUser := parts[0]

			// First try DOMAIN + username (common for SSPI).
			if client, err := gssapi.NewSSPIClientWithUserCredentials(upnDomain, upnUser, password); err == nil {
				return client, client.Close, nil
			}

			// Fallback: pass full UPN as username with empty domain.
			if client, err := gssapi.NewSSPIClientWithUserCredentials("", user, password); err == nil {
				return client, client.Close, nil
			}
		} else {
			userDomain, username := splitDomainUser(user, domain)
			if client, err := gssapi.NewSSPIClientWithUserCredentials(userDomain, username, password); err == nil {
				return client, client.Close, nil
			}
		}

		return nil, nil, fmt.Errorf("failed to acquire SSPI credentials for provided user")
	}

	client, err := gssapi.NewSSPIClient()
	if err != nil {
		return nil, nil, err
	}
	return client, client.Close, nil
}

func splitDomainUser(user, fallbackDomain string) (string, string) {
	if strings.Contains(user, "\\") {
		parts := strings.SplitN(user, "\\", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(user, "@") {
		// For UPN formats, pass the full UPN as the username and leave domain empty.
		return "", user
	}
	return fallbackDomain, user
}
