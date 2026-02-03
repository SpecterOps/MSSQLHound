// Package ad provides Active Directory integration for SPN enumeration and SID resolution.
package ad

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// Client handles Active Directory operations via LDAP
type Client struct {
	conn             *ldap.Conn
	domain           string
	domainController string
	baseDN           string
	skipPrivateCheck bool
	ldapUser         string
	ldapPassword     string

	// Caches
	sidCache    map[string]*types.DomainPrincipal
	domainCache map[string]bool
}

// NewClient creates a new AD client
func NewClient(domain, domainController string, skipPrivateCheck bool, ldapUser, ldapPassword string) *Client {
	return &Client{
		domain:           domain,
		domainController: domainController,
		skipPrivateCheck: skipPrivateCheck,
		ldapUser:         ldapUser,
		ldapPassword:     ldapPassword,
		sidCache:         make(map[string]*types.DomainPrincipal),
		domainCache:      make(map[string]bool),
	}
}

// Connect establishes a connection to the domain controller
func (c *Client) Connect() error {
	dc := c.domainController
	if dc == "" {
		// Try to resolve domain controller
		var err error
		dc, err = c.resolveDomainController()
		if err != nil {
			return fmt.Errorf("failed to resolve domain controller: %w", err)
		}
	}

	// Connect to LDAP
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	// Set timeout
	conn.SetTimeout(30 * time.Second)

	// Try authentication methods in order of preference
	var bindErr error

	// If explicit credentials provided, try NTLM first (more reliable with explicit creds)
	if c.ldapUser != "" && c.ldapPassword != "" {
		// Attempt StartTLS first for NTLM
		_ = c.startTLS(conn, dc)

		bindErr = c.ntlmBind(conn)
		if bindErr == nil {
			c.conn = conn
			c.baseDN = domainToDN(c.domain)
			return nil
		}

		// NTLM failed, try GSSAPI with explicit creds
		bindErr = c.gssapiBind(conn, dc)
		if bindErr == nil {
			c.conn = conn
			c.baseDN = domainToDN(c.domain)
			return nil
		}

		return fmt.Errorf("failed to bind with provided credentials (NTLM and GSSAPI both failed): %w", bindErr)
	}

	// No explicit credentials - try GSSAPI with current user context
	// Attempt StartTLS to satisfy LDAP signing requirements
	_ = c.startTLS(conn, dc)

	bindErr = c.gssapiBind(conn, dc)
	if bindErr == nil {
		c.conn = conn
		c.baseDN = domainToDN(c.domain)
		return nil
	}

	return fmt.Errorf("failed to bind via GSSAPI: %w", bindErr)
}

// ntlmBind performs NTLM authentication
func (c *Client) ntlmBind(conn *ldap.Conn) error {
	// Parse domain and username
	domain := c.domain
	username := c.ldapUser

	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		domain = parts[0]
		username = parts[1]
	} else if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		domain = parts[1]
	}

	return conn.NTLMBind(domain, username, c.ldapPassword)
}

func (c *Client) gssapiBind(conn *ldap.Conn, dc string) error {
	gssClient, closeFn, err := newGSSAPIClient(c.domain, c.ldapUser, c.ldapPassword)
	if err != nil {
		return err
	}
	defer closeFn()

	serviceHost := dc
	if !strings.Contains(serviceHost, ".") && c.domain != "" {
		serviceHost = fmt.Sprintf("%s.%s", dc, c.domain)
	}

	servicePrincipal := fmt.Sprintf("ldap/%s", strings.ToLower(serviceHost))
	if err := conn.GSSAPIBind(gssClient, servicePrincipal, ""); err == nil {
		return nil
	} else {
		// Retry with short hostname SPN if FQDN failed.
		shortHost := strings.SplitN(serviceHost, ".", 2)[0]
		if shortHost != "" && shortHost != serviceHost {
			fallbackSPN := fmt.Sprintf("ldap/%s", strings.ToLower(shortHost))
			if err2 := conn.GSSAPIBind(gssClient, fallbackSPN, ""); err2 == nil {
				return nil
			}
			return fmt.Errorf("GSSAPI bind failed for %s (%v) and %s", servicePrincipal, err, fallbackSPN)
		}
		return fmt.Errorf("GSSAPI bind failed for %s: %w", servicePrincipal, err)
	}
}

func (c *Client) startTLS(conn *ldap.Conn, dc string) error {
	serverName := dc
	if !strings.Contains(serverName, ".") && c.domain != "" {
		serverName = fmt.Sprintf("%s.%s", dc, c.domain)
	}

	return conn.StartTLS(&tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
}

// Close closes the LDAP connection
func (c *Client) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

// resolveDomainController attempts to find a domain controller for the domain
func (c *Client) resolveDomainController() (string, error) {
	// Try SRV record lookup
	_, addrs, err := net.LookupSRV("ldap", "tcp", c.domain)
	if err == nil && len(addrs) > 0 {
		return strings.TrimSuffix(addrs[0].Target, "."), nil
	}

	// Fall back to using domain name directly
	return c.domain, nil
}

// EnumerateMSSQLSPNs finds all MSSQL service principal names in the domain
func (c *Client) EnumerateMSSQLSPNs() ([]types.SPN, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	// Search for accounts with MSSQLSvc SPNs
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(servicePrincipalName=MSSQLSvc/*)",
		[]string{"servicePrincipalName", "sAMAccountName", "objectSid", "distinguishedName"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var spns []types.SPN

	for _, entry := range result.Entries {
		accountName := entry.GetAttributeValue("sAMAccountName")
		sidBytes := entry.GetRawAttributeValue("objectSid")
		accountSID := decodeSID(sidBytes)

		for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
			if !strings.HasPrefix(strings.ToUpper(spn), "MSSQLSVC/") {
				continue
			}

			parsed := parseSPN(spn)
			parsed.AccountName = accountName
			parsed.AccountSID = accountSID

			spns = append(spns, parsed)
		}
	}

	return spns, nil
}

// EnumerateAllComputers returns all computer objects in the domain
func (c *Client) EnumerateAllComputers() ([]string, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=computer)(objectClass=computer))",
		[]string{"dNSHostName", "name"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var computers []string
	for _, entry := range result.Entries {
		hostname := entry.GetAttributeValue("dNSHostName")
		if hostname == "" {
			hostname = entry.GetAttributeValue("name")
		}
		if hostname != "" {
			computers = append(computers, hostname)
		}
	}

	return computers, nil
}

// ResolveSID resolves a SID to a domain principal
func (c *Client) ResolveSID(sid string) (*types.DomainPrincipal, error) {
	// Check cache first
	if cached, ok := c.sidCache[sid]; ok {
		return cached, nil
	}

	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	// Convert SID string to binary for LDAP search
	sidFilter := fmt.Sprintf("(objectSid=%s)", escapeSIDForLDAP(sid))

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		sidFilter,
		[]string{"sAMAccountName", "distinguishedName", "objectClass", "userAccountControl", "memberOf"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("SID not found: %s", sid)
	}

	entry := result.Entries[0]

	principal := &types.DomainPrincipal{
		SID:               sid,
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		Domain:            c.domain,
		MemberOf:          entry.GetAttributeValues("memberOf"),
	}

	// Determine object class
	classes := entry.GetAttributeValues("objectClass")
	for _, class := range classes {
		switch strings.ToLower(class) {
		case "user":
			principal.ObjectClass = "user"
		case "group":
			principal.ObjectClass = "group"
		case "computer":
			principal.ObjectClass = "computer"
		}
	}

	// Determine if enabled (for users/computers)
	uac := entry.GetAttributeValue("userAccountControl")
	if uac != "" {
		// UAC flag 0x0002 = ACCOUNTDISABLE
		principal.Enabled = !strings.Contains(uac, "2")
	}

	principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)
	principal.ObjectIdentifier = sid

	// Cache the result
	c.sidCache[sid] = principal

	return principal, nil
}

// ResolveName resolves a name (DOMAIN\user or user@domain) to a domain principal
func (c *Client) ResolveName(name string) (*types.DomainPrincipal, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	var samAccountName string

	// Parse the name format
	if strings.Contains(name, "\\") {
		parts := strings.SplitN(name, "\\", 2)
		samAccountName = parts[1]
	} else if strings.Contains(name, "@") {
		parts := strings.SplitN(name, "@", 2)
		samAccountName = parts[0]
	} else {
		samAccountName = name
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(samAccountName)),
		[]string{"sAMAccountName", "distinguishedName", "objectClass", "objectSid", "userAccountControl", "memberOf"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("name not found: %s", name)
	}

	entry := result.Entries[0]
	sidBytes := entry.GetRawAttributeValue("objectSid")
	sid := decodeSID(sidBytes)

	principal := &types.DomainPrincipal{
		SID:               sid,
		SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
		DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		Domain:            c.domain,
		MemberOf:          entry.GetAttributeValues("memberOf"),
		ObjectIdentifier:  sid,
	}

	// Determine object class
	classes := entry.GetAttributeValues("objectClass")
	for _, class := range classes {
		switch strings.ToLower(class) {
		case "user":
			principal.ObjectClass = "user"
		case "group":
			principal.ObjectClass = "group"
		case "computer":
			principal.ObjectClass = "computer"
		}
	}

	principal.Name = fmt.Sprintf("%s\\%s", c.domain, principal.SAMAccountName)

	// Cache by SID
	c.sidCache[sid] = principal

	return principal, nil
}

// ValidateDomain checks if a domain is reachable and valid
func (c *Client) ValidateDomain(domain string) bool {
	// Check cache
	if valid, ok := c.domainCache[domain]; ok {
		return valid
	}

	// Try to resolve the domain
	addrs, err := net.LookupHost(domain)
	if err != nil {
		c.domainCache[domain] = false
		return false
	}

	// Check if the IP is private (RFC 1918) unless skipped
	if !c.skipPrivateCheck {
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil && isPrivateIP(ip) {
				c.domainCache[domain] = true
				return true
			}
		}
		// No private IPs found
		c.domainCache[domain] = false
		return false
	}

	c.domainCache[domain] = len(addrs) > 0
	return len(addrs) > 0
}

// ResolveComputerSID resolves a computer name to its SID
// The computer name can be provided with or without the trailing $
func (c *Client) ResolveComputerSID(computerName string) (string, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return "", err
		}
	}

	// Ensure computer name ends with $ for the sAMAccountName search
	samName := computerName
	if !strings.HasSuffix(samName, "$") {
		samName = samName + "$"
	}

	// Check cache
	if cached, ok := c.sidCache[samName]; ok {
		return cached.SID, nil
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))", ldap.EscapeFilter(samName)),
		[]string{"sAMAccountName", "objectSid"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("computer not found: %s", computerName)
	}

	entry := result.Entries[0]
	sidBytes := entry.GetRawAttributeValue("objectSid")
	sid := decodeSID(sidBytes)

	if sid == "" {
		return "", fmt.Errorf("could not decode SID for computer: %s", computerName)
	}

	// Cache the result
	c.sidCache[samName] = &types.DomainPrincipal{
		SID:            sid,
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		ObjectClass:    "computer",
	}

	return sid, nil
}

// Helper functions

// domainToDN converts a domain name to an LDAP distinguished name
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, fmt.Sprintf("DC=%s", part))
	}
	return strings.Join(dnParts, ",")
}

// parseSPN parses an SPN string into its components
func parseSPN(spn string) types.SPN {
	result := types.SPN{FullSPN: spn}

	// Format: service/host:port or service/host
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) < 2 {
		return result
	}

	result.ServiceClass = parts[0]
	hostPart := parts[1]

	// Check for port or instance name
	if idx := strings.Index(hostPart, ":"); idx != -1 {
		result.Hostname = hostPart[:idx]
		portOrInstance := hostPart[idx+1:]

		// If it's a number, it's a port; otherwise instance name
		if _, err := fmt.Sscanf(portOrInstance, "%d", new(int)); err == nil {
			result.Port = portOrInstance
		} else {
			result.InstanceName = portOrInstance
		}
	} else {
		result.Hostname = hostPart
	}

	return result
}

// decodeSID converts a binary SID to a string representation
func decodeSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subAuthCount := int(b[1])

	// Build authority (6 bytes, big-endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	// Add sub-authorities (4 bytes each, little-endian)
	for i := 0; i < subAuthCount && 8+i*4+4 <= len(b); i++ {
		subAuth := uint32(b[8+i*4]) |
			uint32(b[8+i*4+1])<<8 |
			uint32(b[8+i*4+2])<<16 |
			uint32(b[8+i*4+3])<<24
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// escapeSIDForLDAP escapes a SID string for use in an LDAP filter
// This converts a SID like S-1-5-21-xxx to its binary escaped form
func escapeSIDForLDAP(sid string) string {
	// For now, use a simpler approach - search by string
	// In production, you'd want to convert the SID to binary and escape it
	return ldap.EscapeFilter(sid)
}

// isPrivateIP checks if an IP address is in a private range (RFC 1918)
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}
