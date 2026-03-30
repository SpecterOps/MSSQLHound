//go:build integration

package collector

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/microsoft/go-mssqldb"
)

// integrationConfig holds configuration for integration tests, loaded from environment variables.
type integrationConfig struct {
	ServerInstance string // SQL Server instance (default: ps1-db.mayyhem.com)
	UserID         string // Sysadmin user for setup (empty = Windows auth)
	Password       string // Sysadmin password
	Domain         string // AD domain name (default: $USERDOMAIN)
	DCIP           string // Domain controller (optional, auto-discovered)
	LDAPUser       string // LDAP credentials for AD operations
	LDAPPassword   string // LDAP password
	LimitToEdge    string // Limit to specific edge type (optional)
	SkipDomain     bool   // Skip AD object creation
	Action         string // "all", "setup", "test", "teardown", "coverage" (default: "all")
	SkipHTMLReport bool   // Skip HTML report generation
	ZipFile        string // Path to existing MSSQLHound .zip output to validate

	// Enumeration user (defaults to MSSQL_USER/MSSQL_PASSWORD)
	EnumUserID   string
	EnumPassword string
}

func loadIntegrationConfig() *integrationConfig {
	cfg := &integrationConfig{
		ServerInstance: envOrDefault("MSSQL_SERVER", "ps1-db.mayyhem.com"),
		UserID:         os.Getenv("MSSQL_USER"),
		Password:       os.Getenv("MSSQL_PASSWORD"),
		Domain:         envOrDefault("MSSQL_DOMAIN", os.Getenv("USERDOMAIN")),
		DCIP:           os.Getenv("MSSQL_DC"),
		LDAPUser:       os.Getenv("LDAP_USER"),
		LDAPPassword:   os.Getenv("LDAP_PASSWORD"),
		LimitToEdge:    os.Getenv("MSSQL_LIMIT_EDGE"),
		SkipDomain:     os.Getenv("MSSQL_SKIP_DOMAIN") == "true",
		Action:         envOrDefault("MSSQL_ACTION", "all"),
		SkipHTMLReport: os.Getenv("MSSQL_SKIP_HTML") == "true",
		ZipFile:        os.Getenv("MSSQL_ZIP"),
		EnumUserID:     envOrDefault("MSSQL_ENUM_USER", os.Getenv("MSSQL_USER")),
		EnumPassword:   envOrDefault("MSSQL_ENUM_PASSWORD", os.Getenv("MSSQL_PASSWORD")),
	}
	return cfg
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// =============================================================================
// SQL CONNECTION
// =============================================================================

// resolveServerInstance resolves the server hostname using the DC as DNS resolver
// when DCIP is set and the system resolver can't resolve the hostname.
// Returns the instance string with the hostname replaced by the resolved IP if needed.
func resolveServerInstance(instance, dcIP string) string {
	if dcIP == "" {
		return instance
	}

	// Split instance into host and optional port/instance-name parts
	host := instance
	suffix := ""
	if idx := strings.LastIndex(instance, ":"); idx != -1 {
		host = instance[:idx]
		suffix = instance[idx:]
	} else if idx := strings.Index(instance, "\\"); idx != -1 {
		host = instance[:idx]
		suffix = instance[idx:]
	}

	// Skip if already an IP
	if net.ParseIP(host) != nil {
		return instance
	}

	// Try resolving with the custom DNS resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dcIP, "53"))
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return instance // fall back to original
	}

	return addrs[0] + suffix
}

// connectSQL creates a SQL connection for setup/teardown operations (sysadmin).
func connectSQL(cfg *integrationConfig) (*sql.DB, error) {
	// Resolve hostname via DC if system DNS can't reach the server
	serverInstance := resolveServerInstance(cfg.ServerInstance, cfg.DCIP)

	var connStr string
	if cfg.UserID != "" {
		connStr = fmt.Sprintf("sqlserver://%s@%s?database=master&encrypt=disable",
			url.UserPassword(cfg.UserID, cfg.Password).String(), serverInstance)
	} else {
		// Windows authentication
		connStr = fmt.Sprintf("sqlserver://%s?database=master&encrypt=disable&integrated+security=sspi",
			serverInstance)
	}

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQL connection: %w", err)
	}

	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxOpenConns(5)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping SQL Server %s: %w", cfg.ServerInstance, err)
	}

	return db, nil
}

// =============================================================================
// SQL BATCH EXECUTION
// =============================================================================

// executeSQLBatches splits SQL on GO statements and executes each batch.
// This mirrors the PS1 Invoke-TestSQL function's batch handling.
func executeSQLBatches(ctx context.Context, db *sql.DB, script string, timeout int) error {
	if timeout == 0 {
		timeout = 60
	}

	batches := splitSQLBatches(script)

	currentDB := "master"
	for i, batch := range batches {
		batch = strings.TrimSpace(batch)
		if batch == "" {
			continue
		}

		batchCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)

		// Execute the batch, prepending USE if needed to maintain database context
		execSQL := batch
		if currentDB != "master" && !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(batch)), "USE ") {
			execSQL = fmt.Sprintf("USE [%s];\n%s", currentDB, batch)
		}

		_, err := db.ExecContext(batchCtx, execSQL)
		cancel()
		if err != nil {
			return fmt.Errorf("batch %d failed (database: %s): %w\nSQL: %s",
				i+1, currentDB, err, truncateSQL(batch, 200))
		}

		// Update currentDB AFTER execution so USE statements within a batch
		// affect subsequent batches, not the current one
		if useDB := extractUseDatabase(batch); useDB != "" {
			currentDB = useDB
		}
	}

	return nil
}

// splitSQLBatches splits a SQL script on GO statement lines.
func splitSQLBatches(script string) []string {
	// GO must be on its own line (optionally preceded/followed by whitespace)
	goPattern := regexp.MustCompile(`(?mi)^\s*GO\s*$`)
	parts := goPattern.Split(script, -1)

	var batches []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			batches = append(batches, p)
		}
	}
	return batches
}

// extractUseDatabase extracts the database name from a USE statement.
func extractUseDatabase(sql string) string {
	usePattern := regexp.MustCompile(`(?i)^\s*USE\s+\[?([^\];\s]+)\]?\s*;?\s*$`)
	lines := strings.Split(sql, "\n")
	for _, line := range lines {
		if m := usePattern.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1]
		}
	}
	return ""
}

func truncateSQL(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// =============================================================================
// DOMAIN SUBSTITUTION
// =============================================================================

// substituteDomain replaces domain references in SQL scripts.
// Handles both $Domain placeholders and hardcoded MAYYHEM references.
func substituteDomain(sql, domain string) string {
	if domain == "" {
		return sql
	}

	// Extract NetBIOS name (first component) for DOMAIN\user style references.
	// SQL Server expects NetBIOS names (e.g. MAYYHEM\user), not FQDNs (mayyhem.com\user).
	netbios := strings.ToUpper(domain)
	if idx := strings.Index(netbios, "."); idx != -1 {
		netbios = netbios[:idx]
	}

	// Replace $Domain placeholder (used in scripts that had PS1 interpolation)
	sql = strings.ReplaceAll(sql, "$Domain", netbios)

	// Replace hardcoded MAYYHEM domain
	sql = strings.ReplaceAll(sql, "MAYYHEM\\", netbios+"\\")

	return sql
}

// =============================================================================
// AD OBJECT CREATION VIA LDAP
// =============================================================================

// domainToDN converts a domain name to an LDAP distinguished name.
// e.g., "mayyhem.com" -> "DC=mayyhem,DC=com"
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dn []string
	for _, p := range parts {
		dn = append(dn, "DC="+p)
	}
	return strings.Join(dn, ",")
}

// ldapConnect establishes an LDAP connection to the domain controller.
func ldapConnect(cfg *integrationConfig) (*ldap.Conn, string, error) {
	dc := cfg.DCIP
	if dc == "" {
		dc = cfg.Domain
	}

	baseDN := domainToDN(cfg.Domain)

	// Try LDAPS first (port 636)
	conn, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:636", dc),
		ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}))
	if err != nil {
		// Fall back to LDAP (port 389)
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
		if err != nil {
			return nil, "", fmt.Errorf("failed to connect to LDAP on %s: %w", dc, err)
		}
	}

	// Bind with credentials
	if cfg.LDAPUser != "" {
		bindDN := cfg.LDAPUser
		if !strings.Contains(bindDN, "=") {
			// Simple username - construct bind DN
			if strings.Contains(bindDN, "\\") {
				// DOMAIN\user format - use UPN bind
				parts := strings.SplitN(bindDN, "\\", 2)
				bindDN = fmt.Sprintf("%s@%s", parts[1], cfg.Domain)
			}
		}
		if err := conn.Bind(bindDN, cfg.LDAPPassword); err != nil {
			conn.Close()
			return nil, "", fmt.Errorf("LDAP bind failed: %w", err)
		}
	}

	return conn, baseDN, nil
}

// createDomainObjects creates all test AD objects needed for integration tests.
func createDomainObjects(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	if cfg.SkipDomain {
		t.Log("Skipping domain object creation (MSSQL_SKIP_DOMAIN=true)")
		return
	}

	conn, baseDN, err := ldapConnect(cfg)
	if err != nil {
		t.Fatalf("Failed to connect to LDAP: %v", err)
	}
	defer conn.Close()

	usersOU := "CN=Users," + baseDN
	computersOU := "CN=Computers," + baseDN

	// Create domain users
	domainUsers := []string{
		"EdgeTestDomainUser1",
		"EdgeTestDomainUser2",
		"EdgeTestSysadmin",
		"EdgeTestServiceAcct",
		"EdgeTestDisabledUser",
		"EdgeTestNoConnect",
		"EdgeTestCoerce",
		"CoerceTestUser",
	}

	for _, username := range domainUsers {
		createDomainUser(t, conn, usersOU, username, "TestP@ssw0rd123!")
	}

	// Create computer accounts
	computers := []string{
		"TestComputer",
		"CoerceTestEnabled1",
		"CoerceTestEnabled2",
		"CoerceTestDisabled",
		"CoerceTestNoConnect",
	}

	for _, name := range computers {
		createComputerAccount(t, conn, computersOU, name)
	}

	// Create security group with membership
	createSecurityGroup(t, conn, usersOU, "EdgeTestDomainGroup")
	addGroupMember(t, conn, "CN=EdgeTestDomainGroup,"+usersOU, "CN=EdgeTestDomainUser1,"+usersOU)
}

// createDomainUser creates an AD user via LDAP.
func createDomainUser(t *testing.T, conn *ldap.Conn, ouDN, username, password string) {
	t.Helper()

	dn := fmt.Sprintf("CN=%s,%s", username, ouDN)

	// Check if user already exists
	searchReq := ldap.NewSearchRequest(
		ouDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", username),
		[]string{"dn"}, nil)
	sr, err := conn.Search(searchReq)
	if err == nil && len(sr.Entries) > 0 {
		t.Logf("Domain user already exists: %s", username)
		return
	}

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("cn", []string{username})
	addReq.Attribute("sAMAccountName", []string{username})
	addReq.Attribute("userPrincipalName", []string{username + "@" + strings.ToLower(extractDomainFromDN(ouDN))})
	addReq.Attribute("userAccountControl", []string{"544"}) // NORMAL_ACCOUNT + PASSWD_NOTREQD

	if err := conn.Add(addReq); err != nil {
		t.Logf("Warning: Failed to create domain user %s: %v", username, err)
		return
	}

	// Set password using LDAP modify
	encodedPassword := encodeADPassword(password)
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Replace("unicodePwd", []string{encodedPassword})
	modReq.Replace("userAccountControl", []string{"512"}) // NORMAL_ACCOUNT (enable)

	if err := conn.Modify(modReq); err != nil {
		t.Logf("Warning: Failed to set password for %s: %v", username, err)
	}

	t.Logf("Created domain user: %s", username)
}

// createComputerAccount creates an AD computer account via LDAP.
func createComputerAccount(t *testing.T, conn *ldap.Conn, ouDN, name string) {
	t.Helper()

	dn := fmt.Sprintf("CN=%s,%s", name, ouDN)

	// Check if computer already exists
	searchReq := ldap.NewSearchRequest(
		ouDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s$)", name),
		[]string{"dn"}, nil)
	sr, err := conn.Search(searchReq)
	if err == nil && len(sr.Entries) > 0 {
		t.Logf("Computer account already exists: %s", name)
		return
	}

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{name})
	addReq.Attribute("sAMAccountName", []string{name + "$"})
	addReq.Attribute("userAccountControl", []string{"4096"}) // WORKSTATION_TRUST_ACCOUNT

	if err := conn.Add(addReq); err != nil {
		t.Logf("Warning: Failed to create computer account %s: %v", name, err)
		return
	}

	t.Logf("Created computer account: %s$", name)
}

// createSecurityGroup creates an AD security group via LDAP.
func createSecurityGroup(t *testing.T, conn *ldap.Conn, ouDN, name string) {
	t.Helper()

	dn := fmt.Sprintf("CN=%s,%s", name, ouDN)

	// Check if group already exists
	searchReq := ldap.NewSearchRequest(
		ouDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", name),
		[]string{"dn"}, nil)
	sr, err := conn.Search(searchReq)
	if err == nil && len(sr.Entries) > 0 {
		t.Logf("Security group already exists: %s", name)
		return
	}

	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"top", "group"})
	addReq.Attribute("cn", []string{name})
	addReq.Attribute("sAMAccountName", []string{name})
	addReq.Attribute("groupType", []string{"-2147483646"}) // Global Security group

	if err := conn.Add(addReq); err != nil {
		t.Logf("Warning: Failed to create security group %s: %v", name, err)
		return
	}

	t.Logf("Created security group: %s", name)
}

// addGroupMember adds a member to an AD group via LDAP.
func addGroupMember(t *testing.T, conn *ldap.Conn, groupDN, memberDN string) {
	t.Helper()

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Add("member", []string{memberDN})

	if err := conn.Modify(modReq); err != nil {
		if !strings.Contains(err.Error(), "Already Exists") &&
			!strings.Contains(err.Error(), "ENTRY_EXISTS") {
			t.Logf("Warning: Failed to add %s to group %s: %v", memberDN, groupDN, err)
		}
	}
}

// removeDomainObjects deletes all test AD objects.
func removeDomainObjects(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	if cfg.SkipDomain {
		t.Log("Skipping domain object removal (MSSQL_SKIP_DOMAIN=true)")
		return
	}

	conn, baseDN, err := ldapConnect(cfg)
	if err != nil {
		t.Logf("Warning: Failed to connect to LDAP for cleanup: %v", err)
		return
	}
	defer conn.Close()

	usersOU := "CN=Users," + baseDN
	computersOU := "CN=Computers," + baseDN

	// Delete in reverse order: group first (has members), then users and computers
	objectsToDelete := []string{
		"CN=EdgeTestDomainGroup," + usersOU,
		"CN=EdgeTestDomainUser1," + usersOU,
		"CN=EdgeTestDomainUser2," + usersOU,
		"CN=EdgeTestSysadmin," + usersOU,
		"CN=EdgeTestServiceAcct," + usersOU,
		"CN=EdgeTestDisabledUser," + usersOU,
		"CN=EdgeTestNoConnect," + usersOU,
		"CN=EdgeTestCoerce," + usersOU,
		"CN=CoerceTestUser," + usersOU,
		"CN=TestComputer," + computersOU,
		"CN=CoerceTestEnabled1," + computersOU,
		"CN=CoerceTestEnabled2," + computersOU,
		"CN=CoerceTestDisabled," + computersOU,
		"CN=CoerceTestNoConnect," + computersOU,
	}

	for _, dn := range objectsToDelete {
		delReq := ldap.NewDelRequest(dn, nil)
		if err := conn.Del(delReq); err != nil {
			if !strings.Contains(err.Error(), "No Such Object") {
				t.Logf("Warning: Failed to delete %s: %v", dn, err)
			}
		} else {
			t.Logf("Deleted domain object: %s", dn)
		}
	}
}

// =============================================================================
// SETUP / TEARDOWN ORCHESTRATION
// =============================================================================

// runSetup executes the full test environment setup.
func runSetup(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	t.Logf("Using %d embedded setup scripts", len(setupScripts))

	// 1. Connect to SQL Server as sysadmin
	db, err := connectSQL(cfg)
	if err != nil {
		t.Fatalf("Failed to connect to SQL Server: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 2. Run cleanup first (idempotent)
	t.Log("Running cleanup SQL...")
	cleanup := substituteDomain(cleanupSQL, cfg.Domain)
	if err := executeSQLBatches(ctx, db, cleanup, 120); err != nil {
		t.Logf("Cleanup had warnings (normal on first run): %v", err)
	}

	// 3. Create AD domain objects
	t.Log("Creating domain objects...")
	createDomainObjects(t, cfg)

	// 4. Run all setup scripts
	for edgeType, sqlScript := range setupScripts {
		if cfg.LimitToEdge != "" {
			shortName := strings.TrimPrefix(cfg.LimitToEdge, "MSSQL_")
			if !strings.EqualFold(edgeType, shortName) {
				continue
			}
		}

		t.Logf("Setting up MSSQL_%s test environment...", edgeType)
		resolved := substituteDomain(sqlScript, cfg.Domain)
		if err := executeSQLBatches(ctx, db, resolved, 60); err != nil {
			t.Fatalf("Failed to setup MSSQL_%s: %v", edgeType, err)
		}
	}

	t.Log("Test environment setup completed successfully")
}

// runTeardown cleans up the test environment.
func runTeardown(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	// 1. Connect to SQL Server
	db, err := connectSQL(cfg)
	if err != nil {
		t.Fatalf("Failed to connect to SQL Server: %v", err)
	}
	defer db.Close()

	// 2. Run cleanup SQL
	t.Log("Running cleanup SQL...")
	ctx := context.Background()
	cleanup := substituteDomain(cleanupSQL, cfg.Domain)
	if err := executeSQLBatches(ctx, db, cleanup, 120); err != nil {
		t.Logf("Warning: Cleanup had errors: %v", err)
	}

	// 3. Remove AD objects
	t.Log("Removing domain objects...")
	removeDomainObjects(t, cfg)

	t.Log("Teardown completed")
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// encodeADPassword encodes a password for AD LDAP unicodePwd attribute.
func encodeADPassword(password string) string {
	quotedPassword := "\"" + password + "\""
	encoded := make([]byte, len(quotedPassword)*2)
	for i, c := range quotedPassword {
		encoded[i*2] = byte(c)
		encoded[i*2+1] = byte(c >> 8)
	}
	return string(encoded)
}

// extractDomainFromDN extracts the domain name from a distinguished name.
// e.g., "CN=Users,DC=mayyhem,DC=com" -> "mayyhem.com"
func extractDomainFromDN(dn string) string {
	var parts []string
	for _, component := range strings.Split(dn, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.Join(parts, ".")
}
