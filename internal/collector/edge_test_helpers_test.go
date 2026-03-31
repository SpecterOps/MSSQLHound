package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// ---------------------------------------------------------------------------
// Test case definitions
// ---------------------------------------------------------------------------

// edgeTestCase describes a single expected (or unexpected) edge in the output.
// It mirrors the PowerShell expectedEdges hashtable structure.
type edgeTestCase struct {
	EdgeType       string                 // BloodHound edge kind (e.g. "MSSQL_AddMember")
	Description    string                 // Human-readable description of what is being tested
	SourcePattern  string                 // Wildcard or exact-match pattern for edge start value
	TargetPattern  string                 // Wildcard or exact-match pattern for edge end value
	Negative       bool                   // If true, this edge must NOT exist
	Reason         string                 // Explanation for negative tests
	EdgeProperties map[string]interface{} // Property assertions (e.g. traversable)
	ExpectedCount  int                    // If >0, assert exactly N matching edges
}

// ---------------------------------------------------------------------------
// Pattern matching (port of PS1 Test-EdgePattern)
// ---------------------------------------------------------------------------

// matchPattern implements PowerShell -like glob semantics.
// It supports '*' as a multi-character wildcard and '?' as a single-character wildcard.
// Matching is case-insensitive.
func matchPattern(value, pattern string) bool {
	v := strings.ToUpper(value)
	p := strings.ToUpper(pattern)
	return globMatch(v, p)
}

// globMatch is a recursive glob matcher supporting * and ? wildcards.
func globMatch(str, pattern string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Skip consecutive stars
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			// Try matching the rest of the pattern at each position
			for i := 0; i <= len(str); i++ {
				if globMatch(str[i:], pattern) {
					return true
				}
			}
			return false
		case '?':
			if len(str) == 0 {
				return false
			}
			str = str[1:]
			pattern = pattern[1:]
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
			str = str[1:]
			pattern = pattern[1:]
		}
	}
	return len(str) == 0
}

// matchEdgeEndpoint implements the PS1 Test-EdgePattern source/target matching logic:
//   - If the pattern contains a wildcard (* or ?), use glob matching.
//   - Otherwise, if the pattern contains '@', extract the name part before '@'
//     from both pattern and actual value, and compare those.
//   - Otherwise, do an exact case-insensitive comparison.
func matchEdgeEndpoint(actual, pattern string) bool {
	hasWildcard := strings.ContainsAny(pattern, "*?")

	if hasWildcard {
		return matchPattern(actual, pattern)
	}

	if strings.Contains(pattern, "@") {
		patternName := strings.SplitN(pattern, "@", 2)[0]
		actualName := actual
		if idx := strings.Index(actual, "@"); idx >= 0 {
			actualName = actual[:idx]
		}
		return strings.EqualFold(actualName, patternName)
	}

	return strings.EqualFold(actual, pattern)
}

// ---------------------------------------------------------------------------
// Edge finding and assertion helpers
// ---------------------------------------------------------------------------

// findEdges returns all edges matching the given kind and source/target patterns.
func findEdges(edges []bloodhound.Edge, kind, srcPattern, tgtPattern string) []bloodhound.Edge {
	var matches []bloodhound.Edge
	for _, e := range edges {
		if e.Kind != kind {
			continue
		}
		if !matchEdgeEndpoint(e.Start.Value, srcPattern) {
			continue
		}
		if !matchEdgeEndpoint(e.End.Value, tgtPattern) {
			continue
		}
		matches = append(matches, e)
	}
	return matches
}

// assertEdgeExists asserts that at least one edge matches.
func assertEdgeExists(t *testing.T, edges []bloodhound.Edge, kind, srcPattern, tgtPattern, desc string) {
	t.Helper()
	matches := findEdges(edges, kind, srcPattern, tgtPattern)
	if len(matches) == 0 {
		t.Errorf("MISSING edge: %s\n  Kind: %s\n  Source: %s\n  Target: %s", desc, kind, srcPattern, tgtPattern)
	}
}

// assertEdgeNotExists asserts that no edges match.
func assertEdgeNotExists(t *testing.T, edges []bloodhound.Edge, kind, srcPattern, tgtPattern, desc string) {
	t.Helper()
	matches := findEdges(edges, kind, srcPattern, tgtPattern)
	if len(matches) > 0 {
		t.Errorf("UNEXPECTED edge: %s\n  Kind: %s\n  Source: %s\n  Target: %s\n  Found %d match(es):",
			desc, kind, srcPattern, tgtPattern, len(matches))
		for _, m := range matches {
			t.Errorf("    %s -> %s", m.Start.Value, m.End.Value)
		}
	}
}

// assertEdgeCount asserts that exactly count edges match.
func assertEdgeCount(t *testing.T, edges []bloodhound.Edge, kind, srcPattern, tgtPattern string, count int, desc string) {
	t.Helper()
	matches := findEdges(edges, kind, srcPattern, tgtPattern)
	if len(matches) != count {
		t.Errorf("WRONG COUNT for edge: %s\n  Kind: %s\n  Source: %s\n  Target: %s\n  Expected: %d, Got: %d",
			desc, kind, srcPattern, tgtPattern, count, len(matches))
	}
}

// assertEdgeProperty asserts that at least one matching edge has the given property value.
func assertEdgeProperty(t *testing.T, edges []bloodhound.Edge, kind, srcPattern, tgtPattern, propName string, propValue interface{}, desc string) {
	t.Helper()
	matches := findEdges(edges, kind, srcPattern, tgtPattern)
	if len(matches) == 0 {
		t.Errorf("MISSING edge (property check): %s\n  Kind: %s\n  Source: %s\n  Target: %s",
			desc, kind, srcPattern, tgtPattern)
		return
	}
	for _, m := range matches {
		if val, ok := m.Properties[propName]; ok && val == propValue {
			return
		}
	}
	t.Errorf("PROPERTY MISMATCH for edge: %s\n  Kind: %s\n  Source: %s\n  Target: %s\n  Property: %s expected=%v",
		desc, kind, srcPattern, tgtPattern, propName, propValue)
}

// ---------------------------------------------------------------------------
// Test case runner
// ---------------------------------------------------------------------------

// runSingleTestCase dispatches a single test case against the edges.
func runSingleTestCase(t *testing.T, edges []bloodhound.Edge, tc edgeTestCase) {
	t.Helper()

	if tc.Negative {
		assertEdgeNotExists(t, edges, tc.EdgeType, tc.SourcePattern, tc.TargetPattern, tc.Description)
		return
	}

	if tc.ExpectedCount > 0 {
		assertEdgeCount(t, edges, tc.EdgeType, tc.SourcePattern, tc.TargetPattern, tc.ExpectedCount, tc.Description)
		return
	}

	assertEdgeExists(t, edges, tc.EdgeType, tc.SourcePattern, tc.TargetPattern, tc.Description)

	// Check additional property assertions
	for propName, propValue := range tc.EdgeProperties {
		assertEdgeProperty(t, edges, tc.EdgeType, tc.SourcePattern, tc.TargetPattern, propName, propValue, tc.Description)
	}
}


// ---------------------------------------------------------------------------
// Edge creation test runner
// ---------------------------------------------------------------------------

// edgeTestResult holds the nodes and edges produced by running edge creation.
type edgeTestResult struct {
	Nodes []bloodhound.Node
	Edges []bloodhound.Edge
}

// runEdgeCreation builds a collector, writes nodes for the given ServerInfo,
// calls createEdges (which internally calls createFixedRoleEdges), and reads
// back the resulting nodes and edges.
func runEdgeCreation(t *testing.T, serverInfo *types.ServerInfo, includeNontraversable bool) edgeTestResult {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "mssqlhound-edge-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	config := &Config{
		TempDir:                    tmpDir,
		Domain:                     "domain.com",
		IncludeNontraversableEdges: includeNontraversable,
	}
	c, _ := New(config)

	outputPath := filepath.Join(tmpDir, "test-output.json")
	writer, err := bloodhound.NewStreamingWriter(outputPath)
	if err != nil {
		t.Fatalf("Failed to create writer: %v", err)
	}

	// Write server node
	serverNode := c.createServerNode(serverInfo)
	if err := writer.WriteNode(serverNode); err != nil {
		t.Fatalf("Failed to write server node: %v", err)
	}

	// Write database nodes and their principal nodes
	for i := range serverInfo.Databases {
		db := &serverInfo.Databases[i]
		dbNode := c.createDatabaseNode(db, serverInfo)
		if err := writer.WriteNode(dbNode); err != nil {
			t.Fatalf("Failed to write database node: %v", err)
		}
		for j := range db.DatabasePrincipals {
			principalNode := c.createDatabasePrincipalNode(&db.DatabasePrincipals[j], db, serverInfo)
			if err := writer.WriteNode(principalNode); err != nil {
				t.Fatalf("Failed to write database principal node: %v", err)
			}
		}
	}

	// Write server principal nodes
	for i := range serverInfo.ServerPrincipals {
		principalNode := c.createServerPrincipalNode(&serverInfo.ServerPrincipals[i], serverInfo, nil)
		if err := writer.WriteNode(principalNode); err != nil {
			t.Fatalf("Failed to write server principal node: %v", err)
		}
	}

	// Create edges (this internally calls createFixedRoleEdges)
	if err := c.createEdges(writer, serverInfo); err != nil {
		t.Fatalf("Failed to create edges: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	nodes, edges, err := bloodhound.ReadFromFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	return edgeTestResult{Nodes: nodes, Edges: edges}
}

// ---------------------------------------------------------------------------
// Mock data builder utilities
// ---------------------------------------------------------------------------

const (
	testDomainSID = "S-1-5-21-1000000000-2000000000-3000000000"
	testServerSID = testDomainSID + "-1001"
	testServerOID = testServerSID + ":1433"
	testSQLName   = "edgetest.domain.com:1433"
	testHostname  = "edgetest"
)

// nextSID is a simple counter used to generate unique SIDs in mock data.
var nextSID = 10000

func uniqueSID() string {
	nextSID++
	return fmt.Sprintf("%s-%d", testDomainSID, nextSID)
}

// nextPrincipalID is a counter for generating unique principal IDs.
var nextPrincipalID = 1000

func uniquePrincipalID() int {
	nextPrincipalID++
	return nextPrincipalID
}

// nextDBID is a counter for generating unique database IDs.
var nextDBID = 100

func uniqueDBID() int {
	nextDBID++
	return nextDBID
}

// baseServerInfo creates a minimal ServerInfo with identity fields and the
// standard fixed server roles: sysadmin, securityadmin, public, processadmin.
func baseServerInfo() *types.ServerInfo {
	return &types.ServerInfo{
		ObjectIdentifier:   testServerOID,
		Hostname:           testHostname,
		ServerName:         strings.ToUpper(testHostname),
		SQLServerName:      testSQLName,
		InstanceName:       "MSSQLSERVER",
		Port:               1433,
		Version:            "Microsoft SQL Server 2019",
		VersionNumber:      "15.0.2000.5",
		IsMixedModeAuth:    true,
		ForceEncryption:    "No",
		ExtendedProtection: "Off",
		ComputerSID:        testServerSID,
		DomainSID:          testDomainSID,
		FQDN:               "edgetest.domain.com",
		ServerPrincipals: []types.ServerPrincipal{
			fixedServerRole("public", 2),
			fixedServerRole("sysadmin", 3),
			fixedServerRole("securityadmin", 4),
			fixedServerRole("processadmin", 8),
		},
	}
}

func fixedServerRole(name string, id int) types.ServerPrincipal {
	return types.ServerPrincipal{
		ObjectIdentifier: name + "@" + testServerOID,
		PrincipalID:      id,
		Name:             name,
		TypeDescription:  "SERVER_ROLE",
		IsFixedRole:      true,
		SQLServerName:    testSQLName,
	}
}

// ---------------------------------------------------------------------------
// Server principal builders
// ---------------------------------------------------------------------------

type serverLoginOption func(*types.ServerPrincipal)

func withDisabled() serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.IsDisabled = true
	}
}

func withMemberOf(memberships ...types.RoleMembership) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.MemberOf = append(sp.MemberOf, memberships...)
	}
}

func withPermissions(perms ...types.Permission) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.Permissions = append(sp.Permissions, perms...)
	}
}

func withMappedCredential(cred *types.Credential) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.MappedCredential = cred
	}
}

func withOwner(ownerOID string) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.OwningObjectIdentifier = ownerOID
	}
}

func withMembers(members ...string) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.Members = append(sp.Members, members...)
	}
}

func withDatabaseUsers(dbUsers ...string) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.DatabaseUsers = append(sp.DatabaseUsers, dbUsers...)
	}
}

func withSecurityIdentifier(sid string) serverLoginOption {
	return func(sp *types.ServerPrincipal) {
		sp.SecurityIdentifier = sid
	}
}

// addSQLLogin adds a SQL_LOGIN server principal to the ServerInfo.
func addSQLLogin(info *types.ServerInfo, name string, opts ...serverLoginOption) *types.ServerPrincipal {
	sp := types.ServerPrincipal{
		ObjectIdentifier:           name + "@" + info.ObjectIdentifier,
		PrincipalID:                uniquePrincipalID(),
		Name:                       name,
		TypeDescription:            "SQL_LOGIN",
		IsActiveDirectoryPrincipal: false,
		SQLServerName:              info.SQLServerName,
		CreateDate:                 time.Now(),
		ModifyDate:                 time.Now(),
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
		},
	}
	for _, opt := range opts {
		opt(&sp)
	}
	info.ServerPrincipals = append(info.ServerPrincipals, sp)
	return &info.ServerPrincipals[len(info.ServerPrincipals)-1]
}

// addWindowsLogin adds a WINDOWS_LOGIN server principal to the ServerInfo.
func addWindowsLogin(info *types.ServerInfo, name, sid string, opts ...serverLoginOption) *types.ServerPrincipal {
	sp := types.ServerPrincipal{
		ObjectIdentifier:           name + "@" + info.ObjectIdentifier,
		PrincipalID:                uniquePrincipalID(),
		Name:                       name,
		TypeDescription:            "WINDOWS_LOGIN",
		IsActiveDirectoryPrincipal: true,
		SecurityIdentifier:         sid,
		SQLServerName:              info.SQLServerName,
		CreateDate:                 time.Now(),
		ModifyDate:                 time.Now(),
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
		},
	}
	for _, opt := range opts {
		opt(&sp)
	}
	info.ServerPrincipals = append(info.ServerPrincipals, sp)
	return &info.ServerPrincipals[len(info.ServerPrincipals)-1]
}

// addWindowsGroup adds a WINDOWS_GROUP server principal to the ServerInfo.
func addWindowsGroup(info *types.ServerInfo, name, sid string, opts ...serverLoginOption) *types.ServerPrincipal {
	sp := types.ServerPrincipal{
		ObjectIdentifier:           name + "@" + info.ObjectIdentifier,
		PrincipalID:                uniquePrincipalID(),
		Name:                       name,
		TypeDescription:            "WINDOWS_GROUP",
		IsActiveDirectoryPrincipal: true,
		SecurityIdentifier:         sid,
		SQLServerName:              info.SQLServerName,
		CreateDate:                 time.Now(),
		ModifyDate:                 time.Now(),
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
		},
	}
	for _, opt := range opts {
		opt(&sp)
	}
	info.ServerPrincipals = append(info.ServerPrincipals, sp)
	return &info.ServerPrincipals[len(info.ServerPrincipals)-1]
}

// addServerRole adds a user-defined SERVER_ROLE to the ServerInfo.
func addServerRole(info *types.ServerInfo, name string, opts ...serverLoginOption) *types.ServerPrincipal {
	sp := types.ServerPrincipal{
		ObjectIdentifier: name + "@" + info.ObjectIdentifier,
		PrincipalID:      uniquePrincipalID(),
		Name:             name,
		TypeDescription:  "SERVER_ROLE",
		IsFixedRole:      false,
		SQLServerName:    info.SQLServerName,
		CreateDate:       time.Now(),
		ModifyDate:       time.Now(),
	}
	for _, opt := range opts {
		opt(&sp)
	}
	info.ServerPrincipals = append(info.ServerPrincipals, sp)
	return &info.ServerPrincipals[len(info.ServerPrincipals)-1]
}

// ---------------------------------------------------------------------------
// Database builders
// ---------------------------------------------------------------------------

type databaseOption func(*types.Database)

func withTrustworthy() databaseOption {
	return func(db *types.Database) {
		db.IsTrustworthy = true
	}
}

func withDBOwner(ownerLogin, ownerOID string) databaseOption {
	return func(db *types.Database) {
		db.OwnerLoginName = ownerLogin
		db.OwnerObjectIdentifier = ownerOID
	}
}

// addDatabase adds a database to the ServerInfo.
func addDatabase(info *types.ServerInfo, name string, opts ...databaseOption) *types.Database {
	db := types.Database{
		ObjectIdentifier: info.ObjectIdentifier + "\\" + name,
		DatabaseID:       uniqueDBID(),
		Name:             name,
		SQLServerName:    info.SQLServerName,
		CreateDate:       time.Now(),
	}
	for _, opt := range opts {
		opt(&db)
	}
	info.Databases = append(info.Databases, db)
	return &info.Databases[len(info.Databases)-1]
}

// ---------------------------------------------------------------------------
// Database principal builders
// ---------------------------------------------------------------------------

type dbPrincipalOption func(*types.DatabasePrincipal)

func withDBPrincipalPermissions(perms ...types.Permission) dbPrincipalOption {
	return func(dp *types.DatabasePrincipal) {
		dp.Permissions = append(dp.Permissions, perms...)
	}
}

func withDBPrincipalMemberOf(memberships ...types.RoleMembership) dbPrincipalOption {
	return func(dp *types.DatabasePrincipal) {
		dp.MemberOf = append(dp.MemberOf, memberships...)
	}
}

func withDBPrincipalMembers(members ...string) dbPrincipalOption {
	return func(dp *types.DatabasePrincipal) {
		dp.Members = append(dp.Members, members...)
	}
}

func withServerLogin(loginOID, loginName string, loginPID int) dbPrincipalOption {
	return func(dp *types.DatabasePrincipal) {
		dp.ServerLogin = &types.ServerLoginRef{
			ObjectIdentifier: loginOID,
			Name:             loginName,
			PrincipalID:      loginPID,
		}
	}
}

func withDBPrincipalOwner(ownerOID string) dbPrincipalOption {
	return func(dp *types.DatabasePrincipal) {
		dp.OwningObjectIdentifier = ownerOID
	}
}

// addDatabaseUser adds a SQL_USER to the given database.
func addDatabaseUser(db *types.Database, name string, opts ...dbPrincipalOption) *types.DatabasePrincipal {
	dp := types.DatabasePrincipal{
		ObjectIdentifier: name + "@" + db.ObjectIdentifier,
		PrincipalID:      uniquePrincipalID(),
		Name:             name,
		TypeDescription:  "SQL_USER",
		DatabaseName:     db.Name,
		SQLServerName:    db.SQLServerName,
		CreateDate:       time.Now(),
		ModifyDate:       time.Now(),
	}
	for _, opt := range opts {
		opt(&dp)
	}
	db.DatabasePrincipals = append(db.DatabasePrincipals, dp)
	return &db.DatabasePrincipals[len(db.DatabasePrincipals)-1]
}

// addWindowsUser adds a WINDOWS_USER to the given database.
func addWindowsUser(db *types.Database, name string, opts ...dbPrincipalOption) *types.DatabasePrincipal {
	dp := types.DatabasePrincipal{
		ObjectIdentifier: name + "@" + db.ObjectIdentifier,
		PrincipalID:      uniquePrincipalID(),
		Name:             name,
		TypeDescription:  "WINDOWS_USER",
		DatabaseName:     db.Name,
		SQLServerName:    db.SQLServerName,
		CreateDate:       time.Now(),
		ModifyDate:       time.Now(),
	}
	for _, opt := range opts {
		opt(&dp)
	}
	db.DatabasePrincipals = append(db.DatabasePrincipals, dp)
	return &db.DatabasePrincipals[len(db.DatabasePrincipals)-1]
}

// addDatabaseRole adds a DATABASE_ROLE to the given database.
func addDatabaseRole(db *types.Database, name string, isFixed bool, opts ...dbPrincipalOption) *types.DatabasePrincipal {
	dp := types.DatabasePrincipal{
		ObjectIdentifier: name + "@" + db.ObjectIdentifier,
		PrincipalID:      uniquePrincipalID(),
		Name:             name,
		TypeDescription:  "DATABASE_ROLE",
		IsFixedRole:      isFixed,
		DatabaseName:     db.Name,
		SQLServerName:    db.SQLServerName,
		CreateDate:       time.Now(),
		ModifyDate:       time.Now(),
	}
	for _, opt := range opts {
		opt(&dp)
	}
	db.DatabasePrincipals = append(db.DatabasePrincipals, dp)
	return &db.DatabasePrincipals[len(db.DatabasePrincipals)-1]
}

// addAppRole adds an APPLICATION_ROLE to the given database.
func addAppRole(db *types.Database, name string, opts ...dbPrincipalOption) *types.DatabasePrincipal {
	dp := types.DatabasePrincipal{
		ObjectIdentifier: name + "@" + db.ObjectIdentifier,
		PrincipalID:      uniquePrincipalID(),
		Name:             name,
		TypeDescription:  "APPLICATION_ROLE",
		DatabaseName:     db.Name,
		SQLServerName:    db.SQLServerName,
		CreateDate:       time.Now(),
		ModifyDate:       time.Now(),
	}
	for _, opt := range opts {
		opt(&dp)
	}
	db.DatabasePrincipals = append(db.DatabasePrincipals, dp)
	return &db.DatabasePrincipals[len(db.DatabasePrincipals)-1]
}

// ---------------------------------------------------------------------------
// Linked server builders
// ---------------------------------------------------------------------------

type linkedServerOption func(*types.LinkedServer)

func withResolvedTarget(oid string) linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.ResolvedObjectIdentifier = oid
	}
}

func withRemoteSysadmin() linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.RemoteIsSysadmin = true
	}
}

func withRemoteMixedMode() linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.RemoteIsMixedMode = true
	}
}

func withRemoteLogin(login string) linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.RemoteLogin = login
	}
}

func withLocalLogin(login string) linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.LocalLogin = login
	}
}

func withSelfMapping() linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.IsSelfMapping = true
	}
}

func withUsesImpersonation() linkedServerOption {
	return func(ls *types.LinkedServer) {
		ls.UsesImpersonation = true
	}
}

// addLinkedServer adds a linked server entry to the ServerInfo.
func addLinkedServer(info *types.ServerInfo, name, dataSource string, opts ...linkedServerOption) *types.LinkedServer {
	ls := types.LinkedServer{
		ServerID:            uniquePrincipalID(),
		Name:                name,
		Product:             "SQL Server",
		Provider:            "SQLNCLI11",
		DataSource:          dataSource,
		IsLinkedServer:      true,
		IsRPCOutEnabled:     true,
		IsDataAccessEnabled: true,
		SourceServer:        info.Hostname,
	}
	for _, opt := range opts {
		opt(&ls)
	}
	info.LinkedServers = append(info.LinkedServers, ls)
	return &info.LinkedServers[len(info.LinkedServers)-1]
}

// ---------------------------------------------------------------------------
// Credential builders
// ---------------------------------------------------------------------------

// addCredential adds a server-level credential to the ServerInfo.
func addCredential(info *types.ServerInfo, name, identity, resolvedSID string) *types.Credential {
	c := types.Credential{
		CredentialID:       uniquePrincipalID(),
		Name:               name,
		CredentialIdentity: identity,
		ResolvedSID:        resolvedSID,
		CreateDate:         time.Now(),
		ModifyDate:         time.Now(),
	}
	info.Credentials = append(info.Credentials, c)
	return &info.Credentials[len(info.Credentials)-1]
}

// addDBScopedCredential adds a database-scoped credential to a database.
func addDBScopedCredential(db *types.Database, name, identity, resolvedSID string) *types.DBScopedCredential {
	c := types.DBScopedCredential{
		CredentialID:       uniquePrincipalID(),
		Name:               name,
		CredentialIdentity: identity,
		ResolvedSID:        resolvedSID,
		CreateDate:         time.Now(),
		ModifyDate:         time.Now(),
	}
	db.DBScopedCredentials = append(db.DBScopedCredentials, c)
	return &db.DBScopedCredentials[len(db.DBScopedCredentials)-1]
}

// addProxyAccount adds a proxy account to the ServerInfo.
func addProxyAccount(info *types.ServerInfo, name, credIdentity, resolvedSID string, enabled bool, subsystems, logins []string) *types.ProxyAccount {
	p := types.ProxyAccount{
		ProxyID:            uniquePrincipalID(),
		Name:               name,
		CredentialID:       uniquePrincipalID(),
		CredentialIdentity: credIdentity,
		ResolvedSID:        resolvedSID,
		Enabled:            enabled,
		Subsystems:         subsystems,
		Logins:             logins,
	}
	info.ProxyAccounts = append(info.ProxyAccounts, p)
	return &info.ProxyAccounts[len(info.ProxyAccounts)-1]
}

// addServiceAccount adds a service account to the ServerInfo.
func addServiceAccount(info *types.ServerInfo, name, sid, serviceName, serviceType string) *types.ServiceAccount {
	sa := types.ServiceAccount{
		ObjectIdentifier: sid,
		Name:             name,
		ServiceName:      serviceName,
		ServiceType:      serviceType,
		SID:              sid,
	}
	info.ServiceAccounts = append(info.ServiceAccounts, sa)
	return &info.ServiceAccounts[len(info.ServiceAccounts)-1]
}

// ---------------------------------------------------------------------------
// Permission builder helpers
// ---------------------------------------------------------------------------

// perm creates a Permission with common defaults.
func perm(permission, state, classDesc string) types.Permission {
	return types.Permission{
		Permission: permission,
		State:      state,
		ClassDesc:  classDesc,
	}
}

// targetPerm creates a Permission targeting a specific principal.
// The targetPrincipalID is required because the edge creation logic uses principalMap[perm.TargetPrincipalID]
// to look up the target and determine its type (login vs role, user vs role vs app role).
func targetPerm(permission, state, classDesc string, targetPrincipalID int, targetOID, targetName string) types.Permission {
	return types.Permission{
		Permission:             permission,
		State:                  state,
		ClassDesc:              classDesc,
		TargetPrincipalID:      targetPrincipalID,
		TargetObjectIdentifier: targetOID,
		TargetName:             targetName,
	}
}

// roleMembership creates a RoleMembership reference.
func roleMembership(name string, serverOID string) types.RoleMembership {
	return types.RoleMembership{
		ObjectIdentifier: name + "@" + serverOID,
		Name:             name,
	}
}

// ---------------------------------------------------------------------------
// Helper to run test cases
// ---------------------------------------------------------------------------

// runTestCases runs all test cases against the given edges.
func runTestCases(t *testing.T, edges []bloodhound.Edge, testCases []edgeTestCase) {
	t.Helper()
	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			runSingleTestCase(t, edges, tc)
		})
	}
}

// ---------------------------------------------------------------------------
// Debug helpers
// ---------------------------------------------------------------------------

// dumpEdges logs all edges grouped by kind (useful for debugging test failures).
func dumpEdges(t *testing.T, edges []bloodhound.Edge) {
	t.Helper()
	byKind := make(map[string][]bloodhound.Edge)
	for _, e := range edges {
		byKind[e.Kind] = append(byKind[e.Kind], e)
	}
	for kind, kindEdges := range byKind {
		t.Logf("  %s (%d edges):", kind, len(kindEdges))
		for _, e := range kindEdges {
			t.Logf("    %s -> %s", e.Start.Value, e.End.Value)
		}
	}
}

// dumpEdgesOfKind logs all edges of a specific kind.
func dumpEdgesOfKind(t *testing.T, edges []bloodhound.Edge, kind string) {
	t.Helper()
	t.Logf("Edges of kind %s:", kind)
	for _, e := range edges {
		if e.Kind == kind {
			t.Logf("  %s -> %s", e.Start.Value, e.End.Value)
		}
	}
}
