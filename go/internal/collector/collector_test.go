// Package collector provides unit tests for MSSQL data collection and edge creation.
package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// TestEdgeCreation tests that edges are created correctly for various scenarios
func TestEdgeCreation(t *testing.T) {
	// Create a temporary directory for output
	tmpDir, err := os.MkdirTemp("", "mssqlhound-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a mock server info with test data
	serverInfo := createMockServerInfo()

	// Create collector with minimal config
	config := &Config{
		TempDir:                    tmpDir,
		IncludeNontraversableEdges: true,
	}
	c := New(config)

	// Create output file
	outputPath := filepath.Join(tmpDir, "test-output.json")
	writer, err := bloodhound.NewStreamingWriter(outputPath)
	if err != nil {
		t.Fatalf("Failed to create writer: %v", err)
	}

	// Write nodes first (manually since createNodes is private)
	// Server node
	serverNode := c.createServerNode(serverInfo)
	if err := writer.WriteNode(serverNode); err != nil {
		t.Fatalf("Failed to write server node: %v", err)
	}

	// Database nodes
	for _, db := range serverInfo.Databases {
		dbNode := c.createDatabaseNode(&db, serverInfo)
		if err := writer.WriteNode(dbNode); err != nil {
			t.Fatalf("Failed to write database node: %v", err)
		}

		// Database principal nodes
		for _, principal := range db.DatabasePrincipals {
			principalNode := c.createDatabasePrincipalNode(&principal, &db, serverInfo)
			if err := writer.WriteNode(principalNode); err != nil {
				t.Fatalf("Failed to write database principal node: %v", err)
			}
		}
	}

	// Server principal nodes
	for _, principal := range serverInfo.ServerPrincipals {
		principalNode := c.createServerPrincipalNode(&principal, serverInfo)
		if err := writer.WriteNode(principalNode); err != nil {
			t.Fatalf("Failed to write server principal node: %v", err)
		}
	}

	// Create edges
	if err := c.createEdges(writer, serverInfo); err != nil {
		t.Fatalf("Failed to create edges: %v", err)
	}

	// Create fixed role edges
	if err := c.createFixedRoleEdges(writer, serverInfo); err != nil {
		t.Fatalf("Failed to create fixed role edges: %v", err)
	}

	// Close writer
	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Read and verify output
	nodes, edges, err := bloodhound.ReadFromFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	// Verify expected edges exist
	verifyEdges(t, edges, nodes)
}

// createMockServerInfo creates a mock ServerInfo for testing
func createMockServerInfo() *types.ServerInfo {
	serverSID := "S-1-5-21-1234567890-1234567890-1234567890-1001"
	serverOID := serverSID + ":1433"

	return &types.ServerInfo{
		ObjectIdentifier:   serverOID,
		Hostname:           "testserver",
		ServerName:         "TESTSERVER",
		SQLServerName:      "testserver.domain.com:1433",
		InstanceName:       "MSSQLSERVER",
		Port:               1433,
		Version:            "Microsoft SQL Server 2019",
		VersionNumber:      "15.0.2000.5",
		IsMixedModeAuth:    true,
		ForceEncryption:    "No",
		ExtendedProtection: "Off",
		ComputerSID:        serverSID,
		FQDN:               "testserver.domain.com",
		ServiceAccounts: []types.ServiceAccount{
			{
				Name:             "DOMAIN\\sqlservice",
				ServiceName:      "SQL Server (MSSQLSERVER)",
				ServiceType:      "SQLServer",
				SID:              "S-1-5-21-1234567890-1234567890-1234567890-2001",
				ObjectIdentifier: "S-1-5-21-1234567890-1234567890-1234567890-2001",
			},
		},
		Credentials: []types.Credential{
			{
				CredentialID:       1,
				Name:               "TestCredential",
				CredentialIdentity: "DOMAIN\\creduser",
				CreateDate:         time.Now(),
				ModifyDate:         time.Now(),
			},
		},
		ProxyAccounts: []types.ProxyAccount{
			{
				ProxyID:            1,
				Name:               "TestProxy",
				CredentialID:       1,
				CredentialIdentity: "DOMAIN\\proxyuser",
				Enabled:            true,
				Subsystems:         []string{"CmdExec", "PowerShell"},
				Logins:             []string{"TestLogin_WithProxy"},
			},
		},
		ServerPrincipals: []types.ServerPrincipal{
			// sa login
			{
				ObjectIdentifier:           "sa@" + serverOID,
				PrincipalID:                1,
				Name:                       "sa",
				TypeDescription:            "SQL_LOGIN",
				IsDisabled:                 false,
				IsFixedRole:                false,
				SecurityIdentifier:         "",
				IsActiveDirectoryPrincipal: false,
				SQLServerName:              "testserver.domain.com:1433",
				MemberOf: []types.RoleMembership{
					{ObjectIdentifier: "sysadmin@" + serverOID, Name: "sysadmin", PrincipalID: 3},
				},
				Permissions: []types.Permission{
					{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
				},
			},
			// public role
			{
				ObjectIdentifier: "public@" + serverOID,
				PrincipalID:      2,
				Name:             "public",
				TypeDescription:  "SERVER_ROLE",
				IsDisabled:       false,
				IsFixedRole:      true,
				SQLServerName:    "testserver.domain.com:1433",
			},
			// sysadmin role
			{
				ObjectIdentifier: "sysadmin@" + serverOID,
				PrincipalID:      3,
				Name:             "sysadmin",
				TypeDescription:  "SERVER_ROLE",
				IsDisabled:       false,
				IsFixedRole:      true,
				SQLServerName:    "testserver.domain.com:1433",
			},
			// securityadmin role
			{
				ObjectIdentifier: "securityadmin@" + serverOID,
				PrincipalID:      4,
				Name:             "securityadmin",
				TypeDescription:  "SERVER_ROLE",
				IsDisabled:       false,
				IsFixedRole:      true,
				SQLServerName:    "testserver.domain.com:1433",
			},
			// Domain user login with sysadmin
			{
				ObjectIdentifier:           "DOMAIN\\testadmin@" + serverOID,
				PrincipalID:                256,
				Name:                       "DOMAIN\\testadmin",
				TypeDescription:            "WINDOWS_LOGIN",
				IsDisabled:                 false,
				IsFixedRole:                false,
				SecurityIdentifier:         "S-1-5-21-1234567890-1234567890-1234567890-1100",
				IsActiveDirectoryPrincipal: true,
				SQLServerName:              "testserver.domain.com:1433",
				MemberOf: []types.RoleMembership{
					{ObjectIdentifier: "sysadmin@" + serverOID, Name: "sysadmin", PrincipalID: 3},
				},
				Permissions: []types.Permission{
					{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
				},
			},
			// Domain user login with CONTROL SERVER
			{
				ObjectIdentifier:           "DOMAIN\\controluser@" + serverOID,
				PrincipalID:                257,
				Name:                       "DOMAIN\\controluser",
				TypeDescription:            "WINDOWS_LOGIN",
				IsDisabled:                 false,
				IsFixedRole:                false,
				SecurityIdentifier:         "S-1-5-21-1234567890-1234567890-1234567890-1101",
				IsActiveDirectoryPrincipal: true,
				SQLServerName:              "testserver.domain.com:1433",
				Permissions: []types.Permission{
					{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
					{Permission: "CONTROL SERVER", State: "GRANT", ClassDesc: "SERVER"},
				},
			},
			// Login with IMPERSONATE ANY LOGIN
			{
				ObjectIdentifier:           "DOMAIN\\impersonateuser@" + serverOID,
				PrincipalID:                258,
				Name:                       "DOMAIN\\impersonateuser",
				TypeDescription:            "WINDOWS_LOGIN",
				IsDisabled:                 false,
				IsFixedRole:                false,
				SecurityIdentifier:         "S-1-5-21-1234567890-1234567890-1234567890-1102",
				IsActiveDirectoryPrincipal: true,
				SQLServerName:              "testserver.domain.com:1433",
				Permissions: []types.Permission{
					{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
					{Permission: "IMPERSONATE ANY LOGIN", State: "GRANT", ClassDesc: "SERVER"},
				},
			},
			// Login with mapped credential
			{
				ObjectIdentifier:           "TestLogin_WithCred@" + serverOID,
				PrincipalID:                259,
				Name:                       "TestLogin_WithCred",
				TypeDescription:            "SQL_LOGIN",
				IsDisabled:                 false,
				IsFixedRole:                false,
				SecurityIdentifier:         "",
				IsActiveDirectoryPrincipal: false,
				SQLServerName:              "testserver.domain.com:1433",
				MappedCredential: &types.Credential{
					CredentialID:       1,
					Name:               "TestCredential",
					CredentialIdentity: "DOMAIN\\creduser",
				},
				Permissions: []types.Permission{
					{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
				},
			},
			// Login authorized to use proxy
			{
				ObjectIdentifier:           "TestLogin_WithProxy@" + serverOID,
				PrincipalID:                260,
				Name:                       "TestLogin_WithProxy",
				TypeDescription:            "SQL_LOGIN",
				IsDisabled:                 false,
				IsFixedRole:                false,
				SecurityIdentifier:         "",
				IsActiveDirectoryPrincipal: false,
				SQLServerName:              "testserver.domain.com:1433",
				Permissions: []types.Permission{
					{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
				},
			},
		},
		Databases: []types.Database{
			{
				ObjectIdentifier:     serverOID + "\\master",
				DatabaseID:           1,
				Name:                 "master",
				OwnerLoginName:       "sa",
				OwnerObjectIdentifier: "sa@" + serverOID,
				IsTrustworthy:        false,
				SQLServerName:        "testserver.domain.com:1433",
				DatabasePrincipals: []types.DatabasePrincipal{
					{
						ObjectIdentifier: "dbo@" + serverOID + "\\master",
						PrincipalID:      1,
						Name:             "dbo",
						TypeDescription:  "SQL_USER",
						DatabaseName:     "master",
						SQLServerName:    "testserver.domain.com:1433",
						ServerLogin: &types.ServerLoginRef{
							ObjectIdentifier: "sa@" + serverOID,
							Name:             "sa",
							PrincipalID:      1,
						},
					},
					{
						ObjectIdentifier: "db_owner@" + serverOID + "\\master",
						PrincipalID:      16384,
						Name:             "db_owner",
						TypeDescription:  "DATABASE_ROLE",
						IsFixedRole:      true,
						DatabaseName:     "master",
						SQLServerName:    "testserver.domain.com:1433",
					},
				},
			},
			// Trustworthy database for ExecuteAsOwner test
			{
				ObjectIdentifier:     serverOID + "\\TrustDB",
				DatabaseID:           5,
				Name:                 "TrustDB",
				OwnerLoginName:       "DOMAIN\\testadmin",
				OwnerObjectIdentifier: "DOMAIN\\testadmin@" + serverOID,
				IsTrustworthy:        true,
				SQLServerName:        "testserver.domain.com:1433",
				DatabasePrincipals: []types.DatabasePrincipal{
					{
						ObjectIdentifier: "dbo@" + serverOID + "\\TrustDB",
						PrincipalID:      1,
						Name:             "dbo",
						TypeDescription:  "SQL_USER",
						DatabaseName:     "TrustDB",
						SQLServerName:    "testserver.domain.com:1433",
					},
				},
			},
			// Database with DB-scoped credential
			{
				ObjectIdentifier:     serverOID + "\\CredDB",
				DatabaseID:           6,
				Name:                 "CredDB",
				OwnerLoginName:       "sa",
				OwnerObjectIdentifier: "sa@" + serverOID,
				IsTrustworthy:        false,
				SQLServerName:        "testserver.domain.com:1433",
				DBScopedCredentials: []types.DBScopedCredential{
					{
						CredentialID:       1,
						Name:               "DBScopedCred",
						CredentialIdentity: "DOMAIN\\dbcreduser",
						CreateDate:         time.Now(),
						ModifyDate:         time.Now(),
					},
				},
			},
		},
		LinkedServers: []types.LinkedServer{
			{
				ServerID:            1,
				Name:                "LINKED_SERVER",
				Product:             "SQL Server",
				Provider:            "SQLNCLI11",
				DataSource:          "linkedserver.domain.com",
				IsLinkedServer:      true,
				IsRPCOutEnabled:     true,
				IsDataAccessEnabled: true,
			},
			// Linked server with admin privileges for LinkedAsAdmin test
			{
				ServerID:                     2,
				Name:                         "ADMIN_LINKED_SERVER",
				Product:                      "SQL Server",
				Provider:                     "SQLNCLI11",
				DataSource:                   "adminlinkedserver.domain.com",
				IsLinkedServer:               true,
				IsRPCOutEnabled:              true,
				IsDataAccessEnabled:          true,
				RemoteLogin:                  "admin_sql_login",
				RemoteIsSysadmin:             true,
				RemoteIsMixedMode:            true,
				ResolvedObjectIdentifier:     "S-1-5-21-9999999999-9999999999-9999999999-1001:1433",
			},
		},
	}
}

// createMockServerInfoWithComputerLogin creates a mock ServerInfo with a computer account login
// for testing CoerceAndRelayToMSSQL edge
func createMockServerInfoWithComputerLogin() *types.ServerInfo {
	info := createMockServerInfo()
	serverOID := info.ObjectIdentifier

	// Add a computer account login
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier:           "DOMAIN\\WORKSTATION1$@" + serverOID,
		PrincipalID:                500,
		Name:                       "DOMAIN\\WORKSTATION1$",
		TypeDescription:            "WINDOWS_LOGIN",
		IsDisabled:                 false,
		IsFixedRole:                false,
		SecurityIdentifier:         "S-1-5-21-1234567890-1234567890-1234567890-3001",
		IsActiveDirectoryPrincipal: true,
		SQLServerName:              "testserver.domain.com:1433",
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
		},
	})

	return info
}

// verifyEdges checks that all expected edges are present
func verifyEdges(t *testing.T, edges []bloodhound.Edge, nodes []bloodhound.Node) {
	// Build edge lookup
	edgesByKind := make(map[string][]bloodhound.Edge)
	for _, edge := range edges {
		edgesByKind[edge.Kind] = append(edgesByKind[edge.Kind], edge)
	}

	// Test: MSSQL_Contains edges
	t.Run("Contains edges", func(t *testing.T) {
		containsEdges := edgesByKind[bloodhound.EdgeKinds.Contains]
		if len(containsEdges) == 0 {
			t.Error("Expected MSSQL_Contains edges, got none")
		}
		// Check server contains databases
		found := false
		for _, e := range containsEdges {
			if strings.HasSuffix(e.End.Value, "\\master") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected MSSQL_Contains edge from server to master database")
		}
	})

	// Test: MSSQL_MemberOf edges
	t.Run("MemberOf edges", func(t *testing.T) {
		memberOfEdges := edgesByKind[bloodhound.EdgeKinds.MemberOf]
		if len(memberOfEdges) == 0 {
			t.Error("Expected MSSQL_MemberOf edges, got none")
		}
		// Check sa is member of sysadmin
		found := false
		for _, e := range memberOfEdges {
			if strings.HasPrefix(e.Start.Value, "sa@") && strings.Contains(e.End.Value, "sysadmin@") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected MSSQL_MemberOf edge from sa to sysadmin")
		}
	})

	// Test: MSSQL_Owns edges
	t.Run("Owns edges", func(t *testing.T) {
		ownsEdges := edgesByKind[bloodhound.EdgeKinds.Owns]
		if len(ownsEdges) == 0 {
			t.Error("Expected MSSQL_Owns edges, got none")
		}
	})

	// Test: MSSQL_ControlServer edges (from sysadmin role)
	t.Run("ControlServer edges", func(t *testing.T) {
		controlServerEdges := edgesByKind[bloodhound.EdgeKinds.ControlServer]
		if len(controlServerEdges) == 0 {
			t.Error("Expected MSSQL_ControlServer edges, got none")
		}
		// Check sysadmin has ControlServer
		found := false
		for _, e := range controlServerEdges {
			if strings.Contains(e.Start.Value, "sysadmin@") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected MSSQL_ControlServer edge from sysadmin")
		}
	})

	// Test: MSSQL_ImpersonateAnyLogin edges
	t.Run("ImpersonateAnyLogin edges", func(t *testing.T) {
		impersonateEdges := edgesByKind[bloodhound.EdgeKinds.ImpersonateAnyLogin]
		if len(impersonateEdges) == 0 {
			t.Error("Expected MSSQL_ImpersonateAnyLogin edges, got none")
		}
	})

	// Test: MSSQL_HasLogin edges
	t.Run("HasLogin edges", func(t *testing.T) {
		hasLoginEdges := edgesByKind[bloodhound.EdgeKinds.HasLogin]
		if len(hasLoginEdges) == 0 {
			t.Error("Expected MSSQL_HasLogin edges, got none")
		}
		// Check domain user has login
		found := false
		for _, e := range hasLoginEdges {
			if strings.HasPrefix(e.Start.Value, "S-1-5-21-") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected MSSQL_HasLogin edge from AD SID to login")
		}
	})

	// Test: MSSQL_ServiceAccountFor edges
	t.Run("ServiceAccountFor edges", func(t *testing.T) {
		saEdges := edgesByKind[bloodhound.EdgeKinds.ServiceAccountFor]
		if len(saEdges) == 0 {
			t.Error("Expected MSSQL_ServiceAccountFor edges, got none")
		}
	})

	// Test: MSSQL_GetAdminTGS edges
	t.Run("GetAdminTGS edges", func(t *testing.T) {
		getAdminTGSEdges := edgesByKind[bloodhound.EdgeKinds.GetAdminTGS]
		if len(getAdminTGSEdges) == 0 {
			t.Error("Expected MSSQL_GetAdminTGS edges, got none")
		}
	})

	// Test: MSSQL_GetTGS edges
	t.Run("GetTGS edges", func(t *testing.T) {
		getTGSEdges := edgesByKind[bloodhound.EdgeKinds.GetTGS]
		if len(getTGSEdges) == 0 {
			t.Error("Expected MSSQL_GetTGS edges, got none")
		}
	})

	// Test: MSSQL_IsTrustedBy edges (for trustworthy database)
	t.Run("IsTrustedBy edges", func(t *testing.T) {
		trustEdges := edgesByKind[bloodhound.EdgeKinds.IsTrustedBy]
		if len(trustEdges) == 0 {
			t.Error("Expected MSSQL_IsTrustedBy edges for trustworthy database, got none")
		}
	})

	// Test: MSSQL_ExecuteAsOwner edges (for trustworthy database owned by sysadmin)
	t.Run("ExecuteAsOwner edges", func(t *testing.T) {
		executeAsOwnerEdges := edgesByKind[bloodhound.EdgeKinds.ExecuteAsOwner]
		if len(executeAsOwnerEdges) == 0 {
			t.Error("Expected MSSQL_ExecuteAsOwner edges for trustworthy database, got none")
		}
	})

	// Test: MSSQL_HasMappedCred edges
	t.Run("HasMappedCred edges", func(t *testing.T) {
		credEdges := edgesByKind[bloodhound.EdgeKinds.HasMappedCred]
		if len(credEdges) == 0 {
			t.Error("Expected MSSQL_HasMappedCred edges, got none")
		}
	})

	// Test: MSSQL_HasProxyCred edges
	t.Run("HasProxyCred edges", func(t *testing.T) {
		proxyEdges := edgesByKind[bloodhound.EdgeKinds.HasProxyCred]
		if len(proxyEdges) == 0 {
			t.Error("Expected MSSQL_HasProxyCred edges, got none")
		}
	})

	// Test: MSSQL_HasDBScopedCred edges
	t.Run("HasDBScopedCred edges", func(t *testing.T) {
		dbCredEdges := edgesByKind[bloodhound.EdgeKinds.HasDBScopedCred]
		if len(dbCredEdges) == 0 {
			t.Error("Expected MSSQL_HasDBScopedCred edges, got none")
		}
	})

	// Test: MSSQL_LinkedTo edges
	t.Run("LinkedTo edges", func(t *testing.T) {
		linkedEdges := edgesByKind[bloodhound.EdgeKinds.LinkedTo]
		if len(linkedEdges) == 0 {
			t.Error("Expected MSSQL_LinkedTo edges, got none")
		}
	})

	// Test: MSSQL_LinkedAsAdmin edges (for linked server with admin privileges)
	t.Run("LinkedAsAdmin edges", func(t *testing.T) {
		linkedAdminEdges := edgesByKind[bloodhound.EdgeKinds.LinkedAsAdmin]
		if len(linkedAdminEdges) == 0 {
			t.Error("Expected MSSQL_LinkedAsAdmin edges for linked server with admin login, got none")
		}
	})

	// Test: MSSQL_IsMappedTo edges (login to database user)
	t.Run("IsMappedTo edges", func(t *testing.T) {
		mappedEdges := edgesByKind[bloodhound.EdgeKinds.IsMappedTo]
		if len(mappedEdges) == 0 {
			t.Error("Expected MSSQL_IsMappedTo edges, got none")
		}
	})

	// Print summary
	t.Logf("Total nodes: %d, Total edges: %d", len(nodes), len(edges))
	t.Logf("Edge counts by type:")
	for kind, kindEdges := range edgesByKind {
		t.Logf("  %s: %d", kind, len(kindEdges))
	}
}

// TestEdgeProperties tests that edge properties are correctly set
func TestEdgeProperties(t *testing.T) {
	tests := []struct {
		name     string
		edgeKind string
		ctx      *bloodhound.EdgeContext
	}{
		{
			name:     "MemberOf edge",
			edgeKind: bloodhound.EdgeKinds.MemberOf,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "testuser",
				SourceType:    bloodhound.NodeKinds.Login,
				TargetName:    "sysadmin",
				TargetType:    bloodhound.NodeKinds.ServerRole,
				SQLServerName: "testserver:1433",
			},
		},
		{
			name:     "ServiceAccountFor edge",
			edgeKind: bloodhound.EdgeKinds.ServiceAccountFor,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "DOMAIN\\sqlservice",
				SourceType:    "Base",
				TargetName:    "testserver:1433",
				TargetType:    bloodhound.NodeKinds.Server,
				SQLServerName: "testserver:1433",
			},
		},
		{
			name:     "HasMappedCred edge",
			edgeKind: bloodhound.EdgeKinds.HasMappedCred,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "testlogin",
				SourceType:    bloodhound.NodeKinds.Login,
				TargetName:    "DOMAIN\\creduser",
				TargetType:    "Base",
				SQLServerName: "testserver:1433",
			},
		},
		{
			name:     "HasProxyCred edge",
			edgeKind: bloodhound.EdgeKinds.HasProxyCred,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "testlogin",
				SourceType:    bloodhound.NodeKinds.Login,
				TargetName:    "DOMAIN\\proxyuser",
				TargetType:    "Base",
				SQLServerName: "testserver:1433",
			},
		},
		{
			name:     "HasDBScopedCred edge",
			edgeKind: bloodhound.EdgeKinds.HasDBScopedCred,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "TestDB",
				SourceType:    bloodhound.NodeKinds.Database,
				TargetName:    "DOMAIN\\dbcreduser",
				TargetType:    "Base",
				SQLServerName: "testserver:1433",
				DatabaseName:  "TestDB",
			},
		},
		{
			name:     "GetTGS edge",
			edgeKind: bloodhound.EdgeKinds.GetTGS,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "DOMAIN\\sqlservice",
				SourceType:    "Base",
				TargetName:    "testlogin",
				TargetType:    bloodhound.NodeKinds.Login,
				SQLServerName: "testserver:1433",
			},
		},
		{
			name:     "GetAdminTGS edge",
			edgeKind: bloodhound.EdgeKinds.GetAdminTGS,
			ctx: &bloodhound.EdgeContext{
				SourceName:    "DOMAIN\\sqlservice",
				SourceType:    "Base",
				TargetName:    "testserver:1433",
				TargetType:    bloodhound.NodeKinds.Server,
				SQLServerName: "testserver:1433",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := bloodhound.GetEdgeProperties(tt.edgeKind, tt.ctx)

			// Check that properties are set
			if props["general"] == nil || props["general"] == "" {
				t.Error("Expected 'general' property to be set")
			}
			if props["windowsAbuse"] == nil {
				t.Error("Expected 'windowsAbuse' property to be set")
			}
			if props["linuxAbuse"] == nil {
				t.Error("Expected 'linuxAbuse' property to be set")
			}
			if props["traversable"] == nil {
				t.Error("Expected 'traversable' property to be set")
			}
		})
	}
}

// TestNodeKinds tests that node kinds are correctly assigned
func TestNodeKinds(t *testing.T) {
	tests := []struct {
		typeDesc     string
		expectedKind string
		isServerType bool
	}{
		{"SERVER_ROLE", bloodhound.NodeKinds.ServerRole, true},
		{"SQL_LOGIN", bloodhound.NodeKinds.Login, true},
		{"WINDOWS_LOGIN", bloodhound.NodeKinds.Login, true},
		{"WINDOWS_GROUP", bloodhound.NodeKinds.Login, true},
		{"DATABASE_ROLE", bloodhound.NodeKinds.DatabaseRole, false},
		{"SQL_USER", bloodhound.NodeKinds.DatabaseUser, false},
		{"WINDOWS_USER", bloodhound.NodeKinds.DatabaseUser, false},
		{"APPLICATION_ROLE", bloodhound.NodeKinds.ApplicationRole, false},
	}

	c := New(&Config{})

	for _, tt := range tests {
		t.Run(tt.typeDesc, func(t *testing.T) {
			var kind string
			if tt.isServerType {
				kind = c.getServerPrincipalType(tt.typeDesc)
			} else {
				kind = c.getDatabasePrincipalType(tt.typeDesc)
			}
			if kind != tt.expectedKind {
				t.Errorf("Expected %s, got %s for type %s", tt.expectedKind, kind, tt.typeDesc)
			}
		})
	}
}

// TestOutputFormat tests that the output JSON is valid BloodHound format
func TestOutputFormat(t *testing.T) {
	// Create a temporary directory for output
	tmpDir, err := os.MkdirTemp("", "mssqlhound-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outputPath := filepath.Join(tmpDir, "test-output.json")
	writer, err := bloodhound.NewStreamingWriter(outputPath)
	if err != nil {
		t.Fatalf("Failed to create writer: %v", err)
	}

	// Write a test node
	node := &bloodhound.Node{
		ID:    "test-node-1",
		Kinds: []string{"MSSQL_Server", "Base"},
		Properties: map[string]interface{}{
			"name":    "TestServer",
			"enabled": true,
		},
	}
	if err := writer.WriteNode(node); err != nil {
		t.Fatalf("Failed to write node: %v", err)
	}

	// Write a test edge
	edge := &bloodhound.Edge{
		Start: bloodhound.EdgeEndpoint{Value: "source-1"},
		End:   bloodhound.EdgeEndpoint{Value: "target-1"},
		Kind:  "MSSQL_Contains",
		Properties: map[string]interface{}{
			"traversable": true,
		},
	}
	if err := writer.WriteEdge(edge); err != nil {
		t.Fatalf("Failed to write edge: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Read and validate the output
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var output struct {
		Schema   string `json:"$schema"`
		Metadata struct {
			SourceKind string `json:"source_kind"`
		} `json:"metadata"`
		Graph struct {
			Nodes []json.RawMessage `json:"nodes"`
			Edges []json.RawMessage `json:"edges"`
		} `json:"graph"`
	}

	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify structure
	if output.Schema == "" {
		t.Error("Expected $schema to be set")
	}
	if output.Metadata.SourceKind != "MSSQL_Base" {
		t.Errorf("Expected source_kind to be MSSQL_Base, got %s", output.Metadata.SourceKind)
	}
	if len(output.Graph.Nodes) != 1 {
		t.Errorf("Expected 1 node, got %d", len(output.Graph.Nodes))
	}
	if len(output.Graph.Edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(output.Graph.Edges))
	}
}

// TestCoerceAndRelayEdge tests that CoerceAndRelayToMSSQL edges are created
// when Extended Protection is Off and a computer account has a login
func TestCoerceAndRelayEdge(t *testing.T) {
	// Create a temporary directory for output
	tmpDir, err := os.MkdirTemp("", "mssqlhound-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a mock server info with a computer account login
	serverInfo := createMockServerInfoWithComputerLogin()

	// Create collector with a domain specified (needed for CoerceAndRelay)
	config := &Config{
		TempDir:                    tmpDir,
		Domain:                     "domain.com",
		IncludeNontraversableEdges: true,
	}
	c := New(config)

	// Create output file
	outputPath := filepath.Join(tmpDir, "test-output.json")
	writer, err := bloodhound.NewStreamingWriter(outputPath)
	if err != nil {
		t.Fatalf("Failed to create writer: %v", err)
	}

	// Write nodes
	serverNode := c.createServerNode(serverInfo)
	if err := writer.WriteNode(serverNode); err != nil {
		t.Fatalf("Failed to write server node: %v", err)
	}

	for _, principal := range serverInfo.ServerPrincipals {
		principalNode := c.createServerPrincipalNode(&principal, serverInfo)
		if err := writer.WriteNode(principalNode); err != nil {
			t.Fatalf("Failed to write server principal node: %v", err)
		}
	}

	// Create edges
	if err := c.createEdges(writer, serverInfo); err != nil {
		t.Fatalf("Failed to create edges: %v", err)
	}

	// Close writer
	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Read and verify output
	_, edges, err := bloodhound.ReadFromFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	// Check for CoerceAndRelayToMSSQL edge
	found := false
	for _, edge := range edges {
		if edge.Kind == bloodhound.EdgeKinds.CoerceAndRelayTo {
			found = true
			// Verify it's from Authenticated Users to the computer login
			if !strings.Contains(edge.Start.Value, "S-1-5-11") {
				t.Errorf("Expected CoerceAndRelayToMSSQL source to be Authenticated Users SID, got %s", edge.Start.Value)
			}
			if !strings.Contains(edge.End.Value, "WORKSTATION1$") {
				t.Errorf("Expected CoerceAndRelayToMSSQL target to be computer login, got %s", edge.End.Value)
			}
			break
		}
	}

	if !found {
		t.Error("Expected CoerceAndRelayToMSSQL edge for computer login with EPA Off, got none")
		t.Logf("Edges found: %d", len(edges))
		for _, edge := range edges {
			t.Logf("  %s: %s -> %s", edge.Kind, edge.Start.Value, edge.End.Value)
		}
	}
}

// TestLinkedAsAdminEdgeProperties tests that LinkedAsAdmin edge properties are correctly set
func TestLinkedAsAdminEdgeProperties(t *testing.T) {
	ctx := &bloodhound.EdgeContext{
		SourceName:    "SourceServer",
		SourceType:    bloodhound.NodeKinds.Server,
		TargetName:    "TargetServer",
		TargetType:    bloodhound.NodeKinds.Server,
		SQLServerName: "sourceserver.domain.com:1433",
	}

	props := bloodhound.GetEdgeProperties(bloodhound.EdgeKinds.LinkedAsAdmin, ctx)

	if props["traversable"] != true {
		t.Error("Expected LinkedAsAdmin to be traversable")
	}
	if props["general"] == nil || props["general"] == "" {
		t.Error("Expected 'general' property to be set")
	}
	if props["windowsAbuse"] == nil {
		t.Error("Expected 'windowsAbuse' property to be set")
	}
}

// TestCoerceAndRelayEdgeProperties tests that CoerceAndRelayToMSSQL edge properties are correctly set
func TestCoerceAndRelayEdgeProperties(t *testing.T) {
	ctx := &bloodhound.EdgeContext{
		SourceName:    "AUTHENTICATED USERS",
		SourceType:    "Group",
		TargetName:    "DOMAIN\\COMPUTER$",
		TargetType:    bloodhound.NodeKinds.Login,
		SQLServerName: "sqlserver.domain.com:1433",
	}

	props := bloodhound.GetEdgeProperties(bloodhound.EdgeKinds.CoerceAndRelayTo, ctx)

	if props["traversable"] != true {
		t.Error("Expected CoerceAndRelayToMSSQL to be traversable")
	}
	if props["general"] == nil || props["general"] == "" {
		t.Error("Expected 'general' property to be set")
	}
	if props["windowsAbuse"] == nil {
		t.Error("Expected 'windowsAbuse' property to be set")
	}
}
