package collector

import (
	"fmt"
	"testing"

	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// =============================================================================
// CONTAINS
// =============================================================================

func buildContainsTestData() *types.ServerInfo {
	info := baseServerInfo()

	addSQLLogin(info, "ContainsTest_Login1")
	addSQLLogin(info, "ContainsTest_Login2")
	addServerRole(info, "ContainsTest_ServerRole1")
	addServerRole(info, "ContainsTest_ServerRole2")

	db := addDatabase(info, "EdgeTest_Contains")
	addDatabaseUser(db, "ContainsTest_User1")
	addDatabaseUser(db, "ContainsTest_User2")
	addDatabaseRole(db, "ContainsTest_DbRole1", false)
	addDatabaseRole(db, "ContainsTest_DbRole2", false)
	addAppRole(db, "ContainsTest_AppRole1")
	addAppRole(db, "ContainsTest_AppRole2")

	return info
}

func TestContainsEdges(t *testing.T) {
	info := buildContainsTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,containsTestCases)
}

// =============================================================================
// MEMBEROF
// =============================================================================

func buildMemberOfTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Server-level roles for nesting
	sr1 := addServerRole(info, "MemberOfTest_ServerRole1")
	sr2 := addServerRole(info, "MemberOfTest_ServerRole2")

	// SQL login member of processadmin
	addSQLLogin(info, "MemberOfTest_Login1",
		withMemberOf(roleMembership("processadmin", testServerOID)))

	// SQL login member of custom server role
	addSQLLogin(info, "MemberOfTest_Login2",
		withMemberOf(roleMembership("MemberOfTest_ServerRole1", testServerOID)))

	// Windows login member of diskadmin
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID(),
		withMemberOf(roleMembership("diskadmin", testServerOID)))

	// Server role nesting: ServerRole1 -> ServerRole2 -> securityadmin
	_ = sr1
	// Update sr1 to be member of sr2
	for i := range info.ServerPrincipals {
		if info.ServerPrincipals[i].Name == "MemberOfTest_ServerRole1" {
			info.ServerPrincipals[i].MemberOf = append(info.ServerPrincipals[i].MemberOf,
				roleMembership("MemberOfTest_ServerRole2", testServerOID))
		}
	}
	_ = sr2
	for i := range info.ServerPrincipals {
		if info.ServerPrincipals[i].Name == "MemberOfTest_ServerRole2" {
			info.ServerPrincipals[i].MemberOf = append(info.ServerPrincipals[i].MemberOf,
				roleMembership("securityadmin", testServerOID))
		}
	}

	// Add fixed role "diskadmin" to server principals since MemberOf edge from
	// Windows login -> diskadmin references it
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier: "diskadmin@" + testServerOID,
		PrincipalID:      uniquePrincipalID(),
		Name:             "diskadmin",
		TypeDescription:  "SERVER_ROLE",
		IsFixedRole:      true,
		SQLServerName:    testSQLName,
	})

	// Database-level memberships
	db := addDatabase(info, "EdgeTest_MemberOf")
	dbRole1 := addDatabaseRole(db, "MemberOfTest_DbRole1", false)
	addDatabaseRole(db, "MemberOfTest_DbRole2", false)
	addDatabaseRole(db, "db_datareader", true)
	addDatabaseRole(db, "db_datawriter", true)
	addDatabaseRole(db, "db_owner", true)

	// Database user member of db_datareader
	addDatabaseUser(db, "MemberOfTest_User1",
		withDBPrincipalMemberOf(roleMembership("db_datareader", db.ObjectIdentifier)))

	// Database user member of custom database role
	addDatabaseUser(db, "MemberOfTest_User2",
		withDBPrincipalMemberOf(roleMembership("MemberOfTest_DbRole1", db.ObjectIdentifier)))

	// Windows database user member of db_datawriter
	addWindowsUser(db, "DOMAIN\\EdgeTestDomainUser1",
		withDBPrincipalMemberOf(roleMembership("db_datawriter", db.ObjectIdentifier)))

	// Database user without login member of role
	addDatabaseUser(db, "MemberOfTest_UserNoLogin",
		withDBPrincipalMemberOf(roleMembership("MemberOfTest_DbRole1", db.ObjectIdentifier)))

	// Database role nesting: DbRole1 -> DbRole2 -> db_owner
	_ = dbRole1
	for i := range db.DatabasePrincipals {
		if db.DatabasePrincipals[i].Name == "MemberOfTest_DbRole1" {
			db.DatabasePrincipals[i].MemberOf = append(db.DatabasePrincipals[i].MemberOf,
				roleMembership("MemberOfTest_DbRole2", db.ObjectIdentifier))
		}
	}
	for i := range db.DatabasePrincipals {
		if db.DatabasePrincipals[i].Name == "MemberOfTest_DbRole2" {
			db.DatabasePrincipals[i].MemberOf = append(db.DatabasePrincipals[i].MemberOf,
				roleMembership("db_owner", db.ObjectIdentifier))
		}
	}

	// Application role member of database role
	addAppRole(db, "MemberOfTest_AppRole",
		withDBPrincipalMemberOf(roleMembership("MemberOfTest_DbRole1", db.ObjectIdentifier)))

	return info
}

func TestMemberOfEdges(t *testing.T) {
	info := buildMemberOfTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,memberOfTestCases)
}

// =============================================================================
// ISMAPPEDTO
// =============================================================================

func buildIsMappedToTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SQL login with database user in primary DB
	sqlLogin := addSQLLogin(info, "IsMappedToTest_SQLLogin_WithDBUser")

	// Windows login mapped to database user
	winLogin1 := addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID())
	winLogin2 := addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser2", uniqueSID())

	// SQL login without any database user
	addSQLLogin(info, "IsMappedToTest_SQLLogin_NoDBUser")

	// Primary database
	dbPrimary := addDatabase(info, "EdgeTest_IsMappedTo_Primary")
	addDatabaseUser(dbPrimary, "IsMappedToTest_SQLLogin_WithDBUser",
		withServerLogin(sqlLogin.ObjectIdentifier, sqlLogin.Name, sqlLogin.PrincipalID))
	addWindowsUser(dbPrimary, "DOMAIN\\EdgeTestDomainUser1",
		withServerLogin(winLogin1.ObjectIdentifier, winLogin1.Name, winLogin1.PrincipalID))
	// Orphaned user (no login)
	addDatabaseUser(dbPrimary, "IsMappedToTest_OrphanedUser")

	// Secondary database
	dbSecondary := addDatabase(info, "EdgeTest_IsMappedTo_Secondary")
	addDatabaseUser(dbSecondary, "IsMappedToTest_DifferentUserName",
		withServerLogin(sqlLogin.ObjectIdentifier, sqlLogin.Name, sqlLogin.PrincipalID))
	addWindowsUser(dbSecondary, "DOMAIN\\EdgeTestDomainUser2",
		withServerLogin(winLogin2.ObjectIdentifier, winLogin2.Name, winLogin2.PrincipalID))

	return info
}

func TestIsMappedToEdges(t *testing.T) {
	info := buildIsMappedToTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,isMappedToTestCases)
}

// =============================================================================
// OWNS
// =============================================================================

func buildOwnsTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Login that owns a database
	dbOwnerLogin := addSQLLogin(info, "OwnsTest_Login_DbOwner")

	// Login that owns a server role
	roleOwnerLogin := addSQLLogin(info, "OwnsTest_Login_RoleOwner")

	// Login with no ownership
	addSQLLogin(info, "OwnsTest_Login_NoOwnership")

	// Server role owned by login
	addServerRole(info, "OwnsTest_ServerRole_Owned",
		withOwner(roleOwnerLogin.ObjectIdentifier))

	// Server role that owns another server role
	ownerRole := addServerRole(info, "OwnsTest_ServerRole_Owner")
	addServerRole(info, "OwnsTest_ServerRole_OwnedByRole",
		withOwner(ownerRole.ObjectIdentifier))

	// Database owned by login
	addDatabase(info, "EdgeTest_Owns_OwnedByLogin",
		withDBOwner(dbOwnerLogin.Name, dbOwnerLogin.ObjectIdentifier))

	// Database for role ownership tests
	dbRoles := addDatabase(info, "EdgeTest_Owns_RoleTests")

	// Database user that owns a role
	roleOwnerUser := addDatabaseUser(dbRoles, "OwnsTest_User_RoleOwner")
	addDatabaseRole(dbRoles, "OwnsTest_DbRole_Owned", false,
		withDBPrincipalOwner(roleOwnerUser.ObjectIdentifier))

	// Database role that owns another role
	ownerDbRole := addDatabaseRole(dbRoles, "OwnsTest_DbRole_Owner", false)
	addDatabaseRole(dbRoles, "OwnsTest_DbRole_OwnedByRole", false,
		withDBPrincipalOwner(ownerDbRole.ObjectIdentifier))

	// Application role that owns a database role
	ownerAppRole := addAppRole(dbRoles, "OwnsTest_AppRole_Owner")
	addDatabaseRole(dbRoles, "OwnsTest_DbRole_OwnedByAppRole", false,
		withDBPrincipalOwner(ownerAppRole.ObjectIdentifier))

	// Database user without ownership
	addDatabaseUser(dbRoles, "OwnsTest_User_NoOwnership")

	return info
}

func TestOwnsEdges(t *testing.T) {
	info := buildOwnsTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,ownsTestCases)
}

// =============================================================================
// HASLOGIN
// =============================================================================

func buildHasLoginTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Domain users with SQL logins (enabled, with CONNECT SQL)
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID())
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser2", uniqueSID())

	// Domain group with SQL login
	addWindowsGroup(info, "DOMAIN\\EdgeTestDomainGroup", uniqueSID())

	// Computer account with SQL login
	addWindowsLogin(info, "DOMAIN\\TestComputer$", uniqueSID())

	// Sysadmin domain user
	addWindowsLogin(info, "DOMAIN\\EdgeTestSysadmin", uniqueSID(),
		withMemberOf(roleMembership("sysadmin", testServerOID)))

	// Disabled Windows login
	addWindowsLogin(info, "DOMAIN\\EdgeTestDisabledUser", uniqueSID(),
		withDisabled())

	// Windows login with CONNECT SQL denied
	noConnectSID := uniqueSID()
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier:           "DOMAIN\\EdgeTestNoConnect@" + info.ObjectIdentifier,
		PrincipalID:                uniquePrincipalID(),
		Name:                       "DOMAIN\\EdgeTestNoConnect",
		TypeDescription:            "WINDOWS_LOGIN",
		IsActiveDirectoryPrincipal: true,
		SecurityIdentifier:         noConnectSID,
		SQLServerName:              info.SQLServerName,
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "DENY", ClassDesc: "SERVER"},
		},
	})

	// SQL login (should NOT create HasLogin edge)
	addSQLLogin(info, "HasLoginTest_SQLLogin")

	// Local group (BUILTIN)
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier:           "BUILTIN\\Remote Desktop Users@" + info.ObjectIdentifier,
		PrincipalID:                uniquePrincipalID(),
		Name:                       "BUILTIN\\Remote Desktop Users",
		TypeDescription:            "WINDOWS_GROUP",
		IsActiveDirectoryPrincipal: false,
		SecurityIdentifier:         "S-1-5-32-555",
		SQLServerName:              info.SQLServerName,
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "GRANT", ClassDesc: "SERVER"},
		},
	})

	return info
}

func TestHasLoginEdges(t *testing.T) {
	info := buildHasLoginTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,hasLoginTestCases)
}

// =============================================================================
// CONTROLSERVER
// =============================================================================

func buildControlServerTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Login with CONTROL SERVER permission
	addSQLLogin(info, "ControlServerTest_Login_HasControlServer",
		withPermissions(perm("CONTROL SERVER", "GRANT", "SERVER")))

	// Server role with CONTROL SERVER permission
	addServerRole(info, "ControlServerTest_ServerRole_HasControlServer",
		withPermissions(perm("CONTROL SERVER", "GRANT", "SERVER")))

	// sysadmin already in base server info (creates ControlServer via fixed role edges)

	return info
}

func TestControlServerEdges(t *testing.T) {
	info := buildControlServerTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,controlServerTestCases)
}

// =============================================================================
// CONTROLDB
// =============================================================================

func buildControlDBTestData() *types.ServerInfo {
	info := baseServerInfo()

	db := addDatabase(info, "EdgeTest_ControlDB")

	// Database user with CONTROL on database
	addDatabaseUser(db, "ControlDBTest_User_HasControlOnDb",
		withDBPrincipalPermissions(perm("CONTROL", "GRANT", "DATABASE")))

	// Database role with CONTROL on database
	addDatabaseRole(db, "ControlDBTest_DbRole_HasControlOnDb", false,
		withDBPrincipalPermissions(perm("CONTROL", "GRANT", "DATABASE")))

	// Application role with CONTROL on database
	addAppRole(db, "ControlDBTest_AppRole_HasControlOnDb",
		withDBPrincipalPermissions(perm("CONTROL", "GRANT", "DATABASE")))

	// db_owner fixed role (creates ControlDB via fixed role edges)
	addDatabaseRole(db, "db_owner", true)

	return info
}

func TestControlDBEdges(t *testing.T) {
	info := buildControlDBTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,controlDBTestCases)
}

// =============================================================================
// CONNECT
// =============================================================================

func buildConnectTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Login with CONNECT SQL permission (already has it from addSQLLogin defaults)
	addSQLLogin(info, "ConnectTest_Login_HasConnectSQL")

	// Server role with CONNECT SQL permission
	addServerRole(info, "ConnectTest_ServerRole_HasConnectSQL",
		withPermissions(perm("CONNECT SQL", "GRANT", "SERVER")))

	// Login with CONNECT SQL denied
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier: "ConnectTest_Login_NoConnectSQL@" + info.ObjectIdentifier,
		PrincipalID:      uniquePrincipalID(),
		Name:             "ConnectTest_Login_NoConnectSQL",
		TypeDescription:  "SQL_LOGIN",
		SQLServerName:    info.SQLServerName,
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "DENY", ClassDesc: "SERVER"},
		},
	})

	// Disabled login with CONNECT SQL
	addSQLLogin(info, "ConnectTest_Login_Disabled", withDisabled())

	// Database level
	db := addDatabase(info, "EdgeTest_Connect")

	// Database user with CONNECT permission
	addDatabaseUser(db, "ConnectTest_User_HasConnect",
		withDBPrincipalPermissions(perm("CONNECT", "GRANT", "DATABASE")))

	// Database role with CONNECT permission
	addDatabaseRole(db, "ConnectTest_DbRole_HasConnect", false,
		withDBPrincipalPermissions(perm("CONNECT", "GRANT", "DATABASE")))

	// Database user with CONNECT denied
	addDatabaseUser(db, "ConnectTest_User_NoConnect",
		withDBPrincipalPermissions(perm("CONNECT", "DENY", "DATABASE")))

	// Application role (cannot have CONNECT)
	addAppRole(db, "ConnectTest_AppRole")

	return info
}

func TestConnectEdges(t *testing.T) {
	info := buildConnectTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,connectTestCases)
}

// =============================================================================
// CONNECTANYDATABASE
// =============================================================================

func buildConnectAnyDatabaseTestData() *types.ServerInfo {
	info := baseServerInfo()

	addSQLLogin(info, "ConnectAnyDatabaseTest_Login_HasConnectAnyDatabase",
		withPermissions(perm("CONNECT ANY DATABASE", "GRANT", "SERVER")))
	addServerRole(info, "ConnectAnyDatabaseTest_ServerRole_HasConnectAnyDatabase",
		withPermissions(perm("CONNECT ANY DATABASE", "GRANT", "SERVER")))

	// ##MS_DatabaseConnector## is a built-in server role
	addServerRole(info, "##MS_DatabaseConnector##",
		withPermissions(perm("CONNECT ANY DATABASE", "GRANT", "SERVER")))

	return info
}

func TestConnectAnyDatabaseEdges(t *testing.T) {
	info := buildConnectAnyDatabaseTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,connectAnyDatabaseTestCases)
}

// =============================================================================
// CONTROL
// =============================================================================

func buildControlTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL
	targetLogin := addSQLLogin(info, "ControlTest_Login_TargetOf_Login_CanControlLogin")
	targetLogin2 := addSQLLogin(info, "ControlTest_Login_TargetOf_ServerRole_CanControlLogin")
	targetSR := addServerRole(info, "ControlTest_ServerRole_TargetOf_Login_CanControlServerRole")
	targetSR2 := addServerRole(info, "ControlTest_ServerRole_TargetOf_ServerRole_CanControlServerRole")

	addSQLLogin(info, "ControlTest_Login_CanControlLogin",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetLogin.PrincipalID, targetLogin.ObjectIdentifier, targetLogin.Name)))
	addSQLLogin(info, "ControlTest_Login_CanControlServerRole",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetSR.PrincipalID, targetSR.ObjectIdentifier, targetSR.Name)))
	addServerRole(info, "ControlTest_ServerRole_CanControlLogin",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetLogin2.PrincipalID, targetLogin2.ObjectIdentifier, targetLogin2.Name)))
	addServerRole(info, "ControlTest_ServerRole_CanControlServerRole",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetSR2.PrincipalID, targetSR2.ObjectIdentifier, targetSR2.Name)))

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_Control")

	// CONTROL on database
	addDatabaseUser(db, "ControlTest_User_CanControlDb",
		withDBPrincipalPermissions(perm("CONTROL", "GRANT", "DATABASE")))
	addDatabaseRole(db, "ControlTest_DbRole_CanControlDb", false,
		withDBPrincipalPermissions(perm("CONTROL", "GRANT", "DATABASE")))
	addAppRole(db, "ControlTest_AppRole_CanControlDb",
		withDBPrincipalPermissions(perm("CONTROL", "GRANT", "DATABASE")))

	// CONTROL on specific db users
	targetDBUser1 := addDatabaseUser(db, "ControlTest_User_TargetOf_User_CanControlDbUser")
	targetDBUser2 := addDatabaseUser(db, "ControlTest_User_TargetOf_DbRole_CanControlDbUser")
	targetDBUser3 := addDatabaseUser(db, "ControlTest_User_TargetOf_AppRole_CanControlDbUser")

	addDatabaseUser(db, "ControlTest_User_CanControlDbUser",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser1.PrincipalID, targetDBUser1.ObjectIdentifier, targetDBUser1.Name)))
	addDatabaseRole(db, "ControlTest_DbRole_CanControlDbUser", false,
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser2.PrincipalID, targetDBUser2.ObjectIdentifier, targetDBUser2.Name)))
	addAppRole(db, "ControlTest_AppRole_CanControlDbUser",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser3.PrincipalID, targetDBUser3.ObjectIdentifier, targetDBUser3.Name)))

	// CONTROL on specific db roles
	targetDBR1 := addDatabaseRole(db, "ControlTest_DbRole_TargetOf_User_CanControlDbRole", false)
	targetDBR2 := addDatabaseRole(db, "ControlTest_DbRole_TargetOf_DbRole_CanControlDbRole", false)
	targetDBR3 := addDatabaseRole(db, "ControlTest_DbRole_TargetOf_AppRole_CanControlDbRole", false)

	addDatabaseUser(db, "ControlTest_User_CanControlDbRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR1.PrincipalID, targetDBR1.ObjectIdentifier, targetDBR1.Name)))
	addDatabaseRole(db, "ControlTest_DbRole_CanControlDbRole", false,
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR2.PrincipalID, targetDBR2.ObjectIdentifier, targetDBR2.Name)))
	addAppRole(db, "ControlTest_AppRole_CanControlDbRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR3.PrincipalID, targetDBR3.ObjectIdentifier, targetDBR3.Name)))

	// CONTROL on specific app roles
	targetAR1 := addAppRole(db, "ControlTest_AppRole_TargetOf_User_CanControlAppRole")
	targetAR2 := addAppRole(db, "ControlTest_AppRole_TargetOf_DbRole_CanControlAppRole")
	targetAR3 := addAppRole(db, "ControlTest_AppRole_TargetOf_AppRole_CanControlAppRole")

	addDatabaseUser(db, "ControlTest_User_CanControlAppRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetAR1.PrincipalID, targetAR1.ObjectIdentifier, targetAR1.Name)))
	addDatabaseRole(db, "ControlTest_DbRole_CanControlAppRole", false,
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetAR2.PrincipalID, targetAR2.ObjectIdentifier, targetAR2.Name)))
	addAppRole(db, "ControlTest_AppRole_CanControlAppRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetAR3.PrincipalID, targetAR3.ObjectIdentifier, targetAR3.Name)))

	return info
}

func TestControlEdges(t *testing.T) {
	info := buildControlTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,controlTestCases)
}

// =============================================================================
// IMPERSONATEANYLOGIN
// =============================================================================

func buildImpersonateAnyLoginTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Direct SQL login with IMPERSONATE ANY LOGIN
	addSQLLogin(info, "ImpersonateAnyLoginTest_Login_Direct",
		withPermissions(perm("IMPERSONATE ANY LOGIN", "GRANT", "SERVER")))

	// Server role with IMPERSONATE ANY LOGIN
	role := addServerRole(info, "ImpersonateAnyLoginTest_Role_HasPermission",
		withPermissions(perm("IMPERSONATE ANY LOGIN", "GRANT", "SERVER")))

	// Windows login with IMPERSONATE ANY LOGIN
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID(),
		withPermissions(perm("IMPERSONATE ANY LOGIN", "GRANT", "SERVER")))

	// Login without IMPERSONATE ANY LOGIN
	addSQLLogin(info, "ImpersonateAnyLoginTest_Login_NoPermission")

	// Login member of the role (should NOT create direct edge)
	addSQLLogin(info, "ImpersonateAnyLoginTest_Login_ViaRole",
		withMemberOf(types.RoleMembership{
			ObjectIdentifier: role.ObjectIdentifier,
			Name:             role.Name,
		}))

	return info
}

func TestImpersonateAnyLoginEdges(t *testing.T) {
	info := buildImpersonateAnyLoginTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,impersonateAnyLoginTestCases)
}

// =============================================================================
// ALTERANYSERVERROLE
// =============================================================================

func buildAlterAnyServerRoleTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Add bulkadmin fixed role
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier: "bulkadmin@" + testServerOID,
		PrincipalID:      uniquePrincipalID(),
		Name:             "bulkadmin",
		TypeDescription:  "SERVER_ROLE",
		IsFixedRole:      true,
		SQLServerName:    testSQLName,
	})

	// Login with ALTER ANY SERVER ROLE - member of processadmin but not bulkadmin
	addSQLLogin(info, "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole",
		withPermissions(perm("ALTER ANY SERVER ROLE", "GRANT", "SERVER")),
		withMemberOf(
			roleMembership("processadmin", testServerOID),
			roleMembership("sysadmin", testServerOID), // member of sysadmin for negative test
		))

	// Server role with ALTER ANY SERVER ROLE - member of bulkadmin but not processadmin
	addServerRole(info, "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole",
		withPermissions(perm("ALTER ANY SERVER ROLE", "GRANT", "SERVER")),
		withMemberOf(roleMembership("bulkadmin", testServerOID)))

	// Target user-defined roles
	addServerRole(info, "AlterAnyServerRoleTest_TargetRole1")
	addServerRole(info, "AlterAnyServerRoleTest_TargetRole2")

	return info
}

func TestAlterAnyServerRoleEdges(t *testing.T) {
	info := buildAlterAnyServerRoleTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,alterAnyServerRoleTestCases)
}

// =============================================================================
// GRANTANYPERMISSION
// =============================================================================

func buildGrantAnyPermTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Login member of securityadmin (should NOT have direct GrantAnyPermission edge)
	addSQLLogin(info, "GrantAnyPermissionTest_Login_InSecurityAdmin",
		withMemberOf(roleMembership("securityadmin", testServerOID)))

	// Regular login with no special permissions
	addSQLLogin(info, "GrantAnyPermissionTest_Login_NoSpecialPerms")

	// Database for testing that GrantAnyPermission doesn't leak to db level
	db := addDatabase(info, "EdgeTest_GrantAnyPermission")
	addDatabaseRole(db, "db_securityadmin", true)

	return info
}

func TestGrantAnyPermissionEdges(t *testing.T) {
	info := buildGrantAnyPermTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,grantAnyPermTestCases)
}

// =============================================================================
// GRANTANYDBPERMISSION
// =============================================================================

func buildGrantAnyDBPermTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Primary database with db_securityadmin
	db := addDatabase(info, "EdgeTest_GrantAnyDBPermission")
	addDatabaseRole(db, "db_securityadmin", true)
	addDatabaseRole(db, "db_owner", true)

	// User member of db_securityadmin (should NOT create edge, only db_securityadmin role itself does)
	addDatabaseUser(db, "GrantAnyDBPermissionTest_User_InDbSecurityAdmin",
		withDBPrincipalMemberOf(roleMembership("db_securityadmin", db.ObjectIdentifier)))

	// Custom role with ALTER ANY ROLE (should NOT create GrantAnyDBPermission edge)
	addDatabaseRole(db, "GrantAnyDBPermissionTest_CustomRole_HasAlterAnyRole", false,
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))

	// Regular user not in db_securityadmin
	addDatabaseUser(db, "GrantAnyDBPermissionTest_User_NotInDbSecurityAdmin")

	// Second database to test cross-db isolation
	db2 := addDatabase(info, "EdgeTest_GrantAnyDBPermission_Second")
	addDatabaseRole(db2, "db_securityadmin", true)

	return info
}

func TestGrantAnyDBPermissionEdges(t *testing.T) {
	info := buildGrantAnyDBPermTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,grantAnyDBPermTestCases)
}

// =============================================================================
// ADDMEMBER
// =============================================================================

func buildAddMemberTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Target server roles
	targetSR1 := addServerRole(info, "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole")
	targetSR2 := addServerRole(info, "AddMemberTest_ServerRole_TargetOf_Login_CanControlServerRole")
	targetSR3 := addServerRole(info, "AddMemberTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole")
	targetSR4 := addServerRole(info, "AddMemberTest_ServerRole_TargetOf_ServerRole_CanControlServerRole")

	// Login with ALTER on role -> AddMember
	addSQLLogin(info, "AddMemberTest_Login_CanAlterServerRole",
		withPermissions(targetPerm("ALTER", "GRANT", "SERVER_PRINCIPAL",
			targetSR1.PrincipalID, targetSR1.ObjectIdentifier, targetSR1.Name)))

	// Login with CONTROL on role -> AddMember
	addSQLLogin(info, "AddMemberTest_Login_CanControlServerRole",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetSR2.PrincipalID, targetSR2.ObjectIdentifier, targetSR2.Name)))

	// Login with ALTER ANY SERVER ROLE -> AddMember to user-defined roles + processadmin (if member)
	addSQLLogin(info, "AddMemberTest_Login_CanAlterAnyServerRole",
		withPermissions(perm("ALTER ANY SERVER ROLE", "GRANT", "SERVER")),
		withMemberOf(roleMembership("processadmin", testServerOID)))

	// ServerRole with ALTER on role -> AddMember
	addServerRole(info, "AddMemberTest_ServerRole_CanAlterServerRole",
		withPermissions(targetPerm("ALTER", "GRANT", "SERVER_PRINCIPAL",
			targetSR3.PrincipalID, targetSR3.ObjectIdentifier, targetSR3.Name)))

	// ServerRole with CONTROL on role -> AddMember
	addServerRole(info, "AddMemberTest_ServerRole_CanControlServerRole",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetSR4.PrincipalID, targetSR4.ObjectIdentifier, targetSR4.Name)))

	// ServerRole with ALTER ANY SERVER ROLE -> AddMember to user-defined roles + processadmin
	addServerRole(info, "AddMemberTest_ServerRole_CanAlterAnyServerRole",
		withPermissions(perm("ALTER ANY SERVER ROLE", "GRANT", "SERVER")),
		withMemberOf(roleMembership("processadmin", testServerOID)))

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_AddMember")
	addDatabaseRole(db, "db_securityadmin", true)
	addDatabaseRole(db, "ddladmin", true) // Fixed role to test negative case

	// Target database roles
	targetDBR1 := addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDbRole", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_DbRole_CanControlDbRole", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDbRole", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_AppRole_CanControlDbRole", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_User_CanAlterDb", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDb", false)
	addDatabaseRole(db, "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDb", false)

	// DatabaseUser with ALTER on role
	addDatabaseUser(db, "AddMemberTest_User_CanAlterDbRole",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR1.PrincipalID, targetDBR1.ObjectIdentifier, targetDBR1.Name)))

	// DatabaseUser with ALTER ANY ROLE
	addDatabaseUser(db, "AddMemberTest_User_CanAlterAnyDbRole",
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))

	// DatabaseUser with ALTER on database
	addDatabaseUser(db, "AddMemberTest_User_CanAlterDb",
		withDBPrincipalPermissions(perm("ALTER", "GRANT", "DATABASE")))

	// DatabaseRole with ALTER on role
	dbr1 := findDBPrincipal(db, "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDbRole")
	addDatabaseRole(db, "AddMemberTest_DbRole_CanAlterDbRole", false,
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			dbr1.PrincipalID, dbr1.ObjectIdentifier, dbr1.Name)))

	// DatabaseRole with CONTROL on role
	dbr2 := findDBPrincipal(db, "AddMemberTest_DbRole_TargetOf_DbRole_CanControlDbRole")
	addDatabaseRole(db, "AddMemberTest_DbRole_CanControlDbRole", false,
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			dbr2.PrincipalID, dbr2.ObjectIdentifier, dbr2.Name)))

	// DatabaseRole with ALTER ANY ROLE
	addDatabaseRole(db, "AddMemberTest_DbRole_CanAlterAnyDbRole", false,
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))

	// DatabaseRole with ALTER on database
	addDatabaseRole(db, "AddMemberTest_DbRole_CanAlterDb", false,
		withDBPrincipalPermissions(perm("ALTER", "GRANT", "DATABASE")))

	// ApplicationRole with ALTER on role
	dbr3 := findDBPrincipal(db, "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDbRole")
	addAppRole(db, "AddMemberTest_AppRole_CanAlterDbRole",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			dbr3.PrincipalID, dbr3.ObjectIdentifier, dbr3.Name)))

	// ApplicationRole with CONTROL on role
	dbr4 := findDBPrincipal(db, "AddMemberTest_DbRole_TargetOf_AppRole_CanControlDbRole")
	addAppRole(db, "AddMemberTest_AppRole_CanControlDbRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			dbr4.PrincipalID, dbr4.ObjectIdentifier, dbr4.Name)))

	// ApplicationRole with ALTER ANY ROLE
	addAppRole(db, "AddMemberTest_AppRole_CanAlterAnyDbRole",
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))

	// ApplicationRole with ALTER on database
	addAppRole(db, "AddMemberTest_AppRole_CanAlterDb",
		withDBPrincipalPermissions(perm("ALTER", "GRANT", "DATABASE")))

	return info
}

// findDBPrincipal looks up a database principal by name from a database.
func findDBPrincipal(db *types.Database, name string) *types.DatabasePrincipal {
	for i := range db.DatabasePrincipals {
		if db.DatabasePrincipals[i].Name == name {
			return &db.DatabasePrincipals[i]
		}
	}
	return nil
}

func TestAddMemberEdges(t *testing.T) {
	info := buildAddMemberTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,addMemberTestCases)
}

// =============================================================================
// ALTER
// =============================================================================

func buildAlterTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL
	targetLogin := addSQLLogin(info, "AlterTest_Login_TargetOf_Login_CanAlterLogin")
	targetLogin2 := addSQLLogin(info, "AlterTest_Login_TargetOf_ServerRole_CanAlterLogin")
	targetSR := addServerRole(info, "AlterTest_ServerRole_TargetOf_Login_CanAlterServerRole")
	targetSR2 := addServerRole(info, "AlterTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole")

	addSQLLogin(info, "AlterTest_Login_CanAlterLogin",
		withPermissions(targetPerm("ALTER", "GRANT", "SERVER_PRINCIPAL",
			targetLogin.PrincipalID, targetLogin.ObjectIdentifier, targetLogin.Name)))
	addSQLLogin(info, "AlterTest_Login_CanAlterServerRole",
		withPermissions(targetPerm("ALTER", "GRANT", "SERVER_PRINCIPAL",
			targetSR.PrincipalID, targetSR.ObjectIdentifier, targetSR.Name)))
	addServerRole(info, "AlterTest_ServerRole_CanAlterLogin",
		withPermissions(targetPerm("ALTER", "GRANT", "SERVER_PRINCIPAL",
			targetLogin2.PrincipalID, targetLogin2.ObjectIdentifier, targetLogin2.Name)))
	addServerRole(info, "AlterTest_ServerRole_CanAlterServerRole",
		withPermissions(targetPerm("ALTER", "GRANT", "SERVER_PRINCIPAL",
			targetSR2.PrincipalID, targetSR2.ObjectIdentifier, targetSR2.Name)))

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_Alter")

	// ALTER on database
	addDatabaseUser(db, "AlterTest_User_CanAlterDb",
		withDBPrincipalPermissions(perm("ALTER", "GRANT", "DATABASE")))
	addDatabaseRole(db, "AlterTest_DbRole_CanAlterDb", false,
		withDBPrincipalPermissions(perm("ALTER", "GRANT", "DATABASE")))
	addAppRole(db, "AlterTest_AppRole_CanAlterDb",
		withDBPrincipalPermissions(perm("ALTER", "GRANT", "DATABASE")))

	// ALTER on specific db users
	targetDBUser1 := addDatabaseUser(db, "AlterTest_User_TargetOf_User_CanAlterDbUser")
	targetDBUser2 := addDatabaseUser(db, "AlterTest_User_TargetOf_DbRole_CanAlterDbUser")
	targetDBUser3 := addDatabaseUser(db, "AlterTest_User_TargetOf_AppRole_CanAlterDbUser")

	addDatabaseUser(db, "AlterTest_User_CanAlterDbUser",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser1.PrincipalID, targetDBUser1.ObjectIdentifier, targetDBUser1.Name)))
	addDatabaseRole(db, "AlterTest_DbRole_CanAlterDbUser", false,
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser2.PrincipalID, targetDBUser2.ObjectIdentifier, targetDBUser2.Name)))
	addAppRole(db, "AlterTest_AppRole_CanAlterDbUser",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser3.PrincipalID, targetDBUser3.ObjectIdentifier, targetDBUser3.Name)))

	// ALTER on specific db roles
	targetDBR1 := addDatabaseRole(db, "AlterTest_DbRole_TargetOf_User_CanAlterDbRole", false)
	targetDBR2 := addDatabaseRole(db, "AlterTest_DbRole_TargetOf_DbRole_CanAlterDbRole", false)
	targetDBR3 := addDatabaseRole(db, "AlterTest_DbRole_TargetOf_AppRole_CanAlterDbRole", false)

	addDatabaseUser(db, "AlterTest_User_CanAlterDbRole",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR1.PrincipalID, targetDBR1.ObjectIdentifier, targetDBR1.Name)))
	addDatabaseRole(db, "AlterTest_DbRole_CanAlterDbRole", false,
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR2.PrincipalID, targetDBR2.ObjectIdentifier, targetDBR2.Name)))
	addAppRole(db, "AlterTest_AppRole_CanAlterDbRole",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR3.PrincipalID, targetDBR3.ObjectIdentifier, targetDBR3.Name)))

	// ALTER on specific app roles
	targetAR1 := addAppRole(db, "AlterTest_AppRole_TargetOf_User_CanAlterAppRole")
	targetAR2 := addAppRole(db, "AlterTest_AppRole_TargetOf_DbRole_CanAlterAppRole")
	targetAR3 := addAppRole(db, "AlterTest_AppRole_TargetOf_AppRole_CanAlterAppRole")

	addDatabaseUser(db, "AlterTest_User_CanAlterAppRole",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetAR1.PrincipalID, targetAR1.ObjectIdentifier, targetAR1.Name)))
	addDatabaseRole(db, "AlterTest_DbRole_CanAlterAppRole", false,
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetAR2.PrincipalID, targetAR2.ObjectIdentifier, targetAR2.Name)))
	addAppRole(db, "AlterTest_AppRole_CanAlterAppRole",
		withDBPrincipalPermissions(targetPerm("ALTER", "GRANT", "DATABASE_PRINCIPAL",
			targetAR3.PrincipalID, targetAR3.ObjectIdentifier, targetAR3.Name)))

	return info
}

func TestAlterEdges(t *testing.T) {
	info := buildAlterTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,alterTestCases)
}

// =============================================================================
// ALTERANYAPPROLE
// =============================================================================

func buildAlterAnyAppRoleTestData() *types.ServerInfo {
	info := baseServerInfo()

	db := addDatabase(info, "EdgeTest_AlterAnyAppRole")

	addDatabaseUser(db, "AlterAnyAppRoleTest_User_HasAlterAnyAppRole",
		withDBPrincipalPermissions(perm("ALTER ANY APPLICATION ROLE", "GRANT", "DATABASE")))
	addDatabaseRole(db, "AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole", false,
		withDBPrincipalPermissions(perm("ALTER ANY APPLICATION ROLE", "GRANT", "DATABASE")))
	addAppRole(db, "AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole",
		withDBPrincipalPermissions(perm("ALTER ANY APPLICATION ROLE", "GRANT", "DATABASE")))
	addDatabaseRole(db, "db_securityadmin", true)

	return info
}

func TestAlterAnyAppRoleEdges(t *testing.T) {
	info := buildAlterAnyAppRoleTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,alterAnyAppRoleTestCases)
}

// =============================================================================
// ALTERANYLOGIN
// =============================================================================

func buildAlterAnyLoginTestData() *types.ServerInfo {
	info := baseServerInfo()

	addSQLLogin(info, "AlterAnyLoginTest_Login_HasAlterAnyLogin",
		withPermissions(perm("ALTER ANY LOGIN", "GRANT", "SERVER")))
	addServerRole(info, "AlterAnyLoginTest_ServerRole_HasAlterAnyLogin",
		withPermissions(perm("ALTER ANY LOGIN", "GRANT", "SERVER")))

	return info
}

func TestAlterAnyLoginEdges(t *testing.T) {
	info := buildAlterAnyLoginTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,alterAnyLoginTestCases)
}

// =============================================================================
// EXECUTEAS
// =============================================================================

func buildExecuteAsTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL: IMPERSONATE creates ExecuteAs edges
	targetLogin := addSQLLogin(info, "ExecuteAsTest_Login_TargetOf_Login_CanImpersonateLogin")
	targetLogin2 := addSQLLogin(info, "ExecuteAsTest_Login_TargetOf_Login_CanControlLogin")
	targetLogin3 := addSQLLogin(info, "ExecuteAsTest_Login_TargetOf_ServerRole_CanImpersonateLogin")
	targetLogin4 := addSQLLogin(info, "ExecuteAsTest_Login_TargetOf_ServerRole_CanControlLogin")

	addSQLLogin(info, "ExecuteAsTest_Login_CanImpersonateLogin",
		withPermissions(targetPerm("IMPERSONATE", "GRANT", "SERVER_PRINCIPAL",
			targetLogin.PrincipalID, targetLogin.ObjectIdentifier, targetLogin.Name)))
	addSQLLogin(info, "ExecuteAsTest_Login_CanControlLogin",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetLogin2.PrincipalID, targetLogin2.ObjectIdentifier, targetLogin2.Name)))
	addServerRole(info, "ExecuteAsTest_ServerRole_CanImpersonateLogin",
		withPermissions(targetPerm("IMPERSONATE", "GRANT", "SERVER_PRINCIPAL",
			targetLogin3.PrincipalID, targetLogin3.ObjectIdentifier, targetLogin3.Name)))
	addServerRole(info, "ExecuteAsTest_ServerRole_CanControlLogin",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetLogin4.PrincipalID, targetLogin4.ObjectIdentifier, targetLogin4.Name)))

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_ExecuteAs")

	targetDBUser := addDatabaseUser(db, "ExecuteAsTest_User_TargetOf_User_CanImpersonateDbUser")
	targetDBUser2 := addDatabaseUser(db, "ExecuteAsTest_User_TargetOf_User_CanControlDbUser")
	targetDBUser3 := addDatabaseUser(db, "ExecuteAsTest_User_TargetOf_DbRole_CanImpersonateDbUser")
	targetDBUser4 := addDatabaseUser(db, "ExecuteAsTest_User_TargetOf_DbRole_CanControlDbUser")
	targetDBUser5 := addDatabaseUser(db, "ExecuteAsTest_User_TargetOf_AppRole_CanImpersonateDbUser")
	targetDBUser6 := addDatabaseUser(db, "ExecuteAsTest_User_TargetOf_AppRole_CanControlDbUser")

	addDatabaseUser(db, "ExecuteAsTest_User_CanImpersonateDbUser",
		withDBPrincipalPermissions(targetPerm("IMPERSONATE", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser.PrincipalID, targetDBUser.ObjectIdentifier, targetDBUser.Name)))
	addDatabaseUser(db, "ExecuteAsTest_User_CanControlDbUser",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser2.PrincipalID, targetDBUser2.ObjectIdentifier, targetDBUser2.Name)))
	addDatabaseRole(db, "ExecuteAsTest_DbRole_CanImpersonateDbUser", false,
		withDBPrincipalPermissions(targetPerm("IMPERSONATE", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser3.PrincipalID, targetDBUser3.ObjectIdentifier, targetDBUser3.Name)))
	addDatabaseRole(db, "ExecuteAsTest_DbRole_CanControlDbUser", false,
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser4.PrincipalID, targetDBUser4.ObjectIdentifier, targetDBUser4.Name)))
	addAppRole(db, "ExecuteAsTest_AppRole_CanImpersonateDbUser",
		withDBPrincipalPermissions(targetPerm("IMPERSONATE", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser5.PrincipalID, targetDBUser5.ObjectIdentifier, targetDBUser5.Name)))
	addAppRole(db, "ExecuteAsTest_AppRole_CanControlDbUser",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser6.PrincipalID, targetDBUser6.ObjectIdentifier, targetDBUser6.Name)))

	return info
}

func TestExecuteAsEdges(t *testing.T) {
	info := buildExecuteAsTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,executeAsTestCases)
}

// =============================================================================
// CHANGEOWNER
// =============================================================================

func buildChangeOwnerTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL
	targetSR1 := addServerRole(info, "ChangeOwnerTest_ServerRole_TargetOf_Login")
	targetSR2 := addServerRole(info, "ChangeOwnerTest_ServerRole_TargetOf_Login_CanControlServerRole")
	targetSR3 := addServerRole(info, "ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanTakeOwnershipServerRole")
	targetSR4 := addServerRole(info, "ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanControlServerRole")

	addSQLLogin(info, "ChangeOwnerTest_Login_CanTakeOwnershipServerRole",
		withPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "SERVER_PRINCIPAL",
			targetSR1.PrincipalID, targetSR1.ObjectIdentifier, targetSR1.Name)))
	addSQLLogin(info, "ChangeOwnerTest_Login_CanControlServerRole",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetSR2.PrincipalID, targetSR2.ObjectIdentifier, targetSR2.Name)))
	addServerRole(info, "ChangeOwnerTest_ServerRole_CanTakeOwnershipServerRole",
		withPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "SERVER_PRINCIPAL",
			targetSR3.PrincipalID, targetSR3.ObjectIdentifier, targetSR3.Name)))
	addServerRole(info, "ChangeOwnerTest_ServerRole_CanControlServerRole",
		withPermissions(targetPerm("CONTROL", "GRANT", "SERVER_PRINCIPAL",
			targetSR4.PrincipalID, targetSR4.ObjectIdentifier, targetSR4.Name)))

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_ChangeOwner")

	targetDBR1 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDb", false)
	targetDBR2 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDb", false)
	targetDBR3 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDb", false)
	targetDBR4 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDbRole", false)
	targetDBR5 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_User_CanControlDbRole", false)
	targetDBR6 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDbRole", false)
	targetDBR7 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanControlDbRole", false)
	targetDBR8 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDbRole", false)
	targetDBR9 := addDatabaseRole(db, "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanControlDbRole", false)

	// TAKE OWNERSHIP on database -> roles
	addDatabaseUser(db, "ChangeOwnerTest_User_CanTakeOwnershipDb",
		withDBPrincipalPermissions(perm("TAKE OWNERSHIP", "GRANT", "DATABASE")))
	addDatabaseRole(db, "ChangeOwnerTest_DbRole_CanTakeOwnershipDb", false,
		withDBPrincipalPermissions(perm("TAKE OWNERSHIP", "GRANT", "DATABASE")))
	addAppRole(db, "ChangeOwnerTest_AppRole_CanTakeOwnershipDb",
		withDBPrincipalPermissions(perm("TAKE OWNERSHIP", "GRANT", "DATABASE")))

	// TAKE OWNERSHIP/CONTROL on specific role
	addDatabaseUser(db, "ChangeOwnerTest_User_CanTakeOwnershipDbRole",
		withDBPrincipalPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR4.PrincipalID, targetDBR4.ObjectIdentifier, targetDBR4.Name)))
	addDatabaseUser(db, "ChangeOwnerTest_User_CanControlDbRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR5.PrincipalID, targetDBR5.ObjectIdentifier, targetDBR5.Name)))
	addDatabaseRole(db, "ChangeOwnerTest_DbRole_CanTakeOwnershipDbRole", false,
		withDBPrincipalPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR6.PrincipalID, targetDBR6.ObjectIdentifier, targetDBR6.Name)))
	addDatabaseRole(db, "ChangeOwnerTest_DbRole_CanControlDbRole", false,
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR7.PrincipalID, targetDBR7.ObjectIdentifier, targetDBR7.Name)))
	addAppRole(db, "ChangeOwnerTest_AppRole_CanTakeOwnershipDbRole",
		withDBPrincipalPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR8.PrincipalID, targetDBR8.ObjectIdentifier, targetDBR8.Name)))
	addAppRole(db, "ChangeOwnerTest_AppRole_CanControlDbRole",
		withDBPrincipalPermissions(targetPerm("CONTROL", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR9.PrincipalID, targetDBR9.ObjectIdentifier, targetDBR9.Name)))

	// Reference unused vars for TAKE OWNERSHIP on database -> ChangeOwner
	_ = targetDBR1
	_ = targetDBR2
	_ = targetDBR3

	return info
}

func TestChangeOwnerEdges(t *testing.T) {
	info := buildChangeOwnerTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,changeOwnerTestCases)
}

// =============================================================================
// CHANGEPASSWORD
// =============================================================================

func buildChangePasswordTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL
	addSQLLogin(info, "ChangePasswordTest_Login_TargetOf_Login_CanAlterAnyLogin")
	addSQLLogin(info, "ChangePasswordTest_Login_TargetOf_ServerRole_CanAlterAnyLogin")
	addSQLLogin(info, "ChangePasswordTest_Login_TargetOf_SecurityAdmin")

	// Login with ALTER ANY LOGIN
	addSQLLogin(info, "ChangePasswordTest_Login_CanAlterAnyLogin",
		withPermissions(perm("ALTER ANY LOGIN", "GRANT", "SERVER")))

	// ServerRole with ALTER ANY LOGIN
	addServerRole(info, "ChangePasswordTest_ServerRole_CanAlterAnyLogin",
		withPermissions(perm("ALTER ANY LOGIN", "GRANT", "SERVER")))

	// Target with sysadmin (should NOT be targetable)
	addSQLLogin(info, "ChangePasswordTest_Login_WithSysadmin",
		withMemberOf(roleMembership("sysadmin", testServerOID)))

	// Target with CONTROL SERVER (should NOT be targetable)
	addSQLLogin(info, "ChangePasswordTest_Login_WithControlServer",
		withPermissions(perm("CONTROL SERVER", "GRANT", "SERVER")))

	// sa login already tested implicitly

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_ChangePassword")

	targetAR1 := addAppRole(db, "ChangePasswordTest_AppRole_TargetOf_User_CanAlterAnyAppRole")
	targetAR2 := addAppRole(db, "ChangePasswordTest_AppRole_TargetOf_DbRole_CanAlterAnyAppRole")
	targetAR3 := addAppRole(db, "ChangePasswordTest_AppRole_TargetOf_AppRole_CanAlterAnyAppRole")
	targetAR4 := addAppRole(db, "ChangePasswordTest_AppRole_TargetOf_DbSecurityAdmin")

	addDatabaseUser(db, "ChangePasswordTest_User_CanAlterAnyAppRole",
		withDBPrincipalPermissions(perm("ALTER ANY APPLICATION ROLE", "GRANT", "DATABASE")))
	addDatabaseRole(db, "ChangePasswordTest_DbRole_CanAlterAnyAppRole", false,
		withDBPrincipalPermissions(perm("ALTER ANY APPLICATION ROLE", "GRANT", "DATABASE")))
	addAppRole(db, "ChangePasswordTest_AppRole_CanAlterAnyAppRole",
		withDBPrincipalPermissions(perm("ALTER ANY APPLICATION ROLE", "GRANT", "DATABASE")))
	addDatabaseRole(db, "db_securityadmin", true)

	_ = targetAR1
	_ = targetAR2
	_ = targetAR3
	_ = targetAR4

	return info
}

func TestChangePasswordEdges(t *testing.T) {
	info := buildChangePasswordTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,changePasswordTestCases)
}

// =============================================================================
// ALTERANYDBROLE
// =============================================================================

func buildAlterAnyDBRoleTestData() *types.ServerInfo {
	info := baseServerInfo()

	db := addDatabase(info, "EdgeTest_AlterAnyDBRole")

	// Target user-defined roles
	addDatabaseRole(db, "AlterAnyDBRoleTest_TargetRole1", false)
	addDatabaseRole(db, "AlterAnyDBRoleTest_TargetRole2", false)
	addDatabaseRole(db, "db_datareader", true)
	addDatabaseRole(db, "db_owner", true)

	// Sources with ALTER ANY ROLE
	addDatabaseUser(db, "AlterAnyDBRoleTest_User_HasAlterAnyRole",
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))
	addDatabaseRole(db, "AlterAnyDBRoleTest_DbRole_HasAlterAnyRole", false,
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))
	addAppRole(db, "AlterAnyDBRoleTest_AppRole_HasAlterAnyRole",
		withDBPrincipalPermissions(perm("ALTER ANY ROLE", "GRANT", "DATABASE")))

	// db_securityadmin fixed role
	addDatabaseRole(db, "db_securityadmin", true)

	return info
}

func TestAlterAnyDBRoleEdges(t *testing.T) {
	info := buildAlterAnyDBRoleTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,alterAnyDBRoleTestCases)
}

// =============================================================================
// TAKEOWNERSHIP
// =============================================================================

func buildTakeOwnershipTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL
	targetSR := addServerRole(info, "TakeOwnershipTest_ServerRole_Target")

	addSQLLogin(info, "TakeOwnershipTest_Login_CanTakeServerRole",
		withPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "SERVER_PRINCIPAL",
			targetSR.PrincipalID, targetSR.ObjectIdentifier, targetSR.Name)))
	addServerRole(info, "TakeOwnershipTest_ServerRole_Source",
		withPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "SERVER_PRINCIPAL",
			targetSR.PrincipalID, targetSR.ObjectIdentifier, targetSR.Name)))

	// Login without permission
	addSQLLogin(info, "TakeOwnershipTest_Login_NoPermission")

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_TakeOwnership")
	addDatabaseRole(db, "db_owner", true)

	targetDBR := addDatabaseRole(db, "TakeOwnershipTest_DbRole_Target", false)

	// Database-level TAKE OWNERSHIP on database
	addDatabaseUser(db, "TakeOwnershipTest_User_CanTakeDb",
		withDBPrincipalPermissions(perm("TAKE OWNERSHIP", "GRANT", "DATABASE")))
	addDatabaseRole(db, "TakeOwnershipTest_DbRole_CanTakeDb", false,
		withDBPrincipalPermissions(perm("TAKE OWNERSHIP", "GRANT", "DATABASE")))
	addAppRole(db, "TakeOwnershipTest_AppRole_CanTakeDb",
		withDBPrincipalPermissions(perm("TAKE OWNERSHIP", "GRANT", "DATABASE")))

	// Database-level TAKE OWNERSHIP on specific role
	addDatabaseUser(db, "TakeOwnershipTest_User_CanTakeRole",
		withDBPrincipalPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR.PrincipalID, targetDBR.ObjectIdentifier, targetDBR.Name)))
	addDatabaseRole(db, "TakeOwnershipTest_DbRole_Source", false,
		withDBPrincipalPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR.PrincipalID, targetDBR.ObjectIdentifier, targetDBR.Name)))
	addAppRole(db, "TakeOwnershipTest_AppRole_CanTakeRole",
		withDBPrincipalPermissions(targetPerm("TAKE OWNERSHIP", "GRANT", "DATABASE_PRINCIPAL",
			targetDBR.PrincipalID, targetDBR.ObjectIdentifier, targetDBR.Name)))

	// User without permission
	addDatabaseUser(db, "TakeOwnershipTest_User_NoPermission")

	return info
}

func TestTakeOwnershipEdges(t *testing.T) {
	info := buildTakeOwnershipTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,takeOwnershipTestCases)
}

// =============================================================================
// EXECUTEASOWNER + ISTRUSTEDBY
// =============================================================================

func buildExecuteAsOwnerTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Login with sysadmin
	loginSysadmin := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithSysadmin",
		withMemberOf(roleMembership("sysadmin", testServerOID)))

	// Login with securityadmin
	loginSecurityadmin := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithSecurityadmin",
		withMemberOf(roleMembership("securityadmin", testServerOID)))

	// Login with nested role in securityadmin
	nestedRole := addServerRole(info, "ExecuteAsOwnerTest_NestedRole",
		withMemberOf(roleMembership("securityadmin", testServerOID)))
	loginNestedSecurityadmin := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithNestedRoleInSecurityadmin",
		withMemberOf(types.RoleMembership{
			ObjectIdentifier: nestedRole.ObjectIdentifier,
			Name:             nestedRole.Name,
		}))

	// Login with CONTROL SERVER
	loginControlServer := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithControlServer",
		withPermissions(perm("CONTROL SERVER", "GRANT", "SERVER")))

	// Login with role that has CONTROL SERVER
	roleWithControlServer := addServerRole(info, "ExecuteAsOwnerTest_RoleWithControlServer",
		withPermissions(perm("CONTROL SERVER", "GRANT", "SERVER")))
	loginRoleControlServer := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithRoleWithControlServer",
		withMemberOf(types.RoleMembership{
			ObjectIdentifier: roleWithControlServer.ObjectIdentifier,
			Name:             roleWithControlServer.Name,
		}))

	// Login with IMPERSONATE ANY LOGIN
	loginImpersonateAny := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithImpersonateAnyLogin",
		withPermissions(perm("IMPERSONATE ANY LOGIN", "GRANT", "SERVER")))

	// Login with role that has IMPERSONATE ANY LOGIN
	roleWithImpersonate := addServerRole(info, "ExecuteAsOwnerTest_RoleWithImpersonateAnyLogin",
		withPermissions(perm("IMPERSONATE ANY LOGIN", "GRANT", "SERVER")))
	loginRoleImpersonate := addSQLLogin(info, "ExecuteAsOwnerTest_Login_WithRoleWithImpersonateAnyLogin",
		withMemberOf(types.RoleMembership{
			ObjectIdentifier: roleWithImpersonate.ObjectIdentifier,
			Name:             roleWithImpersonate.Name,
		}))

	// Login without high privileges
	loginNoHighPriv := addSQLLogin(info, "ExecuteAsOwnerTest_Login_NoHighPrivileges")

	// TRUSTWORTHY databases owned by each login type
	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin",
		withTrustworthy(),
		withDBOwner(loginSysadmin.Name, loginSysadmin.ObjectIdentifier))

	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin",
		withTrustworthy(),
		withDBOwner(loginSecurityadmin.Name, loginSecurityadmin.ObjectIdentifier))

	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithNestedRoleInSecurityadmin",
		withTrustworthy(),
		withDBOwner(loginNestedSecurityadmin.Name, loginNestedSecurityadmin.ObjectIdentifier))

	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithControlServer",
		withTrustworthy(),
		withDBOwner(loginControlServer.Name, loginControlServer.ObjectIdentifier))

	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithControlServer",
		withTrustworthy(),
		withDBOwner(loginRoleControlServer.Name, loginRoleControlServer.ObjectIdentifier))

	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithImpersonateAnyLogin",
		withTrustworthy(),
		withDBOwner(loginImpersonateAny.Name, loginImpersonateAny.ObjectIdentifier))

	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithImpersonateAnyLogin",
		withTrustworthy(),
		withDBOwner(loginRoleImpersonate.Name, loginRoleImpersonate.ObjectIdentifier))

	// TRUSTWORTHY db owned by login WITHOUT high privileges (negative)
	addDatabase(info, "EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges",
		withTrustworthy(),
		withDBOwner(loginNoHighPriv.Name, loginNoHighPriv.ObjectIdentifier))

	// Non-trustworthy db (negative)
	addDatabase(info, "EdgeTest_ExecuteAsOwner_NotTrustworthy",
		withDBOwner(loginSysadmin.Name, loginSysadmin.ObjectIdentifier))

	return info
}

func TestExecuteAsOwnerEdges(t *testing.T) {
	info := buildExecuteAsOwnerTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,executeAsOwnerTestCases)
}

// =============================================================================
// EXECUTEONHOST + HOSTFOR
// =============================================================================

func TestExecuteOnHostEdges(t *testing.T) {
	info := baseServerInfo()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,executeOnHostTestCases)
}

// =============================================================================
// LINKEDTO + LINKEDASADMIN
// =============================================================================

func buildLinkedServerTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Create 11 linked servers pointing back to ourselves (loopback)
	// to match test expectation of 11 LinkedTo edges.
	// Each gets a unique LocalLogin so StreamingWriter dedup doesn't collapse them.
	for i := 0; i < 11; i++ {
		name := "LinkedServer" + string(rune('A'+i))
		opts := []linkedServerOption{
			withResolvedTarget(testServerOID),
			withLocalLogin(fmt.Sprintf("locallogin%d", i)),
		}
		// 8 of them are admin (SQL login, sysadmin, mixed mode)
		if i < 8 {
			opts = append(opts,
				withRemoteLogin("adminuser"),
				withRemoteSysadmin(),
				withRemoteMixedMode(),
			)
		} else {
			// The other 3 are non-admin (Windows login with backslash)
			opts = append(opts,
				withRemoteLogin("DOMAIN\\windowsuser"),
				withRemoteMixedMode(),
			)
		}
		addLinkedServer(info, name, "edgetest.domain.com", opts...)
	}

	return info
}

func TestLinkedAsAdminEdges(t *testing.T) {
	info := buildLinkedServerTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,linkedAsAdminTestCases)
}

// =============================================================================
// LINKEDTO
// =============================================================================

func TestLinkedToEdges(t *testing.T) {
	info := buildLinkedServerTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,linkedToTestCases)
}

// =============================================================================
// HASMAPPEDCRED
// =============================================================================

func buildHasMappedCredTestData() *types.ServerInfo {
	info := baseServerInfo()

	domainUser1SID := uniqueSID()
	domainUser2SID := uniqueSID()
	computerSID := uniqueSID()
	differentUserSID := uniqueSID()

	// Credentials
	cred1 := &types.Credential{
		CredentialID:       uniquePrincipalID(),
		Name:               "DomainUser1Cred",
		CredentialIdentity: "DOMAIN\\DomainUser1",
		ResolvedSID:        domainUser1SID,
	}
	cred2 := &types.Credential{
		CredentialID:       uniquePrincipalID(),
		Name:               "DomainUser2Cred",
		CredentialIdentity: "DOMAIN\\DomainUser2",
		ResolvedSID:        domainUser2SID,
	}
	cred3 := &types.Credential{
		CredentialID:       uniquePrincipalID(),
		Name:               "ComputerCred",
		CredentialIdentity: "DOMAIN\\TestComputer$",
		ResolvedSID:        computerSID,
	}
	cred4 := &types.Credential{
		CredentialID:       uniquePrincipalID(),
		Name:               "DifferentUserCred",
		CredentialIdentity: "DOMAIN\\DifferentUser",
		ResolvedSID:        differentUserSID,
	}

	// SQL logins mapped to domain credentials
	addSQLLogin(info, "HasMappedCredTest_SQLLogin_MappedToDomainUser1",
		withMappedCredential(cred1))
	addSQLLogin(info, "HasMappedCredTest_SQLLogin_MappedToDomainUser2",
		withMappedCredential(cred2))
	addSQLLogin(info, "HasMappedCredTest_SQLLogin_MappedToComputerAccount",
		withMappedCredential(cred3))
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID(),
		withMappedCredential(cred4))
	addSQLLogin(info, "HasMappedCredTest_SQLLogin_NoCredential")

	info.Credentials = append(info.Credentials, *cred1, *cred2, *cred3, *cred4)

	return info
}

func TestHasMappedCredEdges(t *testing.T) {
	info := buildHasMappedCredTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,hasMappedCredTestCases)
}

// =============================================================================
// HASPROXYCRED
// =============================================================================

func buildHasProxyCredTestData() *types.ServerInfo {
	info := baseServerInfo()

	domainUser1SID := uniqueSID()
	domainUser2SID := uniqueSID()

	// Server principals that are authorized for proxies
	addSQLLogin(info, "HasProxyCredTest_ETLOperator")
	addSQLLogin(info, "HasProxyCredTest_BackupOperator")
	addServerRole(info, "HasProxyCredTest_ProxyUsers")
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID())
	addSQLLogin(info, "HasProxyCredTest_NoProxyAccess")

	// Proxy accounts
	addProxyAccount(info, "ETLProxy", "DOMAIN\\DomainUser1", domainUser1SID, true,
		[]string{"SSIS"}, []string{"HasProxyCredTest_ETLOperator", "HasProxyCredTest_ProxyUsers"})

	addProxyAccount(info, "BackupProxy", "DOMAIN\\DomainUser2", domainUser2SID, true,
		[]string{"CmdExec"}, []string{"HasProxyCredTest_BackupOperator", "DOMAIN\\EdgeTestDomainUser1"})

	// Disabled proxy (edge still created per PS1)
	addProxyAccount(info, "DisabledProxy", "DOMAIN\\DomainUser1", domainUser1SID, false,
		[]string{"SSIS"}, []string{"HasProxyCredTest_ETLOperator"})

	return info
}

func TestHasProxyCredEdges(t *testing.T) {
	info := buildHasProxyCredTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,hasProxyCredTestCases)
}

// =============================================================================
// IMPERSONATE
// =============================================================================

func buildImpersonateTestData() *types.ServerInfo {
	info := baseServerInfo()

	// SERVER LEVEL
	targetLogin := addSQLLogin(info, "ImpersonateTest_Login_TargetOf_Login_CanImpersonateLogin")
	targetLogin2 := addSQLLogin(info, "ImpersonateTest_Login_TargetOf_ServerRole_CanImpersonateLogin")

	addSQLLogin(info, "ImpersonateTest_Login_CanImpersonateLogin",
		withPermissions(targetPerm("IMPERSONATE", "GRANT", "SERVER_PRINCIPAL",
			targetLogin.PrincipalID, targetLogin.ObjectIdentifier, targetLogin.Name)))
	addServerRole(info, "ImpersonateTest_ServerRole_CanImpersonateLogin",
		withPermissions(targetPerm("IMPERSONATE", "GRANT", "SERVER_PRINCIPAL",
			targetLogin2.PrincipalID, targetLogin2.ObjectIdentifier, targetLogin2.Name)))

	// DATABASE LEVEL
	db := addDatabase(info, "EdgeTest_Impersonate")

	targetDBUser1 := addDatabaseUser(db, "ImpersonateTest_User_TargetOf_User_CanImpersonateDbUser")
	targetDBUser2 := addDatabaseUser(db, "ImpersonateTest_User_TargetOf_DbRole_CanImpersonateDbUser")
	targetDBUser3 := addDatabaseUser(db, "ImpersonateTest_User_TargetOf_AppRole_CanImpersonateDbUser")

	addDatabaseUser(db, "ImpersonateTest_User_CanImpersonateDbUser",
		withDBPrincipalPermissions(targetPerm("IMPERSONATE", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser1.PrincipalID, targetDBUser1.ObjectIdentifier, targetDBUser1.Name)))
	addDatabaseRole(db, "ImpersonateTest_DbRole_CanImpersonateDbUser", false,
		withDBPrincipalPermissions(targetPerm("IMPERSONATE", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser2.PrincipalID, targetDBUser2.ObjectIdentifier, targetDBUser2.Name)))
	addAppRole(db, "ImpersonateTest_AppRole_CanImpersonateDbUser",
		withDBPrincipalPermissions(targetPerm("IMPERSONATE", "GRANT", "DATABASE_PRINCIPAL",
			targetDBUser3.PrincipalID, targetDBUser3.ObjectIdentifier, targetDBUser3.Name)))

	return info
}

func TestImpersonateEdges(t *testing.T) {
	info := buildImpersonateTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,impersonateTestCases)
}

// =============================================================================
// HASDBSCOPEDCRED
// =============================================================================

func buildHasDBScopedCredTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Database with scoped credential
	db := addDatabase(info, "EdgeTest_HasDBScopedCred")
	addDBScopedCredential(db, "DomainUserCred", "DOMAIN\\CredUser", uniqueSID())

	// master database without scoped credentials
	addDatabase(info, "master")

	return info
}

func TestHasDBScopedCredEdges(t *testing.T) {
	info := buildHasDBScopedCredTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,hasDBScopedCredTestCases)
}

// =============================================================================
// COERCEANDRELAYTOMSSQL
// =============================================================================

func buildCoerceAndRelayTestData() *types.ServerInfo {
	info := baseServerInfo()
	// EPA must be Off for CoerceAndRelay edges
	info.ExtendedProtection = "Off"

	coerceEnabled1SID := uniqueSID()
	coerceEnabled2SID := uniqueSID()
	coerceDisabledSID := uniqueSID()
	coerceNoConnectSID := uniqueSID()
	coerceUserSID := uniqueSID()

	// Computer accounts with SQL logins (enabled, CONNECT SQL)
	addWindowsLogin(info, "DOMAIN\\CoerceTestEnabled1$", coerceEnabled1SID,
		withSecurityIdentifier(coerceEnabled1SID))
	addWindowsLogin(info, "DOMAIN\\CoerceTestEnabled2$", coerceEnabled2SID,
		withSecurityIdentifier(coerceEnabled2SID))

	// Computer with disabled SQL login
	addWindowsLogin(info, "DOMAIN\\CoerceTestDisabled$", coerceDisabledSID,
		withSecurityIdentifier(coerceDisabledSID),
		withDisabled())

	// Computer with CONNECT SQL denied
	info.ServerPrincipals = append(info.ServerPrincipals, types.ServerPrincipal{
		ObjectIdentifier:           "DOMAIN\\CoerceTestNoConnect$@" + info.ObjectIdentifier,
		PrincipalID:                uniquePrincipalID(),
		Name:                       "DOMAIN\\CoerceTestNoConnect$",
		TypeDescription:            "WINDOWS_LOGIN",
		IsActiveDirectoryPrincipal: true,
		SecurityIdentifier:         coerceNoConnectSID,
		SQLServerName:              info.SQLServerName,
		Permissions: []types.Permission{
			{Permission: "CONNECT SQL", State: "DENY", ClassDesc: "SERVER"},
		},
	})

	// Regular user (not computer - name doesn't end with $)
	addWindowsLogin(info, "DOMAIN\\CoerceTestUser", coerceUserSID,
		withSecurityIdentifier(coerceUserSID))

	// SQL login (not Windows login - no HasLogin edge target)
	addSQLLogin(info, "CoerceTestSQLLogin")

	return info
}

func TestCoerceAndRelayEdges(t *testing.T) {
	info := buildCoerceAndRelayTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,coerceAndRelayTestCases)
}

// =============================================================================
// GETTGS
// =============================================================================

func buildGetTGSTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Domain users with SQL logins (enabled, CONNECT SQL)
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser1", uniqueSID())
	addWindowsLogin(info, "DOMAIN\\EdgeTestDomainUser2", uniqueSID())
	addWindowsGroup(info, "DOMAIN\\EdgeTestDomainGroup", uniqueSID())
	addWindowsLogin(info, "DOMAIN\\EdgeTestSysadmin", uniqueSID(),
		withMemberOf(roleMembership("sysadmin", testServerOID)))

	// Service account (domain account)
	saSID := uniqueSID()
	addServiceAccount(info, "DOMAIN\\SQLService", saSID, "MSSQLSERVER", "SQL Server")

	return info
}

func TestGetTGSEdges(t *testing.T) {
	info := buildGetTGSTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,getTGSTestCases)
}

// =============================================================================
// GETADMINTGS
// =============================================================================

func TestGetAdminTGSEdges(t *testing.T) {
	info := buildGetTGSTestData() // Re-use GetTGS data since it has domain sysadmin
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,getAdminTGSTestCases)
}

// =============================================================================
// SERVICEACCOUNTFOR + HASSESSION
// =============================================================================

func buildServiceAccountForTestData() *types.ServerInfo {
	info := baseServerInfo()

	// Domain service account (not a computer account)
	saSID := uniqueSID()
	addServiceAccount(info, "DOMAIN\\SQLService", saSID, "MSSQLSERVER", "SQL Server")

	return info
}

func TestServiceAccountForEdges(t *testing.T) {
	info := buildServiceAccountForTestData()
	result := runEdgeCreation(t, info, true)
	runTestCases(t, result.Edges,serviceAccountForTestCases)
}

// =============================================================================
// COVERAGE TEST: Verify all edge types have test cases
// =============================================================================

func TestAllEdgeTypesHaveCoverage(t *testing.T) {
	byType := testCasesByEdgeType()

	// All edge kinds that should have test coverage
	allKinds := []string{
		bloodhound.EdgeKinds.AddMember,
		bloodhound.EdgeKinds.Alter,
		bloodhound.EdgeKinds.AlterAnyAppRole,
		bloodhound.EdgeKinds.AlterAnyDBRole,
		bloodhound.EdgeKinds.AlterAnyLogin,
		bloodhound.EdgeKinds.AlterAnyServerRole,
		bloodhound.EdgeKinds.ChangeOwner,
		bloodhound.EdgeKinds.ChangePassword,
		bloodhound.EdgeKinds.CoerceAndRelayTo,
		bloodhound.EdgeKinds.Connect,
		bloodhound.EdgeKinds.ConnectAnyDatabase,
		bloodhound.EdgeKinds.Contains,
		bloodhound.EdgeKinds.Control,
		bloodhound.EdgeKinds.ControlDB,
		bloodhound.EdgeKinds.ControlServer,
		bloodhound.EdgeKinds.ExecuteAs,
		bloodhound.EdgeKinds.ExecuteAsOwner,
		bloodhound.EdgeKinds.ExecuteOnHost,
		bloodhound.EdgeKinds.GetAdminTGS,
		bloodhound.EdgeKinds.GetTGS,
		bloodhound.EdgeKinds.GrantAnyDBPermission,
		bloodhound.EdgeKinds.GrantAnyPermission,
		bloodhound.EdgeKinds.HasDBScopedCred,
		bloodhound.EdgeKinds.HasLogin,
		bloodhound.EdgeKinds.HasMappedCred,
		bloodhound.EdgeKinds.HasProxyCred,
		bloodhound.EdgeKinds.HasSession,
		bloodhound.EdgeKinds.HostFor,
		bloodhound.EdgeKinds.Impersonate,
		bloodhound.EdgeKinds.ImpersonateAnyLogin,
		bloodhound.EdgeKinds.IsMappedTo,
		bloodhound.EdgeKinds.IsTrustedBy,
		bloodhound.EdgeKinds.LinkedAsAdmin,
		bloodhound.EdgeKinds.LinkedTo,
		bloodhound.EdgeKinds.MemberOf,
		bloodhound.EdgeKinds.Owns,
		bloodhound.EdgeKinds.ServiceAccountFor,
		bloodhound.EdgeKinds.TakeOwnership,
	}

	for _, kind := range allKinds {
		if _, ok := byType[kind]; !ok {
			t.Errorf("Edge type %s has no test cases", kind)
		}
	}
}
