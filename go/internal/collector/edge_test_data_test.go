package collector

// This file contains all test case definitions translated 1:1 from
// Invoke-MSSQLHoundUnitTests.ps1 lines 3953-7284.
// Each Go variable corresponds to a PS1 $script:expectedEdges_* array.
// NOTE: Defensive-only test cases have been removed.

// ---------------------------------------------------------------------------
// MSSQL_AddMember
// ---------------------------------------------------------------------------

var addMemberTestCases = []edgeTestCase{
	// Fixed role permissions
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "db_securityadmin can add members to user-defined database roles",
		SourcePattern: "db_securityadmin@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "db_securityadmin has ALTER ANY ROLE but cannot add members to fixed roles",
		SourcePattern: "db_securityadmin@*\\EdgeTest_AddMember",
		TargetPattern: "ddladmin@*",
		Negative:      true,
		Reason:        "Only db_owner can add members to fixed roles",
		Perspective:   "offensive",
	},

	// SERVER LEVEL: Login -> ServerRole
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "Login with ALTER on role can add members",
		SourcePattern: "AddMemberTest_Login_CanAlterServerRole@*",
		TargetPattern: "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "Login with CONTROL on role can add members",
		SourcePattern: "AddMemberTest_Login_CanControlServerRole@*",
		TargetPattern: "AddMemberTest_ServerRole_TargetOf_Login_CanControlServerRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "Login with ALTER ANY SERVER ROLE can add to user-defined roles",
		SourcePattern: "AddMemberTest_Login_CanAlterAnyServerRole@*",
		TargetPattern: "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "Login member of processadmin can add to processadmin",
		SourcePattern: "AddMemberTest_Login_CanAlterAnyServerRole@*",
		TargetPattern: "processadmin@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "Login with ALTER ANY SERVER ROLE CANNOT add to sysadmin",
		SourcePattern: "AddMemberTest_Login_CanAlterAnyServerRole@*",
		TargetPattern: "sysadmin@*",
		Negative:      true,
		Reason:        "sysadmin role does not accept new members via ALTER ANY SERVER ROLE",
		Perspective:   "offensive",
	},

	// SERVER LEVEL: ServerRole -> ServerRole
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ServerRole with ALTER on role can add members",
		SourcePattern: "AddMemberTest_ServerRole_CanAlterServerRole@*",
		TargetPattern: "AddMemberTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ServerRole with CONTROL on role can add members",
		SourcePattern: "AddMemberTest_ServerRole_CanControlServerRole@*",
		TargetPattern: "AddMemberTest_ServerRole_TargetOf_ServerRole_CanControlServerRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ServerRole with ALTER ANY SERVER ROLE can add to user-defined roles",
		SourcePattern: "AddMemberTest_ServerRole_CanAlterAnyServerRole@*",
		TargetPattern: "AddMemberTest_ServerRole_TargetOf_Login_CanAlterServerRole@*",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ServerRole member of processadmin can add to processadmin",
		SourcePattern: "AddMemberTest_ServerRole_CanAlterAnyServerRole@*",
		TargetPattern: "processadmin@*",
		Perspective:   "offensive",
	},

	// DATABASE LEVEL: DatabaseUser -> DatabaseRole
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseUser with ALTER on role can add members",
		SourcePattern: "AddMemberTest_User_CanAlterDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseUser with ALTER ANY ROLE can add to user-defined roles",
		SourcePattern: "AddMemberTest_User_CanAlterAnyDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseUser with ALTER on database can add to user-defined roles",
		SourcePattern: "AddMemberTest_User_CanAlterDb@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_User_CanAlterDb@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},

	// DATABASE LEVEL: DatabaseRole -> DatabaseRole
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseRole with ALTER on role can add members",
		SourcePattern: "AddMemberTest_DbRole_CanAlterDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseRole with CONTROL on role can add members",
		SourcePattern: "AddMemberTest_DbRole_CanControlDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_DbRole_CanControlDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseRole with ALTER ANY ROLE can add to user-defined roles",
		SourcePattern: "AddMemberTest_DbRole_CanAlterAnyDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "DatabaseRole with ALTER on database can add to user-defined roles",
		SourcePattern: "AddMemberTest_DbRole_CanAlterDb@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_DbRole_CanAlterDb@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},

	// DATABASE LEVEL: ApplicationRole -> DatabaseRole
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ApplicationRole with ALTER on role can add members",
		SourcePattern: "AddMemberTest_AppRole_CanAlterDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ApplicationRole with CONTROL on role can add members",
		SourcePattern: "AddMemberTest_AppRole_CanControlDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_AppRole_CanControlDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ApplicationRole with ALTER ANY ROLE can add to user-defined roles",
		SourcePattern: "AddMemberTest_AppRole_CanAlterAnyDbRole@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_User_CanAlterDbRole@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
	{
		EdgeType:      "MSSQL_AddMember",
		Description:   "ApplicationRole with ALTER on database can add to user-defined roles",
		SourcePattern: "AddMemberTest_AppRole_CanAlterDb@*\\EdgeTest_AddMember",
		TargetPattern: "AddMemberTest_DbRole_TargetOf_AppRole_CanAlterDb@*\\EdgeTest_AddMember",
		Perspective:   "offensive",
	},
}

// ---------------------------------------------------------------------------
// MSSQL_Alter
// ---------------------------------------------------------------------------

var alterTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_Alter", Description: "Login with ALTER on login", SourcePattern: "AlterTest_Login_CanAlterLogin@*", TargetPattern: "AlterTest_Login_TargetOf_Login_CanAlterLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "Login with ALTER on role can alter role", SourcePattern: "AlterTest_Login_CanAlterServerRole@*", TargetPattern: "AlterTest_ServerRole_TargetOf_Login_CanAlterServerRole@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "ServerRole with ALTER on login", SourcePattern: "AlterTest_ServerRole_CanAlterLogin@*", TargetPattern: "AlterTest_Login_TargetOf_ServerRole_CanAlterLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "ServerRole with ALTER on role can alter role", SourcePattern: "AlterTest_ServerRole_CanAlterServerRole@*", TargetPattern: "AlterTest_ServerRole_TargetOf_ServerRole_CanAlterServerRole@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseUser with ALTER on database can alter database", SourcePattern: "AlterTest_User_CanAlterDb@*\\EdgeTest_Alter", TargetPattern: "*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseRole with ALTER on database can alter database", SourcePattern: "AlterTest_DbRole_CanAlterDb@*\\EdgeTest_Alter", TargetPattern: "*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "ApplicationRole with ALTER on database can alter database", SourcePattern: "AlterTest_AppRole_CanAlterDb@*\\EdgeTest_Alter", TargetPattern: "*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseUser with ALTER on user", SourcePattern: "AlterTest_User_CanAlterDbUser@*\\EdgeTest_Alter", TargetPattern: "AlterTest_User_TargetOf_User_CanAlterDbUser@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseRole with ALTER on user", SourcePattern: "AlterTest_DbRole_CanAlterDbUser@*\\EdgeTest_Alter", TargetPattern: "AlterTest_User_TargetOf_DbRole_CanAlterDbUser@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "ApplicationRole with ALTER on user", SourcePattern: "AlterTest_AppRole_CanAlterDbUser@*\\EdgeTest_Alter", TargetPattern: "AlterTest_User_TargetOf_AppRole_CanAlterDbUser@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseUser with ALTER on role can alter role", SourcePattern: "AlterTest_User_CanAlterDbRole@*\\EdgeTest_Alter", TargetPattern: "AlterTest_DbRole_TargetOf_User_CanAlterDbRole@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseRole with ALTER on role can alter role", SourcePattern: "AlterTest_DbRole_CanAlterDbRole@*\\EdgeTest_Alter", TargetPattern: "AlterTest_DbRole_TargetOf_DbRole_CanAlterDbRole@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "ApplicationRole with ALTER on role can alter role", SourcePattern: "AlterTest_AppRole_CanAlterDbRole@*\\EdgeTest_Alter", TargetPattern: "AlterTest_DbRole_TargetOf_AppRole_CanAlterDbRole@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseUser with ALTER on app role", SourcePattern: "AlterTest_User_CanAlterAppRole@*\\EdgeTest_Alter", TargetPattern: "AlterTest_AppRole_TargetOf_User_CanAlterAppRole@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "DatabaseRole with ALTER on app role", SourcePattern: "AlterTest_DbRole_CanAlterAppRole@*\\EdgeTest_Alter", TargetPattern: "AlterTest_AppRole_TargetOf_DbRole_CanAlterAppRole@*\\EdgeTest_Alter", Perspective: "offensive"},
	{EdgeType: "MSSQL_Alter", Description: "ApplicationRole with ALTER on app role", SourcePattern: "AlterTest_AppRole_CanAlterAppRole@*\\EdgeTest_Alter", TargetPattern: "AlterTest_AppRole_TargetOf_AppRole_CanAlterAppRole@*\\EdgeTest_Alter", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_AlterAnyAppRole
// ---------------------------------------------------------------------------

var alterAnyAppRoleTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_AlterAnyAppRole", Description: "DatabaseUser with ALTER ANY APPLICATION ROLE targets database", SourcePattern: "AlterAnyAppRoleTest_User_HasAlterAnyAppRole@*\\EdgeTest_AlterAnyAppRole", TargetPattern: "*\\EdgeTest_AlterAnyAppRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyAppRole", Description: "DatabaseRole with ALTER ANY APPLICATION ROLE targets database", SourcePattern: "AlterAnyAppRoleTest_DbRole_HasAlterAnyAppRole@*\\EdgeTest_AlterAnyAppRole", TargetPattern: "*\\EdgeTest_AlterAnyAppRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyAppRole", Description: "ApplicationRole with ALTER ANY APPLICATION ROLE targets database", SourcePattern: "AlterAnyAppRoleTest_AppRole_HasAlterAnyAppRole@*\\EdgeTest_AlterAnyAppRole", TargetPattern: "*\\EdgeTest_AlterAnyAppRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyAppRole", Description: "db_securityadmin targets database", SourcePattern: "db_securityadmin@*\\EdgeTest_AlterAnyAppRole", TargetPattern: "*\\EdgeTest_AlterAnyAppRole", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_AlterAnyDBRole
// ---------------------------------------------------------------------------

var alterAnyDBRoleTestCases = []edgeTestCase{
	// OFFENSIVE: Source -> Database
	{EdgeType: "MSSQL_AlterAnyDBRole", Description: "DatabaseUser with ALTER ANY ROLE targets database", SourcePattern: "AlterAnyDBRoleTest_User_HasAlterAnyRole@*\\EdgeTest_AlterAnyDBRole", TargetPattern: "*\\EdgeTest_AlterAnyDBRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyDBRole", Description: "DatabaseRole with ALTER ANY ROLE targets database", SourcePattern: "AlterAnyDBRoleTest_DbRole_HasAlterAnyRole@*\\EdgeTest_AlterAnyDBRole", TargetPattern: "*\\EdgeTest_AlterAnyDBRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyDBRole", Description: "ApplicationRole with ALTER ANY ROLE targets database", SourcePattern: "AlterAnyDBRoleTest_AppRole_HasAlterAnyRole@*\\EdgeTest_AlterAnyDBRole", TargetPattern: "*\\EdgeTest_AlterAnyDBRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyDBRole", Description: "db_securityadmin targets database", SourcePattern: "db_securityadmin@*\\EdgeTest_AlterAnyDBRole", TargetPattern: "*\\EdgeTest_AlterAnyDBRole", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyDBRole", Description: "db_owner targets database", SourcePattern: "db_owner@*\\EdgeTest_AlterAnyDBRole", TargetPattern: "*\\EdgeTest_AlterAnyDBRole", Perspective: "offensive", Negative: true, Reason: "db_owner is not drawing edge, included under ControlDB"},
}

// ---------------------------------------------------------------------------
// MSSQL_AlterAnyLogin
// ---------------------------------------------------------------------------

var alterAnyLoginTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_AlterAnyLogin", Description: "Login with ALTER ANY LOGIN targets server", SourcePattern: "AlterAnyLoginTest_Login_HasAlterAnyLogin@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyLogin", Description: "ServerRole with ALTER ANY LOGIN targets server", SourcePattern: "AlterAnyLoginTest_ServerRole_HasAlterAnyLogin@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyLogin", Description: "securityadmin role targets server", SourcePattern: "securityadmin@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_AlterAnyServerRole
// ---------------------------------------------------------------------------

var alterAnyServerRoleTestCases = []edgeTestCase{
	// OFFENSIVE: Source -> Server
	{EdgeType: "MSSQL_AlterAnyServerRole", Description: "Login with ALTER ANY SERVER ROLE targets server", SourcePattern: "AlterAnyServerRoleTest_Login_HasAlterAnyServerRole@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyServerRole", Description: "ServerRole with ALTER ANY SERVER ROLE targets server", SourcePattern: "AlterAnyServerRoleTest_ServerRole_HasAlterAnyServerRole@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
	{EdgeType: "MSSQL_AlterAnyServerRole", Description: "sysadmin does not have AlterAnyServerRole edge drawn (covered by ControlServer)", SourcePattern: "sysadmin@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive", Negative: true},
}

// ---------------------------------------------------------------------------
// MSSQL_ChangeOwner
// ---------------------------------------------------------------------------

var changeOwnerTestCases = []edgeTestCase{
	// SERVER LEVEL
	{EdgeType: "MSSQL_ChangeOwner", Description: "Login with TAKE OWNERSHIP on server role", SourcePattern: "ChangeOwnerTest_Login_CanTakeOwnershipServerRole@*", TargetPattern: "ChangeOwnerTest_ServerRole_TargetOf_Login@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "Login with CONTROL on server role", SourcePattern: "ChangeOwnerTest_Login_CanControlServerRole@*", TargetPattern: "ChangeOwnerTest_ServerRole_TargetOf_Login_CanControlServerRole@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "ServerRole with TAKE OWNERSHIP on server role", SourcePattern: "ChangeOwnerTest_ServerRole_CanTakeOwnershipServerRole@*", TargetPattern: "ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanTakeOwnershipServerRole@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "ServerRole with CONTROL on server role", SourcePattern: "ChangeOwnerTest_ServerRole_CanControlServerRole@*", TargetPattern: "ChangeOwnerTest_ServerRole_TargetOf_ServerRole_CanControlServerRole@*", Perspective: "offensive"},

	// DATABASE LEVEL: TAKE OWNERSHIP on database -> roles
	{EdgeType: "MSSQL_ChangeOwner", Description: "DatabaseUser with TAKE OWNERSHIP on database -> roles", SourcePattern: "ChangeOwnerTest_User_CanTakeOwnershipDb@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDb@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "DatabaseRole with TAKE OWNERSHIP on database -> roles", SourcePattern: "ChangeOwnerTest_DbRole_CanTakeOwnershipDb@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDb@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "ApplicationRole with TAKE OWNERSHIP on database -> roles", SourcePattern: "ChangeOwnerTest_AppRole_CanTakeOwnershipDb@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDb@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},

	// DATABASE LEVEL: TAKE OWNERSHIP/CONTROL on specific role
	{EdgeType: "MSSQL_ChangeOwner", Description: "DatabaseUser with TAKE OWNERSHIP on specific role", SourcePattern: "ChangeOwnerTest_User_CanTakeOwnershipDbRole@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_User_CanTakeOwnershipDbRole@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "DatabaseUser with CONTROL on specific role", SourcePattern: "ChangeOwnerTest_User_CanControlDbRole@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_User_CanControlDbRole@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "DatabaseRole with TAKE OWNERSHIP on specific role", SourcePattern: "ChangeOwnerTest_DbRole_CanTakeOwnershipDbRole@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanTakeOwnershipDbRole@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "DatabaseRole with CONTROL on specific role", SourcePattern: "ChangeOwnerTest_DbRole_CanControlDbRole@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_DbRole_CanControlDbRole@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "ApplicationRole with TAKE OWNERSHIP on specific role", SourcePattern: "ChangeOwnerTest_AppRole_CanTakeOwnershipDbRole@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanTakeOwnershipDbRole@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangeOwner", Description: "ApplicationRole with CONTROL on specific role", SourcePattern: "ChangeOwnerTest_AppRole_CanControlDbRole@*\\EdgeTest_ChangeOwner", TargetPattern: "ChangeOwnerTest_DbRole_TargetOf_AppRole_CanControlDbRole@*\\EdgeTest_ChangeOwner", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_ChangePassword
// ---------------------------------------------------------------------------

var changePasswordTestCases = []edgeTestCase{
	// SERVER LEVEL
	{EdgeType: "MSSQL_ChangePassword", Description: "Login with ALTER ANY LOGIN can change password of SQL login", SourcePattern: "ChangePasswordTest_Login_CanAlterAnyLogin@*", TargetPattern: "ChangePasswordTest_Login_TargetOf_Login_CanAlterAnyLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "ServerRole with ALTER ANY LOGIN can change password of SQL login", SourcePattern: "ChangePasswordTest_ServerRole_CanAlterAnyLogin@*", TargetPattern: "ChangePasswordTest_Login_TargetOf_ServerRole_CanAlterAnyLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "securityadmin can change password of SQL login", SourcePattern: "securityadmin@*", TargetPattern: "ChangePasswordTest_Login_TargetOf_SecurityAdmin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "Cannot change password of login with sysadmin without CONTROL SERVER", SourcePattern: "ChangePasswordTest_Login_CanAlterAnyLogin@*", TargetPattern: "ChangePasswordTest_Login_WithSysadmin@*", Negative: true, Reason: "Target has sysadmin and source lacks CONTROL SERVER", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "Cannot change password of login with CONTROL SERVER", SourcePattern: "ChangePasswordTest_Login_CanAlterAnyLogin@*", TargetPattern: "ChangePasswordTest_Login_WithControlServer@*", Negative: true, Reason: "Target has CONTROL SERVER and source lacks CONTROL SERVER", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "Cannot change password of sa login", SourcePattern: "ChangePasswordTest_Login_CanAlterAnyLogin@*", TargetPattern: "sa@*", Negative: true, Reason: "sa login password cannot be changed via ALTER ANY LOGIN", Perspective: "offensive"},

	// DATABASE LEVEL: ApplicationRole password change
	{EdgeType: "MSSQL_ChangePassword", Description: "DatabaseUser with ALTER ANY APPLICATION ROLE can change app role password", SourcePattern: "ChangePasswordTest_User_CanAlterAnyAppRole@*\\EdgeTest_ChangePassword", TargetPattern: "ChangePasswordTest_AppRole_TargetOf_User_CanAlterAnyAppRole@*\\EdgeTest_ChangePassword", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "DatabaseRole with ALTER ANY APPLICATION ROLE can change app role password", SourcePattern: "ChangePasswordTest_DbRole_CanAlterAnyAppRole@*\\EdgeTest_ChangePassword", TargetPattern: "ChangePasswordTest_AppRole_TargetOf_DbRole_CanAlterAnyAppRole@*\\EdgeTest_ChangePassword", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "ApplicationRole with ALTER ANY APPLICATION ROLE can change app role password", SourcePattern: "ChangePasswordTest_AppRole_CanAlterAnyAppRole@*\\EdgeTest_ChangePassword", TargetPattern: "ChangePasswordTest_AppRole_TargetOf_AppRole_CanAlterAnyAppRole@*\\EdgeTest_ChangePassword", Perspective: "offensive"},
	{EdgeType: "MSSQL_ChangePassword", Description: "db_securityadmin can change app role password", SourcePattern: "db_securityadmin@*\\EdgeTest_ChangePassword", TargetPattern: "ChangePasswordTest_AppRole_TargetOf_DbSecurityAdmin@*\\EdgeTest_ChangePassword", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// CoerceAndRelayToMSSQL
// ---------------------------------------------------------------------------

var coerceAndRelayTestCases = []edgeTestCase{
	{EdgeType: "CoerceAndRelayToMSSQL", Description: "Authenticated Users can coerce and relay to computer with SQL login", SourcePattern: "*S-1-5-11", TargetPattern: "*CoerceTestEnabled1*", Perspective: "both"},
	{EdgeType: "CoerceAndRelayToMSSQL", Description: "Authenticated Users can coerce and relay to second computer with SQL login", SourcePattern: "*S-1-5-11", TargetPattern: "*CoerceTestEnabled2*", Perspective: "both"},
	{EdgeType: "CoerceAndRelayToMSSQL", Description: "No edge to computer with disabled SQL login", SourcePattern: "*S-1-5-11", TargetPattern: "*CoerceTestDisabled*", Negative: true, Reason: "Computer's SQL login is disabled", Perspective: "both"},
	{EdgeType: "CoerceAndRelayToMSSQL", Description: "No edge to computer with CONNECT SQL denied", SourcePattern: "*S-1-5-11", TargetPattern: "*CoerceTestNoConnect*", Negative: true, Reason: "Computer's SQL login has CONNECT SQL denied", Perspective: "both"},
	{EdgeType: "CoerceAndRelayToMSSQL", Description: "No edge for regular user account", SourcePattern: "*S-1-5-11", TargetPattern: "*CoerceTestUser*", Negative: true, Reason: "Target is not a computer account", Perspective: "both"},
	{EdgeType: "CoerceAndRelayToMSSQL", Description: "No edge for SQL login", SourcePattern: "*S-1-5-11", TargetPattern: "*CoerceTestSQLLogin*", Negative: true, Reason: "Target is not a Windows login", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_Connect
// ---------------------------------------------------------------------------

var connectTestCases = []edgeTestCase{
	// Server level - positive
	{EdgeType: "MSSQL_Connect", Description: "Login with CONNECT SQL permission", SourcePattern: "ConnectTest_Login_HasConnectSQL@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_Connect", Description: "Server role with CONNECT SQL permission", SourcePattern: "ConnectTest_ServerRole_HasConnectSQL@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},

	// Database level - positive
	{EdgeType: "MSSQL_Connect", Description: "Database user with CONNECT permission", SourcePattern: "ConnectTest_User_HasConnect@*\\EdgeTest_Connect", TargetPattern: "*\\EdgeTest_Connect", Perspective: "both"},
	{EdgeType: "MSSQL_Connect", Description: "Database role with CONNECT permission", SourcePattern: "ConnectTest_DbRole_HasConnect@*\\EdgeTest_Connect", TargetPattern: "*\\EdgeTest_Connect", Perspective: "both"},

	// Server level - negative
	{EdgeType: "MSSQL_Connect", Description: "Login with CONNECT SQL denied", SourcePattern: "ConnectTest_Login_NoConnectSQL@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "CONNECT SQL is denied", Perspective: "both"},
	{EdgeType: "MSSQL_Connect", Description: "Disabled login should not have Connect edge", SourcePattern: "ConnectTest_Login_Disabled@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Login is disabled", Perspective: "both"},

	// Database level - negative
	{EdgeType: "MSSQL_Connect", Description: "Database user with CONNECT denied", SourcePattern: "ConnectTest_User_NoConnect@*\\EdgeTest_Connect", TargetPattern: "*\\EdgeTest_Connect", Negative: true, Reason: "CONNECT is denied", Perspective: "both"},
	{EdgeType: "MSSQL_Connect", Description: "Application role cannot have CONNECT permission", SourcePattern: "ConnectTest_AppRole@*\\EdgeTest_Connect", TargetPattern: "*\\EdgeTest_Connect", Negative: true, Reason: "Application roles cannot be assigned CONNECT permission", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_ConnectAnyDatabase
// ---------------------------------------------------------------------------

var connectAnyDatabaseTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_ConnectAnyDatabase", Description: "Login with CONNECT ANY DATABASE permission", SourcePattern: "ConnectAnyDatabaseTest_Login_HasConnectAnyDatabase@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ConnectAnyDatabase", Description: "Server role with CONNECT ANY DATABASE permission", SourcePattern: "ConnectAnyDatabaseTest_ServerRole_HasConnectAnyDatabase@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ConnectAnyDatabase", Description: "##MS_DatabaseConnector## has CONNECT ANY DATABASE permission", SourcePattern: "##MS_DatabaseConnector##@*", TargetPattern: "S-1-5-21-*", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_Contains
// ---------------------------------------------------------------------------

var containsTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_Contains", Description: "Server contains database", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*\\EdgeTest_Contains", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Server contains login 1", SourcePattern: "S-1-5-21-*", TargetPattern: "ContainsTest_Login1@*", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Server contains login 2", SourcePattern: "S-1-5-21-*", TargetPattern: "ContainsTest_Login2@*", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Server contains server role 1", SourcePattern: "S-1-5-21-*", TargetPattern: "ContainsTest_ServerRole1@*", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Server contains server role 2", SourcePattern: "S-1-5-21-*", TargetPattern: "ContainsTest_ServerRole2@*", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Database contains database user 1", SourcePattern: "*\\EdgeTest_Contains", TargetPattern: "ContainsTest_User1@*\\EdgeTest_Contains", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Database contains database user 2", SourcePattern: "*\\EdgeTest_Contains", TargetPattern: "ContainsTest_User2@*\\EdgeTest_Contains", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Database contains database role 1", SourcePattern: "*\\EdgeTest_Contains", TargetPattern: "ContainsTest_DbRole1@*\\EdgeTest_Contains", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Database contains database role 2", SourcePattern: "*\\EdgeTest_Contains", TargetPattern: "ContainsTest_DbRole2@*\\EdgeTest_Contains", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Database contains application role 1", SourcePattern: "*\\EdgeTest_Contains", TargetPattern: "ContainsTest_AppRole1@*\\EdgeTest_Contains", Perspective: "both"},
	{EdgeType: "MSSQL_Contains", Description: "Database contains application role 2", SourcePattern: "*\\EdgeTest_Contains", TargetPattern: "ContainsTest_AppRole2@*\\EdgeTest_Contains", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_Control
// ---------------------------------------------------------------------------

var controlTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_Control", Description: "Login with CONTROL on login", SourcePattern: "ControlTest_Login_CanControlLogin@*", TargetPattern: "ControlTest_Login_TargetOf_Login_CanControlLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "Login with CONTROL on role can alter role", SourcePattern: "ControlTest_Login_CanControlServerRole@*", TargetPattern: "ControlTest_ServerRole_TargetOf_Login_CanControlServerRole@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "ServerRole with CONTROL on login", SourcePattern: "ControlTest_ServerRole_CanControlLogin@*", TargetPattern: "ControlTest_Login_TargetOf_ServerRole_CanControlLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "ServerRole with CONTROL on role can alter role", SourcePattern: "ControlTest_ServerRole_CanControlServerRole@*", TargetPattern: "ControlTest_ServerRole_TargetOf_ServerRole_CanControlServerRole@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseUser with CONTROL on database can alter database", SourcePattern: "ControlTest_User_CanControlDb@*\\EdgeTest_Control", TargetPattern: "*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseRole with CONTROL on database can alter database", SourcePattern: "ControlTest_DbRole_CanControlDb@*\\EdgeTest_Control", TargetPattern: "*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "ApplicationRole with CONTROL on database can alter database", SourcePattern: "ControlTest_AppRole_CanControlDb@*\\EdgeTest_Control", TargetPattern: "*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseUser with CONTROL on user", SourcePattern: "ControlTest_User_CanControlDbUser@*\\EdgeTest_Control", TargetPattern: "ControlTest_User_TargetOf_User_CanControlDbUser@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseRole with CONTROL on user", SourcePattern: "ControlTest_DbRole_CanControlDbUser@*\\EdgeTest_Control", TargetPattern: "ControlTest_User_TargetOf_DbRole_CanControlDbUser@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "ApplicationRole with CONTROL on user", SourcePattern: "ControlTest_AppRole_CanControlDbUser@*\\EdgeTest_Control", TargetPattern: "ControlTest_User_TargetOf_AppRole_CanControlDbUser@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseUser with CONTROL on role can alter role", SourcePattern: "ControlTest_User_CanControlDbRole@*\\EdgeTest_Control", TargetPattern: "ControlTest_DbRole_TargetOf_User_CanControlDbRole@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseRole with CONTROL on role can alter role", SourcePattern: "ControlTest_DbRole_CanControlDbRole@*\\EdgeTest_Control", TargetPattern: "ControlTest_DbRole_TargetOf_DbRole_CanControlDbRole@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "ApplicationRole with CONTROL on role can alter role", SourcePattern: "ControlTest_AppRole_CanControlDbRole@*\\EdgeTest_Control", TargetPattern: "ControlTest_DbRole_TargetOf_AppRole_CanControlDbRole@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseUser with CONTROL on app role", SourcePattern: "ControlTest_User_CanControlAppRole@*\\EdgeTest_Control", TargetPattern: "ControlTest_AppRole_TargetOf_User_CanControlAppRole@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "DatabaseRole with CONTROL on app role", SourcePattern: "ControlTest_DbRole_CanControlAppRole@*\\EdgeTest_Control", TargetPattern: "ControlTest_AppRole_TargetOf_DbRole_CanControlAppRole@*\\EdgeTest_Control", Perspective: "offensive"},
	{EdgeType: "MSSQL_Control", Description: "ApplicationRole with CONTROL on app role", SourcePattern: "ControlTest_AppRole_CanControlAppRole@*\\EdgeTest_Control", TargetPattern: "ControlTest_AppRole_TargetOf_AppRole_CanControlAppRole@*\\EdgeTest_Control", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_ControlDB
// ---------------------------------------------------------------------------

var controlDBTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_ControlDB", Description: "DatabaseUser with CONTROL on database", SourcePattern: "ControlDBTest_User_HasControlOnDb@*\\EdgeTest_ControlDB", TargetPattern: "*\\EdgeTest_ControlDB", Perspective: "both"},
	{EdgeType: "MSSQL_ControlDB", Description: "DatabaseRole with CONTROL on database", SourcePattern: "ControlDBTest_DbRole_HasControlOnDb@*\\EdgeTest_ControlDB", TargetPattern: "*\\EdgeTest_ControlDB", Perspective: "both"},
	{EdgeType: "MSSQL_ControlDB", Description: "ApplicationRole with CONTROL on database", SourcePattern: "ControlDBTest_AppRole_HasControlOnDb@*\\EdgeTest_ControlDB", TargetPattern: "*\\EdgeTest_ControlDB", Perspective: "both"},
	{EdgeType: "MSSQL_ControlDB", Description: "db_owner has implicit CONTROL of databases", SourcePattern: "db_owner@*\\EdgeTest_ControlDB", TargetPattern: "*\\EdgeTest_ControlDB", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_ControlServer
// ---------------------------------------------------------------------------

var controlServerTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_ControlServer", Description: "Login with CONTROL SERVER permission", SourcePattern: "ControlServerTest_Login_HasControlServer@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ControlServer", Description: "ServerRole with CONTROL SERVER permission", SourcePattern: "ControlServerTest_ServerRole_HasControlServer@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ControlServer", Description: "sysadmin fixed role has CONTROL SERVER by default", SourcePattern: "sysadmin@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_ExecuteAs
// ---------------------------------------------------------------------------

var executeAsTestCases = []edgeTestCase{
	// SERVER LEVEL
	{EdgeType: "MSSQL_ExecuteAs", Description: "Login with IMPERSONATE on login can execute as", SourcePattern: "ExecuteAsTest_Login_CanImpersonateLogin@*", TargetPattern: "ExecuteAsTest_Login_TargetOf_Login_CanImpersonateLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "Login with CONTROL on login can execute as", SourcePattern: "ExecuteAsTest_Login_CanControlLogin@*", TargetPattern: "ExecuteAsTest_Login_TargetOf_Login_CanControlLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "ServerRole with IMPERSONATE on login can execute as", SourcePattern: "ExecuteAsTest_ServerRole_CanImpersonateLogin@*", TargetPattern: "ExecuteAsTest_Login_TargetOf_ServerRole_CanImpersonateLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "ServerRole with CONTROL on login can execute as", SourcePattern: "ExecuteAsTest_ServerRole_CanControlLogin@*", TargetPattern: "ExecuteAsTest_Login_TargetOf_ServerRole_CanControlLogin@*", Perspective: "offensive"},

	// DATABASE LEVEL
	{EdgeType: "MSSQL_ExecuteAs", Description: "DatabaseUser with IMPERSONATE on user can execute as", SourcePattern: "ExecuteAsTest_User_CanImpersonateDbUser@*\\EdgeTest_ExecuteAs", TargetPattern: "ExecuteAsTest_User_TargetOf_User_CanImpersonateDbUser@*\\EdgeTest_ExecuteAs", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "DatabaseUser with CONTROL on user can execute as", SourcePattern: "ExecuteAsTest_User_CanControlDbUser@*\\EdgeTest_ExecuteAs", TargetPattern: "ExecuteAsTest_User_TargetOf_User_CanControlDbUser@*\\EdgeTest_ExecuteAs", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "DatabaseRole with IMPERSONATE on user can execute as", SourcePattern: "ExecuteAsTest_DbRole_CanImpersonateDbUser@*\\EdgeTest_ExecuteAs", TargetPattern: "ExecuteAsTest_User_TargetOf_DbRole_CanImpersonateDbUser@*\\EdgeTest_ExecuteAs", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "DatabaseRole with CONTROL on user can execute as", SourcePattern: "ExecuteAsTest_DbRole_CanControlDbUser@*\\EdgeTest_ExecuteAs", TargetPattern: "ExecuteAsTest_User_TargetOf_DbRole_CanControlDbUser@*\\EdgeTest_ExecuteAs", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "ApplicationRole with IMPERSONATE on user can execute as", SourcePattern: "ExecuteAsTest_AppRole_CanImpersonateDbUser@*\\EdgeTest_ExecuteAs", TargetPattern: "ExecuteAsTest_User_TargetOf_AppRole_CanImpersonateDbUser@*\\EdgeTest_ExecuteAs", Perspective: "offensive"},
	{EdgeType: "MSSQL_ExecuteAs", Description: "ApplicationRole with CONTROL on user can execute as", SourcePattern: "ExecuteAsTest_AppRole_CanControlDbUser@*\\EdgeTest_ExecuteAs", TargetPattern: "ExecuteAsTest_User_TargetOf_AppRole_CanControlDbUser@*\\EdgeTest_ExecuteAs", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_ExecuteAsOwner + MSSQL_IsTrustedBy
// ---------------------------------------------------------------------------

var executeAsOwnerTestCases = []edgeTestCase{
	// ExecuteAsOwner positive
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with sysadmin", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with securityadmin", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with nested role in securityadmin", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithNestedRoleInSecurityadmin", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with CONTROL SERVER", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithControlServer", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with role with CONTROL SERVER", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithControlServer", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with IMPERSONATE ANY LOGIN", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithImpersonateAnyLogin", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login with role with IMPERSONATE ANY LOGIN", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithRoleWithImpersonateAnyLogin", TargetPattern: "S-1-5-21-*", Perspective: "both"},

	// ExecuteAsOwner negative
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "TRUSTWORTHY database owned by login without high privileges", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Database owner does not have high privileges", Perspective: "both"},
	{EdgeType: "MSSQL_ExecuteAsOwner", Description: "Non-TRUSTWORTHY database owned by sysadmin", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_NotTrustworthy", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Database is not TRUSTWORTHY", Perspective: "both"},

	// IsTrustedBy companion edges
	{EdgeType: "MSSQL_IsTrustedBy", Description: "TRUSTWORTHY database creates IsTrustedBy edge (sysadmin owner)", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSysadmin", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_IsTrustedBy", Description: "TRUSTWORTHY database creates IsTrustedBy edge (securityadmin owner)", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByLoginWithSecurityadmin", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_IsTrustedBy", Description: "TRUSTWORTHY database creates IsTrustedBy edge (no high privileges owner)", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_OwnedByNoHighPrivileges", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_IsTrustedBy", Description: "Non-TRUSTWORTHY database should not have IsTrustedBy edge", SourcePattern: "*\\EdgeTest_ExecuteAsOwner_NotTrustworthy", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Database is not TRUSTWORTHY", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_ExecuteOnHost + MSSQL_HostFor
// ---------------------------------------------------------------------------

var executeOnHostTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_ExecuteOnHost", Description: "SQL Server has ExecuteOnHost edge to its host computer", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HostFor", Description: "Computer has HostFor edge to SQL Server", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_GrantAnyDBPermission
// ---------------------------------------------------------------------------

var grantAnyDBPermTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "db_securityadmin role targets its database", SourcePattern: "db_securityadmin@*\\EdgeTest_GrantAnyDBPermission", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "db_securityadmin role targets its database (second DB)", SourcePattern: "db_securityadmin@*\\EdgeTest_GrantAnyDBPermission_Second", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission_Second", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "User member of db_securityadmin does not create edge", SourcePattern: "GrantAnyDBPermissionTest_User_InDbSecurityAdmin@*", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission", Negative: true, Reason: "Only the db_securityadmin role itself creates the edge, not its members", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "Custom role with ALTER ANY ROLE does not create edge", SourcePattern: "GrantAnyDBPermissionTest_CustomRole_HasAlterAnyRole@*", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission", Negative: true, Reason: "Only db_securityadmin fixed role creates this edge", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "db_owner does not create GrantAnyDBPermission edge", SourcePattern: "db_owner@*\\EdgeTest_GrantAnyDBPermission", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission", Negative: true, Reason: "db_owner uses MSSQL_ControlDB edge instead", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "db_securityadmin cannot grant permissions in other databases", SourcePattern: "db_securityadmin@*\\EdgeTest_GrantAnyDBPermission", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission_Second", Negative: true, Reason: "db_securityadmin only affects its own database", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyDBPermission", Description: "Regular user does not create edge", SourcePattern: "GrantAnyDBPermissionTest_User_NotInDbSecurityAdmin@*", TargetPattern: "*\\EdgeTest_GrantAnyDBPermission", Negative: true, Reason: "User is not db_securityadmin", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_GrantAnyPermission
// ---------------------------------------------------------------------------

var grantAnyPermTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_GrantAnyPermission", Description: "securityadmin role targets the server", SourcePattern: "securityadmin@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyPermission", Description: "Login member of securityadmin does not create edge", SourcePattern: "GrantAnyPermissionTest_Login_InSecurityAdmin@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Only the securityadmin role itself creates the edge, not its members", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyPermission", Description: "sysadmin does not create GrantAnyPermission edge", SourcePattern: "sysadmin@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "sysadmin uses MSSQL_ControlServer edge instead", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyPermission", Description: "Regular login does not create edge", SourcePattern: "GrantAnyPermissionTest_Login_NoSpecialPerms@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Login has no special permissions", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyPermission", Description: "securityadmin cannot grant permissions at database level", SourcePattern: "securityadmin@*", TargetPattern: "*\\EdgeTest_GrantAnyPermission", Negative: true, Reason: "GrantAnyPermission is server-level only", Perspective: "both"},
	{EdgeType: "MSSQL_GrantAnyPermission", Description: "db_securityadmin does not create GrantAnyPermission edge", SourcePattern: "db_securityadmin@*\\EdgeTest_GrantAnyPermission", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "db_securityadmin uses MSSQL_GrantAnyDBPermission edge at database level", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_HasDBScopedCred
// ---------------------------------------------------------------------------

var hasDBScopedCredTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_HasDBScopedCred", Description: "Database has scoped credential for domain user", SourcePattern: "*\\EdgeTest_HasDBScopedCred", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasDBScopedCred", Description: "Database without credentials does not create edge", SourcePattern: "*\\master", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "master database has no database-scoped credentials", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_HasLogin
// ---------------------------------------------------------------------------

var hasLoginTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_HasLogin", Description: "Domain user has SQL login", SourcePattern: "S-1-5-21*", TargetPattern: "*\\EdgeTestDomainUser1@*", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Second domain user has SQL login", SourcePattern: "S-1-5-21*", TargetPattern: "*\\EdgeTestDomainUser2@*", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Domain group has SQL login", SourcePattern: "S-1-5-21*", TargetPattern: "*\\EdgeTestDomainGroup@*", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Computer account has SQL login", SourcePattern: "S-1-5-21-*", TargetPattern: "*\\TestComputer$@*", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Local group has SQL login", SourcePattern: "*-S-1-5-32-555", TargetPattern: "BUILTIN\\Remote Desktop Users@*", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Disabled login does not create edge", SourcePattern: "S-1-5-21-*", TargetPattern: "*\\EdgeTestDisabledUser@*", Negative: true, Reason: "Login is disabled", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Login with CONNECT SQL denied does not create edge", SourcePattern: "S-1-5-21-*", TargetPattern: "*\\EdgeTestNoConnect@*", Negative: true, Reason: "CONNECT SQL permission is denied", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "SQL login does not create HasLogin edge", SourcePattern: "*", TargetPattern: "HasLoginTest_SQLLogin@*", Negative: true, Reason: "SQL logins don't create HasLogin edges (only Windows logins)", Perspective: "both"},
	{EdgeType: "MSSQL_HasLogin", Description: "Non-existent domain account has no edge", SourcePattern: "S-1-5-21-*", TargetPattern: "*\\NonExistentUser@*", Negative: true, Reason: "No login exists for this account", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_HasMappedCred
// ---------------------------------------------------------------------------

var hasMappedCredTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_HasMappedCred", Description: "SQL login has mapped credential for domain user 1", SourcePattern: "HasMappedCredTest_SQLLogin_MappedToDomainUser1@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasMappedCred", Description: "SQL login has mapped credential for domain user 2", SourcePattern: "HasMappedCredTest_SQLLogin_MappedToDomainUser2@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasMappedCred", Description: "SQL login has mapped credential for computer account", SourcePattern: "HasMappedCredTest_SQLLogin_MappedToComputerAccount@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasMappedCred", Description: "Windows login has mapped credential for different user", SourcePattern: "*\\EdgeTestDomainUser1@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasMappedCred", Description: "SQL login without mapped credential has no edge", SourcePattern: "HasMappedCredTest_SQLLogin_NoCredential@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Login has no mapped credential", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_HasProxyCred
// ---------------------------------------------------------------------------

var hasProxyCredTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_HasProxyCred", Description: "SQL login authorized to use ETL proxy for domain user 1", SourcePattern: "HasProxyCredTest_ETLOperator@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "Server role authorized to use ETL proxy for domain user 1", SourcePattern: "HasProxyCredTest_ProxyUsers@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "SQL login authorized to use backup proxy for domain user 2", SourcePattern: "HasProxyCredTest_BackupOperator@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "Windows login authorized to use backup proxy", SourcePattern: "*\\EdgeTestDomainUser1@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "SQL login authorized to disabled proxy still creates edge", SourcePattern: "HasProxyCredTest_ETLOperator@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "Login without proxy access has no edge", SourcePattern: "HasProxyCredTest_NoProxyAccess@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Login is not authorized to use any proxy", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "Proxy with local credential does not create edge", SourcePattern: "*", TargetPattern: "*LocalService*", Negative: true, Reason: "Only domain credentials create HasProxyCred edges", Perspective: "both"},
	{EdgeType: "MSSQL_HasProxyCred", Description: "Database users cannot have proxy access", SourcePattern: "*@*\\*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Only server-level principals can use SQL Agent proxies", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_Impersonate
// ---------------------------------------------------------------------------

var impersonateTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_Impersonate", Description: "Login with IMPERSONATE on login can impersonate", SourcePattern: "ImpersonateTest_Login_CanImpersonateLogin@*", TargetPattern: "ImpersonateTest_Login_TargetOf_Login_CanImpersonateLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Impersonate", Description: "ServerRole with IMPERSONATE on login can impersonate", SourcePattern: "ImpersonateTest_ServerRole_CanImpersonateLogin@*", TargetPattern: "ImpersonateTest_Login_TargetOf_ServerRole_CanImpersonateLogin@*", Perspective: "offensive"},
	{EdgeType: "MSSQL_Impersonate", Description: "DatabaseUser with IMPERSONATE on user can impersonate", SourcePattern: "ImpersonateTest_User_CanImpersonateDbUser@*\\EdgeTest_Impersonate", TargetPattern: "ImpersonateTest_User_TargetOf_User_CanImpersonateDbUser@*\\EdgeTest_Impersonate", Perspective: "offensive"},
	{EdgeType: "MSSQL_Impersonate", Description: "DatabaseRole with IMPERSONATE on user can impersonate", SourcePattern: "ImpersonateTest_DbRole_CanImpersonateDbUser@*\\EdgeTest_Impersonate", TargetPattern: "ImpersonateTest_User_TargetOf_DbRole_CanImpersonateDbUser@*\\EdgeTest_Impersonate", Perspective: "offensive"},
	{EdgeType: "MSSQL_Impersonate", Description: "ApplicationRole with IMPERSONATE on user can impersonate", SourcePattern: "ImpersonateTest_AppRole_CanImpersonateDbUser@*\\EdgeTest_Impersonate", TargetPattern: "ImpersonateTest_User_TargetOf_AppRole_CanImpersonateDbUser@*\\EdgeTest_Impersonate", Perspective: "offensive"},
}

// ---------------------------------------------------------------------------
// MSSQL_ImpersonateAnyLogin
// ---------------------------------------------------------------------------

var impersonateAnyLoginTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "SQL login with IMPERSONATE ANY LOGIN targets server", SourcePattern: "ImpersonateAnyLoginTest_Login_Direct@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "Server role with IMPERSONATE ANY LOGIN targets server", SourcePattern: "ImpersonateAnyLoginTest_Role_HasPermission@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "Windows login with IMPERSONATE ANY LOGIN targets server", SourcePattern: "*\\EdgeTestDomainUser1@*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "Login without IMPERSONATE ANY LOGIN has no edge", SourcePattern: "ImpersonateAnyLoginTest_Login_NoPermission@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Login does not have IMPERSONATE ANY LOGIN permission", Perspective: "both"},
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "Login member of role does not have direct edge", SourcePattern: "ImpersonateAnyLoginTest_Login_ViaRole@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "Only the role with the permission has the edge, not its members", Perspective: "both"},
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "sysadmin does not create ImpersonateAnyLogin edge", SourcePattern: "sysadmin@*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "sysadmin uses ControlServer edge instead", Perspective: "both"},
	{EdgeType: "MSSQL_ImpersonateAnyLogin", Description: "Database users cannot have IMPERSONATE ANY LOGIN", SourcePattern: "*@*\\*", TargetPattern: "S-1-5-21-*", Negative: true, Reason: "IMPERSONATE ANY LOGIN is a server-level permission", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_IsMappedTo
// ---------------------------------------------------------------------------

var isMappedToTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_IsMappedTo", Description: "SQL login mapped to database user in primary database", SourcePattern: "IsMappedToTest_SQLLogin_WithDBUser@*", TargetPattern: "IsMappedToTest_SQLLogin_WithDBUser@*\\EdgeTest_IsMappedTo_Primary", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "Windows login mapped to database user in primary database", SourcePattern: "*\\EdgeTestDomainUser1@*", TargetPattern: "*\\EdgeTestDomainUser1@*\\EdgeTest_IsMappedTo_Primary", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "SQL login mapped to differently named user in secondary database", SourcePattern: "IsMappedToTest_SQLLogin_WithDBUser@*", TargetPattern: "IsMappedToTest_DifferentUserName@*\\EdgeTest_IsMappedTo_Secondary", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "Windows login 2 mapped to database user in secondary database", SourcePattern: "*\\EdgeTestDomainUser2@*", TargetPattern: "*\\EdgeTestDomainUser2@*\\EdgeTest_IsMappedTo_Secondary", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "Login without database user has no mapping", SourcePattern: "IsMappedToTest_SQLLogin_NoDBUser@*", TargetPattern: "*", Negative: true, Reason: "Login has no corresponding database user", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "Orphaned database user has no login mapping", SourcePattern: "*", TargetPattern: "IsMappedToTest_OrphanedUser@*\\EdgeTest_IsMappedTo_Primary", Negative: true, Reason: "Database user was created WITHOUT LOGIN", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "Login is not mapped to users in databases where it doesn't exist", SourcePattern: "*\\EdgeTestDomainUser1@*", TargetPattern: "*\\EdgeTest_IsMappedTo_Secondary", Negative: true, Reason: "Windows login 1 has no user in secondary database", Perspective: "both"},
	{EdgeType: "MSSQL_IsMappedTo", Description: "Server roles cannot be mapped to database users", SourcePattern: "sysadmin@*", TargetPattern: "*", Negative: true, Reason: "Only logins can be mapped to database users", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_GetTGS
// ---------------------------------------------------------------------------

var getTGSTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_GetTGS", Description: "Service account can get TGS for domain user with SQL login", SourcePattern: "*", TargetPattern: "*\\EdgeTestDomainUser1@*", Perspective: "both"},
	{EdgeType: "MSSQL_GetTGS", Description: "Service account can get TGS for second domain user", SourcePattern: "*", TargetPattern: "*\\EdgeTestDomainUser2@*", Perspective: "both"},
	{EdgeType: "MSSQL_GetTGS", Description: "Service account can get TGS for domain group with SQL login", SourcePattern: "*", TargetPattern: "*\\EdgeTestDomainGroup@*", Perspective: "both"},
	{EdgeType: "MSSQL_GetTGS", Description: "Service account can get TGS for domain user with sysadmin", SourcePattern: "*", TargetPattern: "*\\EdgeTestSysadmin@*", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_GetAdminTGS
// ---------------------------------------------------------------------------

var getAdminTGSTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_GetAdminTGS", Description: "Service account can get admin TGS (domain principal has sysadmin)", SourcePattern: "*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_LinkedAsAdmin
// ---------------------------------------------------------------------------

var linkedAsAdminTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_LinkedAsAdmin", Description: "Admin SQL login linked servers create LinkedAsAdmin edges (including nested roles)", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*", Perspective: "both", ExpectedCount: 8},
}

// ---------------------------------------------------------------------------
// MSSQL_LinkedTo
// ---------------------------------------------------------------------------

var linkedToTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_LinkedTo", Description: "All 10 loopback linked servers create LinkedTo edges", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*", ExpectedCount: 11, Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_MemberOf
// ---------------------------------------------------------------------------

var memberOfTestCases = []edgeTestCase{
	// SERVER LEVEL: Login -> ServerRole
	{EdgeType: "MSSQL_MemberOf", Description: "SQL login member of processadmin", SourcePattern: "MemberOfTest_Login1@*", TargetPattern: "processadmin@*", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "SQL login member of custom server role", SourcePattern: "MemberOfTest_Login2@*", TargetPattern: "MemberOfTest_ServerRole1@*", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Windows login member of diskadmin", SourcePattern: "*\\EdgeTestDomainUser1@*", TargetPattern: "diskadmin@*", Perspective: "both"},

	// SERVER LEVEL: ServerRole -> ServerRole
	{EdgeType: "MSSQL_MemberOf", Description: "Server role member of another server role", SourcePattern: "MemberOfTest_ServerRole1@*", TargetPattern: "MemberOfTest_ServerRole2@*", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Custom server role member of securityadmin", SourcePattern: "MemberOfTest_ServerRole2@*", TargetPattern: "securityadmin@*", Perspective: "both"},

	// DATABASE LEVEL: DatabaseUser -> DatabaseRole
	{EdgeType: "MSSQL_MemberOf", Description: "Database user member of db_datareader", SourcePattern: "MemberOfTest_User1@*\\EdgeTest_MemberOf", TargetPattern: "db_datareader@*\\EdgeTest_MemberOf", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Database user member of custom database role", SourcePattern: "MemberOfTest_User2@*\\EdgeTest_MemberOf", TargetPattern: "MemberOfTest_DbRole1@*\\EdgeTest_MemberOf", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Windows database user member of db_datawriter", SourcePattern: "*\\EdgeTestDomainUser1@*\\EdgeTest_MemberOf", TargetPattern: "db_datawriter@*\\EdgeTest_MemberOf", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Database user without login member of role", SourcePattern: "MemberOfTest_UserNoLogin@*\\EdgeTest_MemberOf", TargetPattern: "MemberOfTest_DbRole1@*\\EdgeTest_MemberOf", Perspective: "both"},

	// DATABASE LEVEL: DatabaseRole -> DatabaseRole
	{EdgeType: "MSSQL_MemberOf", Description: "Database role member of another database role", SourcePattern: "MemberOfTest_DbRole1@*\\EdgeTest_MemberOf", TargetPattern: "MemberOfTest_DbRole2@*\\EdgeTest_MemberOf", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Custom database role member of db_owner", SourcePattern: "MemberOfTest_DbRole2@*\\EdgeTest_MemberOf", TargetPattern: "db_owner@*\\EdgeTest_MemberOf", Perspective: "both"},

	// DATABASE LEVEL: ApplicationRole -> DatabaseRole
	{EdgeType: "MSSQL_MemberOf", Description: "Application role member of database role", SourcePattern: "MemberOfTest_AppRole@*\\EdgeTest_MemberOf", TargetPattern: "MemberOfTest_DbRole1@*\\EdgeTest_MemberOf", Perspective: "both"},

	// NEGATIVE
	{EdgeType: "MSSQL_MemberOf", Description: "Server roles cannot be added to sysadmin", SourcePattern: "MemberOfTest_ServerRole*@*", TargetPattern: "sysadmin@*", Negative: true, Reason: "Server roles cannot be added as members of sysadmin", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "No cross-database role memberships", SourcePattern: "*@*\\EdgeTest_MemberOf", TargetPattern: "*@*\\master", Negative: true, Reason: "Role memberships don't cross database boundaries", Perspective: "both"},
	{EdgeType: "MSSQL_MemberOf", Description: "Server login not directly member of database role", SourcePattern: "MemberOfTest_Login1@*", TargetPattern: "*@*\\EdgeTest_MemberOf", Negative: true, Reason: "Server principals must be mapped to database users first", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_Owns
// ---------------------------------------------------------------------------

var ownsTestCases = []edgeTestCase{
	// SERVER LEVEL
	{EdgeType: "MSSQL_Owns", Description: "Login owns database", SourcePattern: "OwnsTest_Login_DbOwner@*", TargetPattern: "*\\EdgeTest_Owns_OwnedByLogin", Perspective: "both"},
	{EdgeType: "MSSQL_Owns", Description: "Login owns server role", SourcePattern: "OwnsTest_Login_RoleOwner@*", TargetPattern: "OwnsTest_ServerRole_Owned@*", Perspective: "both"},
	{EdgeType: "MSSQL_Owns", Description: "Server role owns another server role", SourcePattern: "OwnsTest_ServerRole_Owner@*", TargetPattern: "OwnsTest_ServerRole_OwnedByRole@*", Perspective: "both"},

	// DATABASE LEVEL
	{EdgeType: "MSSQL_Owns", Description: "Database user owns database role", SourcePattern: "OwnsTest_User_RoleOwner@*\\EdgeTest_Owns_RoleTests", TargetPattern: "OwnsTest_DbRole_Owned@*\\EdgeTest_Owns_RoleTests", Perspective: "both"},
	{EdgeType: "MSSQL_Owns", Description: "Database role owns another database role", SourcePattern: "OwnsTest_DbRole_Owner@*\\EdgeTest_Owns_RoleTests", TargetPattern: "OwnsTest_DbRole_OwnedByRole@*\\EdgeTest_Owns_RoleTests", Perspective: "both"},
	{EdgeType: "MSSQL_Owns", Description: "Application role owns database role", SourcePattern: "OwnsTest_AppRole_Owner@*\\EdgeTest_Owns_RoleTests", TargetPattern: "OwnsTest_DbRole_OwnedByAppRole@*\\EdgeTest_Owns_RoleTests", Perspective: "both"},

	// NEGATIVE
	{EdgeType: "MSSQL_Owns", Description: "Login without ownership has no Owns edges", SourcePattern: "OwnsTest_Login_NoOwnership@*", TargetPattern: "*", Negative: true, Reason: "Login doesn't own any objects", Perspective: "both"},
	{EdgeType: "MSSQL_Owns", Description: "Database user without ownership has no Owns edges", SourcePattern: "OwnsTest_User_NoOwnership@*", TargetPattern: "*", Negative: true, Reason: "User doesn't own any objects", Perspective: "both"},
	{EdgeType: "MSSQL_Owns", Description: "No cross-database ownership edges", SourcePattern: "*@*\\EdgeTest_Owns_RoleTests", TargetPattern: "*@*\\EdgeTest_Owns_OwnedByLogin", Negative: true, Reason: "Ownership doesn't cross database boundaries", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_ServiceAccountFor + HasSession
// ---------------------------------------------------------------------------

var serviceAccountForTestCases = []edgeTestCase{
	{EdgeType: "MSSQL_ServiceAccountFor", Description: "Service account for SQL Server instance", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*", ExpectedCount: 1, Perspective: "both"},
	{EdgeType: "HasSession", Description: "Computer has session for domain service account", SourcePattern: "S-1-5-21-*", TargetPattern: "S-1-5-21-*", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// MSSQL_TakeOwnership
// ---------------------------------------------------------------------------

var takeOwnershipTestCases = []edgeTestCase{
	// POSITIVE (non-traversable)
	{EdgeType: "MSSQL_TakeOwnership", Description: "Login can take ownership of server role", SourcePattern: "TakeOwnershipTest_Login_CanTakeServerRole@*", TargetPattern: "TakeOwnershipTest_ServerRole_Target@*", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Server role can take ownership of another server role", SourcePattern: "TakeOwnershipTest_ServerRole_Source@*", TargetPattern: "TakeOwnershipTest_ServerRole_Target@*", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Database user can take ownership of database", SourcePattern: "TakeOwnershipTest_User_CanTakeDb@*\\EdgeTest_TakeOwnership", TargetPattern: "*\\EdgeTest_TakeOwnership", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Database role can take ownership of database", SourcePattern: "TakeOwnershipTest_DbRole_CanTakeDb@*\\EdgeTest_TakeOwnership", TargetPattern: "*\\EdgeTest_TakeOwnership", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Application role can take ownership of database", SourcePattern: "TakeOwnershipTest_AppRole_CanTakeDb@*\\EdgeTest_TakeOwnership", TargetPattern: "*\\EdgeTest_TakeOwnership", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Database user can take ownership of database role", SourcePattern: "TakeOwnershipTest_User_CanTakeRole@*\\EdgeTest_TakeOwnership", TargetPattern: "TakeOwnershipTest_DbRole_Target@*\\EdgeTest_TakeOwnership", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Database role can take ownership of another database role", SourcePattern: "TakeOwnershipTest_DbRole_Source@*\\EdgeTest_TakeOwnership", TargetPattern: "TakeOwnershipTest_DbRole_Target@*\\EdgeTest_TakeOwnership", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Application role can take ownership of database role", SourcePattern: "TakeOwnershipTest_AppRole_CanTakeRole@*\\EdgeTest_TakeOwnership", TargetPattern: "TakeOwnershipTest_DbRole_Target@*\\EdgeTest_TakeOwnership", Perspective: "offensive", EdgeProperties: map[string]interface{}{"traversable": false}},

	// NEGATIVE
	{EdgeType: "MSSQL_TakeOwnership", Description: "Cannot take ownership of fixed server roles", SourcePattern: "*", TargetPattern: "sysadmin@*", Negative: true, Reason: "Fixed server roles cannot have ownership changed", Perspective: "both"},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Cannot take ownership of fixed database roles", SourcePattern: "*", TargetPattern: "db_owner@*\\*", Negative: true, Reason: "Fixed database roles cannot have ownership changed", Perspective: "both"},
	{EdgeType: "MSSQL_TakeOwnership", Description: "Login without TAKE OWNERSHIP permission has no edge", SourcePattern: "TakeOwnershipTest_Login_NoPermission@*", TargetPattern: "*", Negative: true, Reason: "No TAKE OWNERSHIP permission granted", Perspective: "both"},
	{EdgeType: "MSSQL_TakeOwnership", Description: "User without TAKE OWNERSHIP permission has no edge", SourcePattern: "TakeOwnershipTest_User_NoPermission@*", TargetPattern: "*", Negative: true, Reason: "No TAKE OWNERSHIP permission granted", Perspective: "both"},
}

// ---------------------------------------------------------------------------
// allTestCases aggregates all edge type test cases into a single slice.
// This is used for coverage analysis and integration test validation.
// ---------------------------------------------------------------------------

var allTestCases = func() []edgeTestCase {
	var all []edgeTestCase
	all = append(all, addMemberTestCases...)
	all = append(all, alterTestCases...)
	all = append(all, alterAnyAppRoleTestCases...)
	all = append(all, alterAnyDBRoleTestCases...)
	all = append(all, alterAnyLoginTestCases...)
	all = append(all, alterAnyServerRoleTestCases...)
	all = append(all, changeOwnerTestCases...)
	all = append(all, changePasswordTestCases...)
	all = append(all, coerceAndRelayTestCases...)
	all = append(all, connectTestCases...)
	all = append(all, connectAnyDatabaseTestCases...)
	all = append(all, containsTestCases...)
	all = append(all, controlTestCases...)
	all = append(all, controlDBTestCases...)
	all = append(all, controlServerTestCases...)
	all = append(all, executeAsTestCases...)
	all = append(all, executeAsOwnerTestCases...)
	all = append(all, executeOnHostTestCases...)
	all = append(all, grantAnyDBPermTestCases...)
	all = append(all, grantAnyPermTestCases...)
	all = append(all, hasDBScopedCredTestCases...)
	all = append(all, hasLoginTestCases...)
	all = append(all, hasMappedCredTestCases...)
	all = append(all, hasProxyCredTestCases...)
	all = append(all, impersonateTestCases...)
	all = append(all, impersonateAnyLoginTestCases...)
	all = append(all, isMappedToTestCases...)
	all = append(all, getTGSTestCases...)
	all = append(all, getAdminTGSTestCases...)
	all = append(all, linkedAsAdminTestCases...)
	all = append(all, linkedToTestCases...)
	all = append(all, memberOfTestCases...)
	all = append(all, ownsTestCases...)
	all = append(all, serviceAccountForTestCases...)
	all = append(all, takeOwnershipTestCases...)
	return all
}()

// testCasesByEdgeType returns a map of edge type -> test cases.
func testCasesByEdgeType() map[string][]edgeTestCase {
	result := make(map[string][]edgeTestCase)
	for _, tc := range allTestCases {
		result[tc.EdgeType] = append(result[tc.EdgeType], tc)
	}
	return result
}
