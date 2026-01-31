// Package mssql provides SQL Server connection and data collection functionality.
package mssql

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// convertHexSIDToString converts a hex SID (like "0x0105000000...") to standard SID format (like "S-1-5-21-...")
// This matches the PowerShell ConvertTo-SecurityIdentifier function behavior
func convertHexSIDToString(hexSID string) string {
	if hexSID == "" || hexSID == "0x" || hexSID == "0x01" {
		return ""
	}

	// Remove "0x" prefix if present
	if strings.HasPrefix(strings.ToLower(hexSID), "0x") {
		hexSID = hexSID[2:]
	}

	// Decode hex string to bytes
	bytes, err := hex.DecodeString(hexSID)
	if err != nil || len(bytes) < 8 {
		return ""
	}

	// Validate SID structure (first byte must be 1 for revision)
	if bytes[0] != 1 {
		return ""
	}

	// Parse SID structure:
	// bytes[0] = revision (always 1)
	// bytes[1] = number of sub-authorities
	// bytes[2:8] = identifier authority (6 bytes, big-endian)
	// bytes[8:] = sub-authorities (4 bytes each, little-endian)

	revision := bytes[0]
	subAuthCount := int(bytes[1])

	// Validate length
	expectedLen := 8 + (subAuthCount * 4)
	if len(bytes) < expectedLen {
		return ""
	}

	// Get identifier authority (6 bytes, big-endian)
	// Usually 5 for NT Authority (S-1-5-...)
	var authority uint64
	for i := 0; i < 6; i++ {
		authority = (authority << 8) | uint64(bytes[2+i])
	}

	// Build SID string
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("S-%d-%d", revision, authority))

	// Parse sub-authorities (4 bytes each, little-endian)
	for i := 0; i < subAuthCount; i++ {
		offset := 8 + (i * 4)
		subAuth := binary.LittleEndian.Uint32(bytes[offset : offset+4])
		sb.WriteString(fmt.Sprintf("-%d", subAuth))
	}

	return sb.String()
}

// Client handles SQL Server connections and data collection
type Client struct {
	db             *sql.DB
	serverInstance string
	hostname       string
	port           int
	instanceName   string
	userID         string
	password       string
	useWindowsAuth bool
}

// NewClient creates a new SQL Server client
func NewClient(serverInstance, userID, password string) *Client {
	hostname, port, instanceName := parseServerInstance(serverInstance)

	return &Client{
		serverInstance: serverInstance,
		hostname:       hostname,
		port:           port,
		instanceName:   instanceName,
		userID:         userID,
		password:       password,
		useWindowsAuth: userID == "" && password == "",
	}
}

// parseServerInstance parses server instance formats:
// - hostname
// - hostname:port
// - hostname\instance
// - hostname\instance:port
func parseServerInstance(instance string) (hostname string, port int, instanceName string) {
	port = 1433 // default

	// Remove any SPN prefix (MSSQLSvc/)
	if strings.HasPrefix(strings.ToUpper(instance), "MSSQLSVC/") {
		instance = instance[9:]
	}

	// Check for instance name (backslash)
	if idx := strings.Index(instance, "\\"); idx != -1 {
		hostname = instance[:idx]
		rest := instance[idx+1:]

		// Check if instance name has port
		if colonIdx := strings.Index(rest, ":"); colonIdx != -1 {
			instanceName = rest[:colonIdx]
			if p, err := strconv.Atoi(rest[colonIdx+1:]); err == nil {
				port = p
			}
		} else {
			instanceName = rest
			port = 0 // Will use SQL Browser
		}
	} else if idx := strings.Index(instance, ":"); idx != -1 {
		// hostname:port format
		hostname = instance[:idx]
		if p, err := strconv.Atoi(instance[idx+1:]); err == nil {
			port = p
		}
	} else {
		hostname = instance
	}

	return
}

// Connect establishes a connection to the SQL Server
func (c *Client) Connect(ctx context.Context) error {
	connStr := c.buildConnectionString()

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return fmt.Errorf("failed to open connection: %w", err)
	}

	// Test the connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.db = db
	return nil
}

// buildConnectionString creates the connection string for go-mssqldb
func (c *Client) buildConnectionString() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("server=%s", c.hostname))

	if c.port > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", c.port))
	}

	if c.instanceName != "" {
		parts = append(parts, fmt.Sprintf("instance=%s", c.instanceName))
	}

	if c.useWindowsAuth {
		// Use Windows integrated auth
		parts = append(parts, "trusted_connection=yes")
	} else {
		parts = append(parts, fmt.Sprintf("user id=%s", c.userID))
		parts = append(parts, fmt.Sprintf("password=%s", c.password))
	}

	// Disable encryption to match PowerShell behavior
	parts = append(parts, "encrypt=false")
	parts = append(parts, "TrustServerCertificate=true")
	parts = append(parts, "app name=MSSQLHound")

	return strings.Join(parts, ";")
}

// Close closes the database connection
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// CollectServerInfo gathers all information about the SQL Server
func (c *Client) CollectServerInfo(ctx context.Context) (*types.ServerInfo, error) {
	info := &types.ServerInfo{
		Hostname:     c.hostname,
		InstanceName: c.instanceName,
		Port:         c.port,
	}

	// Get server properties
	if err := c.collectServerProperties(ctx, info); err != nil {
		return nil, fmt.Errorf("failed to collect server properties: %w", err)
	}

	// Get computer SID for ObjectIdentifier (like PowerShell does)
	if err := c.collectComputerSID(ctx, info); err != nil {
		// Non-fatal - fall back to hostname-based identifier
		fmt.Printf("Warning: failed to get computer SID, using hostname: %v\n", err)
		info.ObjectIdentifier = fmt.Sprintf("%s:%d", strings.ToLower(info.ServerName), info.Port)
	} else {
		// Use SID-based ObjectIdentifier like PowerShell
		info.ObjectIdentifier = fmt.Sprintf("%s:%d", info.ComputerSID, info.Port)
	}

	// Set SQLServerName for display purposes (FQDN:Port format)
	info.SQLServerName = fmt.Sprintf("%s:%d", info.FQDN, info.Port)

	// Collect authentication mode
	if err := c.collectAuthenticationMode(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect auth mode: %v\n", err)
	}

	// Collect encryption settings (Force Encryption, Extended Protection)
	if err := c.collectEncryptionSettings(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect encryption settings: %v\n", err)
	}

	// Get service accounts
	if err := c.collectServiceAccounts(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect service accounts: %v\n", err)
	}

	// Get server-level credentials
	if err := c.collectCredentials(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect credentials: %v\n", err)
	}

	// Get proxy accounts
	if err := c.collectProxyAccounts(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect proxy accounts: %v\n", err)
	}

	// Get server principals
	principals, err := c.collectServerPrincipals(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("failed to collect server principals: %w", err)
	}
	info.ServerPrincipals = principals

	// Get credential mappings for logins
	if err := c.collectLoginCredentialMappings(ctx, principals, info); err != nil {
		fmt.Printf("Warning: failed to collect login credential mappings: %v\n", err)
	}

	// Get databases
	databases, err := c.collectDatabases(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("failed to collect databases: %w", err)
	}

	// Collect database-scoped credentials for each database
	for i := range databases {
		if err := c.collectDBScopedCredentials(ctx, &databases[i]); err != nil {
			fmt.Printf("Warning: failed to collect DB-scoped credentials for %s: %v\n", databases[i].Name, err)
		}
	}
	info.Databases = databases

	// Get linked servers
	linkedServers, err := c.collectLinkedServers(ctx)
	if err != nil {
		// Non-fatal - just log and continue
		fmt.Printf("Warning: failed to collect linked servers: %v\n", err)
	}
	info.LinkedServers = linkedServers

	return info, nil
}

// collectServerProperties gets basic server information
func (c *Client) collectServerProperties(ctx context.Context, info *types.ServerInfo) error {
	query := `
		SELECT 
			SERVERPROPERTY('ServerName') AS ServerName,
			SERVERPROPERTY('MachineName') AS MachineName,
			SERVERPROPERTY('InstanceName') AS InstanceName,
			SERVERPROPERTY('ProductVersion') AS ProductVersion,
			SERVERPROPERTY('ProductLevel') AS ProductLevel,
			SERVERPROPERTY('Edition') AS Edition,
			SERVERPROPERTY('IsClustered') AS IsClustered,
			@@VERSION AS FullVersion
	`

	row := c.db.QueryRowContext(ctx, query)

	var serverName, machineName, productVersion, productLevel, edition, fullVersion sql.NullString
	var instanceName sql.NullString
	var isClustered sql.NullInt64

	err := row.Scan(&serverName, &machineName, &instanceName, &productVersion,
		&productLevel, &edition, &isClustered, &fullVersion)
	if err != nil {
		return err
	}

	info.ServerName = serverName.String
	if info.Hostname == "" {
		info.Hostname = machineName.String
	}
	if instanceName.Valid {
		info.InstanceName = instanceName.String
	}
	info.VersionNumber = productVersion.String
	info.ProductLevel = productLevel.String
	info.Edition = edition.String
	info.Version = fullVersion.String
	info.IsClustered = isClustered.Int64 == 1

	// Try to get FQDN
	if fqdn, err := net.LookupAddr(info.Hostname); err == nil && len(fqdn) > 0 {
		info.FQDN = strings.TrimSuffix(fqdn[0], ".")
	} else {
		info.FQDN = info.Hostname
	}

	return nil
}

// collectComputerSID gets the computer account's SID from Active Directory
// This is used to generate ObjectIdentifiers that match PowerShell's format
func (c *Client) collectComputerSID(ctx context.Context, info *types.ServerInfo) error {
	// Try to get the computer SID by querying for logins that match the computer account
	// The computer account login will have a SID like S-1-5-21-xxx-xxx-xxx-xxx
	query := `
		SELECT TOP 1
			CONVERT(VARCHAR(85), sid, 1) AS sid
		FROM sys.server_principals
		WHERE type_desc = 'WINDOWS_LOGIN'
		AND name LIKE '%$'
		AND name LIKE '%' + CAST(SERVERPROPERTY('MachineName') AS VARCHAR(128)) + '$'
	`

	var computerSID sql.NullString
	err := c.db.QueryRowContext(ctx, query).Scan(&computerSID)
	if err == nil && computerSID.Valid && computerSID.String != "" {
		// Convert hex SID to string format
		sidStr := convertHexSIDToString(computerSID.String)
		if sidStr != "" {
			info.ComputerSID = sidStr
			return nil
		}
	}

	// Alternative: Try to extract domain SID from any Windows login
	// The computer SID is typically the domain SID + RID
	query = `
		SELECT TOP 1
			CONVERT(VARCHAR(85), sid, 1) AS sid,
			name
		FROM sys.server_principals
		WHERE type_desc IN ('WINDOWS_LOGIN', 'WINDOWS_GROUP')
		AND sid IS NOT NULL
		AND LEN(CONVERT(VARCHAR(85), sid, 1)) > 10
		ORDER BY principal_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var sid, name sql.NullString
		if err := rows.Scan(&sid, &name); err != nil {
			continue
		}

		if sid.Valid && sid.String != "" {
			// Convert hex SID to string format
			sidStr := convertHexSIDToString(sid.String)
			if sidStr == "" {
				continue
			}

			// If it's a computer account (ends with $), use its SID directly
			if strings.HasSuffix(name.String, "$") {
				info.ComputerSID = sidStr
				return nil
			}

			// Otherwise extract domain SID and we'll need to lookup computer SID separately
			// For now, just use this domain principal's SID as a reference
			// The actual computer SID lookup would require LDAP which we'll skip for now
			sidParts := strings.Split(sidStr, "-")
			if len(sidParts) > 4 {
				// Domain SID is everything except the last part (RID)
				info.DomainSID = strings.Join(sidParts[:len(sidParts)-1], "-")
			}
		}
	}

	// If we found a domain SID but no computer SID, we need to return an error
	// so the caller can fall back to hostname-based identifiers
	if info.ComputerSID == "" {
		return fmt.Errorf("could not determine computer SID")
	}

	return nil
}

// collectServerPrincipals gets all server-level principals (logins and server roles)
func (c *Client) collectServerPrincipals(ctx context.Context, serverInfo *types.ServerInfo) ([]types.ServerPrincipal, error) {
	query := `
		SELECT 
			p.principal_id,
			p.name,
			p.type_desc,
			p.is_disabled,
			p.is_fixed_role,
			p.create_date,
			p.modify_date,
			p.default_database_name,
			CONVERT(VARCHAR(85), p.sid, 1) AS sid,
			p.owning_principal_id
		FROM sys.server_principals p
		WHERE p.type IN ('S', 'U', 'G', 'R', 'C', 'K')
		ORDER BY p.principal_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var principals []types.ServerPrincipal

	for rows.Next() {
		var p types.ServerPrincipal
		var defaultDB, sid sql.NullString
		var owningPrincipalID sql.NullInt64
		var isDisabled, isFixedRole sql.NullBool

		err := rows.Scan(
			&p.PrincipalID,
			&p.Name,
			&p.TypeDescription,
			&isDisabled,
			&isFixedRole,
			&p.CreateDate,
			&p.ModifyDate,
			&defaultDB,
			&sid,
			&owningPrincipalID,
		)
		if err != nil {
			return nil, err
		}

		p.IsDisabled = isDisabled.Bool
		p.IsFixedRole = isFixedRole.Bool
		p.DefaultDatabaseName = defaultDB.String
		// Convert hex SID to standard S-1-5-21-... format
		p.SecurityIdentifier = convertHexSIDToString(sid.String)
		p.SQLServerName = serverInfo.SQLServerName

		if owningPrincipalID.Valid {
			p.OwningPrincipalID = int(owningPrincipalID.Int64)
		}

		// Determine if this is an AD principal
		p.IsActiveDirectoryPrincipal = p.TypeDescription == "WINDOWS_LOGIN" ||
			p.TypeDescription == "WINDOWS_GROUP"

		// Generate object identifier: Name@ServerObjectIdentifier
		p.ObjectIdentifier = fmt.Sprintf("%s@%s", p.Name, serverInfo.ObjectIdentifier)

		principals = append(principals, p)
	}

	// Resolve ownership - set OwningObjectIdentifier based on OwningPrincipalID
	principalMap := make(map[int]*types.ServerPrincipal)
	for i := range principals {
		principalMap[principals[i].PrincipalID] = &principals[i]
	}
	for i := range principals {
		if principals[i].OwningPrincipalID > 0 {
			if owner, ok := principalMap[principals[i].OwningPrincipalID]; ok {
				principals[i].OwningObjectIdentifier = owner.ObjectIdentifier
			}
		}
	}

	// Get role memberships for each principal
	if err := c.collectServerRoleMemberships(ctx, principals, serverInfo); err != nil {
		return nil, err
	}

	// Get permissions for each principal
	if err := c.collectServerPermissions(ctx, principals, serverInfo); err != nil {
		return nil, err
	}

	return principals, nil
}

// collectServerRoleMemberships gets role memberships for server principals
func (c *Client) collectServerRoleMemberships(ctx context.Context, principals []types.ServerPrincipal, serverInfo *types.ServerInfo) error {
	query := `
		SELECT 
			rm.member_principal_id,
			rm.role_principal_id,
			r.name AS role_name
		FROM sys.server_role_members rm
		JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
		ORDER BY rm.member_principal_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Build a map of principal ID to index for quick lookup
	principalMap := make(map[int]int)
	for i, p := range principals {
		principalMap[p.PrincipalID] = i
	}

	for rows.Next() {
		var memberID, roleID int
		var roleName string

		if err := rows.Scan(&memberID, &roleID, &roleName); err != nil {
			return err
		}

		if idx, ok := principalMap[memberID]; ok {
			membership := types.RoleMembership{
				ObjectIdentifier: fmt.Sprintf("%s@%s", roleName, serverInfo.ObjectIdentifier),
				Name:             roleName,
				PrincipalID:      roleID,
			}
			principals[idx].MemberOf = append(principals[idx].MemberOf, membership)
		}

		// Also track members for role principals
		if idx, ok := principalMap[roleID]; ok {
			memberName := ""
			if memberIdx, ok := principalMap[memberID]; ok {
				memberName = principals[memberIdx].Name
			}
			principals[idx].Members = append(principals[idx].Members, memberName)
		}
	}

	// Add implicit public role membership for all logins
	// SQL Server has implicit membership in public role for all logins
	publicRoleOID := fmt.Sprintf("public@%s", serverInfo.ObjectIdentifier)
	for i := range principals {
		// Only add for login types, not for roles
		if principals[i].TypeDescription != "SERVER_ROLE" {
			// Check if already a member of public
			hasPublic := false
			for _, m := range principals[i].MemberOf {
				if m.Name == "public" {
					hasPublic = true
					break
				}
			}
			if !hasPublic {
				membership := types.RoleMembership{
					ObjectIdentifier: publicRoleOID,
					Name:             "public",
					PrincipalID:      2, // public role always has principal_id = 2 at server level
				}
				principals[i].MemberOf = append(principals[i].MemberOf, membership)
			}
		}
	}

	return nil
}

// collectServerPermissions gets explicit permissions for server principals
func (c *Client) collectServerPermissions(ctx context.Context, principals []types.ServerPrincipal, serverInfo *types.ServerInfo) error {
	query := `
		SELECT 
			p.grantee_principal_id,
			p.permission_name,
			p.state_desc,
			p.class_desc,
			p.major_id,
			COALESCE(pr.name, '') AS grantor_name
		FROM sys.server_permissions p
		LEFT JOIN sys.server_principals pr ON p.major_id = pr.principal_id AND p.class_desc = 'SERVER_PRINCIPAL'
		WHERE p.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION', 'DENY')
		ORDER BY p.grantee_principal_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Build a map of principal ID to index
	principalMap := make(map[int]int)
	for i, p := range principals {
		principalMap[p.PrincipalID] = i
	}

	for rows.Next() {
		var granteeID, majorID int
		var permName, stateDesc, classDesc, grantorName string

		if err := rows.Scan(&granteeID, &permName, &stateDesc, &classDesc, &majorID, &grantorName); err != nil {
			return err
		}

		if idx, ok := principalMap[granteeID]; ok {
			perm := types.Permission{
				Permission: permName,
				State:      stateDesc,
				ClassDesc:  classDesc,
			}

			// If permission is on a principal, set target info
			if classDesc == "SERVER_PRINCIPAL" && majorID > 0 {
				perm.TargetPrincipalID = majorID
				perm.TargetName = grantorName
				if targetIdx, ok := principalMap[majorID]; ok {
					perm.TargetObjectIdentifier = principals[targetIdx].ObjectIdentifier
				}
			}

			principals[idx].Permissions = append(principals[idx].Permissions, perm)
		}
	}

	return nil
}

// collectDatabases gets all accessible databases and their principals
func (c *Client) collectDatabases(ctx context.Context, serverInfo *types.ServerInfo) ([]types.Database, error) {
	query := `
		SELECT 
			d.database_id,
			d.name,
			d.owner_sid,
			SUSER_SNAME(d.owner_sid) AS owner_name,
			d.create_date,
			d.compatibility_level,
			d.collation_name,
			d.is_read_only,
			d.is_trustworthy_on,
			d.is_encrypted
		FROM sys.databases d
		WHERE d.state = 0  -- ONLINE
		ORDER BY d.database_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var databases []types.Database

	for rows.Next() {
		var db types.Database
		var ownerSID []byte
		var ownerName, collation sql.NullString

		err := rows.Scan(
			&db.DatabaseID,
			&db.Name,
			&ownerSID,
			&ownerName,
			&db.CreateDate,
			&db.CompatibilityLevel,
			&collation,
			&db.IsReadOnly,
			&db.IsTrustworthy,
			&db.IsEncrypted,
		)
		if err != nil {
			return nil, err
		}

		db.OwnerLoginName = ownerName.String
		db.CollationName = collation.String
		db.SQLServerName = serverInfo.SQLServerName
		// Database ObjectIdentifier format: ServerObjectIdentifier\DatabaseName (like PowerShell)
		db.ObjectIdentifier = fmt.Sprintf("%s\\%s", serverInfo.ObjectIdentifier, db.Name)

		// Find owner principal ID
		for _, p := range serverInfo.ServerPrincipals {
			if p.Name == db.OwnerLoginName {
				db.OwnerPrincipalID = p.PrincipalID
				db.OwnerObjectIdentifier = p.ObjectIdentifier
				break
			}
		}

		databases = append(databases, db)
	}

	// Collect principals for each database
	for i := range databases {
		principals, err := c.collectDatabasePrincipals(ctx, &databases[i], serverInfo)
		if err != nil {
			fmt.Printf("Warning: failed to collect principals for database %s: %v\n", databases[i].Name, err)
			continue
		}
		databases[i].DatabasePrincipals = principals
	}

	return databases, nil
}

// collectDatabasePrincipals gets all principals in a specific database
func (c *Client) collectDatabasePrincipals(ctx context.Context, db *types.Database, serverInfo *types.ServerInfo) ([]types.DatabasePrincipal, error) {
	// Query all principals using fully-qualified table name
	// The USE statement doesn't always work properly with go-mssqldb
	query := fmt.Sprintf(`
		SELECT 
			p.principal_id,
			p.name,
			p.type_desc,
			ISNULL(p.create_date, '1900-01-01') as create_date,
			ISNULL(p.modify_date, '1900-01-01') as modify_date,
			ISNULL(p.is_fixed_role, 0) as is_fixed_role,
			p.owning_principal_id,
			p.default_schema_name,
			p.sid
		FROM [%s].sys.database_principals p
		ORDER BY p.principal_id
	`, db.Name)

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var principals []types.DatabasePrincipal
	for rows.Next() {
		var p types.DatabasePrincipal
		var owningPrincipalID sql.NullInt64
		var defaultSchema sql.NullString
		var sid []byte
		var isFixedRole sql.NullBool

		err := rows.Scan(
			&p.PrincipalID,
			&p.Name,
			&p.TypeDescription,
			&p.CreateDate,
			&p.ModifyDate,
			&isFixedRole,
			&owningPrincipalID,
			&defaultSchema,
			&sid,
		)
		if err != nil {
			return nil, err
		}

		p.IsFixedRole = isFixedRole.Bool
		p.DefaultSchemaName = defaultSchema.String
		p.DatabaseName = db.Name
		p.SQLServerName = serverInfo.SQLServerName

		if owningPrincipalID.Valid {
			p.OwningPrincipalID = int(owningPrincipalID.Int64)
		}

		// Generate object identifier: Name@ServerObjectIdentifier\DatabaseName (like PowerShell)
		p.ObjectIdentifier = fmt.Sprintf("%s@%s\\%s", p.Name, serverInfo.ObjectIdentifier, db.Name)

		principals = append(principals, p)
	}

	// Link database users to server logins using SQL join (like PowerShell does)
	// This is more accurate than name/SID matching
	if err := c.linkDatabaseUsersToServerLogins(ctx, principals, db, serverInfo); err != nil {
		// Non-fatal - continue without login mapping
		fmt.Printf("Warning: failed to link database users to server logins for %s: %v\n", db.Name, err)
	}

	// Resolve ownership - set OwningObjectIdentifier based on OwningPrincipalID
	principalMap := make(map[int]*types.DatabasePrincipal)
	for i := range principals {
		principalMap[principals[i].PrincipalID] = &principals[i]
	}
	for i := range principals {
		if principals[i].OwningPrincipalID > 0 {
			if owner, ok := principalMap[principals[i].OwningPrincipalID]; ok {
				principals[i].OwningObjectIdentifier = owner.ObjectIdentifier
			}
		}
	}

	// Get role memberships
	if err := c.collectDatabaseRoleMemberships(ctx, principals, db, serverInfo); err != nil {
		return nil, err
	}

	// Get permissions
	if err := c.collectDatabasePermissions(ctx, principals, db, serverInfo); err != nil {
		return nil, err
	}

	return principals, nil
}

// linkDatabaseUsersToServerLogins links database users to their server logins using SID join
// This is the same approach PowerShell uses and is more accurate than name matching
func (c *Client) linkDatabaseUsersToServerLogins(ctx context.Context, principals []types.DatabasePrincipal, db *types.Database, serverInfo *types.ServerInfo) error {
	// Build a map of server logins by principal_id for quick lookup
	serverLoginMap := make(map[int]*types.ServerPrincipal)
	for i := range serverInfo.ServerPrincipals {
		serverLoginMap[serverInfo.ServerPrincipals[i].PrincipalID] = &serverInfo.ServerPrincipals[i]
	}

	// Query to join database principals to server principals by SID
	query := fmt.Sprintf(`
		SELECT 
			dp.principal_id AS db_principal_id,
			sp.name AS server_login_name,
			sp.principal_id AS server_principal_id
		FROM [%s].sys.database_principals dp
		JOIN sys.server_principals sp ON dp.sid = sp.sid
		WHERE dp.sid IS NOT NULL
	`, db.Name)

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Build principal map by principal_id
	principalMap := make(map[int]int)
	for i, p := range principals {
		principalMap[p.PrincipalID] = i
	}

	for rows.Next() {
		var dbPrincipalID, serverPrincipalID int
		var serverLoginName string

		if err := rows.Scan(&dbPrincipalID, &serverLoginName, &serverPrincipalID); err != nil {
			return err
		}

		if idx, ok := principalMap[dbPrincipalID]; ok {
			// Get the server login's ObjectIdentifier
			if serverLogin, ok := serverLoginMap[serverPrincipalID]; ok {
				principals[idx].ServerLogin = &types.ServerLoginRef{
					ObjectIdentifier: serverLogin.ObjectIdentifier,
					Name:             serverLoginName,
					PrincipalID:      serverPrincipalID,
				}
			}
		}
	}

	return nil
}

// collectDatabaseRoleMemberships gets role memberships for database principals
func (c *Client) collectDatabaseRoleMemberships(ctx context.Context, principals []types.DatabasePrincipal, db *types.Database, serverInfo *types.ServerInfo) error {
	query := fmt.Sprintf(`
		SELECT 
			rm.member_principal_id,
			rm.role_principal_id,
			r.name AS role_name
		FROM [%s].sys.database_role_members rm
		JOIN [%s].sys.database_principals r ON rm.role_principal_id = r.principal_id
		ORDER BY rm.member_principal_id
	`, db.Name, db.Name)

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Build principal map
	principalMap := make(map[int]int)
	for i, p := range principals {
		principalMap[p.PrincipalID] = i
	}

	for rows.Next() {
		var memberID, roleID int
		var roleName string

		if err := rows.Scan(&memberID, &roleID, &roleName); err != nil {
			return err
		}

		if idx, ok := principalMap[memberID]; ok {
			membership := types.RoleMembership{
				ObjectIdentifier: fmt.Sprintf("%s@%s\\%s", roleName, serverInfo.ObjectIdentifier, db.Name),
				Name:             roleName,
				PrincipalID:      roleID,
			}
			principals[idx].MemberOf = append(principals[idx].MemberOf, membership)
		}

		// Track members for role principals
		if idx, ok := principalMap[roleID]; ok {
			memberName := ""
			if memberIdx, ok := principalMap[memberID]; ok {
				memberName = principals[memberIdx].Name
			}
			principals[idx].Members = append(principals[idx].Members, memberName)
		}
	}

	// Add implicit public role membership for all database users
	// SQL Server has implicit membership in public role for all database principals
	publicRoleOID := fmt.Sprintf("public@%s\\%s", serverInfo.ObjectIdentifier, db.Name)
	userTypes := map[string]bool{
		"SQL_USER":                   true,
		"WINDOWS_USER":               true,
		"WINDOWS_GROUP":              true,
		"ASYMMETRIC_KEY_MAPPED_USER": true,
		"CERTIFICATE_MAPPED_USER":    true,
		"EXTERNAL_USER":              true,
		"EXTERNAL_GROUPS":            true,
	}
	for i := range principals {
		// Only add for user types, not for roles
		if userTypes[principals[i].TypeDescription] {
			// Check if already a member of public
			hasPublic := false
			for _, m := range principals[i].MemberOf {
				if m.Name == "public" {
					hasPublic = true
					break
				}
			}
			if !hasPublic {
				membership := types.RoleMembership{
					ObjectIdentifier: publicRoleOID,
					Name:             "public",
					PrincipalID:      0, // public role always has principal_id = 0 at database level
				}
				principals[i].MemberOf = append(principals[i].MemberOf, membership)
			}
		}
	}

	return nil
}

// collectDatabasePermissions gets explicit permissions for database principals
func (c *Client) collectDatabasePermissions(ctx context.Context, principals []types.DatabasePrincipal, db *types.Database, serverInfo *types.ServerInfo) error {
	query := fmt.Sprintf(`
		SELECT 
			p.grantee_principal_id,
			p.permission_name,
			p.state_desc,
			p.class_desc,
			p.major_id,
			COALESCE(pr.name, '') AS target_name
		FROM [%s].sys.database_permissions p
		LEFT JOIN [%s].sys.database_principals pr ON p.major_id = pr.principal_id AND p.class_desc = 'DATABASE_PRINCIPAL'
		WHERE p.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION', 'DENY')
		ORDER BY p.grantee_principal_id
	`, db.Name, db.Name)

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	principalMap := make(map[int]int)
	for i, p := range principals {
		principalMap[p.PrincipalID] = i
	}

	for rows.Next() {
		var granteeID, majorID int
		var permName, stateDesc, classDesc, targetName string

		if err := rows.Scan(&granteeID, &permName, &stateDesc, &classDesc, &majorID, &targetName); err != nil {
			return err
		}

		if idx, ok := principalMap[granteeID]; ok {
			perm := types.Permission{
				Permission: permName,
				State:      stateDesc,
				ClassDesc:  classDesc,
			}

			if classDesc == "DATABASE_PRINCIPAL" && majorID > 0 {
				perm.TargetPrincipalID = majorID
				perm.TargetName = targetName
				if targetIdx, ok := principalMap[majorID]; ok {
					perm.TargetObjectIdentifier = principals[targetIdx].ObjectIdentifier
				}
			}

			principals[idx].Permissions = append(principals[idx].Permissions, perm)
		}
	}

	return nil
}

// collectLinkedServers gets all linked server configurations
func (c *Client) collectLinkedServers(ctx context.Context) ([]types.LinkedServer, error) {
	query := `
		SELECT 
			s.server_id,
			s.name,
			s.product,
			s.provider,
			s.data_source,
			s.catalog,
			s.is_linked,
			s.is_remote_login_enabled,
			s.is_rpc_out_enabled,
			s.is_data_access_enabled
		FROM sys.servers s
		WHERE s.is_linked = 1
		ORDER BY s.server_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []types.LinkedServer

	for rows.Next() {
		var s types.LinkedServer
		var catalog sql.NullString

		err := rows.Scan(
			&s.ServerID,
			&s.Name,
			&s.Product,
			&s.Provider,
			&s.DataSource,
			&catalog,
			&s.IsLinkedServer,
			&s.IsRemoteLoginEnabled,
			&s.IsRPCOutEnabled,
			&s.IsDataAccessEnabled,
		)
		if err != nil {
			return nil, err
		}

		s.Catalog = catalog.String
		servers = append(servers, s)
	}

	// Get login mappings for each linked server
	for i := range servers {
		if err := c.collectLinkedServerLogins(ctx, &servers[i]); err != nil {
			// Non-fatal
			fmt.Printf("Warning: failed to get logins for linked server %s: %v\n", servers[i].Name, err)
		}
	}

	return servers, nil
}

// collectLinkedServerLogins gets login mappings for a linked server
func (c *Client) collectLinkedServerLogins(ctx context.Context, server *types.LinkedServer) error {
	query := `
		SELECT
			ll.local_principal_id,
			ll.uses_self_credential,
			ll.remote_name,
			COALESCE(sp.name, '') AS local_name
		FROM sys.linked_logins ll
		LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
		WHERE ll.server_id = @serverID
	`

	rows, err := c.db.QueryContext(ctx, query, sql.Named("serverID", server.ServerID))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var localPrincipalID int
		var usesSelf bool
		var remoteName, localName sql.NullString

		if err := rows.Scan(&localPrincipalID, &usesSelf, &remoteName, &localName); err != nil {
			return err
		}

		server.LocalLogin = localName.String
		server.RemoteLogin = remoteName.String
		server.IsSelfMapping = usesSelf
	}

	return nil
}

// collectServiceAccounts gets SQL Server service account information
func (c *Client) collectServiceAccounts(ctx context.Context, info *types.ServerInfo) error {
	// Try sys.dm_server_services first (SQL Server 2008 R2+)
	query := `
		SELECT
			servicename,
			service_account,
			startup_type_desc
		FROM sys.dm_server_services
		WHERE servicename LIKE 'SQL Server%'
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		// DMV might not exist or user doesn't have permission
		// Fall back to registry read
		return c.collectServiceAccountFromRegistry(ctx, info)
	}
	defer rows.Close()

	for rows.Next() {
		var serviceName, serviceAccount, startupType sql.NullString

		if err := rows.Scan(&serviceName, &serviceAccount, &startupType); err != nil {
			continue
		}

		if serviceAccount.Valid && serviceAccount.String != "" {
			sa := types.ServiceAccount{
				Name:        serviceAccount.String,
				ServiceName: serviceName.String,
				StartupType: startupType.String,
			}

			// Determine service type
			if strings.Contains(serviceName.String, "Agent") {
				sa.ServiceType = "SQLServerAgent"
			} else {
				sa.ServiceType = "SQLServer"
			}

			info.ServiceAccounts = append(info.ServiceAccounts, sa)
		}
	}

	// If no results, try registry fallback
	if len(info.ServiceAccounts) == 0 {
		return c.collectServiceAccountFromRegistry(ctx, info)
	}

	return nil
}

// collectServiceAccountFromRegistry tries to get service account from registry via xp_instance_regread
func (c *Client) collectServiceAccountFromRegistry(ctx context.Context, info *types.ServerInfo) error {
	query := `
		DECLARE @ServiceAccount NVARCHAR(256)
		EXEC master.dbo.xp_instance_regread
			N'HKEY_LOCAL_MACHINE',
			N'SYSTEM\CurrentControlSet\Services\MSSQLSERVER',
			N'ObjectName',
			@ServiceAccount OUTPUT
		SELECT @ServiceAccount AS ServiceAccount
	`

	var serviceAccount sql.NullString
	err := c.db.QueryRowContext(ctx, query).Scan(&serviceAccount)
	if err != nil || !serviceAccount.Valid {
		// Try named instance path
		query = `
			DECLARE @ServiceAccount NVARCHAR(256)
			DECLARE @ServiceKey NVARCHAR(256)
			SET @ServiceKey = N'SYSTEM\CurrentControlSet\Services\MSSQL$' + CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR)
			EXEC master.dbo.xp_instance_regread
				N'HKEY_LOCAL_MACHINE',
				@ServiceKey,
				N'ObjectName',
				@ServiceAccount OUTPUT
			SELECT @ServiceAccount AS ServiceAccount
		`
		err = c.db.QueryRowContext(ctx, query).Scan(&serviceAccount)
	}

	if err == nil && serviceAccount.Valid && serviceAccount.String != "" {
		sa := types.ServiceAccount{
			Name:        serviceAccount.String,
			ServiceName: "SQL Server",
			ServiceType: "SQLServer",
		}
		info.ServiceAccounts = append(info.ServiceAccounts, sa)
	}

	return nil
}

// collectCredentials gets server-level credentials
func (c *Client) collectCredentials(ctx context.Context, info *types.ServerInfo) error {
	query := `
		SELECT
			credential_id,
			name,
			credential_identity,
			create_date,
			modify_date
		FROM sys.credentials
		ORDER BY credential_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		// User might not have permission to view credentials
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var cred types.Credential

		err := rows.Scan(
			&cred.CredentialID,
			&cred.Name,
			&cred.CredentialIdentity,
			&cred.CreateDate,
			&cred.ModifyDate,
		)
		if err != nil {
			continue
		}

		info.Credentials = append(info.Credentials, cred)
	}

	return nil
}

// collectLoginCredentialMappings gets credential mappings for logins
func (c *Client) collectLoginCredentialMappings(ctx context.Context, principals []types.ServerPrincipal, serverInfo *types.ServerInfo) error {
	// Query to get login-to-credential mappings
	query := `
		SELECT
			sp.principal_id,
			c.credential_id,
			c.name AS credential_name,
			c.credential_identity
		FROM sys.server_principals sp
		JOIN sys.server_principal_credentials spc ON sp.principal_id = spc.principal_id
		JOIN sys.credentials c ON spc.credential_id = c.credential_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		// sys.server_principal_credentials might not exist in older versions
		return nil
	}
	defer rows.Close()

	// Build principal map
	principalMap := make(map[int]*types.ServerPrincipal)
	for i := range principals {
		principalMap[principals[i].PrincipalID] = &principals[i]
	}

	for rows.Next() {
		var principalID, credentialID int
		var credName, credIdentity string

		if err := rows.Scan(&principalID, &credentialID, &credName, &credIdentity); err != nil {
			continue
		}

		if principal, ok := principalMap[principalID]; ok {
			principal.MappedCredential = &types.Credential{
				CredentialID:       credentialID,
				Name:               credName,
				CredentialIdentity: credIdentity,
			}
		}
	}

	return nil
}

// collectProxyAccounts gets SQL Agent proxy accounts
func (c *Client) collectProxyAccounts(ctx context.Context, info *types.ServerInfo) error {
	// Query for proxy accounts with their credentials and subsystems
	query := `
		SELECT
			p.proxy_id,
			p.name AS proxy_name,
			p.credential_id,
			c.credential_identity,
			p.enabled,
			ISNULL(p.description, '') AS description
		FROM msdb.dbo.sysproxies p
		JOIN sys.credentials c ON p.credential_id = c.credential_id
		ORDER BY p.proxy_id
	`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		// User might not have access to msdb
		return nil
	}
	defer rows.Close()

	proxies := make(map[int]*types.ProxyAccount)

	for rows.Next() {
		var proxy types.ProxyAccount
		var enabled int

		err := rows.Scan(
			&proxy.ProxyID,
			&proxy.Name,
			&proxy.CredentialID,
			&proxy.CredentialIdentity,
			&enabled,
			&proxy.Description,
		)
		if err != nil {
			continue
		}

		proxy.Enabled = enabled == 1
		proxies[proxy.ProxyID] = &proxy
	}
	rows.Close()

	// Get subsystems for each proxy
	subsystemQuery := `
		SELECT
			ps.proxy_id,
			s.subsystem
		FROM msdb.dbo.sysproxysubsystem ps
		JOIN msdb.dbo.syssubsystems s ON ps.subsystem_id = s.subsystem_id
	`

	rows, err = c.db.QueryContext(ctx, subsystemQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var proxyID int
			var subsystem string
			if err := rows.Scan(&proxyID, &subsystem); err != nil {
				continue
			}
			if proxy, ok := proxies[proxyID]; ok {
				proxy.Subsystems = append(proxy.Subsystems, subsystem)
			}
		}
	}

	// Get login authorizations for each proxy
	loginQuery := `
		SELECT
			pl.proxy_id,
			sp.name AS login_name
		FROM msdb.dbo.sysproxylogin pl
		JOIN sys.server_principals sp ON pl.sid = sp.sid
	`

	rows, err = c.db.QueryContext(ctx, loginQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var proxyID int
			var loginName string
			if err := rows.Scan(&proxyID, &loginName); err != nil {
				continue
			}
			if proxy, ok := proxies[proxyID]; ok {
				proxy.Logins = append(proxy.Logins, loginName)
			}
		}
	}

	// Add all proxies to server info
	for _, proxy := range proxies {
		info.ProxyAccounts = append(info.ProxyAccounts, *proxy)
	}

	return nil
}

// collectDBScopedCredentials gets database-scoped credentials for a database
func (c *Client) collectDBScopedCredentials(ctx context.Context, db *types.Database) error {
	query := fmt.Sprintf(`
		SELECT
			credential_id,
			name,
			credential_identity,
			create_date,
			modify_date
		FROM [%s].sys.database_scoped_credentials
		ORDER BY credential_id
	`, db.Name)

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		// sys.database_scoped_credentials might not exist (pre-SQL 2016) or user lacks permission
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var cred types.DBScopedCredential

		err := rows.Scan(
			&cred.CredentialID,
			&cred.Name,
			&cred.CredentialIdentity,
			&cred.CreateDate,
			&cred.ModifyDate,
		)
		if err != nil {
			continue
		}

		db.DBScopedCredentials = append(db.DBScopedCredentials, cred)
	}

	return nil
}

// collectAuthenticationMode gets the authentication mode (Windows-only vs Mixed)
func (c *Client) collectAuthenticationMode(ctx context.Context, info *types.ServerInfo) error {
	query := `
		SELECT
			CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
				WHEN 1 THEN 0  -- Windows Authentication only
				WHEN 0 THEN 1  -- Mixed mode
			END AS IsMixedModeAuthEnabled
	`

	var isMixed int
	if err := c.db.QueryRowContext(ctx, query).Scan(&isMixed); err == nil {
		info.IsMixedModeAuth = isMixed == 1
	}

	return nil
}

// collectEncryptionSettings gets the force encryption and EPA settings
func (c *Client) collectEncryptionSettings(ctx context.Context, info *types.ServerInfo) error {
	query := `
		DECLARE @ForceEncryption INT
		DECLARE @ExtendedProtection INT

		EXEC master.dbo.xp_instance_regread
			N'HKEY_LOCAL_MACHINE',
			N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
			N'ForceEncryption',
			@ForceEncryption OUTPUT

		EXEC master.dbo.xp_instance_regread
			N'HKEY_LOCAL_MACHINE',
			N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
			N'ExtendedProtection',
			@ExtendedProtection OUTPUT

		SELECT
			@ForceEncryption AS ForceEncryption,
			@ExtendedProtection AS ExtendedProtection
	`

	var forceEnc, extProt sql.NullInt64

	err := c.db.QueryRowContext(ctx, query).Scan(&forceEnc, &extProt)
	if err != nil {
		return nil // Non-fatal - user might not have permission
	}

	if forceEnc.Valid {
		if forceEnc.Int64 == 1 {
			info.ForceEncryption = "Yes"
		} else {
			info.ForceEncryption = "No"
		}
	}

	if extProt.Valid {
		switch extProt.Int64 {
		case 0:
			info.ExtendedProtection = "Off"
		case 1:
			info.ExtendedProtection = "Allowed"
		case 2:
			info.ExtendedProtection = "Required"
		}
	}

	return nil
}

// TestConnection tests if a connection can be established
func TestConnection(serverInstance, userID, password string, timeout time.Duration) error {
	client := NewClient(serverInstance, userID, password)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return err
	}
	defer client.Close()

	return nil
}
