// Package collector orchestrates the MSSQL data collection process.
package collector

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/ad"
	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/mssql"
	"github.com/SpecterOps/MSSQLHound/internal/types"
)

// Config holds the collector configuration
type Config struct {
	// Connection options
	ServerInstance   string
	ServerListFile   string
	ServerList       string
	UserID           string
	Password         string
	Domain           string
	DomainController string
	LDAPUser         string
	LDAPPassword     string

	// Output options
	OutputFormat  string
	TempDir       string
	ZipDir        string
	FileSizeLimit string

	// Collection options
	DomainEnumOnly                  bool
	SkipLinkedServerEnum            bool
	CollectFromLinkedServers        bool
	SkipPrivateAddress              bool
	ScanAllComputers                bool
	SkipADNodeCreation              bool
	IncludeNontraversableEdges      bool
	MakeInterestingEdgesTraversable bool

	// Timeouts and limits
	LinkedServerTimeout    int
	MemoryThresholdPercent int
	FileSizeUpdateInterval int
}

// Collector handles the data collection process
type Collector struct {
	config           *Config
	tempDir          string
	outputFiles      []string
	serversToProcess []string
}

// New creates a new collector
func New(config *Config) *Collector {
	return &Collector{
		config: config,
	}
}

// Run executes the collection process
func (c *Collector) Run() error {
	// Setup temp directory
	if err := c.setupTempDir(); err != nil {
		return fmt.Errorf("failed to setup temp directory: %w", err)
	}
	fmt.Printf("Temporary output directory: %s\n", c.tempDir)

	// Build list of servers to process
	if err := c.buildServerList(); err != nil {
		return fmt.Errorf("failed to build server list: %w", err)
	}

	if len(c.serversToProcess) == 0 {
		return fmt.Errorf("no servers to process")
	}

	fmt.Printf("\nProcessing %d SQL Server(s)...\n", len(c.serversToProcess))

	// Process each server
	for i, server := range c.serversToProcess {
		fmt.Printf("\n[%d/%d] Processing %s...\n", i+1, len(c.serversToProcess), server)

		if err := c.processServer(server); err != nil {
			fmt.Printf("Warning: failed to process %s: %v\n", server, err)
			// Continue with other servers
		}
	}

	// Create zip file
	if len(c.outputFiles) > 0 {
		zipPath, err := c.createZipFile()
		if err != nil {
			return fmt.Errorf("failed to create zip file: %w", err)
		}
		fmt.Printf("\nOutput written to: %s\n", zipPath)
	} else {
		fmt.Println("\nNo data collected - no output file created")
	}

	return nil
}

// setupTempDir creates the temporary directory for output files
func (c *Collector) setupTempDir() error {
	if c.config.TempDir != "" {
		c.tempDir = c.config.TempDir
		return nil
	}

	timestamp := time.Now().Format("20060102-150405")
	tempPath := os.TempDir()
	c.tempDir = filepath.Join(tempPath, fmt.Sprintf("mssql-bloodhound-%s", timestamp))

	return os.MkdirAll(c.tempDir, 0755)
}

// buildServerList builds the list of servers to process
func (c *Collector) buildServerList() error {
	// From command line argument
	if c.config.ServerInstance != "" {
		c.serversToProcess = append(c.serversToProcess, c.config.ServerInstance)
	}

	// From comma-separated list
	if c.config.ServerList != "" {
		servers := strings.Split(c.config.ServerList, ",")
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s != "" {
				c.serversToProcess = append(c.serversToProcess, s)
			}
		}
	}

	// From file
	if c.config.ServerListFile != "" {
		data, err := os.ReadFile(c.config.ServerListFile)
		if err != nil {
			return fmt.Errorf("failed to read server list file: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				c.serversToProcess = append(c.serversToProcess, line)
			}
		}
	}

	// If no servers specified, enumerate SPNs from Active Directory
	if len(c.serversToProcess) == 0 && c.config.Domain != "" {
		fmt.Println("No servers specified, enumerating MSSQL SPNs from Active Directory...")
		if err := c.enumerateServersFromAD(); err != nil {
			fmt.Printf("Warning: SPN enumeration failed: %v\n", err)
		}
	}

	return nil
}

// enumerateServersFromAD discovers MSSQL servers from Active Directory SPNs
func (c *Collector) enumerateServersFromAD() error {
	adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
	defer adClient.Close()

	// Enumerate MSSQL SPNs
	spns, err := adClient.EnumerateMSSQLSPNs()
	if err != nil {
		return fmt.Errorf("failed to enumerate MSSQL SPNs: %w", err)
	}

	fmt.Printf("Found %d MSSQL SPNs\n", len(spns))

	// Track unique servers
	seenServers := make(map[string]bool)

	for _, spn := range spns {
		// Build server string from SPN
		var serverStr string
		if spn.Port != "" {
			serverStr = fmt.Sprintf("%s:%s", spn.Hostname, spn.Port)
		} else if spn.InstanceName != "" {
			serverStr = fmt.Sprintf("%s\\%s", spn.Hostname, spn.InstanceName)
		} else {
			serverStr = spn.Hostname
		}

		if !seenServers[serverStr] {
			seenServers[serverStr] = true
			c.serversToProcess = append(c.serversToProcess, serverStr)
			fmt.Printf("  Found: %s (service account: %s)\n", serverStr, spn.AccountName)
		}
	}

	// If ScanAllComputers is enabled, also enumerate all domain computers
	if c.config.ScanAllComputers {
		fmt.Println("ScanAllComputers enabled, enumerating all domain computers...")
		computers, err := adClient.EnumerateAllComputers()
		if err != nil {
			fmt.Printf("Warning: failed to enumerate domain computers: %v\n", err)
		} else {
			for _, computer := range computers {
				if !seenServers[computer] {
					seenServers[computer] = true
					c.serversToProcess = append(c.serversToProcess, computer)
				}
			}
			fmt.Printf("Added %d additional computers to scan\n", len(computers))
		}
	}

	return nil
}

// processServer collects data from a single SQL Server
func (c *Collector) processServer(serverInstance string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Connect to the server
	client := mssql.NewClient(serverInstance, c.config.UserID, c.config.Password)
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	fmt.Println("  Connected successfully")

	// Collect server information
	serverInfo, err := client.CollectServerInfo(ctx)
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	// If we couldn't get the computer SID from SQL Server, try LDAP
	if serverInfo.ComputerSID == "" && c.config.Domain != "" {
		c.resolveComputerSIDViaLDAP(serverInfo)
	}

	// Resolve service account SIDs via LDAP if they don't have SIDs
	if c.config.Domain != "" {
		c.resolveServiceAccountSIDsViaLDAP(serverInfo)
	}

	fmt.Printf("  Collected: %d principals, %d databases\n",
		len(serverInfo.ServerPrincipals), len(serverInfo.Databases))

	// Generate output
	outputFile := filepath.Join(c.tempDir, fmt.Sprintf("mssql-%s.json", sanitizeFilename(serverInstance)))

	if err := c.generateOutput(serverInfo, outputFile); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	c.outputFiles = append(c.outputFiles, outputFile)
	fmt.Printf("  Output: %s\n", outputFile)

	return nil
}

// resolveComputerSIDViaLDAP attempts to resolve the computer SID via LDAP
func (c *Collector) resolveComputerSIDViaLDAP(serverInfo *types.ServerInfo) {
	// Try to determine the domain from the FQDN if not provided
	domain := c.config.Domain
	if domain == "" && strings.Contains(serverInfo.FQDN, ".") {
		// Extract domain from FQDN (e.g., server.domain.com -> domain.com)
		parts := strings.SplitN(serverInfo.FQDN, ".", 2)
		if len(parts) > 1 {
			domain = parts[1]
		}
	}

	if domain == "" {
		return
	}

	// Create AD client
	adClient := ad.NewClient(domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
	defer adClient.Close()

	// Try to resolve the computer SID
	// Use the machine name (without the FQDN)
	machineName := serverInfo.Hostname
	if strings.Contains(machineName, ".") {
		machineName = strings.Split(machineName, ".")[0]
	}

	sid, err := adClient.ResolveComputerSID(machineName)
	if err != nil {
		fmt.Printf("  Note: Could not resolve computer SID via LDAP: %v\n", err)
		return
	}

	// Store the old ObjectIdentifier to update references
	oldObjectIdentifier := serverInfo.ObjectIdentifier

	serverInfo.ComputerSID = sid
	serverInfo.ObjectIdentifier = fmt.Sprintf("%s:%d", sid, serverInfo.Port)
	fmt.Printf("  Resolved computer SID via LDAP: %s\n", sid)

	// Update all ObjectIdentifiers that reference the old server identifier
	c.updateObjectIdentifiers(serverInfo, oldObjectIdentifier)
}

// updateObjectIdentifiers updates all ObjectIdentifiers after computer SID is resolved
func (c *Collector) updateObjectIdentifiers(serverInfo *types.ServerInfo, oldServerID string) {
	newServerID := serverInfo.ObjectIdentifier

	// Update server principals
	for i := range serverInfo.ServerPrincipals {
		p := &serverInfo.ServerPrincipals[i]
		// Update ObjectIdentifier: Name@OldServerID -> Name@NewServerID
		p.ObjectIdentifier = strings.Replace(p.ObjectIdentifier, "@"+oldServerID, "@"+newServerID, 1)
		// Update OwningObjectIdentifier if it references the server
		if p.OwningObjectIdentifier != "" {
			p.OwningObjectIdentifier = strings.Replace(p.OwningObjectIdentifier, "@"+oldServerID, "@"+newServerID, 1)
		}
	}

	// Update databases and database principals
	for i := range serverInfo.Databases {
		db := &serverInfo.Databases[i]
		// Update database ObjectIdentifier: OldServerID\DBName -> NewServerID\DBName
		db.ObjectIdentifier = strings.Replace(db.ObjectIdentifier, oldServerID+"\\", newServerID+"\\", 1)

		// Update database principals
		for j := range db.DatabasePrincipals {
			p := &db.DatabasePrincipals[j]
			// Update ObjectIdentifier: Name@OldServerID\DBName -> Name@NewServerID\DBName
			p.ObjectIdentifier = strings.Replace(p.ObjectIdentifier, "@"+oldServerID+"\\", "@"+newServerID+"\\", 1)
			// Update OwningObjectIdentifier
			if p.OwningObjectIdentifier != "" {
				p.OwningObjectIdentifier = strings.Replace(p.OwningObjectIdentifier, "@"+oldServerID+"\\", "@"+newServerID+"\\", 1)
			}
			// Update ServerLogin.ObjectIdentifier
			if p.ServerLogin != nil && p.ServerLogin.ObjectIdentifier != "" {
				p.ServerLogin.ObjectIdentifier = strings.Replace(p.ServerLogin.ObjectIdentifier, "@"+oldServerID, "@"+newServerID, 1)
			}
		}
	}
}

// resolveServiceAccountSIDsViaLDAP resolves service account SIDs via LDAP
func (c *Collector) resolveServiceAccountSIDsViaLDAP(serverInfo *types.ServerInfo) {
	// Skip if no domain
	if c.config.Domain == "" {
		return
	}

	// Create AD client
	adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
	defer adClient.Close()

	for i := range serverInfo.ServiceAccounts {
		sa := &serverInfo.ServiceAccounts[i]

		// Skip if already has a SID
		if sa.SID != "" {
			continue
		}

		// Skip non-domain accounts (Local System, Local Service, etc.)
		if !strings.Contains(sa.Name, "\\") && !strings.Contains(sa.Name, "@") {
			continue
		}

		// Skip virtual accounts like NT SERVICE\*
		if strings.HasPrefix(strings.ToUpper(sa.Name), "NT SERVICE\\") ||
			strings.HasPrefix(strings.ToUpper(sa.Name), "NT AUTHORITY\\") {
			continue
		}

		// Try to resolve the service account name to a SID
		principal, err := adClient.ResolveName(sa.Name)
		if err != nil {
			fmt.Printf("  Note: Could not resolve service account %s via LDAP: %v\n", sa.Name, err)
			continue
		}

		sa.SID = principal.SID
		sa.ObjectIdentifier = principal.SID
		fmt.Printf("  Resolved service account SID for %s: %s\n", sa.Name, sa.SID)
	}
}

// generateOutput creates the BloodHound JSON output for a server
func (c *Collector) generateOutput(serverInfo *types.ServerInfo, outputFile string) error {
	writer, err := bloodhound.NewStreamingWriter(outputFile)
	if err != nil {
		return err
	}
	defer writer.Close()

	// Create server node
	serverNode := c.createServerNode(serverInfo)
	if err := writer.WriteNode(serverNode); err != nil {
		return err
	}

	// Create server principal nodes
	for _, principal := range serverInfo.ServerPrincipals {
		node := c.createServerPrincipalNode(&principal, serverInfo)
		if err := writer.WriteNode(node); err != nil {
			return err
		}
	}

	// Create database and database principal nodes
	for _, db := range serverInfo.Databases {
		dbNode := c.createDatabaseNode(&db, serverInfo)
		if err := writer.WriteNode(dbNode); err != nil {
			return err
		}

		for _, principal := range db.DatabasePrincipals {
			node := c.createDatabasePrincipalNode(&principal, &db, serverInfo)
			if err := writer.WriteNode(node); err != nil {
				return err
			}
		}
	}

	// Create AD nodes (User, Group, Computer) if not skipped
	if !c.config.SkipADNodeCreation {
		if err := c.createADNodes(writer, serverInfo); err != nil {
			return err
		}
	}

	// Create edges
	if err := c.createEdges(writer, serverInfo); err != nil {
		return err
	}

	nodes, edges := writer.Stats()
	fmt.Printf("  Wrote %d nodes and %d edges\n", nodes, edges)

	return nil
}

// createServerNode creates a BloodHound node for the SQL Server
func (c *Collector) createServerNode(info *types.ServerInfo) *bloodhound.Node {
	props := map[string]interface{}{
		"name":          info.ServerName,
		"hostname":      info.Hostname,
		"fqdn":          info.FQDN,
		"version":       info.Version,
		"versionNumber": info.VersionNumber,
		"edition":       info.Edition,
		"productLevel":  info.ProductLevel,
		"isClustered":   info.IsClustered,
		"port":          info.Port,
	}

	if info.InstanceName != "" {
		props["instanceName"] = info.InstanceName
	}

	return &bloodhound.Node{
		ID:         info.ObjectIdentifier,
		Kinds:      []string{bloodhound.NodeKinds.Server},
		Properties: props,
		Icon:       bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.Server]),
	}
}

// createServerPrincipalNode creates a BloodHound node for a server principal
func (c *Collector) createServerPrincipalNode(principal *types.ServerPrincipal, serverInfo *types.ServerInfo) *bloodhound.Node {
	props := map[string]interface{}{
		"name":        principal.Name,
		"principalId": principal.PrincipalID,
		"createDate":  principal.CreateDate.Format(time.RFC3339),
		"modifyDate":  principal.ModifyDate.Format(time.RFC3339),
		"SQLServer":   principal.SQLServerName,
	}

	var kinds []string
	var icon *bloodhound.Icon

	switch principal.TypeDescription {
	case "SERVER_ROLE":
		kinds = []string{bloodhound.NodeKinds.ServerRole}
		icon = bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.ServerRole])
		props["isFixedRole"] = principal.IsFixedRole
		if len(principal.Members) > 0 {
			props["members"] = principal.Members
		}
	default:
		// Logins (SQL_LOGIN, WINDOWS_LOGIN, WINDOWS_GROUP, etc.)
		kinds = []string{bloodhound.NodeKinds.Login}
		icon = bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.Login])
		props["type"] = principal.TypeDescription
		props["disabled"] = principal.IsDisabled
		props["defaultDatabase"] = principal.DefaultDatabaseName
		props["isActiveDirectoryPrincipal"] = principal.IsActiveDirectoryPrincipal

		if principal.SecurityIdentifier != "" {
			props["activeDirectorySID"] = principal.SecurityIdentifier
		}
	}

	// Add role memberships
	if len(principal.MemberOf) > 0 {
		roleNames := make([]string, len(principal.MemberOf))
		for i, m := range principal.MemberOf {
			roleNames[i] = m.Name
		}
		props["memberOfRoles"] = roleNames
	}

	// Add explicit permissions
	if len(principal.Permissions) > 0 {
		perms := make([]string, len(principal.Permissions))
		for i, p := range principal.Permissions {
			perms[i] = p.Permission
		}
		props["explicitPermissions"] = perms
	}

	return &bloodhound.Node{
		ID:         principal.ObjectIdentifier,
		Kinds:      kinds,
		Properties: props,
		Icon:       icon,
	}
}

// createDatabaseNode creates a BloodHound node for a database
func (c *Collector) createDatabaseNode(db *types.Database, serverInfo *types.ServerInfo) *bloodhound.Node {
	props := map[string]interface{}{
		"name":               db.Name,
		"databaseId":         db.DatabaseID,
		"createDate":         db.CreateDate.Format(time.RFC3339),
		"compatibilityLevel": db.CompatibilityLevel,
		"isReadOnly":         db.IsReadOnly,
		"isTrustworthy":      db.IsTrustworthy,
		"isEncrypted":        db.IsEncrypted,
		"SQLServer":          db.SQLServerName,
	}

	if db.OwnerLoginName != "" {
		props["ownerLoginName"] = db.OwnerLoginName
	}
	if db.CollationName != "" {
		props["collationName"] = db.CollationName
	}

	return &bloodhound.Node{
		ID:         db.ObjectIdentifier,
		Kinds:      []string{bloodhound.NodeKinds.Database},
		Properties: props,
		Icon:       bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.Database]),
	}
}

// createDatabasePrincipalNode creates a BloodHound node for a database principal
func (c *Collector) createDatabasePrincipalNode(principal *types.DatabasePrincipal, db *types.Database, serverInfo *types.ServerInfo) *bloodhound.Node {
	props := map[string]interface{}{
		"name":         principal.Name,
		"principalId":  principal.PrincipalID,
		"createDate":   principal.CreateDate.Format(time.RFC3339),
		"modifyDate":   principal.ModifyDate.Format(time.RFC3339),
		"databaseName": principal.DatabaseName,
		"SQLServer":    principal.SQLServerName,
	}

	var kinds []string
	var icon *bloodhound.Icon

	switch principal.TypeDescription {
	case "DATABASE_ROLE":
		kinds = []string{bloodhound.NodeKinds.DatabaseRole}
		icon = bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.DatabaseRole])
		props["isFixedRole"] = principal.IsFixedRole
		if len(principal.Members) > 0 {
			props["members"] = principal.Members
		}
	case "APPLICATION_ROLE":
		kinds = []string{bloodhound.NodeKinds.ApplicationRole}
		icon = bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.ApplicationRole])
	default:
		// Database users
		kinds = []string{bloodhound.NodeKinds.DatabaseUser}
		icon = bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.DatabaseUser])
		props["type"] = principal.TypeDescription
		if principal.DefaultSchemaName != "" {
			props["defaultSchema"] = principal.DefaultSchemaName
		}
		if principal.ServerLogin != nil {
			props["serverLogin"] = principal.ServerLogin.Name
		}
	}

	// Add role memberships
	if len(principal.MemberOf) > 0 {
		roleNames := make([]string, len(principal.MemberOf))
		for i, m := range principal.MemberOf {
			roleNames[i] = m.Name
		}
		props["memberOfRoles"] = roleNames
	}

	// Add explicit permissions
	if len(principal.Permissions) > 0 {
		perms := make([]string, len(principal.Permissions))
		for i, p := range principal.Permissions {
			perms[i] = p.Permission
		}
		props["explicitPermissions"] = perms
	}

	return &bloodhound.Node{
		ID:         principal.ObjectIdentifier,
		Kinds:      kinds,
		Properties: props,
		Icon:       icon,
	}
}

// createADNodes creates BloodHound nodes for Active Directory principals referenced by SQL logins
func (c *Collector) createADNodes(writer *bloodhound.StreamingWriter, serverInfo *types.ServerInfo) error {
	createdNodes := make(map[string]bool)

	// Track if we need to create Authenticated Users node for CoerceAndRelayToMSSQL
	needsAuthUsersNode := false

	// Check for computer accounts with EPA disabled (CoerceAndRelayToMSSQL condition)
	if serverInfo.ExtendedProtection == "Off" {
		for _, principal := range serverInfo.ServerPrincipals {
			if principal.IsActiveDirectoryPrincipal &&
				strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") &&
				strings.HasSuffix(principal.Name, "$") &&
				!principal.IsDisabled {
				needsAuthUsersNode = true
				break
			}
		}
	}

	// Create Authenticated Users node if needed
	if needsAuthUsersNode {
		authedUsersSID := "S-1-5-11"
		if c.config.Domain != "" {
			authedUsersSID = c.config.Domain + "-S-1-5-11"
		}

		if !createdNodes[authedUsersSID] {
			node := &bloodhound.Node{
				ID:    authedUsersSID,
				Kinds: []string{bloodhound.NodeKinds.Group, "Base"},
				Properties: map[string]interface{}{
					"name": "AUTHENTICATED USERS@" + c.config.Domain,
				},
			}
			if err := writer.WriteNode(node); err != nil {
				return err
			}
			createdNodes[authedUsersSID] = true
		}
	}

	// Create nodes for domain principals with SQL logins
	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Skip if not a domain SID (skip NT AUTHORITY, NT SERVICE, etc.)
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
			continue
		}

		// Skip disabled logins and those without CONNECT SQL
		if principal.IsDisabled {
			continue
		}

		// Check if has CONNECT SQL permission
		hasConnectSQL := false
		for _, perm := range principal.Permissions {
			if perm.Permission == "CONNECT SQL" && (perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
				hasConnectSQL = true
				break
			}
		}
		// Also check if member of sysadmin or securityadmin (they have implicit CONNECT SQL)
		if !hasConnectSQL {
			for _, membership := range principal.MemberOf {
				if membership.Name == "sysadmin" || membership.Name == "securityadmin" {
					hasConnectSQL = true
					break
				}
			}
		}
		if !hasConnectSQL {
			continue
		}

		// Skip if already created
		if createdNodes[principal.SecurityIdentifier] {
			continue
		}

		// Determine the node kind based on the principal name
		var kinds []string
		if strings.HasSuffix(principal.Name, "$") {
			kinds = []string{bloodhound.NodeKinds.Computer, "Base"}
		} else if strings.Contains(principal.TypeDescription, "GROUP") {
			kinds = []string{bloodhound.NodeKinds.Group, "Base"}
		} else {
			kinds = []string{bloodhound.NodeKinds.User, "Base"}
		}

		// Build the display name with domain
		displayName := principal.Name
		if c.config.Domain != "" && !strings.Contains(displayName, "@") {
			displayName = principal.Name + "@" + c.config.Domain
		}

		node := &bloodhound.Node{
			ID:    principal.SecurityIdentifier,
			Kinds: kinds,
			Properties: map[string]interface{}{
				"name": displayName,
			},
		}
		if err := writer.WriteNode(node); err != nil {
			return err
		}
		createdNodes[principal.SecurityIdentifier] = true
	}

	// Create nodes for service accounts
	for _, sa := range serverInfo.ServiceAccounts {
		saID := sa.SID
		if saID == "" {
			saID = sa.ObjectIdentifier
		}
		if saID == "" || createdNodes[saID] {
			continue
		}

		// Skip if not a domain SID
		if !strings.HasPrefix(saID, "S-1-5-21-") {
			continue
		}

		// Determine kind based on account name
		var kinds []string
		if strings.HasSuffix(sa.Name, "$") {
			kinds = []string{bloodhound.NodeKinds.Computer, "Base"}
		} else {
			kinds = []string{bloodhound.NodeKinds.User, "Base"}
		}

		displayName := sa.Name
		if c.config.Domain != "" && !strings.Contains(displayName, "@") {
			displayName = sa.Name + "@" + c.config.Domain
		}

		node := &bloodhound.Node{
			ID:    saID,
			Kinds: kinds,
			Properties: map[string]interface{}{
				"name": displayName,
			},
		}
		if err := writer.WriteNode(node); err != nil {
			return err
		}
		createdNodes[saID] = true
	}

	return nil
}

// createEdges creates all edges for the server
func (c *Collector) createEdges(writer *bloodhound.StreamingWriter, serverInfo *types.ServerInfo) error {
	// =========================================================================
	// CONTAINS EDGES
	// =========================================================================

	// Server contains databases
	for _, db := range serverInfo.Databases {
		edge := c.createEdge(
			serverInfo.ObjectIdentifier,
			db.ObjectIdentifier,
			bloodhound.EdgeKinds.Contains,
			&bloodhound.EdgeContext{
				SourceName: serverInfo.ServerName,
				SourceType: bloodhound.NodeKinds.Server,
				TargetName: db.Name,
				TargetType: bloodhound.NodeKinds.Database,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// Server contains server principals (logins and server roles)
	for _, principal := range serverInfo.ServerPrincipals {
		targetType := c.getServerPrincipalType(principal.TypeDescription)
		edge := c.createEdge(
			serverInfo.ObjectIdentifier,
			principal.ObjectIdentifier,
			bloodhound.EdgeKinds.Contains,
			&bloodhound.EdgeContext{
				SourceName: serverInfo.ServerName,
				SourceType: bloodhound.NodeKinds.Server,
				TargetName: principal.Name,
				TargetType: targetType,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// Database contains database principals (users, roles, application roles)
	for _, db := range serverInfo.Databases {
		for _, principal := range db.DatabasePrincipals {
			targetType := c.getDatabasePrincipalType(principal.TypeDescription)
			edge := c.createEdge(
				db.ObjectIdentifier,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.Contains,
				&bloodhound.EdgeContext{
					SourceName:    db.Name,
					SourceType:    bloodhound.NodeKinds.Database,
					TargetName:    principal.Name,
					TargetType:    targetType,
					SQLServerName: serverInfo.SQLServerName,
					DatabaseName:  db.Name,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// =========================================================================
	// OWNERSHIP EDGES
	// =========================================================================

	// Database ownership (login owns database)
	for _, db := range serverInfo.Databases {
		if db.OwnerObjectIdentifier != "" {
			edge := c.createEdge(
				db.OwnerObjectIdentifier,
				db.ObjectIdentifier,
				bloodhound.EdgeKinds.Owns,
				&bloodhound.EdgeContext{
					SourceName:    db.OwnerLoginName,
					SourceType:    bloodhound.NodeKinds.Login,
					TargetName:    db.Name,
					TargetType:    bloodhound.NodeKinds.Database,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Server role ownership
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.TypeDescription == "SERVER_ROLE" && principal.OwningObjectIdentifier != "" {
			edge := c.createEdge(
				principal.OwningObjectIdentifier,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.Owns,
				&bloodhound.EdgeContext{
					SourceName:    "", // Will be filled by owner lookup
					SourceType:    bloodhound.NodeKinds.Login,
					TargetName:    principal.Name,
					TargetType:    bloodhound.NodeKinds.ServerRole,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Database role ownership
	for _, db := range serverInfo.Databases {
		for _, principal := range db.DatabasePrincipals {
			if principal.TypeDescription == "DATABASE_ROLE" && principal.OwningObjectIdentifier != "" {
				edge := c.createEdge(
					principal.OwningObjectIdentifier,
					principal.ObjectIdentifier,
					bloodhound.EdgeKinds.Owns,
					&bloodhound.EdgeContext{
						SourceName:    "", // Owner name
						SourceType:    bloodhound.NodeKinds.DatabaseUser,
						TargetName:    principal.Name,
						TargetType:    bloodhound.NodeKinds.DatabaseRole,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}
			}
		}
	}

	// =========================================================================
	// MEMBEROF EDGES
	// =========================================================================

	// Server role memberships (explicit only - PowerShell doesn't add implicit public membership)
	for _, principal := range serverInfo.ServerPrincipals {
		for _, role := range principal.MemberOf {
			edge := c.createEdge(
				principal.ObjectIdentifier,
				role.ObjectIdentifier,
				bloodhound.EdgeKinds.MemberOf,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    c.getServerPrincipalType(principal.TypeDescription),
					TargetName:    role.Name,
					TargetType:    bloodhound.NodeKinds.ServerRole,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Database role memberships (explicit only - PowerShell doesn't add implicit public membership)
	for _, db := range serverInfo.Databases {
		for _, principal := range db.DatabasePrincipals {
			for _, role := range principal.MemberOf {
				edge := c.createEdge(
					principal.ObjectIdentifier,
					role.ObjectIdentifier,
					bloodhound.EdgeKinds.MemberOf,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
						TargetName:    role.Name,
						TargetType:    bloodhound.NodeKinds.DatabaseRole,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}
			}
		}
	}

	// =========================================================================
	// MAPPING EDGES
	// =========================================================================

	// Login to database user mapping
	for _, db := range serverInfo.Databases {
		for _, principal := range db.DatabasePrincipals {
			if principal.ServerLogin != nil {
				edge := c.createEdge(
					principal.ServerLogin.ObjectIdentifier,
					principal.ObjectIdentifier,
					bloodhound.EdgeKinds.IsMappedTo,
					&bloodhound.EdgeContext{
						SourceName:    principal.ServerLogin.Name,
						SourceType:    bloodhound.NodeKinds.Login,
						TargetName:    principal.Name,
						TargetType:    bloodhound.NodeKinds.DatabaseUser,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}
			}
		}
	}

	// =========================================================================
	// FIXED ROLE PERMISSION EDGES
	// =========================================================================

	// Create edges for fixed role capabilities
	if err := c.createFixedRoleEdges(writer, serverInfo); err != nil {
		return err
	}

	// =========================================================================
	// EXPLICIT PERMISSION EDGES
	// =========================================================================

	// Server principal permissions
	if err := c.createServerPermissionEdges(writer, serverInfo); err != nil {
		return err
	}

	// Database principal permissions
	for _, db := range serverInfo.Databases {
		if err := c.createDatabasePermissionEdges(writer, &db, serverInfo); err != nil {
			return err
		}
	}

	// =========================================================================
	// LINKED SERVER AND TRUSTWORTHY EDGES
	// =========================================================================

	// Linked servers
	for _, linked := range serverInfo.LinkedServers {
		// Determine target ObjectIdentifier for linked server
		targetID := linked.DataSource
		if linked.ResolvedObjectIdentifier != "" {
			targetID = linked.ResolvedObjectIdentifier
		}

		// MSSQL_LinkedTo edge
		edge := c.createEdge(
			serverInfo.ObjectIdentifier,
			targetID,
			bloodhound.EdgeKinds.LinkedTo,
			&bloodhound.EdgeContext{
				SourceName:    serverInfo.ServerName,
				SourceType:    bloodhound.NodeKinds.Server,
				TargetName:    linked.Name,
				TargetType:    bloodhound.NodeKinds.Server,
				SQLServerName: serverInfo.SQLServerName,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}

		// MSSQL_LinkedAsAdmin edge if conditions are met:
		// - Remote login exists and is a SQL login (no backslash)
		// - Remote login has admin privileges (sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN)
		// - Target server has mixed mode authentication enabled
		if linked.RemoteLogin != "" &&
			!strings.Contains(linked.RemoteLogin, "\\") &&
			(linked.RemoteIsSysadmin || linked.RemoteIsSecurityAdmin ||
				linked.RemoteHasControlServer || linked.RemoteHasImpersonateAnyLogin) &&
			linked.RemoteIsMixedMode {

			edge := c.createEdge(
				serverInfo.ObjectIdentifier,
				targetID,
				bloodhound.EdgeKinds.LinkedAsAdmin,
				&bloodhound.EdgeContext{
					SourceName:    serverInfo.ServerName,
					SourceType:    bloodhound.NodeKinds.Server,
					TargetName:    linked.Name,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Trustworthy databases - create IsTrustedBy and potentially ExecuteAsOwner edges
	for _, db := range serverInfo.Databases {
		if db.IsTrustworthy {
			// Always create IsTrustedBy edge for trustworthy databases
			edge := c.createEdge(
				db.ObjectIdentifier,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.IsTrustedBy,
				&bloodhound.EdgeContext{
					SourceName:    db.Name,
					SourceType:    bloodhound.NodeKinds.Database,
					TargetName:    serverInfo.ServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}

			// Check if database owner has high privileges (sysadmin membership)
			if db.OwnerObjectIdentifier != "" {
				// Find the owner in server principals
				var ownerHasSysadmin bool
				for _, owner := range serverInfo.ServerPrincipals {
					if owner.ObjectIdentifier == db.OwnerObjectIdentifier {
						// Check if owner is a member of sysadmin
						for _, role := range owner.MemberOf {
							if role.Name == "sysadmin" {
								ownerHasSysadmin = true
								break
							}
						}
						break
					}
				}

				if ownerHasSysadmin {
					// Create ExecuteAsOwner edge
					edge := c.createEdge(
						db.ObjectIdentifier,
						serverInfo.ObjectIdentifier,
						bloodhound.EdgeKinds.ExecuteAsOwner,
						&bloodhound.EdgeContext{
							SourceName:    db.Name,
							SourceType:    bloodhound.NodeKinds.Database,
							TargetName:    serverInfo.SQLServerName,
							TargetType:    bloodhound.NodeKinds.Server,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
			}
		}
	}

	// =========================================================================
	// COMPUTER-SERVER RELATIONSHIP EDGES
	// =========================================================================

	// Create Computer node and edges if we have the computer SID
	if serverInfo.ComputerSID != "" {
		// MSSQL_HostFor: Computer -> Server
		edge := c.createEdge(
			serverInfo.ComputerSID,
			serverInfo.ObjectIdentifier,
			bloodhound.EdgeKinds.HostFor,
			&bloodhound.EdgeContext{
				SourceName:    serverInfo.Hostname,
				SourceType:    "Computer",
				TargetName:    serverInfo.SQLServerName,
				TargetType:    bloodhound.NodeKinds.Server,
				SQLServerName: serverInfo.SQLServerName,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}

		// MSSQL_ExecuteOnHost: Server -> Computer
		edge = c.createEdge(
			serverInfo.ObjectIdentifier,
			serverInfo.ComputerSID,
			bloodhound.EdgeKinds.ExecuteOnHost,
			&bloodhound.EdgeContext{
				SourceName:    serverInfo.SQLServerName,
				SourceType:    bloodhound.NodeKinds.Server,
				TargetName:    serverInfo.Hostname,
				TargetType:    "Computer",
				SQLServerName: serverInfo.SQLServerName,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// =========================================================================
	// AD PRINCIPAL RELATIONSHIP EDGES
	// =========================================================================

	// Create HasLogin edges from AD principals (users/groups) to their SQL logins
	// Match PowerShell logic: only create for enabled logins with domain SIDs (S-1-5-21-*)
	// that have CONNECT SQL permission
	principalsWithLogin := make(map[string]bool)
	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Skip disabled logins
		if principal.IsDisabled {
			continue
		}

		// Only process domain SIDs (S-1-5-21-*), skip NT AUTHORITY, NT SERVICE, etc.
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
			continue
		}

		// Check if has CONNECT SQL permission (through explicit permission or role membership)
		hasConnectSQL := false
		for _, perm := range principal.Permissions {
			if perm.Permission == "CONNECT SQL" && (perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
				hasConnectSQL = true
				break
			}
		}

		// Also check if member of sysadmin or securityadmin (they have implicit CONNECT SQL)
		if !hasConnectSQL {
			for _, membership := range principal.MemberOf {
				if membership.Name == "sysadmin" || membership.Name == "securityadmin" {
					hasConnectSQL = true
					break
				}
			}
		}

		if !hasConnectSQL {
			continue
		}

		// Skip if we already created HasLogin for this SID
		if principalsWithLogin[principal.SecurityIdentifier] {
			continue
		}
		principalsWithLogin[principal.SecurityIdentifier] = true

		// MSSQL_HasLogin: AD Principal (SID) -> SQL Login
		edge := c.createEdge(
			principal.SecurityIdentifier,
			principal.ObjectIdentifier,
			bloodhound.EdgeKinds.HasLogin,
			&bloodhound.EdgeContext{
				SourceName:    principal.Name,
				SourceType:    "Base", // Generic AD principal type
				TargetName:    principal.Name,
				TargetType:    bloodhound.NodeKinds.Login,
				SQLServerName: serverInfo.SQLServerName,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}

		// CoerceAndRelayToMSSQL edge if conditions are met:
		// - Extended Protection (EPA) is Off
		// - Login is for a computer account (name ends with $)
		if serverInfo.ExtendedProtection == "Off" && strings.HasSuffix(principal.Name, "$") {
			// Create edge from Authenticated Users (S-1-5-11) to the SQL login
			// The SID S-1-5-11 is prefixed with the domain SID for the full ObjectIdentifier
			authedUsersSID := "S-1-5-11"
			if c.config.Domain != "" {
				authedUsersSID = c.config.Domain + "-S-1-5-11"
			}

			edge := c.createEdge(
				authedUsersSID,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.CoerceAndRelayTo,
				&bloodhound.EdgeContext{
					SourceName:    "AUTHENTICATED USERS",
					SourceType:    "Group",
					TargetName:    principal.Name,
					TargetType:    bloodhound.NodeKinds.Login,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// =========================================================================
	// SERVICE ACCOUNT EDGES (including Kerberoasting edges)
	// =========================================================================

	// Track domain principals with admin privileges for GetAdminTGS
	var domainPrincipalsWithAdmin []string
	var enabledDomainLoginsWithConnectSQL []types.ServerPrincipal

	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Skip non-domain SIDs
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
			continue
		}

		// Check if has admin-level access
		hasAdmin := false

		// Check for sysadmin or securityadmin membership
		for _, membership := range principal.MemberOf {
			if membership.Name == "sysadmin" || membership.Name == "securityadmin" {
				hasAdmin = true
				break
			}
		}

		// Check for CONTROL SERVER or IMPERSONATE ANY LOGIN
		if !hasAdmin {
			for _, perm := range principal.Permissions {
				if (perm.Permission == "CONTROL SERVER" || perm.Permission == "IMPERSONATE ANY LOGIN") &&
					(perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
					hasAdmin = true
					break
				}
			}
		}

		if hasAdmin {
			domainPrincipalsWithAdmin = append(domainPrincipalsWithAdmin, principal.ObjectIdentifier)
		}

		// Track enabled domain logins with CONNECT SQL for GetTGS
		if !principal.IsDisabled {
			hasConnect := false
			for _, perm := range principal.Permissions {
				if perm.Permission == "CONNECT SQL" && (perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
					hasConnect = true
					break
				}
			}
			// Also check if member of sysadmin (implies CONNECT)
			if !hasConnect {
				for _, membership := range principal.MemberOf {
					if membership.Name == "sysadmin" || membership.Name == "securityadmin" {
						hasConnect = true
						break
					}
				}
			}
			if hasConnect {
				enabledDomainLoginsWithConnectSQL = append(enabledDomainLoginsWithConnectSQL, principal)
			}
		}
	}

	// Create ServiceAccountFor and Kerberoasting edges from service accounts to the server
	for _, sa := range serverInfo.ServiceAccounts {
		if sa.ObjectIdentifier == "" && sa.SID == "" {
			continue
		}

		saID := sa.SID
		if saID == "" {
			saID = sa.ObjectIdentifier
		}

		// ServiceAccountFor: Service Account (SID) -> SQL Server
		edge := c.createEdge(
			saID,
			serverInfo.ObjectIdentifier,
			bloodhound.EdgeKinds.ServiceAccountFor,
			&bloodhound.EdgeContext{
				SourceName:    sa.Name,
				SourceType:    "Base", // Could be User or Computer
				TargetName:    serverInfo.SQLServerName,
				TargetType:    bloodhound.NodeKinds.Server,
				SQLServerName: serverInfo.SQLServerName,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}

		// GetAdminTGS: Service Account -> Server (if any domain principal has admin)
		if len(domainPrincipalsWithAdmin) > 0 {
			edge := c.createEdge(
				saID,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.GetAdminTGS,
				&bloodhound.EdgeContext{
					SourceName:    sa.Name,
					SourceType:    "Base",
					TargetName:    serverInfo.SQLServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}

		// GetTGS: Service Account -> each enabled domain login with CONNECT SQL
		for _, login := range enabledDomainLoginsWithConnectSQL {
			edge := c.createEdge(
				saID,
				login.ObjectIdentifier,
				bloodhound.EdgeKinds.GetTGS,
				&bloodhound.EdgeContext{
					SourceName:    sa.Name,
					SourceType:    "Base",
					TargetName:    login.Name,
					TargetType:    bloodhound.NodeKinds.Login,
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// =========================================================================
	// CREDENTIAL EDGES
	// =========================================================================

	// Create HasMappedCred edges from logins to their mapped credentials
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.MappedCredential == nil {
			continue
		}

		cred := principal.MappedCredential

		// Only create edges for domain credentials (has backslash or @ in identity)
		if !strings.Contains(cred.CredentialIdentity, "\\") && !strings.Contains(cred.CredentialIdentity, "@") {
			continue
		}

		// HasMappedCred: Login -> AD Principal (based on credential identity)
		// Note: In a real implementation, we'd resolve the credential identity to a SID
		// For now, we create an edge using the credential identity as the target
		edge := c.createEdge(
			principal.ObjectIdentifier,
			cred.CredentialIdentity, // This would ideally be the resolved SID
			bloodhound.EdgeKinds.HasMappedCred,
			&bloodhound.EdgeContext{
				SourceName:    principal.Name,
				SourceType:    bloodhound.NodeKinds.Login,
				TargetName:    cred.CredentialIdentity,
				TargetType:    "Base",
				SQLServerName: serverInfo.SQLServerName,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// =========================================================================
	// PROXY ACCOUNT EDGES
	// =========================================================================

	// Create HasProxyCred edges from logins authorized to use proxies
	for _, proxy := range serverInfo.ProxyAccounts {
		// Only create edges for domain credentials
		if !strings.Contains(proxy.CredentialIdentity, "\\") && !strings.Contains(proxy.CredentialIdentity, "@") {
			continue
		}

		// For each login authorized to use this proxy
		for _, loginName := range proxy.Logins {
			// Find the login's ObjectIdentifier
			var loginObjectID string
			for _, principal := range serverInfo.ServerPrincipals {
				if principal.Name == loginName {
					loginObjectID = principal.ObjectIdentifier
					break
				}
			}

			if loginObjectID == "" {
				continue
			}

			// HasProxyCred: Login -> AD Principal (credential identity)
			edge := c.createEdge(
				loginObjectID,
				proxy.CredentialIdentity, // This would ideally be the resolved SID
				bloodhound.EdgeKinds.HasProxyCred,
				&bloodhound.EdgeContext{
					SourceName:    loginName,
					SourceType:    bloodhound.NodeKinds.Login,
					TargetName:    proxy.CredentialIdentity,
					TargetType:    "Base",
					SQLServerName: serverInfo.SQLServerName,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// =========================================================================
	// DATABASE-SCOPED CREDENTIAL EDGES
	// =========================================================================

	// Create HasDBScopedCred edges from databases to credential identities
	for _, db := range serverInfo.Databases {
		for _, cred := range db.DBScopedCredentials {
			// Only create edges for domain credentials
			if !strings.Contains(cred.CredentialIdentity, "\\") && !strings.Contains(cred.CredentialIdentity, "@") {
				continue
			}

			// HasDBScopedCred: Database -> AD Principal (credential identity)
			edge := c.createEdge(
				db.ObjectIdentifier,
				cred.CredentialIdentity, // This would ideally be the resolved SID
				bloodhound.EdgeKinds.HasDBScopedCred,
				&bloodhound.EdgeContext{
					SourceName:    db.Name,
					SourceType:    bloodhound.NodeKinds.Database,
					TargetName:    cred.CredentialIdentity,
					TargetType:    "Base",
					SQLServerName: serverInfo.SQLServerName,
					DatabaseName:  db.Name,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	return nil
}

// createFixedRoleEdges creates edges for fixed server and database role capabilities
func (c *Collector) createFixedRoleEdges(writer *bloodhound.StreamingWriter, serverInfo *types.ServerInfo) error {
	// Fixed server roles with special capabilities
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.TypeDescription != "SERVER_ROLE" || !principal.IsFixedRole {
			continue
		}

		switch principal.Name {
		case "sysadmin":
			// sysadmin has CONTROL SERVER
			edge := c.createEdge(
				principal.ObjectIdentifier,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.ControlServer,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    bloodhound.NodeKinds.ServerRole,
					TargetName:    serverInfo.ServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
					IsFixedRole:   true,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}

		case "securityadmin":
			// securityadmin can grant any permission
			edge := c.createEdge(
				principal.ObjectIdentifier,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.GrantAnyPermission,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    bloodhound.NodeKinds.ServerRole,
					TargetName:    serverInfo.ServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
					IsFixedRole:   true,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Fixed database roles with special capabilities
	for _, db := range serverInfo.Databases {
		for _, principal := range db.DatabasePrincipals {
			if principal.TypeDescription != "DATABASE_ROLE" || !principal.IsFixedRole {
				continue
			}

			switch principal.Name {
			case "db_owner":
				// db_owner has CONTROL on the database
				edge := c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.ControlDB,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    bloodhound.NodeKinds.DatabaseRole,
						TargetName:    db.Name,
						TargetType:    bloodhound.NodeKinds.Database,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
						IsFixedRole:   true,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// NOTE: db_owner does NOT create explicit AddMember edges
				// Its ability to add members comes from ControlDB permission
				// PowerShell doesn't create AddMember from db_owner either

				// db_owner can change passwords for application roles
				for _, appRole := range db.DatabasePrincipals {
					if appRole.TypeDescription == "APPLICATION_ROLE" {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							appRole.ObjectIdentifier,
							bloodhound.EdgeKinds.ChangePassword,
							&bloodhound.EdgeContext{
								SourceName:    principal.Name,
								SourceType:    bloodhound.NodeKinds.DatabaseRole,
								TargetName:    appRole.Name,
								TargetType:    bloodhound.NodeKinds.ApplicationRole,
								SQLServerName: serverInfo.SQLServerName,
								DatabaseName:  db.Name,
								IsFixedRole:   true,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}

			case "db_securityadmin":
				// db_securityadmin can grant any database permission
				edge := c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.GrantAnyDBPermission,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    bloodhound.NodeKinds.DatabaseRole,
						TargetName:    db.Name,
						TargetType:    bloodhound.NodeKinds.Database,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
						IsFixedRole:   true,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// db_securityadmin has ALTER ANY APPLICATION ROLE permission
				edge = c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.AlterAnyAppRole,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    bloodhound.NodeKinds.DatabaseRole,
						TargetName:    db.Name,
						TargetType:    bloodhound.NodeKinds.Database,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
						IsFixedRole:   true,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// db_securityadmin has ALTER ANY ROLE permission
				edge = c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.AlterAnyDBRole,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    bloodhound.NodeKinds.DatabaseRole,
						TargetName:    db.Name,
						TargetType:    bloodhound.NodeKinds.Database,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
						IsFixedRole:   true,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// db_securityadmin can add members to user-defined roles only (not fixed roles)
				// Also exclude the public role as its membership cannot be changed
				for _, targetRole := range db.DatabasePrincipals {
					if targetRole.TypeDescription == "DATABASE_ROLE" &&
						!targetRole.IsFixedRole &&
						targetRole.Name != "public" {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							targetRole.ObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
							&bloodhound.EdgeContext{
								SourceName:    principal.Name,
								SourceType:    bloodhound.NodeKinds.DatabaseRole,
								TargetName:    targetRole.Name,
								TargetType:    bloodhound.NodeKinds.DatabaseRole,
								SQLServerName: serverInfo.SQLServerName,
								DatabaseName:  db.Name,
								IsFixedRole:   true,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}

			case "db_accessadmin":
				// db_accessadmin can change password for application roles (limited)
				for _, appRole := range db.DatabasePrincipals {
					if appRole.TypeDescription == "APPLICATION_ROLE" {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							appRole.ObjectIdentifier,
							bloodhound.EdgeKinds.ChangePassword,
							&bloodhound.EdgeContext{
								SourceName:    principal.Name,
								SourceType:    bloodhound.NodeKinds.DatabaseRole,
								TargetName:    appRole.Name,
								TargetType:    bloodhound.NodeKinds.ApplicationRole,
								SQLServerName: serverInfo.SQLServerName,
								DatabaseName:  db.Name,
								IsFixedRole:   true,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}
			}
		}
	}

	return nil
}

// createServerPermissionEdges creates edges based on server-level permissions
func (c *Collector) createServerPermissionEdges(writer *bloodhound.StreamingWriter, serverInfo *types.ServerInfo) error {
	principalMap := make(map[int]*types.ServerPrincipal)
	for i := range serverInfo.ServerPrincipals {
		principalMap[serverInfo.ServerPrincipals[i].PrincipalID] = &serverInfo.ServerPrincipals[i]
	}

	for _, principal := range serverInfo.ServerPrincipals {
		for _, perm := range principal.Permissions {
			if perm.State != "GRANT" && perm.State != "GRANT_WITH_GRANT_OPTION" {
				continue
			}

			switch perm.Permission {
			case "CONTROL SERVER":
				edge := c.createEdge(
					principal.ObjectIdentifier,
					serverInfo.ObjectIdentifier,
					bloodhound.EdgeKinds.ControlServer,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getServerPrincipalType(principal.TypeDescription),
						TargetName:    serverInfo.ServerName,
						TargetType:    bloodhound.NodeKinds.Server,
						SQLServerName: serverInfo.SQLServerName,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

			case "CONNECT SQL":
				// CONNECT SQL permission allows connecting to the server
				// Only create edge if the principal is not disabled
				if !principal.IsDisabled {
					edge := c.createEdge(
						principal.ObjectIdentifier,
						serverInfo.ObjectIdentifier,
						bloodhound.EdgeKinds.Connect,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    serverInfo.ServerName,
							TargetType:    bloodhound.NodeKinds.Server,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}

			case "CONNECT ANY DATABASE":
				// CONNECT ANY DATABASE permission allows connecting to any database
				edge := c.createEdge(
					principal.ObjectIdentifier,
					serverInfo.ObjectIdentifier,
					bloodhound.EdgeKinds.ConnectAnyDatabase,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getServerPrincipalType(principal.TypeDescription),
						TargetName:    serverInfo.ServerName,
						TargetType:    bloodhound.NodeKinds.Server,
						SQLServerName: serverInfo.SQLServerName,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

			case "CONTROL":
				// CONTROL on a server principal (login/role)
				if perm.ClassDesc == "SERVER_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.Login
					isServerRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						if targetPrincipal.TypeDescription == "SERVER_ROLE" {
							targetType = bloodhound.NodeKinds.ServerRole
							isServerRole = true
						}
					}

					// Use specific edge type based on target
					edgeKind := bloodhound.EdgeKinds.ControlLogin
					if isServerRole {
						edgeKind = bloodhound.EdgeKinds.ControlServerRole
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						edgeKind,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    targetType,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// CONTROL implies ChangeOwner for server roles
					if isServerRole {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ChangeOwner,
							&bloodhound.EdgeContext{
								SourceName:    principal.Name,
								SourceType:    c.getServerPrincipalType(principal.TypeDescription),
								TargetName:    targetName,
								TargetType:    targetType,
								SQLServerName: serverInfo.SQLServerName,
								Permission:    perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}

			case "ALTER":
				// ALTER on a server principal (login/role)
				if perm.ClassDesc == "SERVER_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.Login
					isServerRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						if targetPrincipal.TypeDescription == "SERVER_ROLE" {
							targetType = bloodhound.NodeKinds.ServerRole
							isServerRole = true
						}
					}

					// Use specific edge type for server roles
					edgeKind := bloodhound.EdgeKinds.Alter
					if isServerRole {
						edgeKind = bloodhound.EdgeKinds.AlterServerRole
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						edgeKind,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    targetType,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}

			case "TAKE OWNERSHIP":
				// TAKE OWNERSHIP on a server principal
				if perm.ClassDesc == "SERVER_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.Login
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						if targetPrincipal.TypeDescription == "SERVER_ROLE" {
							targetType = bloodhound.NodeKinds.ServerRole
						}
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.TakeOwnership,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    targetType,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}

			case "IMPERSONATE":
				if perm.ClassDesc == "SERVER_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
					}

					// ImpersonateLogin edge (specific for login impersonation)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.ImpersonateLogin,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    bloodhound.NodeKinds.Login,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// Also create ExecuteAs edge (PowerShell creates both)
					edge = c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.ExecuteAs,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    bloodhound.NodeKinds.Login,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}

			case "IMPERSONATE ANY LOGIN":
				edge := c.createEdge(
					principal.ObjectIdentifier,
					serverInfo.ObjectIdentifier,
					bloodhound.EdgeKinds.ImpersonateAnyLogin,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getServerPrincipalType(principal.TypeDescription),
						TargetName:    serverInfo.ServerName,
						TargetType:    bloodhound.NodeKinds.Server,
						SQLServerName: serverInfo.SQLServerName,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

			case "ALTER ANY LOGIN":
				edge := c.createEdge(
					principal.ObjectIdentifier,
					serverInfo.ObjectIdentifier,
					bloodhound.EdgeKinds.AlterAnyLogin,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getServerPrincipalType(principal.TypeDescription),
						TargetName:    serverInfo.ServerName,
						TargetType:    bloodhound.NodeKinds.Server,
						SQLServerName: serverInfo.SQLServerName,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// ALTER ANY LOGIN also creates ChangePassword edges to SQL logins
				// PowerShell logic: target must be SQL_LOGIN, not sa, not sysadmin/CONTROL SERVER
				for _, targetPrincipal := range serverInfo.ServerPrincipals {
					if targetPrincipal.TypeDescription != "SQL_LOGIN" {
						continue
					}
					if targetPrincipal.Name == "sa" {
						continue
					}
					if targetPrincipal.ObjectIdentifier == principal.ObjectIdentifier {
						continue
					}

					// Check if target has sysadmin or CONTROL SERVER
					// For simplicity, just check direct sysadmin membership
					targetHasSysadmin := false
					for _, m := range targetPrincipal.MemberOf {
						if m.Name == "sysadmin" {
							targetHasSysadmin = true
							break
						}
					}
					// Check for CONTROL SERVER permission
					targetHasControlServer := false
					for _, p := range targetPrincipal.Permissions {
						if p.Permission == "CONTROL SERVER" && (p.State == "GRANT" || p.State == "GRANT_WITH_GRANT_OPTION") {
							targetHasControlServer = true
							break
						}
					}

					if targetHasSysadmin || targetHasControlServer {
						continue
					}

					// Create ChangePassword edge
					edge := c.createEdge(
						principal.ObjectIdentifier,
						targetPrincipal.ObjectIdentifier,
						bloodhound.EdgeKinds.ChangePassword,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getServerPrincipalType(principal.TypeDescription),
							TargetName:    targetPrincipal.Name,
							TargetType:    bloodhound.NodeKinds.Login,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}

			case "ALTER ANY SERVER ROLE":
				edge := c.createEdge(
					principal.ObjectIdentifier,
					serverInfo.ObjectIdentifier,
					bloodhound.EdgeKinds.AlterAnyServerRole,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getServerPrincipalType(principal.TypeDescription),
						TargetName:    serverInfo.ServerName,
						TargetType:    bloodhound.NodeKinds.Server,
						SQLServerName: serverInfo.SQLServerName,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// createDatabasePermissionEdges creates edges based on database-level permissions
func (c *Collector) createDatabasePermissionEdges(writer *bloodhound.StreamingWriter, db *types.Database, serverInfo *types.ServerInfo) error {
	principalMap := make(map[int]*types.DatabasePrincipal)
	for i := range db.DatabasePrincipals {
		principalMap[db.DatabasePrincipals[i].PrincipalID] = &db.DatabasePrincipals[i]
	}

	for _, principal := range db.DatabasePrincipals {
		for _, perm := range principal.Permissions {
			if perm.State != "GRANT" && perm.State != "GRANT_WITH_GRANT_OPTION" {
				continue
			}

			switch perm.Permission {
			case "CONTROL":
				if perm.ClassDesc == "DATABASE" {
					// Create MSSQL_Control (non-traversable) edge
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.Control,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    db.Name,
							TargetType:    bloodhound.NodeKinds.Database,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// Create MSSQL_ControlDB (traversable) edge
					edge = c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.ControlDB,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    db.Name,
							TargetType:    bloodhound.NodeKinds.Database,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				} else if perm.ClassDesc == "DATABASE_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					// CONTROL on a database principal (user/role)
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.DatabaseUser
					isRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetType = c.getDatabasePrincipalType(targetPrincipal.TypeDescription)
						isRole = targetPrincipal.TypeDescription == "DATABASE_ROLE"
					}

					// Use specific edge type based on target
					edgeKind := bloodhound.EdgeKinds.ControlDBUser
					if isRole {
						edgeKind = bloodhound.EdgeKinds.ControlDBRole
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						edgeKind,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    targetType,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
				break

			case "CONNECT":
				if perm.ClassDesc == "DATABASE" {
					// Create MSSQL_Connect edge from user/role to database
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.Connect,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    db.Name,
							TargetType:    bloodhound.NodeKinds.Database,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
				break
			case "ALTER":
				if perm.ClassDesc == "DATABASE" {
					// ALTER on the database itself
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.AlterDB,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    db.Name,
							TargetType:    bloodhound.NodeKinds.Database,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				} else if perm.ClassDesc == "DATABASE_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					// ALTER on a database principal
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.DatabaseUser
					isRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetType = c.getDatabasePrincipalType(targetPrincipal.TypeDescription)
						isRole = targetPrincipal.TypeDescription == "DATABASE_ROLE"
					}

					// Use specific edge type for roles
					edgeKind := bloodhound.EdgeKinds.Alter
					if isRole {
						edgeKind = bloodhound.EdgeKinds.AlterDBRole
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						edgeKind,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    targetType,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
				break
			case "ALTER ANY ROLE":
				edge := c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.AlterAnyDBRole,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
						TargetName:    db.Name,
						TargetType:    bloodhound.NodeKinds.Database,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}
				break
			case "ALTER ANY APPLICATION ROLE":
				edge := c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.AlterAnyAppRole,
					&bloodhound.EdgeContext{
						SourceName:    principal.Name,
						SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
						TargetName:    db.Name,
						TargetType:    bloodhound.NodeKinds.Database,
						SQLServerName: serverInfo.SQLServerName,
						DatabaseName:  db.Name,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}
				break

			case "IMPERSONATE":
				// IMPERSONATE on a database user
				if perm.ClassDesc == "DATABASE_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.ImpersonateDBUser,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    targetName,
							TargetType:    bloodhound.NodeKinds.DatabaseUser,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
				break

			case "TAKE OWNERSHIP":
				// TAKE OWNERSHIP on the database
				if perm.ClassDesc == "DATABASE" {
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.DBTakeOwnership,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:    db.Name,
							TargetType:    bloodhound.NodeKinds.Database,
							SQLServerName: serverInfo.SQLServerName,
							DatabaseName:  db.Name,
							Permission:    perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
				break
			}
		}
	}

	return nil
}

// createEdge creates a BloodHound edge with properties
func (c *Collector) createEdge(sourceID, targetID, kind string, ctx *bloodhound.EdgeContext) *bloodhound.Edge {
	props := bloodhound.GetEdgeProperties(kind, ctx)

	// Handle traversability based on config
	if !c.config.IncludeNontraversableEdges && !bloodhound.IsTraversableEdge(kind) {
		props["traversable"] = false
	}
	if c.config.MakeInterestingEdgesTraversable {
		// Make certain edges traversable for offensive use
		switch kind {
		case bloodhound.EdgeKinds.LinkedTo,
			bloodhound.EdgeKinds.IsTrustedBy,
			bloodhound.EdgeKinds.ServiceAccountFor,
			bloodhound.EdgeKinds.HasDBScopedCred,
			bloodhound.EdgeKinds.HasMappedCred,
			bloodhound.EdgeKinds.HasProxyCred:
			props["traversable"] = true
		}
	}

	return &bloodhound.Edge{
		Start:      bloodhound.EdgeEndpoint{Value: sourceID},
		End:        bloodhound.EdgeEndpoint{Value: targetID},
		Kind:       kind,
		Properties: props,
	}
}

// getServerPrincipalType returns the BloodHound node type for a server principal
func (c *Collector) getServerPrincipalType(typeDesc string) string {
	switch typeDesc {
	case "SERVER_ROLE":
		return bloodhound.NodeKinds.ServerRole
	default:
		return bloodhound.NodeKinds.Login
	}
}

// getDatabasePrincipalType returns the BloodHound node type for a database principal
func (c *Collector) getDatabasePrincipalType(typeDesc string) string {
	switch typeDesc {
	case "DATABASE_ROLE":
		return bloodhound.NodeKinds.DatabaseRole
	case "APPLICATION_ROLE":
		return bloodhound.NodeKinds.ApplicationRole
	default:
		return bloodhound.NodeKinds.DatabaseUser
	}
}

// createZipFile creates the final zip file from all output files
func (c *Collector) createZipFile() (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	zipDir := c.config.ZipDir
	if zipDir == "" {
		zipDir = "."
	}

	zipPath := filepath.Join(zipDir, fmt.Sprintf("mssql-bloodhound-%s.zip", timestamp))

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, filePath := range c.outputFiles {
		if err := addFileToZip(zipWriter, filePath); err != nil {
			return "", fmt.Errorf("failed to add %s to zip: %w", filePath, err)
		}
	}

	return zipPath, nil
}

// addFileToZip adds a file to a zip archive
func addFileToZip(zipWriter *zip.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

// sanitizeFilename makes a string safe for use as a filename
func sanitizeFilename(s string) string {
	// Replace problematic characters
	replacer := strings.NewReplacer(
		"\\", "-",
		"/", "-",
		":", "-",
		"*", "-",
		"?", "-",
		"\"", "-",
		"<", "-",
		">", "-",
		"|", "-",
	)
	return replacer.Replace(s)
}
