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

	mssqldb "github.com/microsoft/go-mssqldb"

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
	verbose        bool
	encrypt        bool              // Whether to use encryption
	usePowerShell  bool              // Whether using PowerShell fallback
	psClient       *PowerShellClient // PowerShell client for fallback
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
// It tries multiple connection strategies to maximize compatibility.
// If go-mssqldb fails with the "untrusted domain" error, it will automatically
// fall back to using PowerShell with System.Data.SqlClient which handles
// some SSPI edge cases that go-mssqldb cannot.
func (c *Client) Connect(ctx context.Context) error {
	// First try native go-mssqldb connection
	err := c.connectNative(ctx)
	if err == nil {
		return nil
	}

	// Check if this is the "untrusted domain" error that PowerShell can handle
	if IsUntrustedDomainError(err) && c.useWindowsAuth {
		c.logVerbose("Native connection failed with untrusted domain error, trying PowerShell fallback...")
		// Try PowerShell fallback
		psErr := c.connectPowerShell(ctx)
		if psErr == nil {
			c.logVerbose("PowerShell fallback succeeded")
			return nil
		}
		// Both methods failed - return combined error for clarity
		c.logVerbose("PowerShell fallback also failed: %v", psErr)
		return fmt.Errorf("all connection methods failed (native: %v, PowerShell: %v)", err, psErr)
	}

	return err
}

// connectNative tries to connect using go-mssqldb
func (c *Client) connectNative(ctx context.Context) error {
	// Connection strategies to try in order
	// NOTE: Some servers with specific SSPI configurations may fail to connect from Go
	// even though PowerShell/System.Data.SqlClient works. This is a known limitation
	// of the go-mssqldb driver's Windows SSPI implementation.

	// Get short hostname for some strategies
	shortHostname := c.hostname
	if idx := strings.Index(c.hostname, "."); idx != -1 {
		shortHostname = c.hostname[:idx]
	}

	type connStrategy struct {
		name         string
		serverName   string // The server name to use in connection string
		encrypt      string // "false", "true", or "strict"
		useServerSPN bool
		spnHost      string // Host to use in SPN
	}

	strategies := []connStrategy{
		// Try FQDN with encryption (most common)
		{"FQDN+encrypt", c.hostname, "true", false, ""},
		// Try with explicit SPN
		{"FQDN+encrypt+SPN", c.hostname, "true", true, c.hostname},
		// Try without encryption
		{"FQDN+no-encrypt", c.hostname, "false", false, ""},
		// Try short hostname
		{"short+encrypt", shortHostname, "true", false, ""},
		{"short+no-encrypt", shortHostname, "false", false, ""},
	}

	var lastErr error
	for _, strategy := range strategies {
		connStr := c.buildConnectionStringForStrategy(strategy.serverName, strategy.encrypt, strategy.useServerSPN, strategy.spnHost)
		c.logVerbose("Trying connection strategy '%s': %s", strategy.name, connStr)

		db, err := sql.Open("sqlserver", connStr)
		if err != nil {
			lastErr = err
			c.logVerbose("  Strategy '%s' failed to open: %v", strategy.name, err)
			continue
		}

		// Test the connection with a short timeout
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = db.PingContext(pingCtx)
		cancel()

		if err != nil {
			db.Close()
			lastErr = err
			c.logVerbose("  Strategy '%s' failed to connect: %v", strategy.name, err)
			continue
		}

		c.logVerbose("  Strategy '%s' succeeded!", strategy.name)
		c.db = db
		return nil
	}

	return fmt.Errorf("all connection strategies failed, last error: %w", lastErr)
}

// connectPowerShell connects using PowerShell and System.Data.SqlClient
func (c *Client) connectPowerShell(ctx context.Context) error {
	c.psClient = NewPowerShellClient(c.serverInstance, c.userID, c.password)
	c.psClient.SetVerbose(c.verbose)

	err := c.psClient.TestConnection(ctx)
	if err != nil {
		c.psClient = nil
		return err
	}

	c.usePowerShell = true
	return nil
}

// UsingPowerShell returns true if the client is using the PowerShell fallback
func (c *Client) UsingPowerShell() bool {
	return c.usePowerShell
}

// executeQuery is a unified query interface that works with both native and PowerShell modes
// It returns the results as []QueryResult, which can be processed uniformly
func (c *Client) executeQuery(ctx context.Context, query string) ([]QueryResult, error) {
	if c.usePowerShell {
		response, err := c.psClient.ExecuteQuery(ctx, query)
		if err != nil {
			return nil, err
		}
		return response.Rows, nil
	}

	// Native mode - use c.db
	rows, err := c.DBW().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []QueryResult
	for rows.Next() {
		// Create slice of interface{} to hold row values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		// Convert to QueryResult
		row := make(QueryResult)
		for i, col := range columns {
			val := values[i]
			// Convert []byte to string for easier handling
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	return results, rows.Err()
}

// executeQueryRow executes a query and returns a single row
func (c *Client) executeQueryRow(ctx context.Context, query string) (QueryResult, error) {
	results, err := c.executeQuery(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, sql.ErrNoRows
	}
	return results[0], nil
}

// DB returns the underlying database connection (nil in PowerShell mode)
// This is used for methods that need direct database access
func (c *Client) DB() *sql.DB {
	return c.db
}

// DBW returns a database wrapper that works with both native and PowerShell modes
// Use this for query methods to ensure compatibility with PowerShell fallback
func (c *Client) DBW() *DBWrapper {
	return NewDBWrapper(c.db, c.psClient, c.usePowerShell)
}

// buildConnectionStringForStrategy creates the connection string for a specific strategy
func (c *Client) buildConnectionStringForStrategy(serverName, encrypt string, useServerSPN bool, spnHost string) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("server=%s", serverName))

	if c.port > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", c.port))
	}

	if c.instanceName != "" {
		parts = append(parts, fmt.Sprintf("instance=%s", c.instanceName))
	}

	if c.useWindowsAuth {
		// Use Windows integrated auth
		parts = append(parts, "trusted_connection=yes")

		// Optionally set ServerSPN using the provided spnHost (could be FQDN or short name)
		if useServerSPN && spnHost != "" {
			if c.instanceName != "" && c.instanceName != "MSSQLSERVER" {
				parts = append(parts, fmt.Sprintf("ServerSPN=MSSQLSvc/%s:%s", spnHost, c.instanceName))
			} else if c.port > 0 {
				parts = append(parts, fmt.Sprintf("ServerSPN=MSSQLSvc/%s:%d", spnHost, c.port))
			}
		}
	} else {
		parts = append(parts, fmt.Sprintf("user id=%s", c.userID))
		parts = append(parts, fmt.Sprintf("password=%s", c.password))
	}

	// Handle encryption setting - supports "false", "true", "strict", "disable"
	parts = append(parts, fmt.Sprintf("encrypt=%s", encrypt))
	parts = append(parts, "TrustServerCertificate=true")
	parts = append(parts, "app name=MSSQLHound")

	return strings.Join(parts, ";")
}

// buildConnectionString creates the connection string for go-mssqldb (uses default options)
func (c *Client) buildConnectionString() string {
	encrypt := "true"
	if !c.encrypt {
		encrypt = "false"
	}
	return c.buildConnectionStringForStrategy(c.hostname, encrypt, true, c.hostname)
}

// SetVerbose enables or disables verbose logging
func (c *Client) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// logVerbose logs a message only if verbose mode is enabled
func (c *Client) logVerbose(format string, args ...interface{}) {
	if c.verbose {
		fmt.Printf(format+"\n", args...)
	}
}

// EPATestResult holds the results of EPA connection testing
type EPATestResult struct {
	UnmodifiedSuccess bool
	NoSBSuccess       bool
	NoCBTSuccess      bool
	ForceEncryption   bool
	EncryptionFlag    byte
	EPAStatus         string
}

// TestEPA performs Extended Protection for Authentication testing
// This tests three connection scenarios to determine the actual EPA configuration:
// 1. Unmodified connection - normal connection attempt
// 2. No SB (Service Binding) connection - without service binding token
// 3. No CBT (Channel Binding Token) connection - without channel binding token
func (c *Client) TestEPA(ctx context.Context) (*EPATestResult, error) {
	result := &EPATestResult{}

	// First, do PRELOGIN to check encryption settings
	preloginResult, err := c.sendPrelogin(ctx)
	if err != nil {
		return nil, fmt.Errorf("PRELOGIN failed: %w", err)
	}

	result.EncryptionFlag = preloginResult.encryptionFlag
	result.ForceEncryption = preloginResult.forceEncryption

	c.logVerbose("Connected via TCP")
	c.logVerbose("Sent PRELOGIN packet")
	c.logVerbose("Received PRELOGIN response")
	c.logVerbose("Encryption flag in response: 0x%02X (%s)", preloginResult.encryptionFlag, preloginResult.encryptionDesc)
	c.logVerbose("Force Encryption: %s", boolToYesNo(preloginResult.forceEncryption))

	c.logVerbose("Testing EPA settings for %s", c.serverInstance)

	// Test 1: Unmodified connection (normal)
	unmodifiedSuccess := c.testConnectionWithEPA(ctx, false, false)
	result.UnmodifiedSuccess = unmodifiedSuccess
	c.logVerbose("  Unmodified connection: %s", boolToSuccessFail(unmodifiedSuccess))

	// Test 2: No Service Binding connection
	noSBSuccess := c.testConnectionWithEPA(ctx, true, false)
	result.NoSBSuccess = noSBSuccess
	c.logVerbose("  No SB connection: %s", boolToSuccessFail(noSBSuccess))

	// Test 3: No Channel Binding Token connection
	noCBTSuccess := c.testConnectionWithEPA(ctx, false, true)
	result.NoCBTSuccess = noCBTSuccess
	c.logVerbose("  No CBT connection: %s", boolToSuccessFail(noCBTSuccess))

	// Determine EPA status based on test results
	result.EPAStatus = c.determineEPAStatus(result)
	c.logVerbose("  Extended Protection: %s", result.EPAStatus)

	return result, nil
}

// preloginResult holds the result of a PRELOGIN exchange
type preloginResult struct {
	encryptionFlag  byte
	encryptionDesc  string
	forceEncryption bool
}

// sendPrelogin sends a TDS PRELOGIN packet and parses the response
func (c *Client) sendPrelogin(ctx context.Context) (*preloginResult, error) {
	// Resolve the actual port if using named instance
	port := c.port
	if port == 0 && c.instanceName != "" {
		// Try to resolve via SQL Browser
		resolvedPort, err := c.resolveInstancePort(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve instance port: %w", err)
		}
		port = resolvedPort
	}
	if port == 0 {
		port = 1433 // Default SQL Server port
	}

	// Connect via TCP
	addr := fmt.Sprintf("%s:%d", c.hostname, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Build PRELOGIN packet
	preloginPacket := buildPreloginPacket()

	// Wrap in TDS packet header
	tdsPacket := buildTDSPacket(0x12, preloginPacket) // 0x12 = PRELOGIN

	// Send PRELOGIN
	if _, err := conn.Write(tdsPacket); err != nil {
		return nil, fmt.Errorf("failed to send PRELOGIN: %w", err)
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read PRELOGIN response: %w", err)
	}

	// Parse response
	return parsePreloginResponse(response[:n])
}

// buildPreloginPacket creates a TDS PRELOGIN packet payload
func buildPreloginPacket() []byte {
	// PRELOGIN options (simplified):
	// VERSION: 0x00
	// ENCRYPTION: 0x01
	// INSTOPT: 0x02
	// THREADID: 0x03
	// MARS: 0x04
	// TERMINATOR: 0xFF

	// We'll send VERSION and ENCRYPTION options
	var packet []byte

	// Calculate offsets (header is 5 bytes per option + 1 terminator)
	// VERSION option header (5 bytes) + ENCRYPTION option header (5 bytes) + TERMINATOR (1 byte) = 11 bytes
	dataOffset := 11

	// VERSION option header: token=0x00, offset, length=6
	packet = append(packet, 0x00)                                  // TOKEN_VERSION
	packet = append(packet, byte(dataOffset>>8), byte(dataOffset)) // Offset (big-endian)
	packet = append(packet, 0x00, 0x06)                            // Length = 6

	// ENCRYPTION option header: token=0x01, offset, length=1
	packet = append(packet, 0x01)                                        // TOKEN_ENCRYPTION
	packet = append(packet, byte((dataOffset+6)>>8), byte(dataOffset+6)) // Offset
	packet = append(packet, 0x00, 0x01)                                  // Length = 1

	// TERMINATOR
	packet = append(packet, 0xFF)

	// VERSION data (6 bytes): major, minor, build (2 bytes), sub-build (2 bytes)
	// Use SQL Server 2019 version format
	packet = append(packet, 0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00) // 15.0.2000.0

	// ENCRYPTION data (1 byte): 0x00 = ENCRYPT_OFF, 0x01 = ENCRYPT_ON, 0x02 = ENCRYPT_NOT_SUP, 0x03 = ENCRYPT_REQ
	packet = append(packet, 0x00) // We don't require encryption for this test

	return packet
}

// buildTDSPacket wraps payload in a TDS packet header
func buildTDSPacket(packetType byte, payload []byte) []byte {
	packetLen := len(payload) + 8 // 8-byte TDS header

	header := []byte{
		packetType,           // Type
		0x01,                 // Status (EOM)
		byte(packetLen >> 8), // Length (big-endian)
		byte(packetLen),
		0x00, 0x00, // SPID
		0x00, // PacketID
		0x00, // Window
	}

	return append(header, payload...)
}

// parsePreloginResponse parses a TDS PRELOGIN response
func parsePreloginResponse(data []byte) (*preloginResult, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Skip TDS header (8 bytes)
	payload := data[8:]

	result := &preloginResult{}

	// Parse PRELOGIN options
	offset := 0
	for offset < len(payload) {
		if payload[offset] == 0xFF {
			break // Terminator
		}

		if offset+5 > len(payload) {
			break
		}

		token := payload[offset]
		dataOffset := int(payload[offset+1])<<8 | int(payload[offset+2])
		dataLen := int(payload[offset+3])<<8 | int(payload[offset+4])

		// Adjust dataOffset relative to payload start
		dataOffset -= 8 // Account for TDS header that we stripped

		if token == 0x01 && dataLen >= 1 && dataOffset >= 0 && dataOffset < len(payload) {
			// ENCRYPTION option
			result.encryptionFlag = payload[dataOffset]
			switch result.encryptionFlag {
			case 0x00:
				result.encryptionDesc = "ENCRYPT_OFF"
				result.forceEncryption = false
			case 0x01:
				result.encryptionDesc = "ENCRYPT_ON"
				result.forceEncryption = false
			case 0x02:
				result.encryptionDesc = "ENCRYPT_NOT_SUP"
				result.forceEncryption = false
			case 0x03:
				result.encryptionDesc = "ENCRYPT_REQ"
				result.forceEncryption = true
			default:
				result.encryptionDesc = fmt.Sprintf("UNKNOWN (0x%02X)", result.encryptionFlag)
			}
		}

		offset += 5
	}

	return result, nil
}

// resolveInstancePort resolves the port for a named SQL Server instance using SQL Browser
func (c *Client) resolveInstancePort(ctx context.Context) (int, error) {
	addr := fmt.Sprintf("%s:1434", c.hostname) // SQL Browser UDP port

	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send instance query: 0x04 + instance name
	query := append([]byte{0x04}, []byte(c.instanceName)...)
	if _, err := conn.Write(query); err != nil {
		return 0, err
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}

	// Parse response - format: 0x05 + length (2 bytes) + data
	// Data contains key=value pairs separated by semicolons
	response := string(buf[3:n])
	parts := strings.Split(response, ";")
	for i, part := range parts {
		if strings.ToLower(part) == "tcp" && i+1 < len(parts) {
			port, err := strconv.Atoi(parts[i+1])
			if err == nil {
				return port, nil
			}
		}
	}

	return 0, fmt.Errorf("port not found in SQL Browser response")
}

// testConnectionWithEPA tests a connection with specific EPA settings
func (c *Client) testConnectionWithEPA(ctx context.Context, disableSB bool, disableCBT bool) bool {
	// Build connection string with specific EPA settings
	var parts []string

	parts = append(parts, fmt.Sprintf("server=%s", c.hostname))

	if c.port > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", c.port))
	}

	if c.instanceName != "" {
		parts = append(parts, fmt.Sprintf("instance=%s", c.instanceName))
	}

	if c.useWindowsAuth {
		parts = append(parts, "trusted_connection=yes")
	} else {
		parts = append(parts, fmt.Sprintf("user id=%s", c.userID))
		parts = append(parts, fmt.Sprintf("password=%s", c.password))
	}

	parts = append(parts, "TrustServerCertificate=true")
	parts = append(parts, "app name=MSSQLHound-EPATest")

	// EPA-specific settings via connection string parameters
	if disableSB {
		// Disable Service Binding by setting an invalid/empty SPN
		// This simulates a connection without proper service binding
		parts = append(parts, "ServerSPN=invalid")
	}

	if disableCBT {
		// To test without Channel Binding, we need to use a connection without encryption
		// When encrypt=disable, no TLS is used, so no CBT is sent
		parts = append(parts, "encrypt=disable")
	} else {
		// Normal encryption setting
		parts = append(parts, "encrypt=false")
	}

	connStr := strings.Join(parts, ";")

	connector, err := mssqldb.NewConnector(connStr)
	if err != nil {
		return false
	}

	// Try to connect using the connector
	db := sql.OpenDB(connector)
	defer db.Close()

	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err = db.PingContext(testCtx)
	return err == nil
}

// determineEPAStatus determines the EPA status based on test results
func (c *Client) determineEPAStatus(result *EPATestResult) string {
	// If all three tests succeed, EPA is Off
	if result.UnmodifiedSuccess && result.NoSBSuccess && result.NoCBTSuccess {
		return "Off"
	}

	// If unmodified works but No SB fails, EPA is using Service Binding
	// This typically happens when Force Encryption is No
	if result.UnmodifiedSuccess && !result.NoSBSuccess && result.NoCBTSuccess {
		return "Allowed" // or Required, using Service Binding
	}

	// If unmodified works but No CBT fails, EPA is using Channel Binding
	// This typically happens when Force Encryption is Yes
	if result.UnmodifiedSuccess && result.NoSBSuccess && !result.NoCBTSuccess {
		return "Allowed" // or Required, using Channel Binding
	}

	// If unmodified works but both No SB and No CBT fail
	if result.UnmodifiedSuccess && !result.NoSBSuccess && !result.NoCBTSuccess {
		return "Required"
	}

	// If unmodified connection fails, something else is wrong
	if !result.UnmodifiedSuccess {
		return "Unknown (connection failed)"
	}

	return "Unknown"
}

// boolToYesNo converts a boolean to "Yes" or "No"
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// boolToSuccessFail converts a boolean to "success" or "failure"
func boolToSuccessFail(b bool) string {
	if b {
		return "success"
	}
	return "failure"
}

// Close closes the database connection
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	// PowerShell client doesn't need explicit cleanup
	c.psClient = nil
	c.usePowerShell = false
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
	c.logVerbose("Collecting service account information from %s", c.serverInstance)
	if err := c.collectServiceAccounts(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect service accounts: %v\n", err)
	}

	// Get server-level credentials
	c.logVerbose("Enumerating credentials...")
	if err := c.collectCredentials(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect credentials: %v\n", err)
	}

	// Get proxy accounts
	c.logVerbose("Enumerating SQL Agent proxy accounts...")
	if err := c.collectProxyAccounts(ctx, info); err != nil {
		fmt.Printf("Warning: failed to collect proxy accounts: %v\n", err)
	}

	// Get server principals
	c.logVerbose("Enumerating server principals...")
	principals, err := c.collectServerPrincipals(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("failed to collect server principals: %w", err)
	}
	info.ServerPrincipals = principals
	c.logVerbose("Checking for inherited high-privilege permissions through role memberships")

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
	c.logVerbose("Enumerating linked servers...")
	linkedServers, err := c.collectLinkedServers(ctx)
	if err != nil {
		// Non-fatal - just log and continue
		fmt.Printf("Warning: failed to collect linked servers: %v\n", err)
	}
	info.LinkedServers = linkedServers

	// Print discovered linked servers with detailed information
	if len(linkedServers) > 0 {
		fmt.Printf("Discovered %d linked server(s):\n", len(linkedServers))
		for _, ls := range linkedServers {
			fmt.Printf("    %s -> %s\n", info.Hostname, ls.Name)
			c.logVerbose("        Name: %s", ls.Name)
			c.logVerbose("        DataSource: %s", ls.DataSource)
			c.logVerbose("        Provider: %s", ls.Provider)
			c.logVerbose("        Product: %s", ls.Product)
			c.logVerbose("        IsRemoteLoginEnabled: %v", ls.IsRemoteLoginEnabled)
			c.logVerbose("        IsRPCOutEnabled: %v", ls.IsRPCOutEnabled)
			c.logVerbose("        IsDataAccessEnabled: %v", ls.IsDataAccessEnabled)
			c.logVerbose("        IsSelfMapping: %v", ls.IsSelfMapping)
			if ls.LocalLogin != "" {
				c.logVerbose("        LocalLogin: %s", ls.LocalLogin)
			}
			if ls.RemoteLogin != "" {
				c.logVerbose("        RemoteLogin: %s", ls.RemoteLogin)
			}
			if ls.Catalog != "" {
				c.logVerbose("        Catalog: %s", ls.Catalog)
			}
		}
	} else {
		c.logVerbose("No linked servers found")
	}

	c.logVerbose("Processing enabled domain principals with CONNECT SQL permission")
	c.logVerbose("Creating server principal nodes")
	c.logVerbose("Creating database principal nodes")
	c.logVerbose("Creating linked server nodes")
	c.logVerbose("Creating domain principal nodes")

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

	row := c.DBW().QueryRowContext(ctx, query)

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
	// Method 1: Try to get the computer SID by querying for logins that match the computer account
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
	err := c.DBW().QueryRowContext(ctx, query).Scan(&computerSID)
	if err == nil && computerSID.Valid && computerSID.String != "" {
		// Convert hex SID to string format
		sidStr := convertHexSIDToString(computerSID.String)
		if sidStr != "" {
			info.ComputerSID = sidStr
			c.logVerbose("Found computer SID from computer account login: %s", sidStr)
			return nil
		}
	}

	// Method 2: Try to find any computer account login (ends with $)
	query = `
		SELECT TOP 1
			CONVERT(VARCHAR(85), sid, 1) AS sid,
			name
		FROM sys.server_principals
		WHERE type_desc = 'WINDOWS_LOGIN'
		AND name LIKE '%$'
		AND sid IS NOT NULL
		AND LEN(CONVERT(VARCHAR(85), sid, 1)) > 10
		ORDER BY principal_id
	`

	var sid, name sql.NullString
	err = c.DBW().QueryRowContext(ctx, query).Scan(&sid, &name)
	if err == nil && sid.Valid && sid.String != "" {
		sidStr := convertHexSIDToString(sid.String)
		if sidStr != "" && strings.HasPrefix(sidStr, "S-1-5-21-") {
			// This is a domain computer account - extract domain SID and try to construct our computer SID
			sidParts := strings.Split(sidStr, "-")
			if len(sidParts) >= 8 {
				// Domain SID is S-1-5-21-X-Y-Z (first 7 parts)
				info.DomainSID = strings.Join(sidParts[:7], "-")
				c.logVerbose("Found domain SID from computer account: %s", info.DomainSID)
			}
		}
	}

	// Method 3: Extract domain SID from any Windows login/group and use LDAP later for computer SID
	if info.DomainSID == "" {
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

		rows, err := c.DBW().QueryContext(ctx, query)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var sid, name sql.NullString
				if err := rows.Scan(&sid, &name); err != nil {
					continue
				}

				if sid.Valid && sid.String != "" {
					sidStr := convertHexSIDToString(sid.String)
					if sidStr == "" || !strings.HasPrefix(sidStr, "S-1-5-21-") {
						continue
					}

					// If it's a computer account (ends with $), use its SID directly
					if strings.HasSuffix(name.String, "$") {
						info.ComputerSID = sidStr
						c.logVerbose("Found computer SID from alternate computer login: %s", sidStr)
						return nil
					}

					// Extract domain SID from this principal
					sidParts := strings.Split(sidStr, "-")
					if len(sidParts) >= 8 {
						info.DomainSID = strings.Join(sidParts[:7], "-")
						c.logVerbose("Found domain SID from Windows principal %s: %s", name.String, info.DomainSID)
						break
					}
				}
			}
		}
	}

	// If we have a domain SID, the collector will try to resolve the computer SID via LDAP
	// For now, return an error so the caller knows to try LDAP resolution
	if info.ComputerSID == "" {
		if info.DomainSID != "" {
			return fmt.Errorf("could not determine computer SID from SQL Server, will try LDAP (domain SID: %s)", info.DomainSID)
		}
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

	rows, err := c.DBW().QueryContext(ctx, query)
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
		// Match PowerShell logic: must be WINDOWS_LOGIN or WINDOWS_GROUP, and name must contain backslash
		// but NOT be NT SERVICE\*, NT AUTHORITY\*, BUILTIN\*, or MACHINENAME\*
		isWindowsType := p.TypeDescription == "WINDOWS_LOGIN" || p.TypeDescription == "WINDOWS_GROUP"
		hasBackslash := strings.Contains(p.Name, "\\")
		isNTService := strings.HasPrefix(strings.ToUpper(p.Name), "NT SERVICE\\")
		isNTAuthority := strings.HasPrefix(strings.ToUpper(p.Name), "NT AUTHORITY\\")
		isBuiltin := strings.HasPrefix(strings.ToUpper(p.Name), "BUILTIN\\")
		// Check if it's a local machine account (MACHINENAME\*)
		machinePrefix := strings.ToUpper(serverInfo.Hostname) + "\\"
		if strings.Contains(serverInfo.Hostname, ".") {
			// Extract just the machine name from FQDN
			machinePrefix = strings.ToUpper(strings.Split(serverInfo.Hostname, ".")[0]) + "\\"
		}
		isLocalMachine := strings.HasPrefix(strings.ToUpper(p.Name), machinePrefix)

		p.IsActiveDirectoryPrincipal = isWindowsType && hasBackslash &&
			!isNTService && !isNTAuthority && !isBuiltin && !isLocalMachine

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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	// Add predefined permissions for fixed server roles that aren't handled by createFixedRoleEdges
	// These are implicit permissions that aren't stored in sys.server_permissions
	// NOTE: sysadmin and securityadmin permissions are NOT added here because
	// createFixedRoleEdges already handles edge creation for those roles by name
	fixedServerRolePermissions := map[string][]string{
		// sysadmin - handled by createFixedRoleEdges, don't add CONTROL SERVER here
		// securityadmin - handled by createFixedRoleEdges, don't add ALTER ANY LOGIN here
		"##MS_LoginManager##":      {"ALTER ANY LOGIN"},
		"##MS_DatabaseConnector##": {"CONNECT ANY DATABASE"},
	}

	for i := range principals {
		if principals[i].IsFixedRole {
			if perms, ok := fixedServerRolePermissions[principals[i].Name]; ok {
				for _, permName := range perms {
					// Check if permission already exists (skip duplicates)
					exists := false
					for _, existingPerm := range principals[i].Permissions {
						if existingPerm.Permission == permName {
							exists = true
							break
						}
					}
					if !exists {
						perm := types.Permission{
							Permission: permName,
							State:      "GRANT",
							ClassDesc:  "SERVER",
						}
						principals[i].Permissions = append(principals[i].Permissions, perm)
					}
				}
			}
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

	rows, err := c.DBW().QueryContext(ctx, query)
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
	// Only keep databases where we successfully collected principals (matching PowerShell behavior)
	var successfulDatabases []types.Database
	for i := range databases {
		c.logVerbose("Processing database: %s", databases[i].Name)
		principals, err := c.collectDatabasePrincipals(ctx, &databases[i], serverInfo)
		if err != nil {
			fmt.Printf("Warning: failed to collect principals for database %s: %v\n", databases[i].Name, err)
			// PowerShell doesn't add databases where it can't access principals,
			// so we skip them here to match that behavior
			continue
		}
		databases[i].DatabasePrincipals = principals
		successfulDatabases = append(successfulDatabases, databases[i])
	}

	return successfulDatabases, nil
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	// Add predefined permissions for fixed database roles that aren't handled by createFixedRoleEdges
	// These are implicit permissions that aren't stored in sys.database_permissions
	// NOTE: db_owner and db_securityadmin permissions are NOT added here because
	// createFixedRoleEdges already handles edge creation for those roles by name
	fixedDatabaseRolePermissions := map[string][]string{
		// db_owner - handled by createFixedRoleEdges, don't add CONTROL here
		// db_securityadmin - handled by createFixedRoleEdges, don't add ALTER ANY APPLICATION ROLE/ROLE here
	}

	for i := range principals {
		if principals[i].IsFixedRole {
			if perms, ok := fixedDatabaseRolePermissions[principals[i].Name]; ok {
				for _, permName := range perms {
					// Check if permission already exists (skip duplicates)
					exists := false
					for _, existingPerm := range principals[i].Permissions {
						if existingPerm.Permission == permName {
							exists = true
							break
						}
					}
					if !exists {
						perm := types.Permission{
							Permission: permName,
							State:      "GRANT",
							ClassDesc:  "DATABASE",
						}
						principals[i].Permissions = append(principals[i].Permissions, perm)
					}
				}
			}
		}
	}

	return nil
}

// collectLinkedServers gets all linked server configurations with login mappings.
// Each login mapping creates a separate LinkedServer entry (matching PowerShell behavior).
func (c *Client) collectLinkedServers(ctx context.Context) ([]types.LinkedServer, error) {
	// Join servers with linked_logins to create one entry per login mapping
	// This matches the PowerShell behavior where each LocalLogin creates a separate edge
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
			s.is_data_access_enabled,
			COALESCE(sp.name, 'All Logins') AS local_login,
			ll.uses_self_credential,
			ll.remote_name
		FROM sys.servers s
		INNER JOIN sys.linked_logins ll ON s.server_id = ll.server_id
		LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
		WHERE s.is_linked = 1
		ORDER BY s.server_id, ll.local_principal_id
	`

	rows, err := c.DBW().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []types.LinkedServer

	for rows.Next() {
		var s types.LinkedServer
		var catalog, localLogin, remoteName sql.NullString
		var usesSelf bool

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
			&localLogin,
			&usesSelf,
			&remoteName,
		)
		if err != nil {
			return nil, err
		}

		s.Catalog = catalog.String
		s.LocalLogin = localLogin.String
		s.IsSelfMapping = usesSelf
		s.RemoteLogin = remoteName.String
		servers = append(servers, s)
	}

	return servers, nil
}

// collectServiceAccounts gets SQL Server service account information
func (c *Client) collectServiceAccounts(ctx context.Context, info *types.ServerInfo) error {
	// Try sys.dm_server_services first (SQL Server 2008 R2+)
	// Note: Exclude SQL Server Agent to match PowerShell behavior
	query := `
		SELECT
			servicename,
			service_account,
			startup_type_desc
		FROM sys.dm_server_services
		WHERE servicename LIKE 'SQL Server%' AND servicename NOT LIKE 'SQL Server Agent%'
	`

	rows, err := c.DBW().QueryContext(ctx, query)
	if err != nil {
		// DMV might not exist or user doesn't have permission
		// Fall back to registry read
		return c.collectServiceAccountFromRegistry(ctx, info)
	}
	defer rows.Close()

	foundService := false
	for rows.Next() {
		var serviceName, serviceAccount, startupType sql.NullString

		if err := rows.Scan(&serviceName, &serviceAccount, &startupType); err != nil {
			continue
		}

		if serviceAccount.Valid && serviceAccount.String != "" {
			if !foundService {
				c.logVerbose("Identified service account in sys.dm_server_services")
				foundService = true
			}

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
				c.logVerbose("SQL Server service account: %s", serviceAccount.String)
			}

			info.ServiceAccounts = append(info.ServiceAccounts, sa)
		}
	}

	// If no results, try registry fallback
	if len(info.ServiceAccounts) == 0 {
		return c.collectServiceAccountFromRegistry(ctx, info)
	}

	// Log if adding machine account
	for _, sa := range info.ServiceAccounts {
		if strings.HasSuffix(sa.Name, "$") {
			c.logVerbose("Adding service account: %s", sa.Name)
		}
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
	err := c.DBW().QueryRowContext(ctx, query).Scan(&serviceAccount)
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
		err = c.DBW().QueryRowContext(ctx, query).Scan(&serviceAccount)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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

	rows, err = c.DBW().QueryContext(ctx, subsystemQuery)
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

	rows, err = c.DBW().QueryContext(ctx, loginQuery)
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

	rows, err := c.DBW().QueryContext(ctx, query)
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
	if err := c.DBW().QueryRowContext(ctx, query).Scan(&isMixed); err == nil {
		info.IsMixedModeAuth = isMixed == 1
	}

	return nil
}

// collectEncryptionSettings gets the force encryption and EPA settings
// When verbose mode is enabled, it performs actual EPA connection testing
func (c *Client) collectEncryptionSettings(ctx context.Context, info *types.ServerInfo) error {
	// If verbose mode is enabled, perform actual EPA testing via connection tests
	if c.verbose {
		epaResult, err := c.TestEPA(ctx)
		if err != nil {
			c.logVerbose("Warning: EPA testing failed: %v, falling back to registry", err)
		} else {
			// Use results from EPA testing
			if epaResult.ForceEncryption {
				info.ForceEncryption = "Yes"
			} else {
				info.ForceEncryption = "No"
			}
			info.ExtendedProtection = epaResult.EPAStatus
			return nil
		}
	}

	// Fall back to registry-based detection (or primary method when not verbose)
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

	err := c.DBW().QueryRowContext(ctx, query).Scan(&forceEnc, &extProt)
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
