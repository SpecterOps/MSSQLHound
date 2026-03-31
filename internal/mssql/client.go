// Package mssql provides SQL Server connection and data collection functionality.
package mssql

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/SpecterOps/MSSQLHound/internal/types"
	mssqldb "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/integratedauth"
	_ "github.com/microsoft/go-mssqldb/integratedauth/krb5" // Register Kerberos auth provider
	"github.com/microsoft/go-mssqldb/msdsn"
)

// epaTLSDialer wraps a TCP connection in TLS before returning it to go-mssqldb.
// This allows us to capture TLSUnique (tls-unique channel binding) from the
// completed TLS handshake, which isn't available from go-mssqldb's VerifyConnection
// callback (called before Finished messages are exchanged).
//
// go-mssqldb uses encrypt=disable so it doesn't do additional TLS on top.
// All data transparently flows through our outer TLS layer, which is correct
// for TDS 8.0 strict encryption (TLS wraps the entire TDS session).
type epaTLSDialer struct {
	underlying interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	epaProvider *epaAuthProvider
	hostname    string
	dnsResolver string
	logger      *slog.Logger
}

func (d *epaTLSDialer) HostName() string { return d.hostname }

func (d *epaTLSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Establish TCP connection
	var conn net.Conn
	var err error
	if d.underlying != nil {
		conn, err = d.underlying.DialContext(ctx, network, addr)
	} else {
		conn, err = dialerWithResolver(d.dnsResolver, 10*time.Second).DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}

	// Perform TLS handshake with TDS 8.0 ALPN and TLS 1.2 cap
	tlsConfig := &tls.Config{
		ServerName:                  d.hostname,
		InsecureSkipVerify:          true, //nolint:gosec // security tool needs to connect to any server
		DynamicRecordSizingDisabled: true,
		MaxVersion:                  tls.VersionTLS12,
		NextProtos:                  []string{"tds/8.0"},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("EPA TLS handshake: %w", err)
	}

	// Capture TLSUnique after handshake is fully complete
	state := tlsConn.ConnectionState()
	if len(state.TLSUnique) > 0 {
		cbt := computeCBTHash("tls-unique:", state.TLSUnique)
		d.epaProvider.SetCBT(cbt)
		if d.logger != nil {
			d.logger.Debug("EPA TLS dialer complete", "tls_version", fmt.Sprintf("0x%04X", state.Version), "tls_unique", fmt.Sprintf("%x", state.TLSUnique), "cbt", fmt.Sprintf("%x", cbt))
		}
	} else if d.logger != nil {
		d.logger.Debug("EPA TLS dialer: TLSUnique empty after handshake", "tls_version", fmt.Sprintf("0x%04X", state.Version))
	}

	return tlsConn, nil
}

// epaTDSDialer performs the full TDS PRELOGIN + TLS-in-TDS handshake before
// returning the connection to go-mssqldb. This allows us to capture TLSUnique
// after the TLS handshake fully completes (including Finished messages), which
// is not available from go-mssqldb's VerifyConnection callback.
//
// go-mssqldb is configured with encrypt=disable so it won't attempt its own TLS.
// A preloginFakerConn wrapper intercepts go-mssqldb's PRELOGIN exchange (since
// we already performed it) and returns a fake response indicating no encryption,
// then transparently passes all subsequent traffic through the TLS connection.
type epaTDSDialer struct {
	underlying interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	epaProvider *epaAuthProvider
	hostname    string
	dnsResolver string
	logger      *slog.Logger
}

func (d *epaTDSDialer) HostName() string { return d.hostname }

func (d *epaTDSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// TCP connect
	var conn net.Conn
	var err error
	if d.underlying != nil {
		conn, err = d.underlying.DialContext(ctx, network, addr)
	} else {
		conn, err = dialerWithResolver(d.dnsResolver, 10*time.Second).DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	tds := newTDSConn(conn)

	// PRELOGIN exchange
	preloginPayload := buildPreloginPacket()
	if err := tds.sendPacket(tdsPacketPrelogin, preloginPayload); err != nil {
		conn.Close()
		return nil, fmt.Errorf("EPA TDS dialer: send PRELOGIN: %w", err)
	}

	_, preloginResp, err := tds.readFullPacket()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("EPA TDS dialer: read PRELOGIN response: %w", err)
	}

	encryptionFlag, err := parsePreloginEncryption(preloginResp)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("EPA TDS dialer: parse encryption: %w", err)
	}

	if encryptionFlag == encryptNotSup {
		conn.Close()
		return nil, fmt.Errorf("EPA TDS dialer: server does not support encryption, cannot do EPA")
	}

	// TLS-in-TDS handshake (TLS records wrapped inside TDS PRELOGIN packets)
	tlsConn, _, err := performTLSHandshake(tds, d.hostname)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("EPA TDS dialer: TLS handshake: %w", err)
	}

	// Clear deadline for go-mssqldb operations
	conn.SetDeadline(time.Time{})

	// Capture TLSUnique after handshake is fully complete (including Finished)
	state := tlsConn.ConnectionState()
	if len(state.TLSUnique) > 0 {
		cbt := computeCBTHash("tls-unique:", state.TLSUnique)
		d.epaProvider.SetCBT(cbt)
		if d.logger != nil {
			d.logger.Debug("EPA TDS dialer complete", "tls_version", fmt.Sprintf("0x%04X", state.Version), "tls_unique", fmt.Sprintf("%x", state.TLSUnique), "cbt", fmt.Sprintf("%x", cbt))
		}
	} else if d.logger != nil {
		d.logger.Debug("EPA TDS dialer: TLSUnique empty after TDS TLS handshake", "tls_version", fmt.Sprintf("0x%04X", state.Version))
	}

	// Return wrapper that intercepts go-mssqldb's PRELOGIN and fakes the response.
	// For ENCRYPT_OFF, the server drops TLS after LOGIN7 — preloginFakerConn
	// detects this and switches to raw TCP for subsequent I/O.
	return &preloginFakerConn{
		Conn:       tlsConn,
		rawConn:    conn,
		fakeResp:   buildFakePreloginResponse(),
		logger:     d.logger,
		encryptOff: encryptionFlag == encryptOff,
	}, nil
}

// preloginFakerConn wraps a TLS connection and intercepts go-mssqldb's PRELOGIN
// exchange. Since we already performed the real PRELOGIN + TLS handshake in the
// dialer, we discard go-mssqldb's PRELOGIN write and return a fake response
// with encryption=NOT_SUP so go-mssqldb skips its own TLS negotiation.
//
// For ENCRYPT_OFF (Force Encryption=No), the server drops TLS immediately after
// LOGIN7, so this wrapper detects LOGIN7 writes and switches subsequent I/O to
// raw TCP — matching the EPA tester's behavior in runEPATest.
type preloginFakerConn struct {
	net.Conn            // TLS connection (used during LOGIN7 phase)
	rawConn    net.Conn // raw TCP connection (used after LOGIN7 for ENCRYPT_OFF)
	state      int      // 0: intercept prelogin, 1: TLS pass-through, 2: raw TCP pass-through
	fakeResp   []byte   // fake PRELOGIN response TDS packet
	fakeOffset int      // bytes consumed from fakeResp
	logger     *slog.Logger
	encryptOff bool // true when server uses ENCRYPT_OFF (drops TLS after LOGIN7)
}

func (c *preloginFakerConn) Write(b []byte) (int, error) {
	if c.state == 0 {
		if len(b) >= tdsHeaderSize && b[0] == tdsPacketPrelogin {
			// Intercept PRELOGIN - don't forward to server
			if c.logger != nil {
				c.logger.Debug("EPA TDS intercepted go-mssqldb PRELOGIN", "bytes", len(b))
			}
			return len(b), nil
		}
		// Not a PRELOGIN packet - switch to TLS pass-through
		c.state = 1
	}
	if c.state == 2 {
		// Post-LOGIN7 for ENCRYPT_OFF: write directly on raw TCP
		return c.rawConn.Write(b)
	}
	// State 1: write through TLS (encrypts LOGIN7)
	n, err := c.Conn.Write(b)
	if err != nil {
		return n, err
	}
	// For ENCRYPT_OFF: after LOGIN7 with EOM is sent, the server drops TLS.
	// Switch to raw TCP for all subsequent I/O (SSPI challenge/response, queries).
	// This matches epa_tester.go line 217-221: "sw.c = conn" after LOGIN7.
	if c.encryptOff && len(b) >= tdsHeaderSize && b[0] == tdsPacketLogin7 && (b[1]&0x01 != 0) {
		c.state = 2
		if c.logger != nil {
			c.logger.Debug("EPA TDS LOGIN7 sent via TLS, switching to raw TCP (ENCRYPT_OFF)")
		}
	}
	return n, err
}

func (c *preloginFakerConn) Read(b []byte) (int, error) {
	if c.state == 0 && c.fakeOffset < len(c.fakeResp) {
		// Return fake PRELOGIN response
		n := copy(b, c.fakeResp[c.fakeOffset:])
		c.fakeOffset += n
		if c.fakeOffset >= len(c.fakeResp) {
			c.state = 1 // Done faking, switch to TLS pass-through
			if c.logger != nil {
				c.logger.Debug("EPA TDS delivered fake PRELOGIN response, switching to pass-through")
			}
		}
		return n, nil
	}
	if c.state == 2 {
		// Post-LOGIN7 for ENCRYPT_OFF: read directly from raw TCP
		return c.rawConn.Read(b)
	}
	return c.Conn.Read(b)
}

// buildFakePreloginResponse constructs a minimal TDS PRELOGIN response packet
// with encryption=NOT_SUP (0x02). This tells go-mssqldb that the server does
// not support encryption, so it skips TLS negotiation (we already did TLS).
func buildFakePreloginResponse() []byte {
	// PRELOGIN option tokens: token(1) + offset(2) + length(2)
	// Option 0x00 (Version): offset=11, length=6
	// Option 0x01 (Encryption): offset=17, length=1
	// Terminator: 0xFF
	// Data: Version(6 bytes) + Encryption(1 byte)
	payload := []byte{
		0x00, 0x00, 0x0B, 0x00, 0x06, // Version: offset=11, len=6
		0x01, 0x00, 0x11, 0x00, 0x01, // Encryption: offset=17, len=1
		0xFF,                               // Terminator
		0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00, // Version data (SQL Server 2019)
		0x02, // Encryption: NOT_SUP
	}

	// Wrap in TDS packet (type 0x04 = Tabular Result, which is the server response type)
	pktLen := tdsHeaderSize + len(payload)
	pkt := make([]byte, pktLen)
	pkt[0] = tdsPacketTabularResult
	pkt[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	copy(pkt[tdsHeaderSize:], payload)

	return pkt
}

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
	db                       *sql.DB
	serverInstance           string
	hostname                 string
	port                     int
	instanceName             string
	userID                   string
	password                 string
	ntHash                   []byte // Pre-computed NT hash (16 bytes) for pass-the-hash authentication
	useKerberos              bool   // Use Kerberos authentication
	krb5ConfigFile           string // Path to krb5.conf
	krb5CCacheFile           string // Path to credential cache file
	krb5KeytabFile           string // Path to keytab file
	krb5Realm                string // Kerberos realm
	domain                   string // Domain for NTLM authentication (needed for EPA testing)
	ldapUser                 string // LDAP user (DOMAIN\user or user@domain) for EPA testing
	ldapPassword             string // LDAP password for EPA testing
	useWindowsAuth           bool
	verbose                  bool
	debug                    bool
	encrypt                  bool              // Whether to use encryption
	usePowerShell            bool              // Whether using PowerShell fallback
	psClient                 *PowerShellClient // PowerShell client for fallback
	collectFromLinkedServers bool              // Whether to collect from linked servers
	epaResult                *EPATestResult    // Pre-computed EPA result (set before Connect)
	dnsResolver              string            // DNS resolver IP (e.g. domain controller)
	logger                   *slog.Logger
	proxyDialer              interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
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
		logger:         slog.New(logging.NewHandler(os.Stderr, nil)),
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

	// Check if this is the "untrusted domain" error that PowerShell can handle.
	// PowerShell fallback is not available when using a proxy since the spawned
	// process cannot route its connections through the Go-level SOCKS proxy.
	if IsUntrustedDomainError(err) && c.useWindowsAuth && c.proxyDialer == nil {
		c.logVerbose("Native connection failed with untrusted domain error, trying PowerShell fallback...")
		// Try PowerShell fallback
		psErr := c.connectPowerShell(ctx)
		if psErr == nil {
			c.logVerbose("PowerShell fallback succeeded")
			return nil
		}
		// Both methods failed - return combined error for clarity
		c.logVerbose("PowerShell fallback also failed", "error", psErr)
		return fmt.Errorf("all connection methods failed (native: %v, PowerShell: %v)", err, psErr)
	}

	return err
}

// CheckPort performs a quick TCP connectivity check against the SQL Server port.
// Call this before EPA testing or authentication to skip unreachable servers fast.
func (c *Client) CheckPort(ctx context.Context) error {
	port := c.port
	if port == 0 && c.instanceName != "" {
		resolvedPort, err := c.resolveInstancePort(ctx)
		if err != nil {
			return fmt.Errorf("port check: failed to resolve instance port: %w", err)
		}
		port = resolvedPort
		c.port = resolvedPort // cache for later EPA/Connect calls
	}
	if port == 0 {
		port = 1433
	}

	addr := fmt.Sprintf("%s:%d", c.hostname, port)

	dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
	defer dialCancel()

	var conn net.Conn
	var err error
	if c.proxyDialer != nil {
		dialAddr, resolveErr := resolveForProxy(dialCtx, c.hostname, port)
		if resolveErr != nil {
			dialAddr = addr
		}
		conn, err = c.proxyDialer.DialContext(dialCtx, "tcp", dialAddr)
	} else {
		dialer := dialerWithResolver(c.dnsResolver, 2*time.Second)
		conn, err = dialer.DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("port %d not reachable on %s: %w", port, c.hostname, err)
	}
	conn.Close()
	return nil
}

// connectNative tries to connect using go-mssqldb
func (c *Client) connectNative(ctx context.Context) error {
	// Auto-generate krb5.conf for Kerberos if needed
	if c.useKerberos && c.krb5ConfigFile == "" {
		// Check if default config exists (KRB5_CONFIG env or /etc/krb5.conf)
		configPath := os.Getenv("KRB5_CONFIG")
		if configPath == "" {
			configPath = "/etc/krb5.conf"
		}
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			if c.domain != "" && c.dnsResolver != "" {
				generated, genErr := GenerateKrb5Config(c.domain, c.dnsResolver)
				if genErr != nil {
					c.logVerbose("Failed to auto-generate krb5.conf", "error", genErr)
				} else {
					c.krb5ConfigFile = generated
					defer os.Remove(generated)
					c.logVerbose("Auto-generated krb5.conf", "path", generated, "domain", c.domain, "kdc", c.dnsResolver)
				}
			} else {
				c.logVerbose("No krb5.conf found and cannot auto-generate (need --domain and --dc-ip)")
			}
		}
	}

	// Connection strategy ordering for go-mssqldb:
	//
	// Multiple connection strings are attempted because SQL Server configurations
	// vary widely: encryption mode (off/on/strict), SPN format expectations, and
	// hostname-vs-IP behavior all differ across environments.
	//
	// Strategy priority depends on EPA pre-test results:
	//   - If EPA detected TDS 8.0 strict encryption: strict strategies first,
	//     then encrypt, then SPN override, then unencrypted fallback.
	//   - Otherwise (most common): encrypt first, then strict, then SPN
	//     override, then unencrypted.
	//
	// For FQDN targets: short hostname variants are appended because some servers
	// only accept the NetBIOS name (not the FQDN) in the Kerberos SPN, causing
	// "cannot generate SSPI context" errors with the full name.
	//
	// For IP targets: reverse DNS is attempted to obtain a FQDN for the
	// HostNameInCertificate field, which strict mode needs for TLS certificate
	// validation (the cert CN/SAN rarely contains an IP).
	//
	// NOTE: Some servers with specific SSPI configurations may fail to connect
	// from Go even though PowerShell/System.Data.SqlClient works. This is a
	// known limitation of the go-mssqldb driver's Windows SSPI implementation.

	// Get short hostname for some strategies (only for FQDNs, not IP addresses)
	shortHostname := ""
	// Determine the cert hostname for strict encryption (HostNameInCertificate).
	// If -s is a FQDN, use it directly. If it's an IP, try reverse DNS.
	certHost := c.hostname
	if net.ParseIP(c.hostname) == nil {
		if idx := strings.Index(c.hostname, "."); idx != -1 {
			shortHostname = c.hostname[:idx]
		}
	} else {
		// IP address: try reverse DNS to get FQDN for certificate matching
		if names, err := net.LookupAddr(c.hostname); err == nil && len(names) > 0 {
			certHost = strings.TrimSuffix(names[0], ".")
			c.logVerbose("Resolved IP to FQDN for HostNameInCertificate", "ip", c.hostname, "fqdn", certHost)
		}
	}

	type connStrategy struct {
		name         string
		serverName   string // The server name to use in connection string
		encrypt      string // "false", "true", or "strict"
		useServerSPN bool
		spnHost      string // Host to use in SPN
		certHostname string // HostNameInCertificate for strict encryption
	}

	var strategies []connStrategy
	if c.epaResult != nil && c.epaResult.StrictEncryption {
		// If EPA tester detected strict encryption, try strict first
		strategies = []connStrategy{
			{"FQDN+strict", c.hostname, "strict", false, "", certHost},
			{"FQDN+encrypt", c.hostname, "true", false, "", ""},
			{"FQDN+encrypt+SPN", c.hostname, "true", true, c.hostname, ""},
			{"FQDN+no-encrypt", c.hostname, "false", false, "", ""},
		}
	} else {
		// Default order: try encryption first (most common)
		strategies = []connStrategy{
			{"FQDN+encrypt", c.hostname, "true", false, "", ""},
			{"FQDN+strict", c.hostname, "strict", false, "", certHost},
			{"FQDN+encrypt+SPN", c.hostname, "true", true, c.hostname, ""},
			{"FQDN+no-encrypt", c.hostname, "false", false, "", ""},
		}
	}

	// Only add short hostname strategies for FQDNs (not IP addresses)
	if shortHostname != "" {
		strategies = append(strategies,
			connStrategy{"short+encrypt", shortHostname, "true", false, "", ""},
			connStrategy{"short+strict", shortHostname, "strict", false, "", certHost},
			connStrategy{"short+no-encrypt", shortHostname, "false", false, "", ""},
		)
	}

	// Register a custom NTLM auth provider when:
	// - EPA is Required/Allowed (needs channel binding tokens)
	// - NT hash is provided (pass-the-hash requires our custom NTLM implementation)
	// go-mssqldb's built-in NTLM on Linux does NOT support EPA or pass-the-hash,
	// so without this, strategies fail with "untrusted domain".
	var epaProvider *epaAuthProvider
	useCustomNTLM := !c.useKerberos && ((c.epaResult != nil && (c.epaResult.EPAStatus == "Required" || c.epaResult.EPAStatus == "Allowed")) || len(c.ntHash) > 0)
	if useCustomNTLM {
		epaProvider = &epaAuthProvider{verbose: c.verbose, debug: c.debug, logger: c.logger}
		port := c.port
		if port == 0 {
			port = 1433
		}
		epaProvider.SetSPN(computeSPN(c.hostname, port))
		if len(c.ntHash) > 0 {
			epaProvider.SetNTHash(c.ntHash)
		}
		integratedauth.SetIntegratedAuthenticationProvider(epaAuthProviderName, epaProvider)
		if c.epaResult != nil {
			c.logVerbose("Using EPA-aware NTLM authentication", "epa_status", c.epaResult.EPAStatus)
		}
		if len(c.ntHash) > 0 {
			c.logVerbose("Using pass-the-hash NTLM authentication")
		}
	}

	// Special strategy for strict encryption + EPA: do TLS ourselves in the dialer
	// so we can capture TLSUnique after the handshake completes (go-mssqldb's
	// VerifyConnection fires before Finished messages, giving all-zero TLSUnique).
	// go-mssqldb uses encrypt=disable so it doesn't add another TLS layer.
	if epaProvider != nil && c.epaResult != nil && c.epaResult.StrictEncryption {
		port := c.port
		if port == 0 {
			port = 1433
		}
		dialer := &epaTLSDialer{
			underlying:  c.proxyDialer,
			epaProvider: epaProvider,
			hostname:    c.hostname,
			dnsResolver: c.dnsResolver,
			logger:      c.logger,
		}
		connStr := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;encrypt=disable;TrustServerCertificate=true;app name=MSSQLHound",
			c.hostname, port, c.userID, c.password)
		c.logVerbose("Trying connection strategy", "strategy", "EPA+strict-TLS", "connstr", redactConnStr(connStr))

		config, parseErr := msdsn.Parse(connStr)
		if parseErr == nil {
			if config.Parameters == nil {
				config.Parameters = make(map[string]string)
			}
			config.Parameters["authenticator"] = epaAuthProviderName

			connector := mssqldb.NewConnectorConfig(config)
			connector.Dialer = dialer
			db := sql.OpenDB(connector)

			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := db.PingContext(pingCtx)
			cancel()

			if err == nil {
				c.logVerbose("Connection strategy succeeded", "strategy", "EPA+strict-TLS")
				c.db = db
				return nil
			}
			db.Close()
			c.logVerbose("Connection strategy failed", "strategy", "EPA+strict-TLS", "error", err)
			if IsAuthError(err) {
				c.logVerbose("Authentication error detected, stopping to prevent account lockout")
				return fmt.Errorf("EPA+strict-TLS authentication failed: %w", err)
			}
		}
	}

	// Strategy for non-strict encryption + EPA: perform the PRELOGIN + TLS-in-TDS
	// handshake ourselves in the dialer so we can capture TLSUnique after the
	// handshake fully completes. go-mssqldb's VerifyConnection callback fires
	// before the TLS Finished messages are exchanged, giving all-zero TLSUnique.
	// The dialer wraps the TLS connection with preloginFakerConn to intercept
	// go-mssqldb's PRELOGIN exchange (already completed) and fake a response.
	if epaProvider != nil && c.epaResult != nil && !c.epaResult.StrictEncryption {
		port := c.port
		if port == 0 {
			port = 1433
		}
		dialer := &epaTDSDialer{
			underlying:  c.proxyDialer,
			epaProvider: epaProvider,
			hostname:    c.hostname,
			dnsResolver: c.dnsResolver,
			logger:      c.logger,
		}
		connStr := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;encrypt=disable;TrustServerCertificate=true;app name=MSSQLHound",
			c.hostname, port, c.userID, c.password)
		c.logVerbose("Trying connection strategy", "strategy", "EPA+TDS-TLS", "connstr", redactConnStr(connStr))

		config, parseErr := msdsn.Parse(connStr)
		if parseErr == nil {
			if config.Parameters == nil {
				config.Parameters = make(map[string]string)
			}
			config.Parameters["authenticator"] = epaAuthProviderName

			connector := mssqldb.NewConnectorConfig(config)
			connector.Dialer = dialer
			db := sql.OpenDB(connector)

			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := db.PingContext(pingCtx)
			cancel()

			if err == nil {
				c.logVerbose("Connection strategy succeeded", "strategy", "EPA+TDS-TLS")
				c.db = db
				return nil
			}
			db.Close()
			c.logVerbose("Connection strategy failed", "strategy", "EPA+TDS-TLS", "error", err)
			if IsAuthError(err) {
				c.logVerbose("Authentication error detected, stopping to prevent account lockout")
				return fmt.Errorf("EPA+TDS-TLS authentication failed: %w", err)
			}
		}
	}

	var lastErr error
	for _, strategy := range strategies {
		connStr := c.buildConnectionStringForStrategy(strategy.serverName, strategy.encrypt, strategy.useServerSPN, strategy.spnHost, strategy.certHostname)
		c.logVerbose("Trying connection strategy", "strategy", strategy.name, "connstr", redactConnStr(connStr))

		// Parse connection string into config and use NewConnectorConfig for all
		// strategies so we can inject a custom proxy dialer when configured.
		config, parseErr := msdsn.Parse(connStr)
		if parseErr != nil {
			lastErr = parseErr
			c.logVerbose("Connection strategy failed to parse", "strategy", strategy.name, "error", parseErr)
			continue
		}

		if strategy.encrypt == "strict" {
			// For strict encryption (TDS 8.0), go-mssqldb forces certificate
			// validation regardless of TrustServerCertificate. Override TLS
			// settings so we can connect to servers with self-signed certs.
			if config.TLSConfig != nil {
				config.TLSConfig.InsecureSkipVerify = true //nolint:gosec // security tool needs to connect to any server
			}
		}

		// When Kerberos is enabled, inject krb5 authenticator parameters.
		if c.useKerberos {
			if config.Parameters == nil {
				config.Parameters = make(map[string]string)
			}
			config.Parameters["authenticator"] = "krb5"
			if c.krb5ConfigFile != "" {
				config.Parameters["krb5-configfile"] = c.krb5ConfigFile
			}
			if c.krb5CCacheFile != "" {
				config.Parameters["krb5-credcachefile"] = c.krb5CCacheFile
			}
			if c.krb5KeytabFile != "" {
				config.Parameters["krb5-keytabfile"] = c.krb5KeytabFile
			}
			if c.krb5Realm != "" {
				config.Parameters["krb5-realm"] = c.krb5Realm
			}
		}

		// When EPA auth is needed, inject our custom authenticator and add a
		// VerifyConnection callback to capture the TLS-unique channel binding
		// value after go-mssqldb's TLS handshake completes.
		if epaProvider != nil {
			if config.Parameters == nil {
				config.Parameters = make(map[string]string)
			}
			config.Parameters["authenticator"] = epaAuthProviderName

			// Ensure TLSConfig exists so we can add the connection callback.
			// For encrypt=false strategies, msdsn.Parse returns nil TLSConfig,
			// but the server may still force TLS.
			if config.TLSConfig == nil {
				config.TLSConfig = &tls.Config{
					ServerName:                  config.Host,
					InsecureSkipVerify:          true, //nolint:gosec // security tool needs to connect to any server
					DynamicRecordSizingDisabled: true,
				}
			}
			// Cap at TLS 1.2 so that TLSUnique (tls-unique channel binding) is
			// available for EPA. TLS 1.3 removed tls-unique (RFC 8446).
			config.TLSConfig.MaxVersion = tls.VersionTLS12

			config.TLSConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				c.logDebug("EPA TLS VerifyConnection fired", "tls_version", fmt.Sprintf("0x%04X", cs.Version), "tls_unique", fmt.Sprintf("%x", cs.TLSUnique), "tls_unique_len", len(cs.TLSUnique), "certs", len(cs.PeerCertificates))
				if len(cs.TLSUnique) > 0 {
					cbt := computeCBTHash("tls-unique:", cs.TLSUnique)
					epaProvider.SetCBT(cbt)
					c.logDebug("EPA TLS set CBT (tls-unique)", "cbt", fmt.Sprintf("%x", cbt))
				} else {
					c.logDebug("EPA TLS WARNING: TLSUnique empty, no CBT set")
				}
				return nil
			}
		}

		connector := mssqldb.NewConnectorConfig(config)
		if c.proxyDialer != nil {
			connector.Dialer = c.proxyDialer
		} else if c.dnsResolver != "" {
			connector.Dialer = dialerWithResolver(c.dnsResolver, 10*time.Second)
		}
		db := sql.OpenDB(connector)

		// Test the connection with a short timeout
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := db.PingContext(pingCtx)
		cancel()

		if err != nil {
			db.Close()
			lastErr = err
			c.logVerbose("Connection strategy failed to connect", "strategy", strategy.name, "error", err)
			if IsAuthError(err) {
				c.logVerbose("Authentication error detected, stopping strategy loop to prevent account lockout")
				break
			}
			continue
		}

		c.logVerbose("Connection strategy succeeded", "strategy", strategy.name)
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

// connStrPasswordRe matches the password field in a semicolon-delimited connection string.
var connStrPasswordRe = regexp.MustCompile(`(?i)(password=)[^;]*`)

// redactConnStr replaces the password field value in a connection string with "****".
func redactConnStr(connStr string) string {
	return connStrPasswordRe.ReplaceAllString(connStr, "${1}****")
}

// buildConnectionStringForStrategy creates the connection string for a specific strategy
func (c *Client) buildConnectionStringForStrategy(serverName, encrypt string, useServerSPN bool, spnHost string, certHostname string) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("server=%s", serverName))

	if c.port > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", c.port))
	}

	if c.instanceName != "" {
		parts = append(parts, fmt.Sprintf("instance=%s", c.instanceName))
	}

	if c.useKerberos {
		// Kerberos authentication via go-mssqldb's krb5 provider
		parts = append(parts, "trusted_connection=yes")
		if c.userID != "" {
			parts = append(parts, fmt.Sprintf("user id=%s", c.userID))
		}
		// Set ServerSPN for Kerberos ticket request
		effectiveHost := serverName
		if spnHost != "" {
			effectiveHost = spnHost
		}
		port := c.port
		if port == 0 {
			port = 1433
		}
		if c.instanceName != "" && c.instanceName != "MSSQLSERVER" {
			parts = append(parts, fmt.Sprintf("ServerSPN=MSSQLSvc/%s:%s", effectiveHost, c.instanceName))
		} else {
			parts = append(parts, fmt.Sprintf("ServerSPN=MSSQLSvc/%s:%d", effectiveHost, port))
		}
	} else if c.useWindowsAuth {
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
	if certHostname != "" {
		parts = append(parts, fmt.Sprintf("HostNameInCertificate=%s", certHostname))
	}
	parts = append(parts, "app name=MSSQLHound")

	return strings.Join(parts, ";")
}

// buildConnectionString creates the connection string for go-mssqldb (uses default options)
func (c *Client) buildConnectionString() string {
	encrypt := "true"
	if !c.encrypt {
		encrypt = "false"
	}
	return c.buildConnectionStringForStrategy(c.hostname, encrypt, true, c.hostname, "")
}

// SetVerbose enables or disables verbose logging
func (c *Client) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// SetDebug enables or disables debug logging (EPA/TLS/NTLM diagnostics)
func (c *Client) SetDebug(debug bool) {
	c.debug = debug
}

func (c *Client) SetCollectFromLinkedServers(collect bool) {
	c.collectFromLinkedServers = collect
}

// SetNTHash sets a pre-computed NT hash (16 bytes) for pass-the-hash authentication.
// When set, NTLM auth will use this hash instead of deriving one from the password.
func (c *Client) SetNTHash(hash []byte) {
	c.ntHash = hash
}

// SetKerberosConfig sets Kerberos authentication parameters.
func (c *Client) SetKerberosConfig(configFile, ccacheFile, keytabFile, realm string) {
	c.useKerberos = true
	c.krb5ConfigFile = configFile
	c.krb5CCacheFile = ccacheFile
	c.krb5KeytabFile = keytabFile
	c.krb5Realm = realm
}

// SetDomain sets the domain for NTLM authentication (needed for EPA testing)
func (c *Client) SetDomain(domain string) {
	c.domain = domain
}

// SetLDAPCredentials sets the LDAP credentials used for EPA testing.
// The ldapUser can be in DOMAIN\user or user@domain format.
func (c *Client) SetLDAPCredentials(ldapUser, ldapPassword string) {
	c.ldapUser = ldapUser
	c.ldapPassword = ldapPassword
}

// SetDNSResolver sets the DNS resolver IP (e.g. domain controller) for hostname lookups.
func (c *Client) SetDNSResolver(resolver string) {
	c.dnsResolver = resolver
}

// SetProxyDialer sets a SOCKS5 proxy dialer for all network operations.
func (c *Client) SetProxyDialer(d interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}) {
	c.proxyDialer = d
}

// SetEPAResult stores a pre-computed EPA test result on the client.
// When set, collectEncryptionSettings will use this instead of running EPA tests.
func (c *Client) SetEPAResult(result *EPATestResult) {
	c.epaResult = result
}

// SetLogger sets the structured logger for the client.
func (c *Client) SetLogger(l *slog.Logger) {
	c.logger = l
}

// logVerbose logs a message at the Verbose level.
func (c *Client) logVerbose(msg string, args ...any) {
	c.logger.Log(context.Background(), logging.LevelVerbose, msg, args...)
}

// logDebug logs a message at the Debug level.
func (c *Client) logDebug(msg string, args ...any) {
	c.logger.Debug(msg, args...)
}

// EPAPrereqError indicates that the EPA prerequisite check failed.
// When this error is returned, no further EPA tests or MSSQL authentication
// attempts should be made (to match the Python mssql.py flow and avoid
// account lockout with invalid credentials).
type EPAPrereqError struct {
	Err error
}

func (e *EPAPrereqError) Error() string {
	return e.Err.Error()
}

func (e *EPAPrereqError) Unwrap() error {
	return e.Err
}

// IsEPAPrereqError checks if an error is an EPA prerequisite failure.
func IsEPAPrereqError(err error) bool {
	var prereqErr *EPAPrereqError
	return errors.As(err, &prereqErr)
}

// EPATestResult holds the results of EPA connection testing
type EPATestResult struct {
	UnmodifiedSuccess bool
	NoSBSuccess       bool
	NoCBTSuccess      bool
	ForceEncryption   bool
	StrictEncryption  bool
	EncryptionFlag    byte
	EPAStatus         string
}

// TestEPA performs Extended Protection for Authentication testing using raw
// TDS+TLS+NTLM connections with controllable Channel Binding and Service Binding.
// This matches the approach used in the Python reference implementation
// (MssqlExtended.py / MssqlInformer.py).
//
// Two-path EPA detection flow (per MS-TDS spec):
//
//   Path 1 - TDS 7.x normal (most servers):
//     PRELOGIN(cleartext) -> TLS-over-TDS handshake -> LOGIN7 with NTLM Type1
//     -> server returns NTLM Type2 challenge (contains encryption flag)
//
//   Path 2 - TDS 8.0 strict (ForceStrictEncryption=1):
//     Direct TLS handshake -> PRELOGIN(inside TLS) -> LOGIN7 with NTLM Type1
//     -> server returns NTLM Type2 challenge
//     Tried only when Path 1 PRELOGIN fails (strict servers reject cleartext PRELOGIN).
//
// EPA determination logic (for encrypted connections):
//   1. Normal login (unmodified NTLM) succeeds -> baseline established
//   2. BogusCBT login (garbage channel binding token) fails with "untrusted domain"
//      -> server is checking channel bindings, proceed to step 3
//      BogusCBT succeeds -> EPA is Off (server ignores channel bindings)
//   3. MissingCBT login (no channel binding token at all):
//      Fails with "untrusted domain" -> EPA = Required
//      Succeeds -> EPA = Allowed (accepts but doesn't require CBT)
//
// For unencrypted connections (ENCRYPT_OFF): service binding is tested instead.
func (c *Client) TestEPA(ctx context.Context) (*EPATestResult, error) {
	result := &EPATestResult{}

	// EPA testing requires LDAP/domain credentials for NTLM authentication.
	// These are separate from the SQL auth credentials (-u/-p).
	// Pass-the-hash (--nt-hash) can substitute for --ldap-password.
	if c.ldapUser == "" || (c.ldapPassword == "" && len(c.ntHash) == 0) {
		return nil, fmt.Errorf("EPA testing requires LDAP credentials (--ldap-user and --ldap-password or --nt-hash)")
	}

	// Parse domain and username from LDAP user (DOMAIN\user or user@domain format)
	epaDomain, epaUsername := parseLDAPUser(c.ldapUser, c.domain)
	if epaDomain == "" {
		return nil, fmt.Errorf("EPA testing requires a domain (from --ldap-user DOMAIN\\user or --domain)")
	}

	c.logVerbose("EPA credentials", "domain", epaDomain, "username", epaUsername)

	// Resolve port if needed
	port := c.port
	if port == 0 && c.instanceName != "" {
		resolvedPort, err := c.resolveInstancePort(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve instance port: %w", err)
		}
		port = resolvedPort
	}
	if port == 0 {
		port = 1433
	}

	c.logVerbose("Testing EPA settings", "server", c.serverInstance)

	// Build a base config using LDAP credentials
	baseConfig := func(mode EPATestMode) *EPATestConfig {
		return &EPATestConfig{
			Hostname: c.hostname, Port: port, InstanceName: c.instanceName,
			Domain: epaDomain, Username: epaUsername, Password: c.ldapPassword,
			NTHash:   c.ntHash,
			TestMode: mode, Verbose: c.verbose, Debug: c.debug,
			DNSResolver: c.dnsResolver,
			ProxyDialer: c.proxyDialer,
			Logger:      c.logger,
		}
	}

	// Step 1: Detect encryption mode and run prerequisite check
	c.logVerbose("Running prerequisite check with normal login...")
	prereqResult, encFlag, err := runEPATest(ctx, baseConfig(EPATestNormal))
	if err != nil {
		// The normal TDS 7.x PRELOGIN failed. This may indicate the server
		// enforces TDS 8.0 strict encryption (TLS before any TDS messages).
		c.logVerbose("Normal PRELOGIN failed, trying TDS 8.0 strict encryption flow", "error", err)
		strictPrereqResult, strictEncFlag, strictErr := runEPATestStrict(ctx, baseConfig(EPATestNormal))
		if strictErr != nil {
			return nil, &EPAPrereqError{Err: fmt.Errorf("EPA prereq check failed (tried normal and TDS 8.0 strict): normal=%v, strict=%v", err, strictErr)}
		}
		// TDS 8.0 strict encryption confirmed - validate prereq result
		if !strictPrereqResult.Success && !strictPrereqResult.IsLoginFailed {
			if strictPrereqResult.IsUntrustedDomain {
				return nil, &EPAPrereqError{Err: fmt.Errorf("EPA prereq check failed (strict): credentials rejected (untrusted domain)")}
			}
			return nil, &EPAPrereqError{Err: fmt.Errorf("EPA prereq check failed (strict): unexpected response: %s", strictPrereqResult.ErrorMessage)}
		}
		result.UnmodifiedSuccess = strictPrereqResult.Success
		result.EncryptionFlag = encryptStrict
		result.StrictEncryption = true
		result.ForceEncryption = strictEncFlag == encryptReq
		c.logVerbose("Server uses TDS 8.0 strict encryption")
		c.logVerbose("Encryption flag (from strict PRELOGIN)", "flag", fmt.Sprintf("0x%02X", strictEncFlag))
		c.logVerbose("Strict Encryption (TDS 8.0): Yes")
		c.logVerbose("Force Encryption", "enabled", boolToYesNo(result.ForceEncryption))
		c.logVerbose("Unmodified connection (strict)", "result", boolToSuccessFail(strictPrereqResult.Success))

		// Determine EPA enforcement via channel binding tests over strict TLS.
		// Strict mode is always encrypted, so test channel binding (like encryptReq path).
		c.logVerbose("Conducting logins while manipulating channel binding av pair over strict encrypted connection")

		bogusResult, _, bogusErr := runEPATestStrict(ctx, baseConfig(EPATestBogusCBT))
		if bogusErr != nil {
			c.logVerbose("Bogus CBT test (strict) failed", "error", bogusErr)
			result.EPAStatus = "Unknown"
			return result, nil
		}

		if bogusResult.IsUntrustedDomain {
			// Bogus CBT rejected - EPA is enforcing channel binding
			missingResult, _, missingErr := runEPATestStrict(ctx, baseConfig(EPATestMissingCBT))
			if missingErr != nil {
				c.logVerbose("Missing CBT test (strict) failed", "error", missingErr)
				result.EPAStatus = "Unknown"
				return result, nil
			}

			result.NoCBTSuccess = missingResult.Success || missingResult.IsLoginFailed
			if missingResult.IsUntrustedDomain {
				result.EPAStatus = "Required"
				c.logVerbose("Extended Protection: Required (channel binding)")
			} else {
				result.EPAStatus = "Allowed"
				c.logVerbose("Extended Protection: Allowed (channel binding)")
			}
		} else {
			// Bogus CBT accepted - EPA is Off
			result.NoCBTSuccess = true
			result.EPAStatus = "Off"
			c.logVerbose("Extended Protection: Off")
		}

		return result, nil
	}

	result.EncryptionFlag = encFlag
	result.ForceEncryption = encFlag == encryptReq

	c.logVerbose("Encryption flag", "flag", fmt.Sprintf("0x%02X", encFlag))
	c.logVerbose("Force Encryption", "enabled", boolToYesNo(result.ForceEncryption))

	// Prereq must succeed or produce "login failed" (valid credentials response)
	if !prereqResult.Success && !prereqResult.IsLoginFailed {
		if prereqResult.IsUntrustedDomain {
			return nil, &EPAPrereqError{Err: fmt.Errorf("EPA prereq check failed: credentials rejected (untrusted domain)")}
		}
		return nil, &EPAPrereqError{Err: fmt.Errorf("EPA prereq check failed: unexpected response: %s", prereqResult.ErrorMessage)}
	}
	result.UnmodifiedSuccess = prereqResult.Success
	c.logVerbose("Unmodified connection", "result", boolToSuccessFail(prereqResult.Success))

	// Step 2: Test based on encryption setting (matching Python mssql.py flow)
	if encFlag == encryptReq {
		// Encrypted path: test channel binding (matching Python lines 57-78)
		c.logVerbose("Conducting logins while manipulating channel binding av pair over encrypted connection")

		// Test with bogus CBT
		bogusResult, _, err := runEPATest(ctx, baseConfig(EPATestBogusCBT))
		if err != nil {
			return nil, fmt.Errorf("EPA bogus CBT test failed: %w", err)
		}

		if bogusResult.IsUntrustedDomain {
			// Bogus CBT rejected - EPA is enforcing channel binding
			// Test with missing CBT to distinguish Allowed vs Required
			missingResult, _, err := runEPATest(ctx, baseConfig(EPATestMissingCBT))
			if err != nil {
				return nil, fmt.Errorf("EPA missing CBT test failed: %w", err)
			}

			result.NoCBTSuccess = missingResult.Success || missingResult.IsLoginFailed
			if missingResult.IsUntrustedDomain {
				result.EPAStatus = "Required"
				c.logVerbose("Extended Protection: Required (channel binding)")
			} else {
				result.EPAStatus = "Allowed"
				c.logVerbose("Extended Protection: Allowed (channel binding)")
			}
		} else {
			// Bogus CBT accepted - EPA is Off
			result.NoCBTSuccess = true
			result.EPAStatus = "Off"
			c.logVerbose("Extended Protection: Off")
		}

	} else if encFlag == encryptOff || encFlag == encryptOn {
		// Unencrypted/optional path: test service binding (matching Python lines 80-103)
		c.logVerbose("Conducting logins while manipulating target service av pair over unencrypted connection")

		// Test with bogus service
		bogusResult, _, err := runEPATest(ctx, baseConfig(EPATestBogusService))
		if err != nil {
			return nil, fmt.Errorf("EPA bogus service test failed: %w", err)
		}

		if bogusResult.IsUntrustedDomain {
			// Bogus service rejected - EPA is enforcing service binding
			// Test with missing service to distinguish Allowed vs Required
			missingResult, _, err := runEPATest(ctx, baseConfig(EPATestMissingService))
			if err != nil {
				return nil, fmt.Errorf("EPA missing service test failed: %w", err)
			}

			result.NoSBSuccess = missingResult.Success || missingResult.IsLoginFailed
			if missingResult.IsUntrustedDomain {
				result.EPAStatus = "Required"
				c.logVerbose("Extended Protection: Required (service binding)")
			} else {
				result.EPAStatus = "Allowed"
				c.logVerbose("Extended Protection: Allowed (service binding)")
			}
		} else {
			// Bogus service accepted - EPA is Off
			result.NoSBSuccess = true
			result.EPAStatus = "Off"
			c.logVerbose("Extended Protection: Off")
		}
	} else {
		result.EPAStatus = "Unknown"
		c.logVerbose("Extended Protection: Unknown", "encryption_flag", fmt.Sprintf("0x%02X", encFlag))
	}

	return result, nil
}

// parseLDAPUser parses an LDAP user string in DOMAIN\user or user@domain format,
// returning the domain and username separately. If no domain is found in the user
// string, fallbackDomain is used.
func parseLDAPUser(ldapUser, fallbackDomain string) (domain, username string) {
	if strings.Contains(ldapUser, "\\") {
		parts := strings.SplitN(ldapUser, "\\", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(ldapUser, "@") {
		parts := strings.SplitN(ldapUser, "@", 2)
		return parts[1], parts[0]
	}
	return fallbackDomain, ldapUser
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

// resolveInstancePort resolves the port for a named SQL Server instance using SQL Browser
func (c *Client) resolveInstancePort(ctx context.Context) (int, error) {
	if c.proxyDialer != nil {
		return 0, fmt.Errorf("SQL Browser UDP resolution is not supported through a SOCKS5 proxy; please specify the port explicitly (e.g., host:port or host\\instance:port)")
	}

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

	// Set initial ObjectIdentifier using hostname; the collector will resolve
	// the computer SID via LDAP and update this to a SID-based identifier.
	info.ObjectIdentifier = fmt.Sprintf("%s:%d", strings.ToLower(info.ServerName), info.Port)

	// Set SQLServerName for display purposes (FQDN:Port format)
	info.SQLServerName = fmt.Sprintf("%s:%d", info.FQDN, info.Port)

	// Collect authentication mode
	if err := c.collectAuthenticationMode(ctx, info); err != nil {
		c.logger.Warn("Failed to collect auth mode", "error", err)
	}

	// Collect encryption settings (Force Encryption, Extended Protection)
	if err := c.collectEncryptionSettings(ctx, info); err != nil {
		c.logger.Warn("Failed to collect encryption settings", "error", err)
	}

	// Get service accounts
	c.logVerbose("Collecting service account information", "server", c.serverInstance)
	if err := c.collectServiceAccounts(ctx, info); err != nil {
		c.logger.Warn("Failed to collect service accounts", "error", err)
	}

	// Get server-level credentials
	c.logVerbose("Enumerating credentials...")
	if err := c.collectCredentials(ctx, info); err != nil {
		c.logger.Warn("Failed to collect credentials", "error", err)
	}

	// Get proxy accounts
	c.logVerbose("Enumerating SQL Agent proxy accounts...")
	if err := c.collectProxyAccounts(ctx, info); err != nil {
		c.logger.Warn("Failed to collect proxy accounts", "error", err)
	}

	// Get server principals
	c.logVerbose("Enumerating server principals...")
	principals, err := c.collectServerPrincipals(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("failed to collect server principals: %w", err)
	}
	info.ServerPrincipals = principals

	// Derive the domain SID from Active Directory principal SIDs.
	// All domain principals share a common S-1-5-21-X-Y-Z prefix; the RID is the last segment.
	if info.DomainSID == "" {
		for _, p := range principals {
			if p.IsActiveDirectoryPrincipal && strings.HasPrefix(p.SecurityIdentifier, "S-1-5-21-") {
				if idx := strings.LastIndex(p.SecurityIdentifier, "-"); idx > 0 {
					info.DomainSID = p.SecurityIdentifier[:idx]
					c.logVerbose("Derived domain SID from principal", "principal", p.Name, "domain_sid", info.DomainSID)
					break
				}
			}
		}
	}

	c.logVerbose("Checking for inherited high-privilege permissions through role memberships")

	// Get credential mappings for logins
	if err := c.collectLoginCredentialMappings(ctx, principals, info); err != nil {
		c.logger.Warn("Failed to collect login credential mappings", "error", err)
	}

	// Get databases
	databases, err := c.collectDatabases(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("failed to collect databases: %w", err)
	}

	// Collect database-scoped credentials for each database
	for i := range databases {
		if err := c.collectDBScopedCredentials(ctx, &databases[i]); err != nil {
			c.logger.Warn("Failed to collect DB-scoped credentials", "database", databases[i].Name, "error", err)
		}
	}
	info.Databases = databases

	// Get linked servers
	c.logVerbose("Enumerating linked servers...")
	linkedServers, err := c.collectLinkedServers(ctx)
	if err != nil {
		// Non-fatal - just log and continue
		c.logger.Warn("Failed to collect linked servers", "error", err)
	}
	info.LinkedServers = linkedServers

	// Print discovered linked servers
	// Note: linkedServers may contain duplicates due to multiple login mappings per server
	// Deduplicate by Name for display purposes
	if len(linkedServers) > 0 {
		// Build a map of unique linked servers by Name
		uniqueServers := make(map[string]types.LinkedServer)
		for _, ls := range linkedServers {
			if _, exists := uniqueServers[ls.Name]; !exists {
				uniqueServers[ls.Name] = ls
			}
		}

		c.logger.Info("Discovered linked servers", "count", len(uniqueServers))

		// Print in consistent order (sorted by name)
		var serverNames []string
		for name := range uniqueServers {
			serverNames = append(serverNames, name)
		}
		sort.Strings(serverNames)

		for _, name := range serverNames {
			ls := uniqueServers[name]
			c.logger.Info("Linked server", "name", ls.Name)

			// Show detailed info only in verbose mode
			c.logVerbose("Linked server details",
				"name", ls.Name,
				"data_source", ls.DataSource,
				"provider", ls.Provider,
				"product", ls.Product,
				"remote_login_enabled", ls.IsRemoteLoginEnabled,
				"rpc_out_enabled", ls.IsRPCOutEnabled,
				"data_access_enabled", ls.IsDataAccessEnabled,
				"self_mapping", ls.IsSelfMapping,
				"local_login", ls.LocalLogin,
				"remote_login", ls.RemoteLogin,
				"catalog", ls.Catalog,
			)
		}

		if !c.collectFromLinkedServers {
			c.logger.Info("Skipping linked server collection (use --collect-from-linked to enable)")
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
		c.logVerbose("Processing database", "database", databases[i].Name)
		principals, err := c.collectDatabasePrincipals(ctx, &databases[i], serverInfo)
		if err != nil {
			c.logger.Warn("Failed to collect principals for database", "database", databases[i].Name, "error", err)
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
		c.logger.Warn("Failed to link database users to server logins", "database", db.Name, "error", err)
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
	// Use a single server-side SQL batch that recursively discovers linked servers
	// through chained links, matching the PowerShell implementation.
	// This discovers not just direct linked servers but also linked servers
	// accessible through other linked servers (e.g., A -> B -> C).
	query := `
SET NOCOUNT ON;

-- Create temp table for linked server discovery
CREATE TABLE #mssqlhound_linked (
	ID INT IDENTITY(1,1),
	Level INT,
	Path NVARCHAR(MAX),
	SourceServer NVARCHAR(128),
	LinkedServer NVARCHAR(128),
	DataSource NVARCHAR(128),
	Product NVARCHAR(128),
	Provider NVARCHAR(128),
	DataAccess BIT,
	RPCOut BIT,
	LocalLogin NVARCHAR(128),
	UsesImpersonation BIT,
	RemoteLogin NVARCHAR(128),
	RemoteIsSysadmin BIT DEFAULT 0,
	RemoteIsSecurityAdmin BIT DEFAULT 0,
	RemoteCurrentLogin NVARCHAR(128),
	RemoteIsMixedMode BIT DEFAULT 0,
	RemoteHasControlServer BIT DEFAULT 0,
	RemoteHasImpersonateAnyLogin BIT DEFAULT 0,
	ErrorMsg NVARCHAR(MAX) NULL
);

-- Insert local server's linked servers (Level 0)
INSERT INTO #mssqlhound_linked (Level, Path, SourceServer, LinkedServer, DataSource, Product, Provider, DataAccess, RPCOut,
                            LocalLogin, UsesImpersonation, RemoteLogin)
SELECT
	0,
	@@SERVERNAME + ' -> ' + s.name,
	@@SERVERNAME,
	s.name,
	s.data_source,
	s.product,
	s.provider,
	s.is_data_access_enabled,
	s.is_rpc_out_enabled,
	COALESCE(sp.name, 'All Logins'),
	ll.uses_self_credential,
	ll.remote_name
FROM sys.servers s
INNER JOIN sys.linked_logins ll ON s.server_id = ll.server_id
LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
WHERE s.is_linked = 1;

-- Declare all variables upfront (T-SQL has batch-level scoping)
DECLARE @CheckID INT, @CheckLinkedServer NVARCHAR(128);
DECLARE @CheckSQL NVARCHAR(MAX);
DECLARE @CheckSQL2 NVARCHAR(MAX);
DECLARE @LinkedServer NVARCHAR(128), @Path NVARCHAR(MAX);
DECLARE @sql NVARCHAR(MAX);
DECLARE @CurrentLevel INT;
DECLARE @MaxLevel INT;
DECLARE @RowsToProcess INT;
DECLARE @PrivilegeResults TABLE (
	IsSysadmin INT,
	IsSecurityAdmin INT,
	CurrentLogin NVARCHAR(128),
	IsMixedMode INT,
	HasControlServer INT,
	HasImpersonateAnyLogin INT
);
DECLARE @ProcessedServers TABLE (ServerName NVARCHAR(128));

-- Check privileges for Level 0 entries

DECLARE check_cursor CURSOR FOR
SELECT ID, LinkedServer FROM #mssqlhound_linked WHERE Level = 0;

OPEN check_cursor;
FETCH NEXT FROM check_cursor INTO @CheckID, @CheckLinkedServer;

WHILE @@FETCH_STATUS = 0
BEGIN
	DELETE FROM @PrivilegeResults;

	BEGIN TRY
		SET @CheckSQL = 'SELECT * FROM OPENQUERY([' + @CheckLinkedServer + '], ''
			WITH RoleHierarchy AS (
				SELECT
					p.principal_id,
					p.name AS principal_name,
					CAST(p.name AS NVARCHAR(MAX)) AS path,
					0 AS level
				FROM sys.server_principals p
				WHERE p.name = SYSTEM_USER

				UNION ALL

				SELECT
					r.principal_id,
					r.name AS principal_name,
					rh.path + '''' -> '''' + r.name,
					rh.level + 1
				FROM RoleHierarchy rh
				INNER JOIN sys.server_role_members rm ON rm.member_principal_id = rh.principal_id
				INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
				WHERE rh.level < 10
			),
			AllPermissions AS (
				SELECT DISTINCT
					sp.permission_name,
					sp.state
				FROM RoleHierarchy rh
				INNER JOIN sys.server_permissions sp ON sp.grantee_principal_id = rh.principal_id
				WHERE sp.state = ''''G''''
			)
			SELECT
				IS_SRVROLEMEMBER(''''sysadmin'''') AS IsSysadmin,
				IS_SRVROLEMEMBER(''''securityadmin'''') AS IsSecurityAdmin,
				SYSTEM_USER AS CurrentLogin,
				CASE SERVERPROPERTY(''''IsIntegratedSecurityOnly'''')
					WHEN 1 THEN 0
					WHEN 0 THEN 1
				END AS IsMixedMode,
				CASE WHEN EXISTS (
					SELECT 1 FROM AllPermissions
					WHERE permission_name = ''''CONTROL SERVER''''
				) THEN 1 ELSE 0 END AS HasControlServer,
				CASE WHEN EXISTS (
					SELECT 1 FROM AllPermissions
					WHERE permission_name = ''''IMPERSONATE ANY LOGIN''''
				) THEN 1 ELSE 0 END AS HasImpersonateAnyLogin
		'')';

		INSERT INTO @PrivilegeResults
		EXEC sp_executesql @CheckSQL;

		UPDATE #mssqlhound_linked
		SET RemoteIsSysadmin = (SELECT IsSysadmin FROM @PrivilegeResults),
			RemoteIsSecurityAdmin = (SELECT IsSecurityAdmin FROM @PrivilegeResults),
			RemoteCurrentLogin = (SELECT CurrentLogin FROM @PrivilegeResults),
			RemoteIsMixedMode = (SELECT IsMixedMode FROM @PrivilegeResults),
			RemoteHasControlServer = (SELECT HasControlServer FROM @PrivilegeResults),
			RemoteHasImpersonateAnyLogin = (SELECT HasImpersonateAnyLogin FROM @PrivilegeResults)
		WHERE ID = @CheckID;

	END TRY
	BEGIN CATCH
		UPDATE #mssqlhound_linked
		SET ErrorMsg = ERROR_MESSAGE()
		WHERE ID = @CheckID;
	END CATCH

	FETCH NEXT FROM check_cursor INTO @CheckID, @CheckLinkedServer;
END

CLOSE check_cursor;
DEALLOCATE check_cursor;

-- Recursive discovery of chained linked servers
SET @CurrentLevel = 0;
SET @MaxLevel = 10;
SET @RowsToProcess = 1;

WHILE @RowsToProcess > 0 AND @CurrentLevel < @MaxLevel
BEGIN
	DECLARE process_cursor CURSOR FOR
		SELECT DISTINCT LinkedServer, MIN(Path)
		FROM #mssqlhound_linked
		WHERE Level = @CurrentLevel
			AND LinkedServer NOT IN (SELECT ServerName FROM @ProcessedServers)
		GROUP BY LinkedServer;

	OPEN process_cursor;
	FETCH NEXT FROM process_cursor INTO @LinkedServer, @Path;

	WHILE @@FETCH_STATUS = 0
	BEGIN
		BEGIN TRY
			SET @sql = '
			INSERT INTO #mssqlhound_linked (Level, Path, SourceServer, LinkedServer, DataSource, Product, Provider, DataAccess, RPCOut,
											LocalLogin, UsesImpersonation, RemoteLogin)
			SELECT DISTINCT
				' + CAST(@CurrentLevel + 1 AS NVARCHAR) + ',
				''' + @Path + ' -> '' + s.name,
				''' + @LinkedServer + ''',
				s.name,
				s.data_source,
				s.product,
				s.provider,
				s.is_data_access_enabled,
				s.is_rpc_out_enabled,
				COALESCE(sp.name, ''All Logins''),
				ll.uses_self_credential,
				ll.remote_name
			FROM [' + @LinkedServer + '].[master].[sys].[servers] s
			INNER JOIN [' + @LinkedServer + '].[master].[sys].[linked_logins] ll ON s.server_id = ll.server_id
			LEFT JOIN [' + @LinkedServer + '].[master].[sys].[server_principals] sp ON ll.local_principal_id = sp.principal_id
			WHERE s.is_linked = 1
				AND ''' + @Path + ''' NOT LIKE ''%'' + s.name + '' ->%''
				AND s.data_source NOT IN (
					SELECT DISTINCT DataSource
					FROM #mssqlhound_linked
					WHERE DataSource IS NOT NULL
				)';

			EXEC sp_executesql @sql;
			INSERT INTO @ProcessedServers VALUES (@LinkedServer);

		END TRY
		BEGIN CATCH
			INSERT INTO @ProcessedServers VALUES (@LinkedServer);
		END CATCH

		FETCH NEXT FROM process_cursor INTO @LinkedServer, @Path;
	END

	CLOSE process_cursor;
	DEALLOCATE process_cursor;

	-- Check privileges for newly discovered servers
	DECLARE privilege_cursor CURSOR FOR
		SELECT ID, LinkedServer
		FROM #mssqlhound_linked
		WHERE Level = @CurrentLevel + 1
			AND RemoteIsSysadmin IS NULL;

	OPEN privilege_cursor;
	FETCH NEXT FROM privilege_cursor INTO @CheckID, @CheckLinkedServer;

	WHILE @@FETCH_STATUS = 0
	BEGIN
		DELETE FROM @PrivilegeResults;

		BEGIN TRY
			SET @CheckSQL2 = 'SELECT * FROM OPENQUERY([' + @CheckLinkedServer + '], ''
				WITH RoleHierarchy AS (
					SELECT
						p.principal_id,
						p.name AS principal_name,
						CAST(p.name AS NVARCHAR(MAX)) AS path,
						0 AS level
					FROM sys.server_principals p
					WHERE p.name = SYSTEM_USER

					UNION ALL

					SELECT
						r.principal_id,
						r.name AS principal_name,
						rh.path + '''' -> '''' + r.name,
						rh.level + 1
					FROM RoleHierarchy rh
					INNER JOIN sys.server_role_members rm ON rm.member_principal_id = rh.principal_id
					INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
					WHERE rh.level < 10
				),
				AllPermissions AS (
					SELECT DISTINCT
						sp.permission_name,
						sp.state
					FROM RoleHierarchy rh
					INNER JOIN sys.server_permissions sp ON sp.grantee_principal_id = rh.principal_id
					WHERE sp.state = ''''G''''
				)
				SELECT
					IS_SRVROLEMEMBER(''''sysadmin'''') AS IsSysadmin,
					IS_SRVROLEMEMBER(''''securityadmin'''') AS IsSecurityAdmin,
					SYSTEM_USER AS CurrentLogin,
					CASE SERVERPROPERTY(''''IsIntegratedSecurityOnly'''')
						WHEN 1 THEN 0
						WHEN 0 THEN 1
					END AS IsMixedMode,
					CASE WHEN EXISTS (
						SELECT 1 FROM AllPermissions
						WHERE permission_name = ''''CONTROL SERVER''''
					) THEN 1 ELSE 0 END AS HasControlServer,
					CASE WHEN EXISTS (
						SELECT 1 FROM AllPermissions
						WHERE permission_name = ''''IMPERSONATE ANY LOGIN''''
					) THEN 1 ELSE 0 END AS HasImpersonateAnyLogin
			'')';

			INSERT INTO @PrivilegeResults
			EXEC sp_executesql @CheckSQL2;

			UPDATE #mssqlhound_linked
			SET RemoteIsSysadmin = (SELECT IsSysadmin FROM @PrivilegeResults),
				RemoteIsSecurityAdmin = (SELECT IsSecurityAdmin FROM @PrivilegeResults),
				RemoteCurrentLogin = (SELECT CurrentLogin FROM @PrivilegeResults),
				RemoteIsMixedMode = (SELECT IsMixedMode FROM @PrivilegeResults),
				RemoteHasControlServer = (SELECT HasControlServer FROM @PrivilegeResults),
				RemoteHasImpersonateAnyLogin = (SELECT HasImpersonateAnyLogin FROM @PrivilegeResults)
			WHERE ID = @CheckID;

		END TRY
		BEGIN CATCH
			-- Continue on error
		END CATCH

		FETCH NEXT FROM privilege_cursor INTO @CheckID, @CheckLinkedServer;
	END

	CLOSE privilege_cursor;
	DEALLOCATE privilege_cursor;

	-- Count new unprocessed servers
	SELECT @RowsToProcess = COUNT(DISTINCT LinkedServer)
	FROM #mssqlhound_linked
	WHERE Level = @CurrentLevel + 1
		AND LinkedServer NOT IN (SELECT ServerName FROM @ProcessedServers);

	SET @CurrentLevel = @CurrentLevel + 1;
END

-- Return all results
SET NOCOUNT OFF;
SELECT
	Level,
	Path,
	SourceServer,
	LinkedServer,
	DataSource,
	Product,
	Provider,
	DataAccess,
	RPCOut,
	LocalLogin,
	UsesImpersonation,
	RemoteLogin,
	RemoteIsSysadmin,
	RemoteIsSecurityAdmin,
	RemoteCurrentLogin,
	RemoteIsMixedMode,
	RemoteHasControlServer,
	RemoteHasImpersonateAnyLogin
FROM #mssqlhound_linked
ORDER BY Level, Path;

DROP TABLE #mssqlhound_linked;
`

	rows, err := c.DBW().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []types.LinkedServer

	for rows.Next() {
		var s types.LinkedServer
		var level int
		var path, sourceServer, localLogin, remoteLogin, remoteCurrentLogin sql.NullString
		var dataAccess, rpcOut, usesImpersonation sql.NullBool
		var isSysadmin, isSecurityAdmin, isMixedMode, hasControlServer, hasImpersonateAnyLogin sql.NullBool

		err := rows.Scan(
			&level,
			&path,
			&sourceServer,
			&s.Name,
			&s.DataSource,
			&s.Product,
			&s.Provider,
			&dataAccess,
			&rpcOut,
			&localLogin,
			&usesImpersonation,
			&remoteLogin,
			&isSysadmin,
			&isSecurityAdmin,
			&remoteCurrentLogin,
			&isMixedMode,
			&hasControlServer,
			&hasImpersonateAnyLogin,
		)
		if err != nil {
			return nil, err
		}

		s.IsLinkedServer = true
		s.Path = path.String
		s.SourceServer = sourceServer.String
		s.LocalLogin = localLogin.String
		s.RemoteLogin = remoteLogin.String
		if dataAccess.Valid {
			s.IsDataAccessEnabled = dataAccess.Bool
		}
		if rpcOut.Valid {
			s.IsRPCOutEnabled = rpcOut.Bool
		}
		if usesImpersonation.Valid {
			s.IsSelfMapping = usesImpersonation.Bool
			s.UsesImpersonation = usesImpersonation.Bool
		}
		if isSysadmin.Valid {
			s.RemoteIsSysadmin = isSysadmin.Bool
		}
		if isSecurityAdmin.Valid {
			s.RemoteIsSecurityAdmin = isSecurityAdmin.Bool
		}
		if remoteCurrentLogin.Valid {
			s.RemoteCurrentLogin = remoteCurrentLogin.String
		}
		if isMixedMode.Valid {
			s.RemoteIsMixedMode = isMixedMode.Bool
		}
		if hasControlServer.Valid {
			s.RemoteHasControlServer = hasControlServer.Bool
		}
		if hasImpersonateAnyLogin.Valid {
			s.RemoteHasImpersonateAnyLogin = hasImpersonateAnyLogin.Bool
		}

		servers = append(servers, s)
	}

	return servers, nil
}

// checkLinkedServerPrivileges is no longer needed as privilege checking
// is now integrated into the recursive collectLinkedServers() query.

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
				c.logVerbose("SQL Server service account", "account", serviceAccount.String)
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
			c.logVerbose("Adding service account", "account", sa.Name)
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
			c.name AS credential_name,
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
			&proxy.CredentialName,
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

// collectEncryptionSettings gets the force encryption and EPA settings.
// It performs actual EPA connection testing when domain credentials are available,
// falling back to registry-based detection otherwise.
func (c *Client) collectEncryptionSettings(ctx context.Context, info *types.ServerInfo) error {
	// Use pre-computed EPA result if available (EPA runs before Connect now)
	if c.epaResult != nil {
		if c.epaResult.ForceEncryption {
			info.ForceEncryption = "Yes"
		} else {
			info.ForceEncryption = "No"
		}
		if c.epaResult.StrictEncryption {
			info.StrictEncryption = "Yes"
		} else {
			info.StrictEncryption = "No"
		}
		info.ExtendedProtection = c.epaResult.EPAStatus
		return nil
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
