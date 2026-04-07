// Package collector orchestrates the MSSQL data collection process.
package collector

import (
	"archive/zip"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/ad"
	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/SpecterOps/MSSQLHound/internal/mssql"
	"github.com/SpecterOps/MSSQLHound/internal/proxydialer"
	"github.com/SpecterOps/MSSQLHound/internal/types"
	"github.com/SpecterOps/MSSQLHound/internal/uploader"
	"github.com/SpecterOps/MSSQLHound/internal/wmi"
)

// Config holds the collector configuration
type Config struct {
	// Connection options
	ServerInstance string
	ServerListFile string
	ServerList     string
	UserID         string
	Password       string
	NTHash         string // NT hash (32 hex chars) for pass-the-hash authentication
	UseKerberos    bool   // Use Kerberos authentication
	Krb5ConfigFile string // Path to krb5.conf
	Krb5CCacheFile string // Path to Kerberos credential cache file
	Krb5KeytabFile string // Path to Kerberos keytab file
	Krb5Realm      string // Kerberos realm
	Domain         string
	DC             string // Domain controller hostname or IP address
	DNSResolver    string // DNS resolver to use for lookups
	LDAPUser       string
	LDAPPassword   string

	// Output options
	TempDir       string
	ZipDir        string
	FileSizeLimit string
	Verbose       bool
	Debug         bool

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

	// Concurrency
	Workers int // Number of concurrent workers (0 = sequential)

	// Proxy
	ProxyAddr string // SOCKS5 proxy address for tunneling all traffic

	// Logging
	Logger       *slog.Logger
	LogPerTarget bool         // Save per-target log files in a separate zip
	LogLevel     slog.Leveler // Shared log level for per-target file handlers

	// BloodHound upload options
	BloodHoundURL  string // BloodHound CE instance URL
	TokenID        string // API token ID
	TokenKey       string // API token key
	UploadSchema   bool   // Upload schema definitions (SCHEMA.json)
	UploadResults  bool   // Upload results after collection
	SkipCollection bool   // Skip data collection (upload-only mode)
}

// Collector handles the data collection process
type Collector struct {
	config                     *Config
	proxyDialer                proxydialer.ContextDialer
	tempDir                    string
	outputFiles                []string
	outputFilesMu              sync.Mutex // Protects outputFiles
	logFiles                   []string   // Per-target log file paths (separate from outputFiles)
	logFilesMu                 sync.Mutex // Protects logFiles
	serversToProcess           []*ServerToProcess
	linkedServersToProcess     []*ServerToProcess        // Linked servers discovered during processing
	linkedServersMu            sync.Mutex                // Protects linkedServersToProcess
	serverSPNData              map[string]*ServerSPNInfo // Track SPN data for each server, keyed by ObjectIdentifier
	serverSPNDataMu            sync.RWMutex              // Protects serverSPNData
	skippedChangePasswordEdges map[string]bool           // Track unique skipped ChangePassword edges for CVE-2025-49758
	skippedChangePasswordMu    sync.Mutex                // Protects skippedChangePasswordEdges
	ntHash                     []byte                    // Parsed NT hash bytes (from config.NTHash hex string)
	ldapAuthFailed             bool                      // Set when LDAP auth fails with invalid credentials to prevent lockout
	ldapAuthFailedMu           sync.RWMutex              // Protects ldapAuthFailed
	spnEnumerationDone         bool                      // true after initial broad SPN sweep completed

	// Accumulated AD nodes across all servers for separate file output
	adComputers []*bloodhound.Node
	adUsers     []*bloodhound.Node
	adGroups    []*bloodhound.Node
	adSeenNodes map[string]bool // Dedup AD nodes by ID across servers
	adNodesMu   sync.Mutex      // Protects adComputers, adUsers, adGroups, adSeenNodes
}

// ServerToProcess holds information about a server to be processed
type ServerToProcess struct {
	Hostname         string // FQDN or short hostname
	Port             int    // Port number (default 1433)
	InstanceName     string // Named instance (empty for default)
	ObjectIdentifier string // SID:port or SID:instance
	ConnectionString string // String to use for SQL connection
	ComputerSID      string // Computer SID
	DiscoveredFrom   string // Hostname of server this was discovered from (for linked servers)
	Domain           string // Domain inferred from the source server (for linked servers)
}

// ServerSPNInfo holds SPN-related data discovered from Active Directory
type ServerSPNInfo struct {
	SPNs            []string
	ServiceAccounts []types.ServiceAccount
	AccountName     string
	AccountSID      string
}

// New creates a new collector
func New(config *Config) (*Collector, error) {
	if config.Logger == nil {
		config.Logger = slog.New(logging.NewHandler(os.Stderr, nil))
	}
	c := &Collector{
		config:        config,
		serverSPNData: make(map[string]*ServerSPNInfo),
		adSeenNodes:   make(map[string]bool),
	}
	if config.NTHash != "" {
		hash, err := hex.DecodeString(config.NTHash)
		if err != nil || len(hash) != 16 {
			return nil, fmt.Errorf("--nt-hash must be exactly 32 hex characters (16 bytes): got %d chars", len(config.NTHash))
		}
		c.ntHash = hash
	}
	// Auto-generate krb5.conf for Kerberos if no config file is available.
	// Done at collector level so both MSSQL and AD clients share the same config.
	if config.UseKerberos && config.Krb5ConfigFile == "" {
		configPath := os.Getenv("KRB5_CONFIG")
		if configPath == "" {
			configPath = "/etc/krb5.conf"
		}
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			if config.Domain != "" && config.DC != "" {
				generated, genErr := mssql.GenerateKrb5Config(config.Domain, config.DC)
				if genErr != nil {
					config.Logger.Warn("Failed to auto-generate krb5.conf", "error", genErr)
				} else {
					config.Krb5ConfigFile = generated
					config.Logger.Info("Auto-generated krb5.conf", "path", generated, "domain", config.Domain, "kdc", config.DC)
				}
			} else {
				return nil, fmt.Errorf("--kerberos requires a krb5.conf file: provide --krb5-configfile, or both --domain and --dc for auto-generation")
			}
		}
	}
	return c, nil
}

// getDNSResolver returns the DNS resolver to use, applying the logic:
// if --dc is specified but --dns-resolver is not, use dc as the resolver
func (c *Collector) getDNSResolver() string {
	if c.config.DNSResolver != "" {
		return c.config.DNSResolver
	}
	if c.config.DC != "" {
		return c.config.DC
	}
	return ""
}

// newADClient creates a new AD client with proxy settings if configured.
// Returns nil if a previous LDAP attempt already failed with invalid credentials
// to prevent further authentication attempts that could lock out the AD account.
func (c *Collector) newADClient(domain string) *ad.Client {
	c.ldapAuthFailedMu.RLock()
	failed := c.ldapAuthFailed
	c.ldapAuthFailedMu.RUnlock()
	if failed {
		return nil
	}
	adClient := ad.NewClient(domain, c.config.DC, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword, c.getDNSResolver())
	if c.config.NTHash != "" {
		adClient.SetNTHash(c.config.NTHash)
	}
	if c.config.UseKerberos {
		adClient.SetKerberosConfig(c.config.Krb5ConfigFile, c.config.Krb5CCacheFile, c.config.Krb5KeytabFile, c.config.Krb5Realm)
	}
	if c.config.Verbose {
		adClient.SetLogger(c.config.Logger)
	}
	if c.proxyDialer != nil {
		adClient.SetProxyDialer(c.proxyDialer)
	}
	return adClient
}

// setLDAPAuthFailed marks LDAP authentication as failed to prevent further attempts.
func (c *Collector) setLDAPAuthFailed() {
	c.ldapAuthFailedMu.Lock()
	c.ldapAuthFailed = true
	c.ldapAuthFailedMu.Unlock()
}

// isLDAPAuthError checks if an error indicates invalid LDAP credentials.
func isLDAPAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "Invalid Credentials") ||
		strings.Contains(errStr, "invalid credentials") ||
		strings.Contains(errStr, "Result Code 49")
}

// newMSSQLClient creates a new MSSQL client with proxy settings if configured.
// If log is nil, the collector's base logger is used.
func (c *Collector) newMSSQLClient(serverInstance, userID, password string, log *slog.Logger) *mssql.Client {
	client := mssql.NewClient(serverInstance, userID, password)
	if log != nil {
		client.SetLogger(log)
	} else {
		client.SetLogger(c.config.Logger)
	}
	if c.proxyDialer != nil {
		client.SetProxyDialer(c.proxyDialer)
	}
	if len(c.ntHash) > 0 {
		client.SetNTHash(c.ntHash)
	}
	if c.config.UseKerberos {
		client.SetKerberosConfig(c.config.Krb5ConfigFile, c.config.Krb5CCacheFile, c.config.Krb5KeytabFile, c.config.Krb5Realm)
	}
	return client
}

// Run executes the collection process
func (c *Collector) Run() error {
	runStart := time.Now()

	// Setup temp directory
	if err := c.setupTempDir(); err != nil {
		return fmt.Errorf("failed to setup temp directory: %w", err)
	}
	c.config.Logger.Info("Temporary output directory", "path", c.tempDir)

	var zipPath string

	if !c.config.SkipCollection {
		// Create proxy dialer if configured
		if c.config.ProxyAddr != "" {
			pd, err := proxydialer.New(c.config.ProxyAddr)
			if err != nil {
				return fmt.Errorf("failed to create proxy dialer: %w", err)
			}
			c.proxyDialer = pd
		}

		// Build list of servers to process
		if err := c.buildServerList(); err != nil {
			return fmt.Errorf("failed to build server list: %w", err)
		}

		if len(c.serversToProcess) == 0 {
			return fmt.Errorf("no servers to process")
		}

		c.config.Logger.Info("Processing SQL Servers", "count", len(c.serversToProcess))
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Memory usage", "usage", c.getMemoryUsage())

		// Track all processed servers to avoid duplicates
		processedServers := make(map[string]bool)

		// Process servers (concurrently if workers > 0)
		if c.config.Workers > 0 {
			c.processServersConcurrently()
			// Mark all initial servers as processed
			for _, server := range c.serversToProcess {
				processedServers[strings.ToLower(server.Hostname)] = true
			}
		} else {
			// Sequential processing
			for i, server := range c.serversToProcess {
				log := c.config.Logger.With("target", server.ConnectionString)
				log.Info("Processing server", "progress", fmt.Sprintf("%d/%d", i+1, len(c.serversToProcess)))
				processedServers[strings.ToLower(server.Hostname)] = true

				if err := c.processServer(server); err != nil {
					log.Warn("Failed to process server", "error", err)
					// Continue with other servers
				}
			}
		}

		// Process linked servers recursively if enabled
		if c.config.CollectFromLinkedServers {
			c.processLinkedServersQueue(processedServers)
		}

		// Write accumulated AD nodes to separate files (computers.json, users.json, groups.json)
		if !c.config.SkipADNodeCreation {
			if err := c.writeADFiles(); err != nil {
				return fmt.Errorf("failed to write AD files: %w", err)
			}
		}

		// Create zip file
		if len(c.outputFiles) > 0 {
			var err error
			zipPath, err = c.createZipFile()
			if err != nil {
				return fmt.Errorf("failed to create zip file: %w", err)
			}
			c.config.Logger.Info("Output written", "path", zipPath)
		} else {
			c.config.Logger.Info("No data collected - no output file created")
		}

		// Create separate zip for per-target log files
		if c.config.LogPerTarget && len(c.logFiles) > 0 {
			logsZipPath, err := c.createLogsZipFile()
			if err != nil {
				return fmt.Errorf("failed to create logs zip file: %w", err)
			}
			c.config.Logger.Info("Per-target logs written", "path", logsZipPath)
		}
	} else {
		c.config.Logger.Info("Skipping collection (--skip-collection)")
	}

	// Upload to BloodHound CE if configured
	if c.config.UploadSchema || (c.config.UploadResults && zipPath != "") {
		if err := c.uploadToBloodHound(zipPath); err != nil {
			c.config.Logger.Warn("BloodHound upload failed", "error", err)
		}
	}

	c.config.Logger.Info("Total run duration", "duration", time.Since(runStart).Round(time.Millisecond))

	return nil
}

// serverJob represents a server processing job
type serverJob struct {
	index  int
	server *ServerToProcess
}

// serverResult represents the result of processing a server
type serverResult struct {
	index      int
	server     *ServerToProcess
	outputFile string
	err        error
}

// processServersConcurrently processes servers using a worker pool
func (c *Collector) processServersConcurrently() {
	numWorkers := c.config.Workers
	totalServers := len(c.serversToProcess)

	c.config.Logger.Info("Using concurrent workers", "count", numWorkers)

	// Create channels
	jobs := make(chan serverJob, totalServers)
	results := make(chan serverResult, totalServers)

	// Start workers
	var wg sync.WaitGroup
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go c.serverWorker(w, jobs, results, &wg)
	}

	// Send jobs
	for i, server := range c.serversToProcess {
		jobs <- serverJob{index: i, server: server}
	}
	close(jobs)

	// Wait for workers in a goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	successCount := 0
	failCount := 0
	completed := 0
	for result := range results {
		completed++
		log := c.config.Logger.With("target", result.server.ConnectionString, "progress", fmt.Sprintf("%d/%d", completed, totalServers))
		if result.err != nil {
			log.Warn("Server processing failed", "error", result.err)
			failCount++
		} else {
			log.Info("Server processing succeeded")
			successCount++
		}
	}

	c.config.Logger.Info("Processing completed", "succeeded", successCount, "failed", failCount)
}

// serverWorker is a worker goroutine that processes servers from the jobs channel.
// Each job is wrapped in a closure with panic recovery to prevent a single panicking
// server from deadlocking the entire worker pool (wg.Wait would hang forever).
func (c *Collector) serverWorker(id int, jobs <-chan serverJob, results chan<- serverResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Worker processing server", "worker", id, "target", job.server.ConnectionString)

		func() {
			defer func() {
				if r := recover(); r != nil {
					c.config.Logger.Error("Worker panic recovered", "worker", id, "target", job.server.ConnectionString, "panic", r)
					results <- serverResult{
						index:  job.index,
						server: job.server,
						err:    fmt.Errorf("worker panicked: %v", r),
					}
				}
			}()

			err := c.processServer(job.server)
			results <- serverResult{
				index:  job.index,
				server: job.server,
				err:    err,
			}
		}()
	}
}

// addOutputFile adds an output file to the list (thread-safe)
func (c *Collector) addOutputFile(path string) {
	c.outputFilesMu.Lock()
	defer c.outputFilesMu.Unlock()
	c.outputFiles = append(c.outputFiles, path)
}

// addLogFile adds a per-target log file to the list (thread-safe)
func (c *Collector) addLogFile(path string) {
	c.logFilesMu.Lock()
	defer c.logFilesMu.Unlock()
	c.logFiles = append(c.logFiles, path)
}

// createTargetLogger creates a logger for a specific server target.
// When LogPerTarget is enabled, it returns a logger that writes to both stderr
// and a per-target log file, plus a cleanup function to close the file.
// When LogPerTarget is disabled, it returns a standard logger with a no-op cleanup.
func (c *Collector) createTargetLogger(server *ServerToProcess) (*slog.Logger, func()) {
	baseLog := c.config.Logger.With("target", server.ConnectionString)

	if !c.config.LogPerTarget {
		return baseLog, func() {}
	}

	logPath := filepath.Join(c.tempDir, c.generateLogFilename(server))
	f, err := os.Create(logPath)
	if err != nil {
		c.config.Logger.Warn("Failed to create per-target log file, falling back to stderr only",
			"target", server.ConnectionString, "path", logPath, "error", err)
		return baseLog, func() {}
	}

	fileHandler := logging.NewHandler(f, &logging.Options{
		Level:   c.config.LogLevel,
		NoColor: true,
	})

	multi := logging.NewMultiHandler(c.config.Logger.Handler(), fileHandler)
	multiLog := slog.New(multi).With("target", server.ConnectionString)

	c.addLogFile(logPath)

	return multiLog, func() { f.Close() }
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

// parseServerString parses a server string (hostname, hostname:port, hostname\instance, SPN)
// and returns a ServerToProcess entry. Does not resolve SIDs.
func (c *Collector) parseServerString(serverStr string) *ServerToProcess {
	server := &ServerToProcess{
		Port: 1433, // Default port
	}

	// Handle SPN format: MSSQLSvc/hostname:portOrInstance
	if strings.HasPrefix(strings.ToUpper(serverStr), "MSSQLSVC/") {
		serverStr = serverStr[9:] // Remove "MSSQLSvc/"
	}

	// Handle formats: hostname, hostname:port, hostname\instance, hostname,port
	if strings.Contains(serverStr, "\\") {
		parts := strings.SplitN(serverStr, "\\", 2)
		server.Hostname = parts[0]
		if len(parts) > 1 {
			server.InstanceName = parts[1]
		}
		server.ConnectionString = serverStr
	} else if strings.Contains(serverStr, ":") {
		parts := strings.SplitN(serverStr, ":", 2)
		server.Hostname = parts[0]
		if len(parts) > 1 {
			// Check if it's a port number or instance name
			if port, err := strconv.Atoi(parts[1]); err == nil {
				server.Port = port
			} else {
				server.InstanceName = parts[1]
			}
		}
		server.ConnectionString = serverStr
	} else if strings.Contains(serverStr, ",") {
		parts := strings.SplitN(serverStr, ",", 2)
		server.Hostname = parts[0]
		if len(parts) > 1 {
			if port, err := strconv.Atoi(parts[1]); err == nil {
				server.Port = port
			}
		}
		server.ConnectionString = serverStr
	} else {
		server.Hostname = serverStr
		server.ConnectionString = serverStr
	}

	return server
}

// extractLineCredentials strips user:pass@ from a target line, applying the
// credentials to config.UserID/Password (first match wins). Returns the cleaned target.
func (c *Collector) extractLineCredentials(line string) string {
	atIdx := strings.LastIndex(line, "@")
	if atIdx < 0 {
		return line
	}

	credentials := line[:atIdx]
	target := line[atIdx+1:]

	colonIdx := strings.Index(credentials, ":")
	if colonIdx < 0 || credentials[:colonIdx] == "" || target == "" {
		return line
	}

	if c.config.UserID == "" {
		c.config.UserID = credentials[:colonIdx]
		c.config.Password = credentials[colonIdx+1:]
		c.config.Logger.Info("Parsed inline credentials from target file", "user", c.config.UserID)
	}
	return target
}

// addServerToProcess adds a server to the processing list, deduplicating by ObjectIdentifier
func (c *Collector) addServerToProcess(server *ServerToProcess) {
	// Build ObjectIdentifier if we have a SID
	if server.ComputerSID != "" {
		if server.InstanceName != "" && server.InstanceName != "MSSQLSERVER" {
			server.ObjectIdentifier = fmt.Sprintf("%s:%s", server.ComputerSID, server.InstanceName)
		} else {
			server.ObjectIdentifier = fmt.Sprintf("%s:%d", server.ComputerSID, server.Port)
		}
	} else {
		// Use hostname-based identifier if no SID
		hostname := strings.ToLower(server.Hostname)
		if server.InstanceName != "" && server.InstanceName != "MSSQLSERVER" {
			server.ObjectIdentifier = fmt.Sprintf("%s:%s", hostname, server.InstanceName)
		} else {
			server.ObjectIdentifier = fmt.Sprintf("%s:%d", hostname, server.Port)
		}
	}

	// Check for duplicates
	for _, existing := range c.serversToProcess {
		if existing.ObjectIdentifier == server.ObjectIdentifier {
			// Update hostname to prefer FQDN
			if !strings.Contains(existing.Hostname, ".") && strings.Contains(server.Hostname, ".") {
				existing.Hostname = server.Hostname
			}
			return // Already exists
		}
	}

	c.serversToProcess = append(c.serversToProcess, server)
}

// buildServerList builds the list of servers to process
func (c *Collector) buildServerList() error {
	// Create a shared AD client for SID resolution across all servers in the list.
	// This avoids creating a new LDAP connection per server.
	var sharedADClient *ad.Client
	if c.config.Domain != "" {
		sharedADClient = c.newADClient(c.config.Domain)
		if sharedADClient != nil {
			defer sharedADClient.Close()
		}
	}

	// From command line argument
	if c.config.ServerInstance != "" {
		server := c.parseServerString(c.config.ServerInstance)
		c.tryResolveSID(server, sharedADClient)
		c.addServerToProcess(server)
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Added server from command line", "server", c.config.ServerInstance)
	}

	// From comma-separated list
	if c.config.ServerList != "" {
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Processing comma-separated server list")
		servers := strings.Split(c.config.ServerList, ",")
		count := 0
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s != "" {
				server := c.parseServerString(s)
				c.tryResolveSID(server, sharedADClient)
				c.addServerToProcess(server)
				count++
			}
		}
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Added servers from list", "count", count)
	}

	// From file
	if c.config.ServerListFile != "" {
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Processing server list file", "path", c.config.ServerListFile)
		data, err := os.ReadFile(c.config.ServerListFile)
		if err != nil {
			return fmt.Errorf("failed to read server list file: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		count := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				line = c.extractLineCredentials(line)
				server := c.parseServerString(line)
				c.tryResolveSID(server, sharedADClient)
				c.addServerToProcess(server)
				count++
			}
		}
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Added servers from file", "count", count)
	}

	// Auto-detect domain if not provided and we have servers
	if c.config.Domain == "" && len(c.serversToProcess) > 0 {
		// Try to extract domain from server FQDNs first
		for _, server := range c.serversToProcess {
			if strings.Contains(server.Hostname, ".") {
				parts := strings.SplitN(server.Hostname, ".", 2)
				if len(parts) == 2 && parts[1] != "" {
					c.config.Domain = strings.ToUpper(parts[1])
					c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Auto-detected domain from server FQDN", "domain", c.config.Domain)
					break
				}
			}
		}
		// Fallback to environment variables
		if c.config.Domain == "" {
			c.config.Domain = c.detectDomain()
		}
	}

	// If no servers specified, enumerate SPNs from Active Directory
	if len(c.serversToProcess) == 0 {
		// Auto-detect domain if not provided
		domain := c.config.Domain
		if domain == "" {
			domain = c.detectDomain()
		}

		if domain != "" {
			// Update config.Domain so it's available for later resolution
			c.config.Domain = domain
			c.config.Logger.With("target", domain).Info("No servers specified, enumerating MSSQL SPNs from Active Directory")
			if err := c.enumerateServersFromAD(); err != nil {
				hint := "Hint: use --server/--server-list/--server-list-file to specify servers manually, or --ldap-user/--ldap-password for LDAP credentials"
				if runtime.GOOS != "windows" && c.config.LDAPUser == "" {
					hint = "On Linux/macOS, explicit LDAP credentials are required for SPN enumeration. Use --ldap-user and --ldap-password, or specify servers manually with --server/--server-list/--server-list-file"
				}
				c.config.Logger.Error(hint, "error", err)
			}
		} else {
			c.config.Logger.Error("No servers specified and could not detect domain. Use --domain to specify a domain or --server to specify a server.")
		}
	}

	// Deduplicate servers that resolve to the same IP (e.g. NetBIOS vs FQDN)
	c.deduplicateByIP()

	return nil
}

// deduplicateByIP removes servers whose hostnames resolve to the same IP address,
// preferring entries with FQDNs over NetBIOS names.
func (c *Collector) deduplicateByIP() {
	type ipKey struct {
		ip       string
		port     int
		instance string
	}

	c.config.Logger.Info("Deduplicating servers by resolved IP", "count", len(c.serversToProcess))

	seen := make(map[ipKey]int) // ipKey -> index in deduplicated slice
	var deduplicated []*ServerToProcess

	resolver := net.DefaultResolver

	for _, server := range c.serversToProcess {
		// Resolve hostname to IP with a short timeout to avoid blocking on unresolvable hosts
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addrs, err := resolver.LookupHost(ctx, server.Hostname)
		cancel()
		if err != nil || len(addrs) == 0 {
			c.config.Logger.Log(context.Background(), logging.LevelVerbose, "DNS lookup failed, keeping server as-is",
				"hostname", server.Hostname, "error", err)
			deduplicated = append(deduplicated, server)
			continue
		}
		ip := addrs[0]
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Resolved hostname",
			"hostname", server.Hostname, "ip", ip)

		key := ipKey{ip: ip, port: server.Port, instance: strings.ToUpper(server.InstanceName)}
		if idx, exists := seen[key]; exists {
			existing := deduplicated[idx]
			// Prefer FQDN over NetBIOS
			isFQDN := strings.Contains(server.Hostname, ".")
			existingIsFQDN := strings.Contains(existing.Hostname, ".")
			if isFQDN && !existingIsFQDN {
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Dedup by IP: replacing",
					"old", existing.Hostname, "new", server.Hostname, "ip", ip)
				deduplicated[idx] = server
			} else {
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Dedup by IP: skipping duplicate",
					"skipped", server.Hostname, "kept", existing.Hostname, "ip", ip)
			}
			continue
		}
		seen[key] = len(deduplicated)
		deduplicated = append(deduplicated, server)
	}

	if removed := len(c.serversToProcess) - len(deduplicated); removed > 0 {
		c.config.Logger.Info("Deduplicated servers by resolved IP", "removed", removed)
	}
	c.serversToProcess = deduplicated
}

// tryResolveSID attempts to resolve the computer SID for a server.
// If sharedClient is non-nil, it is used for LDAP lookups instead of creating a new connection.
func (c *Collector) tryResolveSID(server *ServerToProcess, sharedClient *ad.Client) {
	if c.config.Domain == "" {
		return
	}

	// Try Windows API first
	if runtime.GOOS == "windows" {
		sid, err := ad.ResolveComputerSIDWindows(server.Hostname, c.config.Domain)
		if err == nil && sid != "" {
			server.ComputerSID = sid
			return
		}
	}

	// Use shared client if available, otherwise create a one-off client
	adClient := sharedClient
	if adClient == nil {
		adClient = c.newADClient(c.config.Domain)
		if adClient == nil {
			return
		}
		defer adClient.Close()
	}

	sid, err := adClient.ResolveComputerSID(server.Hostname)
	if err != nil && isLDAPAuthError(err) {
		c.setLDAPAuthFailed()
		return
	}
	if err == nil && sid != "" {
		server.ComputerSID = sid
	}
}

// detectDomain attempts to auto-detect the domain from environment variables or system configuration.
// Returns the domain name in UPPERCASE to match BloodHound conventions.
func (c *Collector) detectDomain() string {
	// Try USERDNSDOMAIN environment variable (Windows domain-joined machines)
	if domain := os.Getenv("USERDNSDOMAIN"); domain != "" {
		domain = strings.ToUpper(domain)
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Detected domain from USERDNSDOMAIN", "domain", domain)
		return domain
	}

	// Try USERDOMAIN environment variable as fallback
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		domain = strings.ToUpper(domain)
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Detected domain from USERDOMAIN", "domain", domain)
		return domain
	}

	// On Linux/Unix, try to get domain from /etc/resolv.conf or similar
	if runtime.GOOS != "windows" {
		if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "search ") {
					parts := strings.Fields(line)
					if len(parts) > 1 {
						domain := strings.ToUpper(parts[1])
						c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Detected domain from /etc/resolv.conf", "domain", domain)
						return domain
					}
				}
				if strings.HasPrefix(line, "domain ") {
					parts := strings.Fields(line)
					if len(parts) > 1 {
						domain := strings.ToUpper(parts[1])
						c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Detected domain from /etc/resolv.conf", "domain", domain)
						return domain
					}
				}
			}
		}
	}

	return ""
}

// enumerateServersFromAD discovers MSSQL servers from Active Directory SPNs.
// Uses a single shared LDAP connection for all SPN enumeration and SID resolution.
func (c *Collector) enumerateServersFromAD() error {
	// Create a single AD client for the entire enumeration phase.
	// This client is reused for SPN enumeration, ScanAllComputers, and per-server SID resolution.
	adClient := c.newADClient(c.config.Domain)
	if adClient == nil {
		return fmt.Errorf("LDAP authentication previously failed, skipping AD enumeration")
	}
	defer adClient.Close()

	spns, err := adClient.EnumerateMSSQLSPNs()

	if err != nil && isLDAPAuthError(err) {
		c.setLDAPAuthFailed()
		return fmt.Errorf("LDAP authentication failed: %w", err)
	}

	// If LDAP failed on Windows, try using PowerShell/ADSI as fallback
	if err != nil && runtime.GOOS == "windows" {
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "LDAP enumeration failed, trying PowerShell/ADSI fallback...")
		spns, err = c.enumerateSPNsViaPowerShell()
	}

	if err != nil {
		return fmt.Errorf("failed to enumerate MSSQL SPNs: %w", err)
	}

	c.config.Logger.Info("LDAP bind successful", "auth", adClient.AuthMethod())
	c.config.Logger.Info("Found MSSQL SPNs", "count", len(spns))

	for _, spn := range spns {
		// Create ServerToProcess from SPN
		server := &ServerToProcess{
			Hostname: spn.Hostname,
			Port:     1433, // Default
		}

		// Parse port or instance from SPN
		if spn.Port != "" {
			if port, err := strconv.Atoi(spn.Port); err == nil {
				server.Port = port
			}
			server.ConnectionString = fmt.Sprintf("%s:%s", spn.Hostname, spn.Port)
		} else if spn.InstanceName != "" {
			server.InstanceName = spn.InstanceName
			server.ConnectionString = fmt.Sprintf("%s\\%s", spn.Hostname, spn.InstanceName)
		} else {
			server.ConnectionString = spn.Hostname
		}

		// Try to resolve computer SID early (reuses shared AD client)
		c.tryResolveSID(server, adClient)

		// Build ObjectIdentifier and add to processing list (handles deduplication)
		c.addServerToProcess(server)

		// Track SPN data by ObjectIdentifier for later use
		c.serverSPNDataMu.Lock()
		spnInfo, exists := c.serverSPNData[server.ObjectIdentifier]
		if !exists {
			spnInfo = &ServerSPNInfo{
				SPNs:        []string{},
				AccountName: spn.AccountName,
				AccountSID:  spn.AccountSID,
			}
			c.serverSPNData[server.ObjectIdentifier] = spnInfo
		}
		c.serverSPNDataMu.Unlock()

		// Build full SPN string and add it
		fullSPN := fmt.Sprintf("MSSQLSvc/%s", spn.Hostname)
		if spn.Port != "" {
			fullSPN = fmt.Sprintf("MSSQLSvc/%s:%s", spn.Hostname, spn.Port)
		} else if spn.InstanceName != "" {
			fullSPN = fmt.Sprintf("MSSQLSvc/%s:%s", spn.Hostname, spn.InstanceName)
		}
		spnInfo.SPNs = append(spnInfo.SPNs, fullSPN)

		c.config.Logger.Info("Found SPN", "server", server.ConnectionString, "objectID", server.ObjectIdentifier, "serviceAccount", spn.AccountName)
	}

	// If ScanAllComputers is enabled, also enumerate all domain computers
	// Reuses the same shared AD client from above.
	if c.config.ScanAllComputers {
		c.config.Logger.Info("ScanAllComputers enabled, enumerating all domain computers")

		computers, err := adClient.EnumerateAllComputers()
		if err != nil && isLDAPAuthError(err) {
			c.setLDAPAuthFailed()
			c.config.Logger.Warn("LDAP authentication failed", "error", err)
			return nil
		}
		if err != nil && runtime.GOOS == "windows" {
			// Try PowerShell fallback on Windows
			c.config.Logger.Info("LDAP enumeration failed, trying PowerShell fallback", "error", err)
			computers, err = c.enumerateComputersViaPowerShell()
		}
		if err != nil {
			c.config.Logger.Warn("Failed to enumerate domain computers", "error", err)
		} else {
			added := 0
			for _, computer := range computers {
				server := c.parseServerString(computer)
				c.tryResolveSID(server, adClient)
				oldLen := len(c.serversToProcess)
				c.addServerToProcess(server)
				if len(c.serversToProcess) > oldLen {
					added++
				}
			}
			c.config.Logger.Info("Added additional computers to scan", "count", added)
		}
	}

	c.config.Logger.Info("Unique servers to process", "count", len(c.serversToProcess))
	c.spnEnumerationDone = true
	return nil
}

// enumerateSPNsViaPowerShell uses PowerShell/ADSI to enumerate MSSQL SPNs (Windows fallback)
func (c *Collector) enumerateSPNsViaPowerShell() ([]types.SPN, error) {
	c.config.Logger.Info("Using PowerShell/ADSI fallback for SPN enumeration")

	// PowerShell script to enumerate MSSQL SPNs using ADSI
	script := `
$searcher = [adsisearcher]"(servicePrincipalName=MSSQLSvc/*)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@('servicePrincipalName', 'samAccountName', 'objectSid'))
$results = $searcher.FindAll()
foreach ($result in $results) {
    $sid = (New-Object System.Security.Principal.SecurityIdentifier($result.Properties['objectsid'][0], 0)).Value
    $samName = $result.Properties['samaccountname'][0]
    foreach ($spn in $result.Properties['serviceprincipalname']) {
        if ($spn -like 'MSSQLSvc/*') {
            Write-Output "$spn|$samName|$sid"
        }
    }
}
`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("PowerShell SPN enumeration failed: %w", err)
	}

	var spns []types.SPN
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		spnStr := parts[0]
		accountName := parts[1]
		accountSID := parts[2]

		// Parse SPN: MSSQLSvc/hostname:port or MSSQLSvc/hostname:instancename
		spn := c.parseSPN(spnStr, accountName, accountSID)
		if spn != nil {
			spns = append(spns, *spn)
		}
	}

	return spns, nil
}

// enumerateComputersViaPowerShell uses PowerShell/ADSI to enumerate all domain computers (Windows fallback)
func (c *Collector) enumerateComputersViaPowerShell() ([]string, error) {
	c.config.Logger.Info("Using PowerShell/ADSI fallback for computer enumeration")

	// PowerShell script to enumerate all domain computers using ADSI
	script := `
$searcher = [adsisearcher]"(&(objectCategory=computer)(objectClass=computer))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@('dNSHostName', 'name'))
$results = $searcher.FindAll()
foreach ($result in $results) {
    $dns = $result.Properties['dnshostname']
    $name = $result.Properties['name']
    if ($dns -and $dns[0]) {
        Write-Output $dns[0]
    } elseif ($name -and $name[0]) {
        Write-Output $name[0]
    }
}
`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("PowerShell computer enumeration failed: %w", err)
	}

	var computers []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			computers = append(computers, line)
		}
	}

	c.config.Logger.Info("PowerShell enumerated computers", "count", len(computers))
	return computers, nil
}

// parseSPN parses an SPN string into an SPN struct
func (c *Collector) parseSPN(spnStr, accountName, accountSID string) *types.SPN {
	// Format: MSSQLSvc/hostname:portOrInstance
	if !strings.HasPrefix(strings.ToUpper(spnStr), "MSSQLSVC/") {
		return nil
	}

	remainder := spnStr[9:] // Remove "MSSQLSvc/"
	parts := strings.SplitN(remainder, ":", 2)
	hostname := parts[0]

	var port, instanceName string
	if len(parts) > 1 {
		portOrInstance := parts[1]
		// Check if it's a port number
		if _, err := fmt.Sscanf(portOrInstance, "%d", new(int)); err == nil {
			port = portOrInstance
		} else {
			instanceName = portOrInstance
		}
	}

	return &types.SPN{
		Hostname:     hostname,
		Port:         port,
		InstanceName: instanceName,
		AccountName:  accountName,
		AccountSID:   accountSID,
	}
}

// processServer collects data from a single SQL Server
func (c *Collector) processServer(server *ServerToProcess) error {
	targetStart := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log, logCleanup := c.createTargetLogger(server)
	defer func() {
		log.Info("Target completed", "duration", time.Since(targetStart).Round(time.Millisecond))
		logCleanup()
	}()

	// Check if we have SPN data for this server (keyed by ObjectIdentifier)
	c.serverSPNDataMu.RLock()
	spnInfo := c.serverSPNData[server.ObjectIdentifier]
	c.serverSPNDataMu.RUnlock()

	// Connect to the server
	client := c.newMSSQLClient(server.ConnectionString, c.config.UserID, c.config.Password, log)
	client.SetDomain(c.config.Domain)
	client.SetLDAPCredentials(c.config.LDAPUser, c.config.LDAPPassword)
	client.SetDNSResolver(c.getDNSResolver())
	client.SetVerbose(c.config.Verbose)
	client.SetDebug(c.config.Debug)
	client.SetCollectFromLinkedServers(c.config.CollectFromLinkedServers)

	// Quick port check before attempting EPA or authentication
	if err := client.CheckPort(ctx); err != nil {
		log.Warn("Port not reachable, skipping", "error", err)
		if spnInfo != nil {
			return c.processServerFromSPNData(server, spnInfo, nil, err, log)
		}
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			return c.processServerFromSPNData(server, spnInfo, nil, err, log)
		}
		return fmt.Errorf("port not reachable: %w", err)
	}

	// Run EPA checks before attempting SQL authentication
	var epaResult *mssql.EPATestResult
	var epaPrereqFailed bool
	if !c.config.UseKerberos && c.config.LDAPUser != "" && (c.config.LDAPPassword != "" || c.config.NTHash != "") {
		var epaErr error
		epaResult, epaErr = client.TestEPA(ctx)
		if epaErr != nil {
			if mssql.IsEPAPrereqError(epaErr) {
				// Prereq check failed - don't continue with authentication attempts
				// (matches Python mssql.py flow: prereq failure => exit)
				log.Warn("EPA prereq check failed, skipping authentication", "error", epaErr)
				epaPrereqFailed = true
			} else {
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "EPA pre-check failed", "target", server.ConnectionString, "error", epaErr)
			}
			epaResult = nil
		} else {
			client.SetEPAResult(epaResult)
		}
	}

	if epaPrereqFailed {
		// Check if we have separate SQL credentials to fall back on.
		// EPA uses LDAP/domain creds (NTLM); SQL auth (UserID/Password) is independent.
		hasSeparateSQLCreds := c.config.UserID != "" && c.config.Password != "" &&
			(c.config.UserID != c.config.LDAPUser || c.config.Password != c.config.LDAPPassword)

		if hasSeparateSQLCreds {
			log.Warn("EPA prereq failed with domain credentials, falling back to SQL auth",
				"sqlUser", c.config.UserID)
			// Fall through to Connect() which uses UserID/Password
		} else {
			// No separate SQL creds - skip authentication, go straight to partial output
			if spnInfo != nil {
				log.Info("EPA prereq failed but server has SPN - creating nodes/edges from SPN data")
				return c.processServerFromSPNData(server, spnInfo, epaResult, fmt.Errorf("EPA prereq check failed"), log)
			}
			spnInfo = c.lookupSPNsForServer(server)
			if spnInfo != nil {
				log.Info("EPA prereq failed - looked up SPN from AD, creating partial output")
				return c.processServerFromSPNData(server, spnInfo, epaResult, fmt.Errorf("EPA prereq check failed"), log)
			}
			return fmt.Errorf("EPA prereq check failed and no SPN data available for %s", server.ConnectionString)
		}
	}

	// If the EPA unmodified connection failed (login_failed), the credentials don't
	// work for SQL login. Skip Connect() to avoid wasted attempts and potential
	// account lockout with the same bad credentials.
	if epaResult != nil && !epaResult.UnmodifiedSuccess {
		log.Info("EPA unmodified connection failed, skipping authentication attempts")
		if spnInfo != nil {
			log.Info("Server has SPN - creating nodes/edges from SPN/EPA data")
			return c.processServerFromSPNData(server, spnInfo, epaResult, fmt.Errorf("EPA unmodified connection failed"), log)
		}
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			log.Info("Looked up SPN from AD, creating partial output")
			return c.processServerFromSPNData(server, spnInfo, epaResult, fmt.Errorf("EPA unmodified connection failed"), log)
		}
		// No SPN data but EPA data is available
		log.Info("No SPN data but EPA data available, creating partial output")
		return c.processServerFromSPNData(server, nil, epaResult, fmt.Errorf("EPA unmodified connection failed"), log)
	}

	if err := client.Connect(ctx); err != nil {
		// If SQL auth failed and the same credentials are used for LDAP, mark LDAP
		// as failed too to prevent redundant auth attempts that could lock out the account.
		if mssql.IsAuthError(err) && c.config.UserID == c.config.LDAPUser {
			c.setLDAPAuthFailed()
		}

		// If hostname doesn't have a domain but we have one from linked server discovery, try FQDN
		if server.Domain != "" && !strings.Contains(server.Hostname, ".") {
			fqdnHostname := server.Hostname + "." + server.Domain
			c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Connection failed, trying FQDN", "fqdn", fqdnHostname)

			// Build FQDN connection string
			fqdnConnStr := fqdnHostname
			if server.Port != 0 && server.Port != 1433 {
				fqdnConnStr = fmt.Sprintf("%s:%d", fqdnHostname, server.Port)
			} else if server.InstanceName != "" {
				fqdnConnStr = fmt.Sprintf("%s\\%s", fqdnHostname, server.InstanceName)
			}

			fqdnClient := c.newMSSQLClient(fqdnConnStr, c.config.UserID, c.config.Password, log)
			fqdnClient.SetDomain(c.config.Domain)
			fqdnClient.SetLDAPCredentials(c.config.LDAPUser, c.config.LDAPPassword)
			fqdnClient.SetVerbose(c.config.Verbose)
			fqdnClient.SetDebug(c.config.Debug)
			fqdnClient.SetCollectFromLinkedServers(c.config.CollectFromLinkedServers)

			// Run EPA checks before attempting SQL authentication on FQDN client
			var fqdnEPAPrereqFailed bool
			if !c.config.UseKerberos && c.config.LDAPUser != "" && (c.config.LDAPPassword != "" || c.config.NTHash != "") {
				fqdnEPAResult, epaErr := fqdnClient.TestEPA(ctx)
				if epaErr != nil {
					if mssql.IsEPAPrereqError(epaErr) {
						log.Warn("EPA prereq check failed for FQDN, skipping authentication", "fqdn", fqdnConnStr, "error", epaErr)
						fqdnEPAPrereqFailed = true
					} else {
						c.config.Logger.Log(context.Background(), logging.LevelVerbose, "EPA pre-check failed", "target", fqdnConnStr, "error", epaErr)
					}
				} else {
					fqdnClient.SetEPAResult(fqdnEPAResult)
					epaResult = fqdnEPAResult // Use FQDN EPA result as the canonical result
				}
			}

			// Skip Connect if EPA prereq failed or unmodified connection failed
			fqdnSkipConnect := fqdnEPAPrereqFailed
			if !fqdnSkipConnect && epaResult != nil && !epaResult.UnmodifiedSuccess {
				log.Info("EPA unmodified connection failed for FQDN, skipping authentication", "fqdn", fqdnConnStr)
				fqdnSkipConnect = true
			}
			if fqdnSkipConnect {
				fqdnClient.Close()
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Skipping Connect (EPA prereq/unmodified failed)", "target", fqdnConnStr)
			} else {
				fqdnErr := fqdnClient.Connect(ctx)
				if fqdnErr == nil {
					// FQDN connection succeeded - update server info and continue
					log.Info("Connected using FQDN", "fqdn", fqdnHostname)
					server.Hostname = fqdnHostname
					server.ConnectionString = fqdnConnStr
					client = fqdnClient
					// Fall through to continue with collection
					goto connected
				}
				fqdnClient.Close()
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "FQDN connection also failed", "error", fqdnErr)
			}
		}

		// Connection failed - check if we have SPN data to create partial output
		if spnInfo != nil {
			log.Info("Connection failed but server has SPN - creating nodes/edges from SPN data")
			return c.processServerFromSPNData(server, spnInfo, epaResult, err, log)
		}

		// No SPN data available - try to look up SPNs from AD for this server
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			log.Info("Connection failed - looked up SPN from AD, creating partial output")
			return c.processServerFromSPNData(server, spnInfo, epaResult, err, log)
		}

		// No SPN data - check if we have EPA data to create a minimal node
		if epaResult != nil {
			log.Info("Connection failed - no SPN data but EPA data available, creating partial output")
			return c.processServerFromSPNData(server, nil, epaResult, err, log)
		}

		// No SPN data and no EPA data - skip this server
		return fmt.Errorf("connection failed and no SPN/EPA data available: %w", err)
	}

connected:
	defer client.Close()

	c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Successfully connected", "target", server.ConnectionString)

	// Collect server information
	serverInfo, err := client.CollectServerInfo(ctx)
	if err != nil {
		// Collection failed after connection - try partial output if we have SPN data
		if spnInfo != nil {
			log.Info("Collection failed but server has SPN - creating nodes/edges from SPN data")
			return c.processServerFromSPNData(server, spnInfo, epaResult, err, log)
		}

		// Try AD lookup for SPN data
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			log.Info("Collection failed - looked up SPN from AD, creating partial output")
			return c.processServerFromSPNData(server, spnInfo, epaResult, err, log)
		}

		// No SPN data - check if we have EPA data to create a minimal node
		if epaResult != nil {
			log.Info("Collection failed - no SPN data but EPA data available, creating partial output")
			return c.processServerFromSPNData(server, nil, epaResult, err, log)
		}

		return fmt.Errorf("collection failed: %w", err)
	}

	// Merge SPN data if available
	if spnInfo != nil {
		if len(serverInfo.SPNs) == 0 {
			serverInfo.SPNs = spnInfo.SPNs
		}
		// Add service account from SPN if not already present
		if len(serverInfo.ServiceAccounts) == 0 && spnInfo.AccountName != "" {
			serverInfo.ServiceAccounts = append(serverInfo.ServiceAccounts, types.ServiceAccount{
				Name:             spnInfo.AccountName,
				SID:              spnInfo.AccountSID,
				ObjectIdentifier: spnInfo.AccountSID,
			})
		}
	}

	// If service accounts are still empty (e.g. Linux SQL Server where the DMV
	// and registry methods both fail), try looking up SPNs from AD as a fallback.
	if len(serverInfo.ServiceAccounts) == 0 && spnInfo == nil {
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			if len(serverInfo.SPNs) == 0 {
				serverInfo.SPNs = spnInfo.SPNs
			}
			if spnInfo.AccountName != "" {
				serverInfo.ServiceAccounts = append(serverInfo.ServiceAccounts, types.ServiceAccount{
					Name:             spnInfo.AccountName,
					SID:              spnInfo.AccountSID,
					ObjectIdentifier: spnInfo.AccountSID,
				})
				log.Info("Resolved service account from AD SPN lookup", "account", spnInfo.AccountName)
			}
		}
	}

	// Warn if no service account could be resolved by any method
	if len(serverInfo.ServiceAccounts) == 0 {
		log.Warn("Could not determine service account (sys.dm_server_services, registry, and SPN lookup all failed)")
	}

	// Create a shared AD client for all LDAP resolution calls within this server.
	// This avoids the N+1 connection problem where each resolution call would
	// create its own LDAP connection (TCP + TLS + bind) per identity.
	var sharedADClient *ad.Client
	if c.config.Domain != "" {
		sharedADClient = c.newADClient(c.config.Domain)
		if sharedADClient != nil {
			defer sharedADClient.Close()
		}
	}

	// If we couldn't get the computer SID from SQL Server, try other methods
	// The resolution function will extract domain from FQDN if not provided
	if serverInfo.ComputerSID == "" {
		c.resolveComputerSIDViaLDAP(serverInfo, log, sharedADClient)
	}

	// Convert built-in service accounts (LocalSystem, Local Service, Network Service)
	// to the computer account, as they authenticate on the network as the computer
	c.preprocessServiceAccounts(serverInfo, log)

	// Resolve service account SIDs via LDAP if they don't have SIDs
	c.resolveServiceAccountSIDsViaLDAP(serverInfo, log, sharedADClient)

	// Resolve credential identity SIDs via LDAP for credential edges
	c.resolveCredentialSIDsViaLDAP(serverInfo, log, sharedADClient)

	// Enumerate local Windows groups that have SQL logins and their domain members
	c.enumerateLocalGroupMembers(serverInfo, log)

	// Check CVE-2025-49758 patch status
	c.logCVE202549758Status(serverInfo, log)

	// Process discovered linked servers
	c.processLinkedServers(serverInfo, server)

	log.Info("Collected server data", "principals", len(serverInfo.ServerPrincipals), "databases", len(serverInfo.Databases))

	// Generate output filename using PowerShell naming convention
	outputFile := filepath.Join(c.tempDir, c.generateFilename(server))

	if err := c.generateOutput(serverInfo, outputFile); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	c.addOutputFile(outputFile)

	return nil
}

// processServerFromSPNData creates partial output when connection fails but SPN and/or EPA data exists.
// spnInfo may be nil if only EPA data is available; epaResult may be nil if only SPN data is available.
func (c *Collector) processServerFromSPNData(server *ServerToProcess, spnInfo *ServerSPNInfo, epaResult *mssql.EPATestResult, connErr error, log *slog.Logger) error {

	// Try to resolve the FQDN
	fqdn := server.Hostname
	if !strings.Contains(server.Hostname, ".") && c.config.Domain != "" {
		fqdn = fmt.Sprintf("%s.%s", server.Hostname, strings.ToLower(c.config.Domain))
	}

	// Try to resolve computer SID if not already resolved
	computerSID := server.ComputerSID
	if computerSID == "" && c.config.Domain != "" {
		if runtime.GOOS == "windows" {
			sid, err := ad.ResolveComputerSIDWindows(server.Hostname, c.config.Domain)
			if err == nil && sid != "" {
				computerSID = sid
				server.ComputerSID = sid
			}
		}
	}

	// Use ObjectIdentifier from server, or build it if needed
	objectIdentifier := server.ObjectIdentifier
	if objectIdentifier == "" {
		if computerSID != "" {
			if server.InstanceName != "" && server.InstanceName != "MSSQLSERVER" {
				objectIdentifier = fmt.Sprintf("%s:%s", computerSID, server.InstanceName)
			} else {
				objectIdentifier = fmt.Sprintf("%s:%d", computerSID, server.Port)
			}
		} else {
			if server.InstanceName != "" && server.InstanceName != "MSSQLSERVER" {
				objectIdentifier = fmt.Sprintf("%s:%s", strings.ToLower(fqdn), server.InstanceName)
			} else {
				objectIdentifier = fmt.Sprintf("%s:%d", strings.ToLower(fqdn), server.Port)
			}
		}
	}

	// Create minimal server info from SPN and/or EPA data
	// NOTE: We intentionally do NOT add ServiceAccounts here to match PowerShell behavior.
	// PS stores ServiceAccountSIDs from SPN but uses ServiceAccounts (from SQL query) for edge creation.
	// For failed connections, ServiceAccounts is empty, so no service account edges are created.
	serverInfo := &types.ServerInfo{
		ObjectIdentifier: objectIdentifier,
		Hostname:         server.Hostname,
		ServerName:       server.ConnectionString,
		SQLServerName:    server.ConnectionString,
		InstanceName:     server.InstanceName,
		Port:             server.Port,
		FQDN:             fqdn,
		ComputerSID:      computerSID,
		// ServiceAccounts intentionally left empty to match PS behavior
	}

	// Add SPN data if available
	if spnInfo != nil {
		serverInfo.SPNs = spnInfo.SPNs
	}

	// Add EPA data if available (encryption and extended protection settings)
	if epaResult != nil {
		if epaResult.ForceEncryption {
			serverInfo.ForceEncryption = "Yes"
		} else {
			serverInfo.ForceEncryption = "No"
		}
		if epaResult.StrictEncryption {
			serverInfo.StrictEncryption = "Yes"
		} else {
			serverInfo.StrictEncryption = "No"
		}
		serverInfo.ExtendedProtection = epaResult.EPAStatus
	}

	// Check CVE-2025-49758 patch status (will show version unknown for SPN-only data)
	c.logCVE202549758Status(serverInfo, log)

	log.Info("Created partial output from SPN/EPA data", "connectionError", connErr)

	// Generate output using the consistent filename generation
	outputFile := filepath.Join(c.tempDir, c.generateFilename(server))

	if err := c.generateOutput(serverInfo, outputFile); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	c.addOutputFile(outputFile)

	return nil
}

// lookupSPNsForServer queries AD for SPNs for a specific server hostname
// This is used as a fallback when we don't have pre-enumerated SPN data
func (c *Collector) lookupSPNsForServer(server *ServerToProcess) *ServerSPNInfo {
	// Need a domain to query AD
	domain := c.config.Domain
	if domain == "" {
		// Try to extract domain from hostname FQDN
		if strings.Contains(server.Hostname, ".") {
			parts := strings.SplitN(server.Hostname, ".", 2)
			if len(parts) > 1 {
				domain = parts[1]
			}
		}
	}
	// Use domain from linked server discovery if available
	if domain == "" && server.Domain != "" {
		domain = server.Domain
		c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Using domain from linked server discovery", "domain", domain)
	}

	if domain == "" {
		c.config.Logger.Warn("Cannot lookup SPN - no domain available")
		return nil
	}

	// If we already did a full SPN sweep for the same domain, a per-host lookup won't find anything new
	if c.spnEnumerationDone && strings.EqualFold(domain, c.config.Domain) {
		return nil
	}

	// Try native LDAP first
	adClient := c.newADClient(domain)
	if adClient == nil {
		return nil
	}

	c.config.Logger.Info("Looking up SPNs in AD", "hostname", server.Hostname, "domain", domain)
	spns, err := adClient.LookupMSSQLSPNsForHost(server.Hostname)
	adClient.Close()

	if err != nil && isLDAPAuthError(err) {
		c.setLDAPAuthFailed()
		c.config.Logger.Warn("AD SPN lookup failed (invalid credentials)", "error", err)
		return nil
	}

	// If LDAP failed on Windows, try PowerShell/ADSI
	if err != nil && runtime.GOOS == "windows" {
		c.config.Logger.Info("LDAP lookup failed, trying PowerShell/ADSI fallback")
		spns, err = c.lookupSPNsViaPowerShell(server.Hostname)
	}

	if err != nil {
		c.config.Logger.Warn("AD SPN lookup failed", "error", err)
		return nil
	}

	if len(spns) == 0 {
		c.config.Logger.Info("No SPNs found in AD", "hostname", server.Hostname)
		return nil
	}

	c.config.Logger.Info("Found SPNs in AD", "count", len(spns), "hostname", server.Hostname)

	// Build ServerSPNInfo from the SPNs
	spnInfo := &ServerSPNInfo{
		SPNs: []string{},
	}

	for _, spn := range spns {
		// Build SPN string
		spnStr := fmt.Sprintf("MSSQLSvc/%s", spn.Hostname)
		if spn.Port != "" {
			spnStr += ":" + spn.Port
		} else if spn.InstanceName != "" {
			spnStr += ":" + spn.InstanceName
		}
		spnInfo.SPNs = append(spnInfo.SPNs, spnStr)

		// Use the first account info we find
		if spnInfo.AccountName == "" {
			spnInfo.AccountName = spn.AccountName
			spnInfo.AccountSID = spn.AccountSID
		}
	}

	// Also resolve computer SID if we don't have it
	if server.ComputerSID == "" {
		sid, err := ad.ResolveComputerSIDWindows(server.Hostname, domain)
		if err == nil && sid != "" {
			server.ComputerSID = sid
			// Rebuild ObjectIdentifier with the new SID
			if server.InstanceName != "" && server.InstanceName != "MSSQLSERVER" {
				server.ObjectIdentifier = fmt.Sprintf("%s:%s", sid, server.InstanceName)
			} else {
				server.ObjectIdentifier = fmt.Sprintf("%s:%d", sid, server.Port)
			}
		}
	}

	// Store in cache for future use
	c.serverSPNDataMu.Lock()
	c.serverSPNData[server.ObjectIdentifier] = spnInfo
	c.serverSPNDataMu.Unlock()

	return spnInfo
}

// lookupSPNsViaPowerShell uses PowerShell/ADSI to look up SPNs for a specific hostname
func (c *Collector) lookupSPNsViaPowerShell(hostname string) ([]types.SPN, error) {
	// Extract short hostname for matching
	shortHost := hostname
	if idx := strings.Index(hostname, "."); idx > 0 {
		shortHost = hostname[:idx]
	}

	// PowerShell script to look up SPNs for a specific hostname
	script := fmt.Sprintf(`
$shortHost = '%s'
$fqdn = '%s'
$searcher = [adsisearcher]"(|(servicePrincipalName=MSSQLSvc/$shortHost*)(servicePrincipalName=MSSQLSvc/$fqdn*))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@('servicePrincipalName', 'samAccountName', 'objectSid'))
$results = $searcher.FindAll()
foreach ($result in $results) {
    $sid = (New-Object System.Security.Principal.SecurityIdentifier($result.Properties['objectsid'][0], 0)).Value
    $samName = $result.Properties['samaccountname'][0]
    foreach ($spn in $result.Properties['serviceprincipalname']) {
        if ($spn -like 'MSSQLSvc/*') {
            # Filter to only matching hostnames
            $spnHost = (($spn -split '/')[1] -split ':')[0]
            if ($spnHost -ieq $shortHost -or $spnHost -ieq $fqdn -or $spnHost -like "$shortHost.*") {
                Write-Output "$spn|$samName|$sid"
            }
        }
    }
}
`, shortHost, hostname)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("PowerShell SPN lookup failed: %w", err)
	}

	var spns []types.SPN
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		spnStr := parts[0]
		accountName := parts[1]
		accountSID := parts[2]

		spn := c.parseSPN(spnStr, accountName, accountSID)
		if spn != nil {
			spns = append(spns, *spn)
		}
	}

	return spns, nil
}

// parseServerInstance parses a server instance string into hostname, port, and instance name
func (c *Collector) parseServerInstance(serverInstance string) (hostname, port, instanceName string) {
	// Handle formats: hostname, hostname:port, hostname\instance, hostname,port
	if strings.Contains(serverInstance, "\\") {
		parts := strings.SplitN(serverInstance, "\\", 2)
		hostname = parts[0]
		if len(parts) > 1 {
			instanceName = parts[1]
		}
	} else if strings.Contains(serverInstance, ":") {
		parts := strings.SplitN(serverInstance, ":", 2)
		hostname = parts[0]
		if len(parts) > 1 {
			port = parts[1]
		}
	} else if strings.Contains(serverInstance, ",") {
		parts := strings.SplitN(serverInstance, ",", 2)
		hostname = parts[0]
		if len(parts) > 1 {
			port = parts[1]
		}
	} else {
		hostname = serverInstance
	}
	return
}

// resolveComputerSIDViaLDAP attempts to resolve the computer SID via multiple methods.
// If sharedClient is non-nil, it is used for LDAP lookups instead of creating a new connection.
func (c *Collector) resolveComputerSIDViaLDAP(serverInfo *types.ServerInfo, log *slog.Logger, sharedClient *ad.Client) {
	// Try to determine the domain from the FQDN if not provided
	domain := c.config.Domain
	if domain == "" && strings.Contains(serverInfo.FQDN, ".") {
		// Extract domain from FQDN (e.g., server.domain.com -> domain.com)
		parts := strings.SplitN(serverInfo.FQDN, ".", 2)
		if len(parts) > 1 {
			domain = parts[1]
		}
	}

	// Use the machine name (without the FQDN)
	machineName := serverInfo.Hostname
	if strings.Contains(machineName, ".") {
		machineName = strings.Split(machineName, ".")[0]
	}

	// Method 1 & 2: Try Windows APIs (only available on Windows)
	if runtime.GOOS == "windows" {
		log.Log(context.Background(), logging.LevelVerbose, "Attempting to resolve computer SID", "machine", machineName, "domain", domain, "method", "WindowsAPI")
		sid, err := ad.ResolveComputerSIDWindows(machineName, domain)
		if err == nil && sid != "" {
			c.applyComputerSID(serverInfo, sid, "WindowsAPI", log)
			return
		}
		log.Log(context.Background(), logging.LevelVerbose, "Windows API LookupAccountName failed", "error", err)

		if serverInfo.DomainSID != "" {
			sid, err := ad.ResolveComputerSIDByDomainSID(machineName, serverInfo.DomainSID, domain)
			if err == nil && sid != "" {
				c.applyComputerSID(serverInfo, sid, "WindowsAPI", log)
				return
			}
			log.Log(context.Background(), logging.LevelVerbose, "Windows API with domain SID context failed", "error", err)
		}
	}

	// Try LDAP
	if domain == "" {
		log.Log(context.Background(), logging.LevelVerbose, "Cannot resolve computer SID: no domain specified (use -d flag)")
		return
	}

	log.Log(context.Background(), logging.LevelVerbose, "Attempting to resolve computer SID", "machine", machineName, "domain", domain, "method", "LDAP")

	// Use shared client if available, otherwise create a one-off client
	adClient := sharedClient
	if adClient == nil {
		adClient = c.newADClient(domain)
		if adClient == nil {
			return
		}
		defer adClient.Close()
	}

	sid, err := adClient.ResolveComputerSID(machineName)
	if err != nil {
		if isLDAPAuthError(err) {
			c.setLDAPAuthFailed()
		}
		log.Info("Could not resolve computer SID via LDAP", "error", err)
		return
	}

	c.applyComputerSID(serverInfo, sid, "LDAP", log)
}

// applyComputerSID applies the resolved computer SID to the server info and updates all references
func (c *Collector) applyComputerSID(serverInfo *types.ServerInfo, sid string, method string, log *slog.Logger) {
	// Store the old ObjectIdentifier to update references
	oldObjectIdentifier := serverInfo.ObjectIdentifier

	serverInfo.ComputerSID = sid
	serverInfo.ObjectIdentifier = fmt.Sprintf("%s:%d", sid, serverInfo.Port)
	log.Info("Resolved computer SID", "computer", serverInfo.Hostname, "sid", sid, "method", method)

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
		// Update MemberOf role references: Role@OldServerID -> Role@NewServerID
		for j := range p.MemberOf {
			p.MemberOf[j].ObjectIdentifier = strings.Replace(p.MemberOf[j].ObjectIdentifier, "@"+oldServerID, "@"+newServerID, 1)
		}
		// Update Permissions target references
		for j := range p.Permissions {
			if p.Permissions[j].TargetObjectIdentifier != "" {
				p.Permissions[j].TargetObjectIdentifier = strings.Replace(p.Permissions[j].TargetObjectIdentifier, "@"+oldServerID, "@"+newServerID, 1)
			}
		}
	}

	// Update databases and database principals
	for i := range serverInfo.Databases {
		db := &serverInfo.Databases[i]
		// Update database ObjectIdentifier: OldServerID\DBName -> NewServerID\DBName
		db.ObjectIdentifier = strings.Replace(db.ObjectIdentifier, oldServerID+"\\", newServerID+"\\", 1)

		// Update database owner ObjectIdentifier: Name@OldServerID -> Name@NewServerID
		if db.OwnerObjectIdentifier != "" {
			db.OwnerObjectIdentifier = strings.Replace(db.OwnerObjectIdentifier, "@"+oldServerID, "@"+newServerID, 1)
		}

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
			// Update MemberOf role references: Role@OldServerID\DBName -> Role@NewServerID\DBName
			for k := range p.MemberOf {
				p.MemberOf[k].ObjectIdentifier = strings.Replace(p.MemberOf[k].ObjectIdentifier, "@"+oldServerID+"\\", "@"+newServerID+"\\", 1)
			}
			// Update Permissions target references
			for k := range p.Permissions {
				if p.Permissions[k].TargetObjectIdentifier != "" {
					p.Permissions[k].TargetObjectIdentifier = strings.Replace(p.Permissions[k].TargetObjectIdentifier, "@"+oldServerID+"\\", "@"+newServerID+"\\", 1)
				}
			}
		}
	}
}

// preprocessServiceAccounts converts built-in service accounts to computer account
// When SQL Server runs as LocalSystem, Local Service, or Network Service,
// it authenticates on the network as the computer account
func (c *Collector) preprocessServiceAccounts(serverInfo *types.ServerInfo, log *slog.Logger) {
	seenSIDs := make(map[string]bool)
	var uniqueServiceAccounts []types.ServiceAccount

	for i := range serverInfo.ServiceAccounts {
		sa := serverInfo.ServiceAccounts[i]

		// Skip NT SERVICE\* virtual service accounts entirely
		// PowerShell doesn't convert these to computer accounts - it just skips them
		// because they can't be resolved in AD (they're virtual accounts)
		if strings.HasPrefix(strings.ToUpper(sa.Name), "NT SERVICE\\") {
			log.Log(context.Background(), logging.LevelVerbose, "Skipping NT SERVICE virtual account", "account", sa.Name)
			continue
		}

		// Check if this is a built-in account that uses the computer account for network auth
		// These DO get converted to computer accounts (LocalSystem, NT AUTHORITY\*)
		isBuiltIn := sa.Name == "LocalSystem" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\SYSTEM" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\LOCAL SERVICE" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\LOCALSERVICE" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\NETWORK SERVICE" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\NETWORKSERVICE"

		if isBuiltIn {
			// Convert to computer account (HOSTNAME$)
			hostname := serverInfo.Hostname
			// Strip domain from FQDN
			if strings.Contains(hostname, ".") {
				hostname = strings.Split(hostname, ".")[0]
			}
			computerAccount := strings.ToUpper(hostname) + "$"

			log.Log(context.Background(), logging.LevelVerbose, "Converting built-in service account to computer account", "from", sa.Name, "to", computerAccount)

			sa.Name = computerAccount
			sa.ConvertedFromBuiltIn = true // Mark as converted from built-in

			// If we already have the computer SID, use it
			if serverInfo.ComputerSID != "" {
				sa.SID = serverInfo.ComputerSID
				sa.ObjectIdentifier = serverInfo.ComputerSID
				log.Log(context.Background(), logging.LevelVerbose, "Using known computer SID", "sid", serverInfo.ComputerSID)
			}
		}

		// De-duplicate: only keep the first occurrence of each SID
		key := sa.SID
		if key == "" {
			key = sa.Name // Use name if SID not resolved yet
		}
		if !seenSIDs[key] {
			seenSIDs[key] = true
			uniqueServiceAccounts = append(uniqueServiceAccounts, sa)
		} else {
			log.Log(context.Background(), logging.LevelVerbose, "Skipping duplicate service account", "account", sa.Name, "key", key)
		}
	}

	serverInfo.ServiceAccounts = uniqueServiceAccounts
}

// resolveServiceAccountSIDsViaLDAP resolves service account SIDs via multiple methods.
// If sharedClient is non-nil, it is used for LDAP lookups instead of creating a new connection per account.
func (c *Collector) resolveServiceAccountSIDsViaLDAP(serverInfo *types.ServerInfo, log *slog.Logger, sharedClient *ad.Client) {
	for i := range serverInfo.ServiceAccounts {
		sa := &serverInfo.ServiceAccounts[i]

		// Skip non-domain accounts (Local System, Local Service, etc.)
		if !strings.Contains(sa.Name, "\\") && !strings.Contains(sa.Name, "@") && !strings.HasSuffix(sa.Name, "$") {
			continue
		}

		// Skip virtual accounts like NT SERVICE\*
		if strings.HasPrefix(strings.ToUpper(sa.Name), "NT SERVICE\\") ||
			strings.HasPrefix(strings.ToUpper(sa.Name), "NT AUTHORITY\\") {
			continue
		}

		// Check if this is a computer account (name ends with $)
		isComputerAccount := strings.HasSuffix(sa.Name, "$")

		// If we don't have a SID yet, try to resolve it
		if sa.SID == "" && runtime.GOOS == "windows" {
			sid, err := ad.ResolveAccountSIDWindows(sa.Name)
			if err == nil && sid != "" && strings.HasPrefix(sid, "S-1-5-21-") {
				sa.SID = sid
				sa.ObjectIdentifier = sid
				log.Info("Resolved service account SID", "account", sa.Name, "sid", sa.SID, "method", "WindowsAPI")
			} else {
				log.Log(context.Background(), logging.LevelVerbose, "Windows API SID resolution failed", "account", sa.Name, "error", err)
			}
		}

		// For computer accounts, we need to look up the DNSHostName via LDAP
		// PowerShell uses DNSHostName for computer account names (e.g., FORS13DA.ad005.onehc.net)
		// instead of SAMAccountName (FORS13DA$)
		if isComputerAccount && sa.SID != "" {
			// First, check if this is the server's own computer account
			// by comparing the SID with the server's ComputerSID
			if sa.SID == serverInfo.ComputerSID && serverInfo.FQDN != "" {
				// Use the server's own FQDN directly
				oldName := sa.Name
				sa.Name = serverInfo.FQDN
				log.Log(context.Background(), logging.LevelVerbose, "Updated computer account name (server's own computer account)", "from", oldName, "to", sa.Name)
				log.Info("Updated computer account name", "from", oldName, "to", sa.Name)
				continue
			}

			// For other computer accounts, try LDAP
			if c.config.Domain != "" {
				// Use shared client if available, otherwise create a one-off client
				adClient := sharedClient
				if adClient == nil {
					adClient = c.newADClient(c.config.Domain)
					if adClient == nil {
						continue
					}
					defer adClient.Close()
				}
				principal, err := adClient.ResolveSID(sa.SID)
				if err != nil && isLDAPAuthError(err) {
					c.setLDAPAuthFailed()
					continue
				}
				if err == nil && principal != nil && principal.ObjectClass == "computer" {
					// Use the resolved name (which is DNSHostName for computers in our updated AD client)
					oldName := sa.Name
					sa.Name = principal.Name
					sa.ResolvedPrincipal = principal
					log.Log(context.Background(), logging.LevelVerbose, "Updated computer account name", "from", oldName, "to", sa.Name)
					log.Info("Updated computer account name", "from", oldName, "to", sa.Name)
				}
			}
			continue
		}

		// If we still don't have a SID and this is not a computer account, try LDAP
		if sa.SID == "" {
			if c.config.Domain == "" {
				log.Info("Could not resolve service account (no domain specified)", "account", sa.Name)
				continue
			}

			// Use shared client if available, otherwise create a one-off client
			adClient := sharedClient
			if adClient == nil {
				adClient = c.newADClient(c.config.Domain)
				if adClient == nil {
					continue
				}
				defer adClient.Close()
			}
			principal, err := adClient.ResolveName(sa.Name)
			if err != nil && isLDAPAuthError(err) {
				c.setLDAPAuthFailed()
				continue
			}
			if err != nil {
				log.Info("Could not resolve service account via LDAP", "account", sa.Name, "error", err)
				continue
			}

			sa.SID = principal.SID
			sa.ObjectIdentifier = principal.SID
			sa.ResolvedPrincipal = principal
			// Also update the name if it's a computer
			if principal.ObjectClass == "computer" {
				sa.Name = principal.Name
			}
			log.Info("Resolved service account SID", "account", sa.Name, "sid", sa.SID, "method", "LDAP")
		}
	}
}

// resolveCredentialSIDsViaLDAP resolves credential identities to AD SIDs.
// This matches PowerShell's Resolve-DomainPrincipal behavior for credential edges.
// If sharedClient is non-nil, it is used for LDAP lookups instead of creating a new connection per credential.
func (c *Collector) resolveCredentialSIDsViaLDAP(serverInfo *types.ServerInfo, log *slog.Logger, sharedClient *ad.Client) {
	if c.config.Domain == "" {
		return
	}

	// Helper to resolve a credential identity to a domain principal via LDAP.
	// Attempts resolution for all identities (not just domain\user or user@domain format),
	// matching PowerShell's Resolve-DomainPrincipal behavior.
	resolveIdentity := func(identity string) *types.DomainPrincipal {
		if identity == "" {
			return nil
		}
		// Use shared client if available, otherwise create a one-off client
		adClient := sharedClient
		if adClient == nil {
			adClient = c.newADClient(c.config.Domain)
			if adClient == nil {
				return nil
			}
			defer adClient.Close()
		}
		principal, err := adClient.ResolveName(identity)
		if err != nil && isLDAPAuthError(err) {
			c.setLDAPAuthFailed()
			return nil
		}
		if err != nil || principal == nil || principal.SID == "" {
			return nil
		}
		return principal
	}

	// Resolve server-level credentials (mapped via ALTER LOGIN ... WITH CREDENTIAL)
	for i := range serverInfo.ServerPrincipals {
		if serverInfo.ServerPrincipals[i].MappedCredential != nil {
			cred := serverInfo.ServerPrincipals[i].MappedCredential
			if principal := resolveIdentity(cred.CredentialIdentity); principal != nil {
				cred.ResolvedSID = principal.SID
				cred.ResolvedPrincipal = principal
				log.Log(context.Background(), logging.LevelVerbose, "Resolved credential", "identity", cred.CredentialIdentity, "sid", principal.SID, "method", "LDAP")
			}
		}
	}

	// Resolve standalone credentials (for HasMappedCred edges)
	for i := range serverInfo.Credentials {
		if principal := resolveIdentity(serverInfo.Credentials[i].CredentialIdentity); principal != nil {
			serverInfo.Credentials[i].ResolvedSID = principal.SID
			serverInfo.Credentials[i].ResolvedPrincipal = principal
			log.Log(context.Background(), logging.LevelVerbose, "Resolved credential", "identity", serverInfo.Credentials[i].CredentialIdentity, "sid", principal.SID, "method", "LDAP")
		}
	}

	// Resolve proxy account credentials
	for i := range serverInfo.ProxyAccounts {
		if principal := resolveIdentity(serverInfo.ProxyAccounts[i].CredentialIdentity); principal != nil {
			serverInfo.ProxyAccounts[i].ResolvedSID = principal.SID
			serverInfo.ProxyAccounts[i].ResolvedPrincipal = principal
			log.Log(context.Background(), logging.LevelVerbose, "Resolved proxy credential", "identity", serverInfo.ProxyAccounts[i].CredentialIdentity, "sid", principal.SID, "method", "LDAP")
		}
	}

	// Resolve database-scoped credentials
	for i := range serverInfo.Databases {
		for j := range serverInfo.Databases[i].DBScopedCredentials {
			cred := &serverInfo.Databases[i].DBScopedCredentials[j]
			if principal := resolveIdentity(cred.CredentialIdentity); principal != nil {
				cred.ResolvedSID = principal.SID
				cred.ResolvedPrincipal = principal
				log.Log(context.Background(), logging.LevelVerbose, "Resolved DB scoped credential", "identity", cred.CredentialIdentity, "sid", principal.SID, "method", "LDAP")
			}
		}
	}
}

// enumerateLocalGroupMembers finds local Windows groups that have SQL logins and enumerates their domain members via WMI
func (c *Collector) enumerateLocalGroupMembers(serverInfo *types.ServerInfo, log *slog.Logger) {
	if runtime.GOOS != "windows" {
		log.Log(context.Background(), logging.LevelVerbose, "Skipping local group enumeration (not on Windows)")
		return
	}

	serverInfo.LocalGroupsWithLogins = make(map[string]*types.LocalGroupInfo)

	// Get the hostname part for matching
	serverHostname := serverInfo.Hostname
	if idx := strings.Index(serverHostname, "."); idx > 0 {
		serverHostname = serverHostname[:idx] // Get just the hostname, not FQDN
	}
	serverHostnameUpper := strings.ToUpper(serverHostname)

	for i := range serverInfo.ServerPrincipals {
		principal := &serverInfo.ServerPrincipals[i]

		// Check if this is a local Windows group
		if principal.TypeDescription != "WINDOWS_GROUP" {
			continue
		}

		isLocalGroup := false
		localGroupName := ""

		// Check for BUILTIN groups (e.g., BUILTIN\Administrators)
		if strings.HasPrefix(strings.ToUpper(principal.Name), "BUILTIN\\") {
			isLocalGroup = true
			parts := strings.SplitN(principal.Name, "\\", 2)
			if len(parts) == 2 {
				localGroupName = parts[1]
			}
		} else if strings.Contains(principal.Name, "\\") {
			// Check for computer-specific local groups (e.g., SERVERNAME\Administrators)
			parts := strings.SplitN(principal.Name, "\\", 2)
			if len(parts) == 2 && strings.ToUpper(parts[0]) == serverHostnameUpper {
				isLocalGroup = true
				localGroupName = parts[1]
			}
		}

		if !isLocalGroup || localGroupName == "" {
			continue
		}

		// Enumerate members using WMI
		members := wmi.GetLocalGroupMembersWithFallback(serverHostname, localGroupName, log)

		// Convert to LocalGroupMember and resolve SIDs
		var localMembers []types.LocalGroupMember
		for _, member := range members {
			lm := types.LocalGroupMember{
				Domain: member.Domain,
				Name:   member.Name,
			}

			// Try to resolve SID
			fullName := fmt.Sprintf("%s\\%s", member.Domain, member.Name)
			if runtime.GOOS == "windows" {
				sid, err := ad.ResolveAccountSIDWindows(fullName)
				if err == nil && sid != "" {
					lm.SID = sid
				}
			}

			// Fall back to LDAP if Windows API didn't work and we have a domain
			if lm.SID == "" && c.config.Domain != "" {
				adClient := c.newADClient(c.config.Domain)
				if adClient != nil {
					resolved, err := adClient.ResolveName(fullName)
					adClient.Close()
					if err != nil && isLDAPAuthError(err) {
						c.setLDAPAuthFailed()
					} else if err == nil && resolved.SID != "" {
						lm.SID = resolved.SID
					}
				}
			}

			localMembers = append(localMembers, lm)
		}

		// Store in server info
		serverInfo.LocalGroupsWithLogins[principal.ObjectIdentifier] = &types.LocalGroupInfo{
			Principal: principal,
			Members:   localMembers,
		}
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

	// Create linked server nodes (matching PowerShell behavior)
	// If a linked server resolves to the same ObjectIdentifier as the primary server,
	// merge the linked server properties into the server node instead of creating a duplicate.
	createdLinkedServerNodes := make(map[string]bool)
	for _, linkedServer := range serverInfo.LinkedServers {
		if linkedServer.DataSource == "" || linkedServer.ResolvedObjectIdentifier == "" {
			continue
		}
		if createdLinkedServerNodes[linkedServer.ResolvedObjectIdentifier] {
			continue
		}

		// If this linked server target is the primary server itself, skip creating a
		// separate node — the properties were already merged into the server node above.
		if linkedServer.ResolvedObjectIdentifier == serverInfo.ObjectIdentifier {
			createdLinkedServerNodes[linkedServer.ResolvedObjectIdentifier] = true
			continue
		}

		// Extract server name from data source (e.g., "SERVER\INSTANCE,1433" -> "SERVER")
		linkedServerName := linkedServer.DataSource
		if idx := strings.IndexAny(linkedServerName, "\\,:"); idx > 0 {
			linkedServerName = linkedServerName[:idx]
		}

		linkedNode := &bloodhound.Node{
			Kinds:      []string{bloodhound.NodeKinds.Server},
			ID:         linkedServer.ResolvedObjectIdentifier,
			Properties: make(map[string]interface{}),
		}
		linkedNode.Properties["name"] = linkedServerName
		linkedNode.Properties["hasLinksFromServers"] = []string{serverInfo.ObjectIdentifier}
		linkedNode.Properties["isLinkedServerTarget"] = true
		linkedNode.Icon = &bloodhound.Icon{
			Type:  "font-awesome",
			Name:  "server",
			Color: "#42b9f5",
		}

		if err := writer.WriteNode(linkedNode); err != nil {
			return err
		}
		createdLinkedServerNodes[linkedServer.ResolvedObjectIdentifier] = true
	}

	// Pre-compute databaseUsers for each login (matching PowerShell behavior).
	// Maps login ObjectIdentifier -> list of "userName@databaseName" strings.
	loginDatabaseUsers := make(map[string][]string)
	for _, db := range serverInfo.Databases {
		for _, principal := range db.DatabasePrincipals {
			if principal.ServerLogin != nil && principal.ServerLogin.ObjectIdentifier != "" {
				entry := fmt.Sprintf("%s@%s", principal.Name, db.Name)
				loginDatabaseUsers[principal.ServerLogin.ObjectIdentifier] = append(
					loginDatabaseUsers[principal.ServerLogin.ObjectIdentifier], entry)
			}
		}
	}

	// Create server principal nodes
	for _, principal := range serverInfo.ServerPrincipals {
		node := c.createServerPrincipalNode(&principal, serverInfo, loginDatabaseUsers)
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

	// Collect AD nodes (User, Group, Computer) if not skipped.
	// These are accumulated across servers and written to separate files (computers.json, users.json, groups.json).
	if !c.config.SkipADNodeCreation {
		if err := c.createADNodes(serverInfo); err != nil {
			return err
		}
	}

	// Create edges
	if err := c.createEdges(writer, serverInfo); err != nil {
		return err
	}

	// Print grouped summary of skipped ChangePassword edges due to CVE-2025-49758 patch
	c.skippedChangePasswordMu.Lock()
	if len(c.skippedChangePasswordEdges) > 0 {
		// Sort names for consistent output
		var names []string
		for name := range c.skippedChangePasswordEdges {
			names = append(names, name)
		}
		sort.Strings(names)

		c.config.Logger.Warn("Targets have securityadmin role or IMPERSONATE ANY LOGIN permission, but server is patched for CVE-2025-49758 -- Skipping ChangePassword edge", "skippedTargets", names)
		// Clear the map for next server
		c.skippedChangePasswordEdges = nil
	}
	c.skippedChangePasswordMu.Unlock()

	nodes, edges := writer.Stats()
	c.config.Logger.Info("Wrote output file", "nodes", nodes, "edges", edges, "file", filepath.Base(outputFile))

	return nil
}

// createServerNode creates a BloodHound node for the SQL Server
func (c *Collector) createServerNode(info *types.ServerInfo) *bloodhound.Node {
	props := map[string]interface{}{
		"name":          info.SQLServerName, // Use consistent FQDN:Port format
		"hostname":      info.Hostname,
		"fqdn":          info.FQDN,
		"sqlServerName": info.ServerName, // Original SQL Server name (may be short name or include instance)
		"version":       info.Version,
		"versionNumber": info.VersionNumber,
		"edition":       info.Edition,
		"productLevel":  info.ProductLevel,
		"isClustered":   info.IsClustered,
		"port":          info.Port,
	}

	// Add instance name
	if info.InstanceName != "" {
		props["instanceName"] = info.InstanceName
	}

	// Add security-relevant properties
	props["isMixedModeAuthEnabled"] = info.IsMixedModeAuth
	if info.ForceEncryption != "" {
		props["forceEncryption"] = info.ForceEncryption
	}
	if info.StrictEncryption != "" {
		props["strictEncryption"] = info.StrictEncryption
	}
	if info.ExtendedProtection != "" {
		props["extendedProtection"] = info.ExtendedProtection
	}

	// Add SPNs
	if len(info.SPNs) > 0 {
		props["servicePrincipalNames"] = info.SPNs
	}

	// Add service account name (first service account, matching PowerShell behavior).
	// PS strips the domain prefix via Resolve-DomainPrincipal which returns bare SAMAccountName.
	if len(info.ServiceAccounts) > 0 {
		saName := info.ServiceAccounts[0].Name
		if idx := strings.Index(saName, "\\"); idx != -1 {
			saName = saName[idx+1:]
		}
		props["serviceAccount"] = saName
	}

	// Add database names
	if len(info.Databases) > 0 {
		dbNames := make([]string, len(info.Databases))
		for i, db := range info.Databases {
			dbNames[i] = db.Name
		}
		props["databases"] = dbNames
	}

	// Add linked server names
	if len(info.LinkedServers) > 0 {
		linkedNames := make([]string, len(info.LinkedServers))
		for i, ls := range info.LinkedServers {
			linkedNames[i] = ls.Name
		}
		props["linkedToServers"] = linkedNames
	}

	// Check if any linked servers resolve back to this server (self-reference).
	// If so, merge the linked server target properties into this node to avoid
	// creating a duplicate node with the same ObjectIdentifier.
	hasLinksFromServers := []string{}
	for _, ls := range info.LinkedServers {
		if ls.ResolvedObjectIdentifier == info.ObjectIdentifier && ls.DataSource != "" {
			hasLinksFromServers = append(hasLinksFromServers, info.ObjectIdentifier)
			break
		}
	}
	if len(hasLinksFromServers) > 0 {
		props["isLinkedServerTarget"] = true
		props["hasLinksFromServers"] = hasLinksFromServers
	}

	// Calculate domain principals with privileged access using effective permission
	// evaluation (including nested role membership and fixed role implied permissions).
	// This matches PowerShell's approach where sysadmin implies CONTROL SERVER.
	domainPrincipalsWithSysadmin := []string{}
	domainPrincipalsWithControlServer := []string{}
	domainPrincipalsWithSecurityadmin := []string{}
	domainPrincipalsWithImpersonateAnyLogin := []string{}

	for _, principal := range info.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.IsDisabled {
			continue
		}

		// Only include principals with domain SIDs (S-1-5-21-<domainSID>-...)
		// This filters out BUILTIN, NT AUTHORITY, NT SERVICE accounts
		if info.DomainSID == "" || !strings.HasPrefix(principal.SecurityIdentifier, info.DomainSID+"-") {
			continue
		}

		// Use effective permission/role checks (including nested roles and fixed role implied permissions)
		if c.hasNestedRoleMembership(principal, "sysadmin", info) {
			domainPrincipalsWithSysadmin = append(domainPrincipalsWithSysadmin, principal.ObjectIdentifier)
		}
		if c.hasNestedRoleMembership(principal, "securityadmin", info) {
			domainPrincipalsWithSecurityadmin = append(domainPrincipalsWithSecurityadmin, principal.ObjectIdentifier)
		}
		if c.hasEffectivePermission(principal, "CONTROL SERVER", info) {
			domainPrincipalsWithControlServer = append(domainPrincipalsWithControlServer, principal.ObjectIdentifier)
		}
		if c.hasEffectivePermission(principal, "IMPERSONATE ANY LOGIN", info) {
			domainPrincipalsWithImpersonateAnyLogin = append(domainPrincipalsWithImpersonateAnyLogin, principal.ObjectIdentifier)
		}
	}

	props["domainPrincipalsWithSysadmin"] = domainPrincipalsWithSysadmin
	props["domainPrincipalsWithControlServer"] = domainPrincipalsWithControlServer
	props["domainPrincipalsWithSecurityadmin"] = domainPrincipalsWithSecurityadmin
	props["domainPrincipalsWithImpersonateAnyLogin"] = domainPrincipalsWithImpersonateAnyLogin
	props["isAnyDomainPrincipalSysadmin"] = len(domainPrincipalsWithSysadmin) > 0

	return &bloodhound.Node{
		ID:         info.ObjectIdentifier,
		Kinds:      []string{bloodhound.NodeKinds.Server},
		Properties: props,
		Icon:       bloodhound.CopyIcon(bloodhound.Icons[bloodhound.NodeKinds.Server]),
	}
}

// createServerPrincipalNode creates a BloodHound node for a server principal
func (c *Collector) createServerPrincipalNode(principal *types.ServerPrincipal, serverInfo *types.ServerInfo, loginDatabaseUsers map[string][]string) *bloodhound.Node {
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
			// Resolve SID to NTAccount-style name (matching PowerShell's activeDirectoryPrincipal)
			if principal.IsActiveDirectoryPrincipal {
				props["activeDirectoryPrincipal"] = principal.Name
			}
		}

		// Add databaseUsers list (matching PowerShell behavior)
		if dbUsers, ok := loginDatabaseUsers[principal.ObjectIdentifier]; ok && len(dbUsers) > 0 {
			props["databaseUsers"] = dbUsers
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
		"SQLServerID":        serverInfo.ObjectIdentifier,
	}

	if db.OwnerLoginName != "" {
		props["ownerLoginName"] = db.OwnerLoginName
	}
	if db.OwnerPrincipalID != 0 {
		props["ownerPrincipalID"] = fmt.Sprintf("%d", db.OwnerPrincipalID)
	}
	if db.OwnerObjectIdentifier != "" {
		props["OwnerObjectIdentifier"] = db.OwnerObjectIdentifier
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
		"name":        fmt.Sprintf("%s@%s", principal.Name, db.Name), // Match PowerShell format: Name@DatabaseName
		"principalId": principal.PrincipalID,
		"createDate":  principal.CreateDate.Format(time.RFC3339),
		"modifyDate":  principal.ModifyDate.Format(time.RFC3339),
		"database":    principal.DatabaseName, // Match PowerShell property name
		"SQLServer":   principal.SQLServerName,
	}

	var kinds []string
	var icon *bloodhound.Icon

	// Add defaultSchema for all database principal types (matching PowerShell behavior)
	if principal.DefaultSchemaName != "" {
		props["defaultSchema"] = principal.DefaultSchemaName
	}

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
func (c *Collector) createADNodes(serverInfo *types.ServerInfo) error {
	createdNodes := make(map[string]bool)

	// addADNode adds a node to the appropriate collector-level AD list (deduplicated across servers)
	addADNode := func(node *bloodhound.Node) {
		c.adNodesMu.Lock()
		defer c.adNodesMu.Unlock()

		if c.adSeenNodes[node.ID] {
			return
		}
		c.adSeenNodes[node.ID] = true

		// Categorize by primary kind (first element)
		switch node.Kinds[0] {
		case bloodhound.NodeKinds.Computer:
			c.adComputers = append(c.adComputers, node)
		case bloodhound.NodeKinds.Group:
			c.adGroups = append(c.adGroups, node)
		default:
			c.adUsers = append(c.adUsers, node)
		}
	}

	// Create Computer node for the server's host computer (matching PowerShell behavior)
	if serverInfo.ComputerSID != "" {
		// Use FQDN as display name (matching PowerShell behavior which uses DNSHostName)
		displayName := serverInfo.FQDN
		if displayName == "" {
			displayName = serverInfo.Hostname
		}

		// Build SAMAccountName (hostname$)
		hostname := serverInfo.Hostname
		if idx := strings.Index(hostname, "."); idx > 0 {
			hostname = hostname[:idx] // Extract short hostname from FQDN
		}
		samAccountName := strings.ToUpper(hostname) + "$"

		node := &bloodhound.Node{
			ID:    serverInfo.ComputerSID,
			Kinds: []string{bloodhound.NodeKinds.Computer, "Base"},
			Properties: map[string]interface{}{
				"name":              displayName,
				"DNSHostName":       serverInfo.FQDN,
				"domain":            c.config.Domain,
				"isDomainPrincipal": true,
				"SID":               serverInfo.ComputerSID,
				"SAMAccountName":    samAccountName,
			},
		}
		addADNode(node)
		createdNodes[serverInfo.ComputerSID] = true
	}

	// Track if we need to create Authenticated Users node for MSSQL_CoerceAndRelayToMSSQL
	needsAuthUsersNode := false

	// Check for computer accounts with EPA disabled (MSSQL_CoerceAndRelayToMSSQL condition)
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
			addADNode(node)
			createdNodes[authedUsersSID] = true
		}
	}

	// Resolve domain login SIDs via LDAP for AD enrichment (matching PowerShell behavior).
	// This provides properties like SAMAccountName, distinguishedName, DNSHostName, etc.
	resolvedPrincipals := make(map[string]*types.DomainPrincipal)
	if c.config.Domain != "" {
		adClient := c.newADClient(c.config.Domain)
		if adClient != nil {
			for _, principal := range serverInfo.ServerPrincipals {
				if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
					continue
				}
				if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
					continue
				}
				if _, already := resolvedPrincipals[principal.SecurityIdentifier]; already {
					continue
				}
				resolved, err := adClient.ResolveSID(principal.SecurityIdentifier)
				if err != nil && isLDAPAuthError(err) {
					c.setLDAPAuthFailed()
					break
				}
				if err == nil && resolved != nil {
					resolvedPrincipals[principal.SecurityIdentifier] = resolved
				}
			}
			adClient.Close()
		}
	}

	// Create nodes for domain principals with SQL logins
	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Only process SIDs from the domain, skip NT AUTHORITY, NT SERVICE, and local accounts
		// The DomainSID (e.g., S-1-5-21-462691900-2967613020-3702357964) identifies domain principals
		if serverInfo.DomainSID == "" || !strings.HasPrefix(principal.SecurityIdentifier, serverInfo.DomainSID+"-") {
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

		nodeProps := map[string]interface{}{
			"name":              displayName,
			"isDomainPrincipal": true,
			"SID":               principal.SecurityIdentifier,
		}

		// Enrich with LDAP-resolved AD attributes (matching PowerShell behavior)
		if resolved, ok := resolvedPrincipals[principal.SecurityIdentifier]; ok {
			nodeProps["SAMAccountName"] = resolved.SAMAccountName
			nodeProps["domain"] = resolved.Domain
			nodeProps["isEnabled"] = resolved.Enabled
			if resolved.DistinguishedName != "" {
				nodeProps["distinguishedName"] = resolved.DistinguishedName
			}
			if resolved.DNSHostName != "" {
				nodeProps["DNSHostName"] = resolved.DNSHostName
			}
			if resolved.UserPrincipalName != "" {
				nodeProps["userPrincipalName"] = resolved.UserPrincipalName
			}
		}

		node := &bloodhound.Node{
			ID:         principal.SecurityIdentifier,
			Kinds:      kinds,
			Properties: nodeProps,
		}
		addADNode(node)
		createdNodes[principal.SecurityIdentifier] = true
	}

	// Create nodes for local groups with SQL logins
	// This handles both BUILTIN groups (S-1-5-32-*) and machine-local groups
	// (S-1-5-21-* SIDs that don't match the domain SID, e.g. ConfigMgr_DViewAccess)
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.SecurityIdentifier == "" {
			continue
		}

		// Identify local groups: BUILTIN (S-1-5-32-*) or machine-local Windows groups
		// Machine-local groups have S-1-5-21-* SIDs belonging to the machine, not the domain
		isLocalGroup := false
		if strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-32-") {
			isLocalGroup = true
		} else if principal.TypeDescription == "WINDOWS_GROUP" &&
			strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") &&
			(serverInfo.DomainSID == "" || !strings.HasPrefix(principal.SecurityIdentifier, serverInfo.DomainSID+"-")) {
			isLocalGroup = true
		}
		if !isLocalGroup {
			continue
		}

		// Skip disabled logins
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

		// ObjectID format: {serverFQDN}-{SID}
		groupObjectID := serverInfo.Hostname + "-" + principal.SecurityIdentifier

		// Skip if already created
		if createdNodes[groupObjectID] {
			continue
		}

		node := &bloodhound.Node{
			ID:    groupObjectID,
			Kinds: []string{bloodhound.NodeKinds.Group, "Base"},
			Properties: map[string]interface{}{
				"name":                       principal.Name,
				"isActiveDirectoryPrincipal": principal.IsActiveDirectoryPrincipal,
			},
		}
		addADNode(node)
		createdNodes[groupObjectID] = true
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

		// Format display name to match PowerShell behavior:
		// PS uses Resolve-DomainPrincipal which returns UserPrincipalName, DNSHostName,
		// or SAMAccountName (in that priority order). For user accounts without UPN,
		// this is just the bare account name (e.g., "sccmsqlsvc" not "DOMAIN\sccmsqlsvc").
		// For computer accounts, resolveServiceAccountSIDsViaLDAP already sets Name to FQDN.
		displayName := sa.Name
		if idx := strings.Index(displayName, "\\"); idx != -1 {
			displayName = displayName[idx+1:]
		}

		nodeProps := map[string]interface{}{
			"name": displayName,
		}

		// Enrich with LDAP-resolved AD attributes (matching PowerShell behavior)
		if sa.ResolvedPrincipal != nil {
			nodeProps["isDomainPrincipal"] = true
			nodeProps["SID"] = sa.ResolvedPrincipal.SID
			nodeProps["SAMAccountName"] = sa.ResolvedPrincipal.SAMAccountName
			nodeProps["domain"] = sa.ResolvedPrincipal.Domain
			nodeProps["isEnabled"] = sa.ResolvedPrincipal.Enabled
			if sa.ResolvedPrincipal.DistinguishedName != "" {
				nodeProps["distinguishedName"] = sa.ResolvedPrincipal.DistinguishedName
			}
			if sa.ResolvedPrincipal.DNSHostName != "" {
				nodeProps["DNSHostName"] = sa.ResolvedPrincipal.DNSHostName
			}
			if sa.ResolvedPrincipal.UserPrincipalName != "" {
				nodeProps["userPrincipalName"] = sa.ResolvedPrincipal.UserPrincipalName
			}
		}

		node := &bloodhound.Node{
			ID:         saID,
			Kinds:      kinds,
			Properties: nodeProps,
		}
		addADNode(node)
		createdNodes[saID] = true
	}

	// Create nodes for credential targets (HasMappedCred, HasDBScopedCred, HasProxyCred)
	// This matches PowerShell's credential Base node creation at MSSQLHound.ps1:8958-9018
	credentialNodeKind := func(objectClass string) string {
		switch objectClass {
		case "computer":
			return bloodhound.NodeKinds.Computer
		case "group":
			return bloodhound.NodeKinds.Group
		default:
			return bloodhound.NodeKinds.User
		}
	}

	addCredentialNode := func(sid string, principal *types.DomainPrincipal) {
		if sid == "" || createdNodes[sid] {
			return
		}
		kind := credentialNodeKind(principal.ObjectClass)
		props := map[string]interface{}{
			"name":              principal.Name,
			"domain":            principal.Domain,
			"isDomainPrincipal": true,
			"SID":               principal.SID,
			"SAMAccountName":    principal.SAMAccountName,
			"isEnabled":         principal.Enabled,
		}
		if principal.DistinguishedName != "" {
			props["distinguishedName"] = principal.DistinguishedName
		}
		if principal.DNSHostName != "" {
			props["DNSHostName"] = principal.DNSHostName
		}
		if principal.UserPrincipalName != "" {
			props["userPrincipalName"] = principal.UserPrincipalName
		}
		node := &bloodhound.Node{
			ID:         sid,
			Kinds:      []string{kind, "Base"},
			Properties: props,
		}
		addADNode(node)
		createdNodes[sid] = true
	}

	// Server-level credentials
	for _, cred := range serverInfo.Credentials {
		if cred.ResolvedPrincipal != nil {
			addCredentialNode(cred.ResolvedSID, cred.ResolvedPrincipal)
		}
	}

	// Database-scoped credentials
	for _, db := range serverInfo.Databases {
		for _, cred := range db.DBScopedCredentials {
			if cred.ResolvedPrincipal != nil {
				addCredentialNode(cred.ResolvedSID, cred.ResolvedPrincipal)
			}
		}
	}

	// Proxy account credentials
	for _, proxy := range serverInfo.ProxyAccounts {
		if proxy.ResolvedPrincipal != nil {
			addCredentialNode(proxy.ResolvedSID, proxy.ResolvedPrincipal)
		}
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
				SourceName:  serverInfo.ServerName,
				SourceType:  bloodhound.NodeKinds.Server,
				TargetName:  db.Name,
				TargetType:  bloodhound.NodeKinds.Database,
				SQLServerID: serverInfo.ObjectIdentifier,
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
				SourceName:  serverInfo.ServerName,
				SourceType:  bloodhound.NodeKinds.Server,
				TargetName:  principal.Name,
				TargetType:  targetType,
				SQLServerID: serverInfo.ObjectIdentifier,
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
					SQLServerID:   serverInfo.ObjectIdentifier,
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
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Server role ownership - look up owner's actual type
	serverPrincipalTypeMap := make(map[string]string)
	for _, p := range serverInfo.ServerPrincipals {
		serverPrincipalTypeMap[p.ObjectIdentifier] = p.TypeDescription
	}
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.TypeDescription == "SERVER_ROLE" && principal.OwningObjectIdentifier != "" {
			ownerType := bloodhound.NodeKinds.Login // default for server-level
			if td, ok := serverPrincipalTypeMap[principal.OwningObjectIdentifier]; ok {
				if td == "SERVER_ROLE" {
					ownerType = bloodhound.NodeKinds.ServerRole
				}
			}
			edge := c.createEdge(
				principal.OwningObjectIdentifier,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.Owns,
				&bloodhound.EdgeContext{
					SourceName:    "", // Will be filled by owner lookup
					SourceType:    ownerType,
					TargetName:    principal.Name,
					TargetType:    bloodhound.NodeKinds.ServerRole,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	// Database role ownership - look up owner's actual type
	for _, db := range serverInfo.Databases {
		dbPrincipalTypeMap := make(map[string]string)
		for _, p := range db.DatabasePrincipals {
			dbPrincipalTypeMap[p.ObjectIdentifier] = p.TypeDescription
		}
		for _, principal := range db.DatabasePrincipals {
			if principal.TypeDescription == "DATABASE_ROLE" && principal.OwningObjectIdentifier != "" {
				ownerType := bloodhound.NodeKinds.DatabaseUser // default for db-level
				if td, ok := dbPrincipalTypeMap[principal.OwningObjectIdentifier]; ok {
					switch td {
					case "DATABASE_ROLE":
						ownerType = bloodhound.NodeKinds.DatabaseRole
					case "APPLICATION_ROLE":
						ownerType = bloodhound.NodeKinds.ApplicationRole
					}
				}
				edge := c.createEdge(
					principal.OwningObjectIdentifier,
					principal.ObjectIdentifier,
					bloodhound.EdgeKinds.Owns,
					&bloodhound.EdgeContext{
						SourceName:    "", // Owner name
						SourceType:    ownerType,
						TargetName:    principal.Name,
						TargetType:    bloodhound.NodeKinds.DatabaseRole,
						SQLServerName: serverInfo.SQLServerName,
						SQLServerID:   serverInfo.ObjectIdentifier,
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
					SQLServerID:   serverInfo.ObjectIdentifier,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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

	// Linked servers - one edge per login mapping (matching PowerShell behavior)
	for _, linked := range serverInfo.LinkedServers {
		// Determine target ObjectIdentifier for linked server
		targetID := linked.DataSource
		if linked.ResolvedObjectIdentifier != "" {
			targetID = linked.ResolvedObjectIdentifier
		}

		// Resolve the source server ObjectIdentifier
		// PowerShell compares linked.SourceServer to current hostname and resolves chains
		sourceID := serverInfo.ObjectIdentifier
		if linked.SourceServer != "" && !strings.EqualFold(linked.SourceServer, serverInfo.Hostname) {
			// Source is a different server (chained linked server) - resolve its ID
			resolvedSourceID := c.resolveLinkedServerSourceID(linked.SourceServer, serverInfo)
			if resolvedSourceID != "" {
				sourceID = resolvedSourceID
			}
		}

		// MSSQL_LinkedTo edge with all properties matching PowerShell
		edge := c.createEdge(
			sourceID,
			targetID,
			bloodhound.EdgeKinds.LinkedTo,
			&bloodhound.EdgeContext{
				SourceName:    serverInfo.ServerName,
				SourceType:    bloodhound.NodeKinds.Server,
				TargetName:    linked.Name,
				TargetType:    bloodhound.NodeKinds.Server,
				SQLServerName: serverInfo.SQLServerName,
				SQLServerID:   serverInfo.ObjectIdentifier,
			},
		)
		if edge != nil {
			// Add linked server specific properties (matching PowerShell)
			edge.Properties["dataAccess"] = linked.IsDataAccessEnabled
			edge.Properties["dataSource"] = linked.DataSource
			edge.Properties["localLogin"] = linked.LocalLogin
			edge.Properties["path"] = linked.Path
			edge.Properties["product"] = linked.Product
			edge.Properties["provider"] = linked.Provider
			edge.Properties["remoteCurrentLogin"] = linked.RemoteCurrentLogin
			edge.Properties["remoteHasControlServer"] = linked.RemoteHasControlServer
			edge.Properties["remoteHasImpersonateAnyLogin"] = linked.RemoteHasImpersonateAnyLogin
			edge.Properties["remoteIsMixedMode"] = linked.RemoteIsMixedMode
			edge.Properties["remoteIsSecurityAdmin"] = linked.RemoteIsSecurityAdmin
			edge.Properties["remoteIsSysadmin"] = linked.RemoteIsSysadmin
			edge.Properties["remoteLogin"] = linked.RemoteLogin
			edge.Properties["rpcOut"] = linked.IsRPCOutEnabled
			edge.Properties["usesImpersonation"] = linked.UsesImpersonation
		}
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
				sourceID,
				targetID,
				bloodhound.EdgeKinds.LinkedAsAdmin,
				&bloodhound.EdgeContext{
					SourceName:    serverInfo.ServerName,
					SourceType:    bloodhound.NodeKinds.Server,
					TargetName:    linked.Name,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if edge != nil {
				// Add linked server specific properties (matching PowerShell)
				edge.Properties["dataAccess"] = linked.IsDataAccessEnabled
				edge.Properties["dataSource"] = linked.DataSource
				edge.Properties["localLogin"] = linked.LocalLogin
				edge.Properties["path"] = linked.Path
				edge.Properties["product"] = linked.Product
				edge.Properties["provider"] = linked.Provider
				edge.Properties["remoteCurrentLogin"] = linked.RemoteCurrentLogin
				edge.Properties["remoteHasControlServer"] = linked.RemoteHasControlServer
				edge.Properties["remoteHasImpersonateAnyLogin"] = linked.RemoteHasImpersonateAnyLogin
				edge.Properties["remoteIsMixedMode"] = linked.RemoteIsMixedMode
				edge.Properties["remoteIsSecurityAdmin"] = linked.RemoteIsSecurityAdmin
				edge.Properties["remoteIsSysadmin"] = linked.RemoteIsSysadmin
				edge.Properties["remoteLogin"] = linked.RemoteLogin
				edge.Properties["rpcOut"] = linked.IsRPCOutEnabled
				edge.Properties["usesImpersonation"] = linked.UsesImpersonation
			}
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
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}

			// Check if database owner has high privileges
			// (sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN)
			// Uses nested role/permission checks matching PowerShell's Get-NestedRoleMembership/Get-EffectivePermissions
			if db.OwnerObjectIdentifier != "" {
				// Find the owner in server principals
				var ownerHasSysadmin, ownerHasSecurityadmin, ownerHasControlServer, ownerHasImpersonateAnyLogin bool
				var ownerLoginName string
				for _, owner := range serverInfo.ServerPrincipals {
					if owner.ObjectIdentifier == db.OwnerObjectIdentifier {
						ownerLoginName = owner.Name
						ownerHasSysadmin = c.hasNestedRoleMembership(owner, "sysadmin", serverInfo)
						ownerHasSecurityadmin = c.hasNestedRoleMembership(owner, "securityadmin", serverInfo)
						ownerHasControlServer = c.hasEffectivePermission(owner, "CONTROL SERVER", serverInfo)
						ownerHasImpersonateAnyLogin = c.hasEffectivePermission(owner, "IMPERSONATE ANY LOGIN", serverInfo)
						break
					}
				}

				if ownerHasSysadmin || ownerHasSecurityadmin || ownerHasControlServer || ownerHasImpersonateAnyLogin {
					// Create ExecuteAsOwner edge with metadata properties matching PowerShell
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
							SQLServerID:   serverInfo.ObjectIdentifier,
							DatabaseName:  db.Name,
						},
					)
					if edge != nil {
						edge.Properties["database"] = db.Name
						edge.Properties["databaseIsTrustworthy"] = db.IsTrustworthy
						edge.Properties["ownerHasControlServer"] = ownerHasControlServer
						edge.Properties["ownerHasImpersonateAnyLogin"] = ownerHasImpersonateAnyLogin
						edge.Properties["ownerHasSecurityadmin"] = ownerHasSecurityadmin
						edge.Properties["ownerHasSysadmin"] = ownerHasSysadmin
						edge.Properties["ownerLoginName"] = ownerLoginName
						edge.Properties["ownerObjectIdentifier"] = db.OwnerObjectIdentifier
						edge.Properties["ownerPrincipalID"] = fmt.Sprintf("%d", db.OwnerPrincipalID)
						edge.Properties["SQLServer"] = serverInfo.ObjectIdentifier
					}
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
				SQLServerID:   serverInfo.ObjectIdentifier,
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
				SQLServerID:   serverInfo.ObjectIdentifier,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// =========================================================================
	// AD PRINCIPAL RELATIONSHIP EDGES
	// =========================================================================

	// Create HasLogin and MSSQL_CoerceAndRelayToMSSQL edges from AD principals to their SQL logins
	// Match PowerShell logic: iterate enabledDomainPrincipalsWithConnectSQL
	// MSSQL_CoerceAndRelayToMSSQL is checked BEFORE the S-1-5-21 filter and dedup (matching PS ordering)
	// HasLogin is only created for S-1-5-21-* SIDs with dedup
	principalsWithLogin := make(map[string]bool)
	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Skip disabled logins
		if principal.IsDisabled {
			continue
		}

		// Check if has CONNECT SQL permission (direct or through sysadmin/securityadmin membership)
		// This matches PowerShell's $enabledDomainPrincipalsWithConnectSQL filter
		hasConnectSQL := false
		for _, perm := range principal.Permissions {
			if perm.Permission == "CONNECT SQL" && (perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
				hasConnectSQL = true
				break
			}
		}
		// Also check sysadmin/securityadmin membership (implies CONNECT SQL)
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

		// MSSQL_CoerceAndRelayToMSSQL edge if conditions are met:
		// - Extended Protection (EPA) is Off
		// - Login is for a computer account (name ends with $)
		// This is checked BEFORE the S-1-5-21 filter and dedup, matching PowerShell ordering
		if serverInfo.ExtendedProtection == "Off" && strings.HasSuffix(principal.Name, "$") {
			// Create edge from Authenticated Users (S-1-5-11) to the SQL login
			// The SID S-1-5-11 is prefixed with the domain for the full ObjectIdentifier
			authedUsersSID := "S-1-5-11"
			if c.config.Domain != "" {
				authedUsersSID = c.config.Domain + "-S-1-5-11"
			}

			edge := c.createEdge(
				authedUsersSID,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.CoerceAndRelayTo,
				&bloodhound.EdgeContext{
					SourceName:         "AUTHENTICATED USERS",
					SourceType:         "Group",
					TargetName:         principal.Name,
					TargetType:         bloodhound.NodeKinds.Login,
					SQLServerName:      serverInfo.SQLServerName,
					SQLServerID:        serverInfo.ObjectIdentifier,
					SecurityIdentifier: principal.SecurityIdentifier,
				},
			)
			if edge != nil {
				// Add coercion victim and relay target pair so users can see
				// which computer to coerce and which SQL server to relay to
				computerName := principal.Name
				if idx := strings.LastIndex(computerName, "\\"); idx >= 0 {
					computerName = computerName[idx+1:]
				}
				computerName = strings.TrimSuffix(computerName, "$")

				victimHost := strings.ToLower(computerName)
				domainSuffix := ""
				if serverInfo.FQDN != "" {
					if idx := strings.Index(serverInfo.FQDN, "."); idx >= 0 {
						domainSuffix = serverInfo.FQDN[idx:]
					}
				}
				if domainSuffix == "" && c.config.Domain != "" {
					domainSuffix = "." + c.config.Domain
				}
				if domainSuffix != "" {
					victimHost = victimHost + domainSuffix
				}

				relayHost := serverInfo.FQDN
				if relayHost == "" {
					relayHost = serverInfo.Hostname
				}
				relayTarget := fmt.Sprintf("%s:%d", relayHost, serverInfo.Port)

				edge.Properties["coercionVictimAndRelayTargetPairs"] = []string{
					fmt.Sprintf("Coerce %s, relay to %s", victimHost, relayTarget),
				}
			}
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}

		// Only process domain SIDs (S-1-5-21-*) for HasLogin edges
		// Skip NT AUTHORITY, NT SERVICE, local accounts, etc.
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
			continue
		}

		// Skip if we already created HasLogin for this SID (dedup)
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
				SQLServerID:   serverInfo.ObjectIdentifier,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// Create HasLogin edges for local groups that have SQL logins
	// This processes ALL local groups (not just BUILTIN S-1-5-32-*), matching PowerShell behavior.
	// LocalGroupsWithLogins contains groups collected via WMI/net localgroup enumeration.
	if serverInfo.LocalGroupsWithLogins != nil {
		for _, groupInfo := range serverInfo.LocalGroupsWithLogins {
			if groupInfo.Principal == nil || groupInfo.Principal.SecurityIdentifier == "" {
				continue
			}

			principal := groupInfo.Principal

			// Track non-BUILTIN SIDs separately (machine-local groups)
			if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-32-") {
				principalsWithLogin[principal.SecurityIdentifier] = true
			}

			// ObjectID format: {serverFQDN}-{SID} (machine-specific)
			groupObjectID := serverInfo.Hostname + "-" + principal.SecurityIdentifier
			principalsWithLogin[groupObjectID] = true

			// MSSQL_HasLogin edge
			edge := c.createEdge(
				groupObjectID,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.HasLogin,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    "Group",
					TargetName:    principal.Name,
					TargetType:    bloodhound.NodeKinds.Login,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	} else {
		// Fallback: process local groups from ServerPrincipals if LocalGroupsWithLogins is not populated
		// This handles both BUILTIN (S-1-5-32-*) and machine-local groups (S-1-5-21-* not matching domain SID)
		for _, principal := range serverInfo.ServerPrincipals {
			if principal.SecurityIdentifier == "" {
				continue
			}

			// Identify local groups: BUILTIN (S-1-5-32-*) or machine-local Windows groups
			isLocalGroup := false
			if strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-32-") {
				isLocalGroup = true
			} else if principal.TypeDescription == "WINDOWS_GROUP" &&
				strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") &&
				(serverInfo.DomainSID == "" || !strings.HasPrefix(principal.SecurityIdentifier, serverInfo.DomainSID+"-")) {
				isLocalGroup = true
			}
			if !isLocalGroup {
				continue
			}

			// Skip disabled logins
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
			// Also check sysadmin/securityadmin membership
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

			// ObjectID format: {serverFQDN}-{SID}
			groupObjectID := serverInfo.Hostname + "-" + principal.SecurityIdentifier

			// Skip if already processed
			if principalsWithLogin[groupObjectID] {
				continue
			}
			principalsWithLogin[groupObjectID] = true

			// MSSQL_HasLogin edge
			edge := c.createEdge(
				groupObjectID,
				principal.ObjectIdentifier,
				bloodhound.EdgeKinds.HasLogin,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    "Group",
					TargetName:    principal.Name,
					TargetType:    bloodhound.NodeKinds.Login,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
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
	// Uses nested role/permission checks matching PowerShell's second pass (lines 7676-7712)
	// Track four separate categories matching PS1's domainPrincipalsWith* arrays
	var domainPrincipalsWithSysadmin []string
	var domainPrincipalsWithSecurityadmin []string
	var domainPrincipalsWithControlServer []string
	var domainPrincipalsWithImpersonateAnyLogin []string
	var enabledDomainLoginsWithConnectSQL []types.ServerPrincipal
	isAnyDomainPrincipalSysadmin := false

	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Skip non-domain SIDs
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
			continue
		}

		// Check each admin-level access category separately (matching PS1)
		if c.hasNestedRoleMembership(principal, "sysadmin", serverInfo) {
			domainPrincipalsWithSysadmin = append(domainPrincipalsWithSysadmin, principal.ObjectIdentifier)
			isAnyDomainPrincipalSysadmin = true
		}
		if c.hasNestedRoleMembership(principal, "securityadmin", serverInfo) {
			domainPrincipalsWithSecurityadmin = append(domainPrincipalsWithSecurityadmin, principal.ObjectIdentifier)
			isAnyDomainPrincipalSysadmin = true
		}
		if c.hasEffectivePermission(principal, "CONTROL SERVER", serverInfo) {
			domainPrincipalsWithControlServer = append(domainPrincipalsWithControlServer, principal.ObjectIdentifier)
			isAnyDomainPrincipalSysadmin = true
		}
		if c.hasEffectivePermission(principal, "IMPERSONATE ANY LOGIN", serverInfo) {
			domainPrincipalsWithImpersonateAnyLogin = append(domainPrincipalsWithImpersonateAnyLogin, principal.ObjectIdentifier)
			isAnyDomainPrincipalSysadmin = true
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

		// Only create edges for domain accounts (skip NT AUTHORITY, LOCAL SERVICE, etc.)
		// Domain accounts have SIDs starting with S-1-5-21-
		isDomainAccount := strings.HasPrefix(saID, "S-1-5-21-")

		if !isDomainAccount {
			continue
		}

		// Check if the service account is the server's own computer account
		// This is used to skip HasSession only - other edges still get created for computer accounts
		// We check two conditions:
		// 1. Name matches SAMAccountName format (HOSTNAME$)
		// 2. SID matches the server's ComputerSID (for when name was converted to FQDN)
		hostname := serverInfo.Hostname
		if strings.Contains(hostname, ".") {
			hostname = strings.Split(hostname, ".")[0]
		}
		isComputerAccountName := strings.EqualFold(sa.Name, hostname+"$")
		isComputerAccountSID := serverInfo.ComputerSID != "" && saID == serverInfo.ComputerSID

		// Check if this service account was converted from a built-in account (LocalSystem, etc.)
		// This is only used for HasSession - we skip that for computer accounts running as themselves
		isConvertedFromBuiltIn := sa.ConvertedFromBuiltIn

		// ServiceAccountFor: Service Account (SID) -> SQL Server
		// We create this edge for all resolved service accounts including computer accounts
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
				SQLServerID:   serverInfo.ObjectIdentifier,
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}

		// HasSession: Computer -> Service Account
		// Skip for computer accounts (when service account IS the computer)
		// Also skip for converted built-in accounts (which become the computer account)
		// Check both name pattern (HOSTNAME$) and SID match
		isBuiltInAccount := strings.ToUpper(sa.Name) == "NT AUTHORITY\\SYSTEM" ||
			sa.Name == "LocalSystem" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\LOCAL SERVICE" ||
			strings.ToUpper(sa.Name) == "NT AUTHORITY\\NETWORK SERVICE"

		if serverInfo.ComputerSID != "" && !isBuiltInAccount && !isComputerAccountName && !isComputerAccountSID && !isConvertedFromBuiltIn {
			edge := c.createEdge(
				serverInfo.ComputerSID,
				saID,
				bloodhound.EdgeKinds.HasSession,
				&bloodhound.EdgeContext{
					SourceName:    serverInfo.Hostname,
					SourceType:    "Computer",
					TargetName:    sa.Name,
					TargetType:    "Base",
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}

		// GetAdminTGS: Service Account -> Server (if any domain principal has admin)
		if isAnyDomainPrincipalSysadmin {
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
					SQLServerID:   serverInfo.ObjectIdentifier,
				},
			)
			if edge != nil {
				// Filter domainPrincipalsWith* to only include enabled logins with CONNECT SQL
				// matching PS1 lines 9869-9900
				enabledOIDs := make(map[string]bool)
				for _, login := range enabledDomainLoginsWithConnectSQL {
					enabledOIDs[login.ObjectIdentifier] = true
				}

				filterEnabled := func(ids []string) []string {
					var filtered []string
					for _, id := range ids {
						if enabledOIDs[id] {
							filtered = append(filtered, id)
						}
					}
					if filtered == nil {
						filtered = []string{}
					}
					return filtered
				}

				edge.Properties["domainPrincipalsWithControlServer"] = filterEnabled(domainPrincipalsWithControlServer)
				edge.Properties["domainPrincipalsWithImpersonateAnyLogin"] = filterEnabled(domainPrincipalsWithImpersonateAnyLogin)
				edge.Properties["domainPrincipalsWithSecurityadmin"] = filterEnabled(domainPrincipalsWithSecurityadmin)
				edge.Properties["domainPrincipalsWithSysadmin"] = filterEnabled(domainPrincipalsWithSysadmin)
			}
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
					SQLServerID:   serverInfo.ObjectIdentifier,
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

	// Build credential lookup map for enriching edge properties with dates
	credentialByID := make(map[int]*types.Credential)
	for i := range serverInfo.Credentials {
		credentialByID[serverInfo.Credentials[i].CredentialID] = &serverInfo.Credentials[i]
	}

	// Create HasMappedCred edges from logins to their mapped credentials
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.MappedCredential == nil {
			continue
		}

		cred := principal.MappedCredential

		// Only create edges for domain credentials with a resolved SID,
		// matching PowerShell's IsDomainPrincipal && ResolvedSID check
		if cred.ResolvedSID == "" {
			continue
		}

		targetID := cred.ResolvedSID

		// HasMappedCred: Login -> AD Principal (resolved SID or credential identity)
		edge := c.createEdge(
			principal.ObjectIdentifier,
			targetID,
			bloodhound.EdgeKinds.HasMappedCred,
			&bloodhound.EdgeContext{
				SourceName:    principal.Name,
				SourceType:    bloodhound.NodeKinds.Login,
				TargetName:    cred.CredentialIdentity,
				TargetType:    "Base",
				SQLServerName: serverInfo.SQLServerName,
				SQLServerID:   serverInfo.ObjectIdentifier,
			},
		)
		if edge != nil {
			edge.Properties["credentialId"] = fmt.Sprintf("%d", cred.CredentialID)
			edge.Properties["credentialIdentity"] = cred.CredentialIdentity
			edge.Properties["credentialName"] = cred.Name
			edge.Properties["resolvedSid"] = cred.ResolvedSID
			// Get createDate/modifyDate from the standalone credentials list
			if fullCred, ok := credentialByID[cred.CredentialID]; ok {
				edge.Properties["createDate"] = fullCred.CreateDate.Format("1/2/2006 3:04:05 PM")
				edge.Properties["modifyDate"] = fullCred.ModifyDate.Format("1/2/2006 3:04:05 PM")
			}
		}
		if err := writer.WriteEdge(edge); err != nil {
			return err
		}
	}

	// =========================================================================
	// PROXY ACCOUNT EDGES
	// =========================================================================

	// Create HasProxyCred edges from logins authorized to use proxies
	for _, proxy := range serverInfo.ProxyAccounts {
		// Only create edges for domain credentials with a resolved SID,
		// matching PowerShell's IsDomainPrincipal && ResolvedSID check
		if proxy.ResolvedSID == "" {
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

			proxyTargetID := proxy.ResolvedSID

			// HasProxyCred: Login -> AD Principal (resolved SID or credential identity)
			edge := c.createEdge(
				loginObjectID,
				proxyTargetID,
				bloodhound.EdgeKinds.HasProxyCred,
				&bloodhound.EdgeContext{
					SourceName:         loginName,
					SourceType:         bloodhound.NodeKinds.Login,
					TargetName:         proxy.CredentialIdentity,
					TargetType:         "Base",
					SQLServerName:      serverInfo.SQLServerName,
					SQLServerID:        serverInfo.ObjectIdentifier,
					CredentialIdentity: proxy.CredentialIdentity,
					IsEnabled:          proxy.Enabled,
					ProxyName:          proxy.Name,
				},
			)
			if edge != nil {
				edge.Properties["authorizedPrincipals"] = strings.Join(proxy.Logins, ", ")
				edge.Properties["credentialId"] = fmt.Sprintf("%d", proxy.CredentialID)
				edge.Properties["credentialIdentity"] = proxy.CredentialIdentity
				edge.Properties["credentialName"] = proxy.CredentialName
				edge.Properties["description"] = proxy.Description
				edge.Properties["isEnabled"] = proxy.Enabled
				edge.Properties["proxyId"] = fmt.Sprintf("%d", proxy.ProxyID)
				edge.Properties["proxyName"] = proxy.Name
				edge.Properties["resolvedSid"] = proxy.ResolvedSID
				edge.Properties["subsystems"] = strings.Join(proxy.Subsystems, ", ")
				if proxy.ResolvedPrincipal != nil {
					resolvedType := proxy.ResolvedPrincipal.ObjectClass
					if len(resolvedType) > 0 {
						resolvedType = strings.ToUpper(resolvedType[:1]) + resolvedType[1:]
					}
					edge.Properties["resolvedType"] = resolvedType
				}
			}
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
			// Only create edges for domain credentials with a resolved SID,
			// matching PowerShell's IsDomainPrincipal && ResolvedSID check
			if cred.ResolvedSID == "" {
				continue
			}

			dbCredTargetID := cred.ResolvedSID

			// HasDBScopedCred: Database -> AD Principal (resolved SID or credential identity)
			edge := c.createEdge(
				db.ObjectIdentifier,
				dbCredTargetID,
				bloodhound.EdgeKinds.HasDBScopedCred,
				&bloodhound.EdgeContext{
					SourceName:    db.Name,
					SourceType:    bloodhound.NodeKinds.Database,
					TargetName:    cred.CredentialIdentity,
					TargetType:    "Base",
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
					DatabaseName:  db.Name,
				},
			)
			if edge != nil {
				edge.Properties["credentialId"] = fmt.Sprintf("%d", cred.CredentialID)
				edge.Properties["credentialIdentity"] = cred.CredentialIdentity
				edge.Properties["credentialName"] = cred.Name
				edge.Properties["createDate"] = cred.CreateDate.Format("1/2/2006 3:04:05 PM")
				edge.Properties["database"] = db.Name
				edge.Properties["modifyDate"] = cred.ModifyDate.Format("1/2/2006 3:04:05 PM")
				edge.Properties["resolvedSid"] = cred.ResolvedSID
			}
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
		}
	}

	return nil
}

// hasNestedRoleMembership checks if a server principal is a member of a target role,
// including through nested role membership chains (DFS traversal).
// This matches PowerShell's Get-NestedRoleMembership function.
func (c *Collector) hasNestedRoleMembership(principal types.ServerPrincipal, targetRoleName string, serverInfo *types.ServerInfo) bool {
	visited := make(map[string]bool)
	return c.hasNestedRoleMembershipDFS(principal.MemberOf, targetRoleName, serverInfo, visited)
}

func (c *Collector) hasNestedRoleMembershipDFS(memberOf []types.RoleMembership, targetRoleName string, serverInfo *types.ServerInfo, visited map[string]bool) bool {
	for _, role := range memberOf {
		roleName := role.Name
		if roleName == "" {
			// Try to extract from ObjectIdentifier (format: "rolename@server")
			parts := strings.SplitN(role.ObjectIdentifier, "@", 2)
			if len(parts) > 0 {
				roleName = parts[0]
			}
		}

		if visited[roleName] {
			continue
		}
		visited[roleName] = true

		if roleName == targetRoleName {
			return true
		}

		// Look up the role in server principals and recurse
		for _, sp := range serverInfo.ServerPrincipals {
			if sp.Name == roleName && sp.TypeDescription == "SERVER_ROLE" {
				if c.hasNestedRoleMembershipDFS(sp.MemberOf, targetRoleName, serverInfo, visited) {
					return true
				}
				break
			}
		}
	}
	return false
}

// fixedServerRolePermissions maps fixed server roles to their implied permissions,
// matching PowerShell's $fixedServerRolePermissions. These are permissions that
// are not explicitly granted in sys.server_permissions but are inherent to the role.
var fixedServerRolePermissions = map[string][]string{
	// sysadmin implicitly has all permissions; CONTROL SERVER is the effective grant
	"sysadmin": {"CONTROL SERVER"},
	// securityadmin can manage logins
	"securityadmin": {"ALTER ANY LOGIN"},
}

// hasEffectivePermission checks if a server principal has a permission, either directly,
// inherited through role membership chains (BFS traversal), or implied by fixed role
// membership (e.g., sysadmin implies CONTROL SERVER).
// This matches PowerShell's Get-EffectivePermissions function combined with
// $fixedServerRolePermissions logic.
func (c *Collector) hasEffectivePermission(principal types.ServerPrincipal, targetPermission string, serverInfo *types.ServerInfo) bool {
	// First check direct permissions (skip DENY)
	for _, perm := range principal.Permissions {
		if perm.Permission == targetPermission && perm.State != "DENY" {
			return true
		}
	}

	// BFS through role membership
	checked := make(map[string]bool)
	queue := []string{}

	// Seed the queue with direct role memberships
	for _, role := range principal.MemberOf {
		roleName := role.Name
		if roleName == "" {
			parts := strings.SplitN(role.ObjectIdentifier, "@", 2)
			if len(parts) > 0 {
				roleName = parts[0]
			}
		}
		queue = append(queue, roleName)
	}

	for len(queue) > 0 {
		currentRoleName := queue[0]
		queue = queue[1:]

		if checked[currentRoleName] || currentRoleName == "public" {
			continue
		}
		checked[currentRoleName] = true

		// Check fixed role implied permissions (e.g., sysadmin -> CONTROL SERVER)
		if impliedPerms, ok := fixedServerRolePermissions[currentRoleName]; ok {
			for _, impliedPerm := range impliedPerms {
				if impliedPerm == targetPermission {
					return true
				}
			}
		}

		// Find the role in server principals
		for _, sp := range serverInfo.ServerPrincipals {
			if sp.Name == currentRoleName && sp.TypeDescription == "SERVER_ROLE" {
				// Check this role's permissions
				for _, perm := range sp.Permissions {
					if perm.Permission == targetPermission {
						return true
					}
				}
				// Add nested roles to queue
				for _, nestedRole := range sp.MemberOf {
					nestedName := nestedRole.Name
					if nestedName == "" {
						parts := strings.SplitN(nestedRole.ObjectIdentifier, "@", 2)
						if len(parts) > 0 {
							nestedName = parts[0]
						}
					}
					queue = append(queue, nestedName)
				}
				break
			}
		}
	}

	return false
}

// hasNestedDBRoleMembership checks if a database principal is a member of a target role,
// including through nested role membership chains (DFS traversal).
func (c *Collector) hasNestedDBRoleMembership(principal types.DatabasePrincipal, targetRoleName string, db *types.Database) bool {
	visited := make(map[string]bool)
	return c.hasNestedDBRoleMembershipDFS(principal.MemberOf, targetRoleName, db, visited)
}

func (c *Collector) hasNestedDBRoleMembershipDFS(memberOf []types.RoleMembership, targetRoleName string, db *types.Database, visited map[string]bool) bool {
	for _, role := range memberOf {
		roleName := role.Name
		if roleName == "" {
			parts := strings.SplitN(role.ObjectIdentifier, "@", 2)
			if len(parts) > 0 {
				roleName = parts[0]
			}
		}

		key := db.Name + "::" + roleName
		if visited[key] {
			continue
		}
		visited[key] = true

		if roleName == targetRoleName {
			return true
		}

		// Look up the role in database principals and recurse
		for _, dp := range db.DatabasePrincipals {
			if dp.Name == roleName && dp.TypeDescription == "DATABASE_ROLE" {
				if c.hasNestedDBRoleMembershipDFS(dp.MemberOf, targetRoleName, db, visited) {
					return true
				}
				break
			}
		}
	}
	return false
}

// hasSecurityadminRole checks if a principal is a member of the securityadmin role (including nested)
func (c *Collector) hasSecurityadminRole(principal types.ServerPrincipal, serverInfo *types.ServerInfo) bool {
	return c.hasNestedRoleMembership(principal, "securityadmin", serverInfo)
}

// hasImpersonateAnyLogin checks if a principal has IMPERSONATE ANY LOGIN permission (including inherited)
func (c *Collector) hasImpersonateAnyLogin(principal types.ServerPrincipal, serverInfo *types.ServerInfo) bool {
	return c.hasEffectivePermission(principal, "IMPERSONATE ANY LOGIN", serverInfo)
}

// shouldCreateChangePasswordEdge determines if a ChangePassword edge should be created for a target SQL login
// based on CVE-2025-49758 patch status. If the server is patched, the edge is only created if the target
// does NOT have securityadmin role or IMPERSONATE ANY LOGIN permission.
func (c *Collector) shouldCreateChangePasswordEdge(serverInfo *types.ServerInfo, targetPrincipal types.ServerPrincipal) bool {
	// Check if server is patched for CVE-2025-49758
	if IsPatchedForCVE202549758(serverInfo.VersionNumber, serverInfo.Version) {
		// Patched - check if target has securityadmin or IMPERSONATE ANY LOGIN
		// If target has either, the patch prevents changing their password without current password
		if c.hasSecurityadminRole(targetPrincipal, serverInfo) || c.hasImpersonateAnyLogin(targetPrincipal, serverInfo) {
			// Track this skipped edge for grouped reporting (using map to deduplicate)
			c.skippedChangePasswordMu.Lock()
			if c.skippedChangePasswordEdges == nil {
				c.skippedChangePasswordEdges = make(map[string]bool)
			}
			c.skippedChangePasswordEdges[targetPrincipal.Name] = true
			c.skippedChangePasswordMu.Unlock()
			return false
		}
	}
	// Unpatched or target doesn't have protected permissions - create the edge
	return true
}

// logCVE202549758Status logs the CVE-2025-49758 vulnerability status for a server
func (c *Collector) logCVE202549758Status(serverInfo *types.ServerInfo, log *slog.Logger) {
	if serverInfo.VersionNumber == "" && serverInfo.Version == "" {
		log.Log(context.Background(), logging.LevelVerbose, "Skipping CVE-2025-49758 patch status check - server version unknown")
		return
	}

	log.Log(context.Background(), logging.LevelVerbose, "Checking for CVE-2025-49758 patch status...")
	result := CheckCVE202549758(serverInfo.VersionNumber, serverInfo.Version)
	if result == nil {
		log.Log(context.Background(), logging.LevelVerbose, "Unable to parse SQL version for CVE-2025-49758 check")
		return
	}

	log.Info("Detected SQL version", "version", result.VersionDetected)
	if result.IsVulnerable {
		log.Warn("CVE-2025-49758: VULNERABLE", "version", result.VersionDetected, "requiredVersion", result.RequiredVersion)
	} else if result.IsPatched {
		log.Log(context.Background(), logging.LevelVerbose, "CVE-2025-49758: NOT vulnerable", "version", result.VersionDetected)
	}
}

// processLinkedServers resolves linked server ObjectIdentifiers and queues them for collection if enabled
func (c *Collector) processLinkedServers(serverInfo *types.ServerInfo, server *ServerToProcess) {
	if len(serverInfo.LinkedServers) == 0 {
		return
	}

	// Only do expensive DNS/LDAP resolution if collecting from linked servers
	if !c.config.CollectFromLinkedServers {
		// When not collecting, just set basic ObjectIdentifiers for edge generation
		for i := range serverInfo.LinkedServers {
			ls := &serverInfo.LinkedServers[i]
			targetHost := ls.DataSource
			if targetHost == "" {
				targetHost = ls.Name
			}
			hostname, port, instanceName := c.parseDataSource(targetHost)

			// Extract domain from source server
			sourceDomain := ""
			if strings.Contains(serverInfo.Hostname, ".") {
				parts := strings.SplitN(serverInfo.Hostname, ".", 2)
				if len(parts) > 1 {
					sourceDomain = parts[1]
				}
			}

			// Resolve ObjectIdentifier (needed for edge generation)
			resolvedID := c.resolveDataSourceToSID(hostname, port, instanceName, sourceDomain)
			ls.ResolvedObjectIdentifier = resolvedID
		}
		return
	}

	// Full processing when collecting from linked servers (includes DNS lookups for queueing)
	for i := range serverInfo.LinkedServers {
		ls := &serverInfo.LinkedServers[i]

		// Resolve the target server hostname
		targetHost := ls.DataSource
		if targetHost == "" {
			targetHost = ls.Name
		}

		// Parse hostname, port, and instance from DataSource
		// Formats: hostname, hostname:port, hostname\instance, hostname,port
		hostname, port, instanceName := c.parseDataSource(targetHost)

		// Strip instance name if present for FQDN resolution
		resolvedHost := hostname

		// If hostname is an IP address, try to resolve to hostname
		if net.ParseIP(hostname) != nil {
			if names, err := net.LookupAddr(hostname); err == nil && len(names) > 0 {
				// Use the first resolved name, strip trailing dot
				resolvedHostFromIP := strings.TrimSuffix(names[0], ".")
				// Extract just hostname part for SID resolution
				if strings.Contains(resolvedHostFromIP, ".") {
					hostname = strings.Split(resolvedHostFromIP, ".")[0]
				} else {
					hostname = resolvedHostFromIP
				}
			}
		}

		// Try to resolve FQDN if not already one
		if !strings.Contains(resolvedHost, ".") {
			// Try DNS resolution
			if addrs, err := net.LookupHost(resolvedHost); err == nil && len(addrs) > 0 {
				if names, err := net.LookupAddr(addrs[0]); err == nil && len(names) > 0 {
					resolvedHost = strings.TrimSuffix(names[0], ".")
				}
			}
		}

		// Extract domain from source server for linked server lookups
		sourceDomain := ""
		if strings.Contains(serverInfo.Hostname, ".") {
			parts := strings.SplitN(serverInfo.Hostname, ".", 2)
			if len(parts) > 1 {
				sourceDomain = parts[1]
			}
		}

		// Resolve the linked server's ResolvedObjectIdentifier (SID:port format)
		resolvedID := c.resolveDataSourceToSID(hostname, port, instanceName, sourceDomain)
		ls.ResolvedObjectIdentifier = resolvedID

		// Check if already in queue
		isAlreadyQueued := false
		for _, existing := range c.serversToProcess {
			if strings.EqualFold(existing.Hostname, resolvedHost) ||
				strings.EqualFold(existing.Hostname, hostname) {
				isAlreadyQueued = true
				break
			}
		}

		// Add to queue if not already there
		if !isAlreadyQueued {
			c.addLinkedServerToQueue(resolvedHost, serverInfo.Hostname, sourceDomain)
		}
	}
}

// parseDataSource parses a SQL Server data source string into hostname, port, and instance name
// Supports formats: hostname, hostname:port, hostname\instance, hostname,port, hostname\instance,port
func (c *Collector) parseDataSource(dataSource string) (hostname, port, instanceName string) {
	// Default port
	port = "1433"
	hostname = dataSource

	// Check for instance name (backslash)
	if idx := strings.Index(dataSource, "\\"); idx != -1 {
		hostname = dataSource[:idx]
		remaining := dataSource[idx+1:]

		// Check if there's a port after the instance
		if commaIdx := strings.Index(remaining, ","); commaIdx != -1 {
			instanceName = remaining[:commaIdx]
			port = remaining[commaIdx+1:]
		} else if colonIdx := strings.Index(remaining, ":"); colonIdx != -1 {
			instanceName = remaining[:colonIdx]
			port = remaining[colonIdx+1:]
		} else {
			instanceName = remaining
		}
		return
	}

	// Check for port (comma or colon without backslash)
	if commaIdx := strings.Index(dataSource, ","); commaIdx != -1 {
		hostname = dataSource[:commaIdx]
		port = dataSource[commaIdx+1:]
		return
	}

	// Also support colon for port (common in JDBC-style connections)
	if colonIdx := strings.LastIndex(dataSource, ":"); colonIdx != -1 {
		// Make sure it's not a drive letter (e.g., C:\...)
		if colonIdx > 1 {
			hostname = dataSource[:colonIdx]
			port = dataSource[colonIdx+1:]
		}
	}

	return
}

// resolveLinkedServerSourceID resolves the source server ObjectIdentifier for a chained linked server.
// When a linked server's SourceServer differs from the current server's hostname, this resolves
// the source to a SID:port format. Falls back to "LinkedServer:hostname" if resolution fails.
// This matches PowerShell's Resolve-DataSourceToSid behavior for linked server source resolution.
func (c *Collector) resolveLinkedServerSourceID(sourceServer string, serverInfo *types.ServerInfo) string {
	hostname, port, instanceName := c.parseDataSource(sourceServer)

	// Extract domain from current server for resolution
	sourceDomain := ""
	if strings.Contains(serverInfo.Hostname, ".") {
		parts := strings.SplitN(serverInfo.Hostname, ".", 2)
		if len(parts) > 1 {
			sourceDomain = parts[1]
		}
	}

	resolved := c.resolveDataSourceToSID(hostname, port, instanceName, sourceDomain)

	// Check if resolution succeeded (starts with S-1-5- means SID was resolved)
	if strings.HasPrefix(resolved, "S-1-5-") {
		return resolved
	}

	// Fallback to LinkedServer:hostname format (matching PowerShell behavior)
	return "LinkedServer:" + sourceServer
}

// resolveDataSourceToSID resolves a data source to SID:port format for linked server edges
// Returns SID:port if the hostname can be resolved, otherwise returns hostname:port
func (c *Collector) resolveDataSourceToSID(hostname, port, instanceName, domain string) string {
	// For cloud SQL servers (Azure, AWS RDS, etc.), use hostname:port format
	if strings.Contains(hostname, ".database.windows.net") ||
		strings.Contains(hostname, ".rds.amazonaws.com") ||
		strings.Contains(hostname, ".database.azure.com") {
		if instanceName != "" {
			return fmt.Sprintf("%s:%s", hostname, instanceName)
		}
		return fmt.Sprintf("%s:%s", hostname, port)
	}

	// Try to resolve the computer SID
	machineName := hostname
	if strings.Contains(machineName, ".") {
		machineName = strings.Split(machineName, ".")[0]
	}

	// Try Windows API first
	sid, err := ad.ResolveComputerSIDWindows(machineName, domain)
	if err == nil && sid != "" {
		if instanceName != "" {
			return fmt.Sprintf("%s:%s", sid, instanceName)
		}
		return fmt.Sprintf("%s:%s", sid, port)
	}

	// Try LDAP if domain is specified and Windows API failed
	if domain != "" {
		adClient := c.newADClient(domain)
		if adClient != nil {
			defer adClient.Close()

			sid, err = adClient.ResolveComputerSID(machineName)
			if err != nil && isLDAPAuthError(err) {
				c.setLDAPAuthFailed()
			} else if err == nil && sid != "" {
				if instanceName != "" {
					return fmt.Sprintf("%s:%s", sid, instanceName)
				}
				return fmt.Sprintf("%s:%s", sid, port)
			}
		}
	}

	// Fallback to hostname:port if SID resolution fails
	if instanceName != "" {
		return fmt.Sprintf("%s:%s", hostname, instanceName)
	}
	return fmt.Sprintf("%s:%s", hostname, port)
}

// addLinkedServerToQueue adds a discovered linked server to the queue for later processing
func (c *Collector) addLinkedServerToQueue(hostname string, discoveredFrom string, domain string) {
	c.linkedServersMu.Lock()
	defer c.linkedServersMu.Unlock()

	// Check for duplicates
	for _, ls := range c.linkedServersToProcess {
		if strings.EqualFold(ls.Hostname, hostname) {
			return
		}
	}

	server := c.parseServerString(hostname)
	server.DiscoveredFrom = discoveredFrom
	server.Domain = domain
	c.tryResolveSID(server, nil)
	c.linkedServersToProcess = append(c.linkedServersToProcess, server)
}

// processLinkedServersQueue processes discovered linked servers recursively
func (c *Collector) processLinkedServersQueue(processedServers map[string]bool) {
	iteration := 0
	for {
		// Get current batch of linked servers to process
		c.linkedServersMu.Lock()
		if len(c.linkedServersToProcess) == 0 {
			c.linkedServersMu.Unlock()
			break
		}

		// Take the current batch and reset
		currentBatch := c.linkedServersToProcess
		c.linkedServersToProcess = nil
		c.linkedServersMu.Unlock()

		// Filter out already processed servers
		var serversToProcess []*ServerToProcess
		for _, server := range currentBatch {
			key := strings.ToLower(server.Hostname)
			if !processedServers[key] {
				serversToProcess = append(serversToProcess, server)
				processedServers[key] = true
			} else {
				c.config.Logger.Log(context.Background(), logging.LevelVerbose, "Skipping already processed linked server", "hostname", server.Hostname)
			}
		}

		if len(serversToProcess) == 0 {
			continue
		}

		iteration++
		c.config.Logger.Info("Processing linked servers", "count", len(serversToProcess), "iteration", iteration)

		// Process this batch
		for i, server := range serversToProcess {
			log := c.config.Logger.With("target", server.ConnectionString)
			log.Info("Processing linked server", "progress", fmt.Sprintf("%d/%d", i+1, len(serversToProcess)), "discoveredFrom", server.DiscoveredFrom)

			if err := c.processServer(server); err != nil {
				log.Warn("Failed to process linked server", "error", err)
				// Continue with other servers
			}
		}
	}
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
					SQLServerID:   serverInfo.ObjectIdentifier,
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
					SQLServerID:   serverInfo.ObjectIdentifier,
					IsFixedRole:   true,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}

			// securityadmin also has ALTER ANY LOGIN
			edge = c.createEdge(
				principal.ObjectIdentifier,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.AlterAnyLogin,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    bloodhound.NodeKinds.ServerRole,
					TargetName:    serverInfo.ServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
					IsFixedRole:   true,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}

			// Also create ChangePassword edges to SQL logins (same logic as explicit ALTER ANY LOGIN)
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

				// Check if target has sysadmin or CONTROL SERVER (including nested)
				targetHasSysadmin := c.hasNestedRoleMembership(targetPrincipal, "sysadmin", serverInfo)
				targetHasControlServer := c.hasEffectivePermission(targetPrincipal, "CONTROL SERVER", serverInfo)

				if !targetHasSysadmin && !targetHasControlServer {
					// Check CVE-2025-49758 patch status to determine if edge should be created
					if !c.shouldCreateChangePasswordEdge(serverInfo, targetPrincipal) {
						continue
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						targetPrincipal.ObjectIdentifier,
						bloodhound.EdgeKinds.ChangePassword,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            bloodhound.NodeKinds.ServerRole,
							TargetName:            targetPrincipal.Name,
							TargetType:            bloodhound.NodeKinds.Login,
							TargetTypeDescription: targetPrincipal.TypeDescription,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            "ALTER ANY LOGIN",
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
			}
		case "##MS_LoginManager##":
			// SQL Server 2022+ fixed role: has ALTER ANY LOGIN permission
			edge := c.createEdge(
				principal.ObjectIdentifier,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.AlterAnyLogin,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    bloodhound.NodeKinds.ServerRole,
					TargetName:    serverInfo.ServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
					IsFixedRole:   true,
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}

			// Also create ChangePassword edges to SQL logins (same logic as ALTER ANY LOGIN)
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

				// Check if target has sysadmin or CONTROL SERVER (including nested)
				targetHasSysadmin := c.hasNestedRoleMembership(targetPrincipal, "sysadmin", serverInfo)
				targetHasControlServer := c.hasEffectivePermission(targetPrincipal, "CONTROL SERVER", serverInfo)

				if !targetHasSysadmin && !targetHasControlServer {
					if !c.shouldCreateChangePasswordEdge(serverInfo, targetPrincipal) {
						continue
					}

					cpEdge := c.createEdge(
						principal.ObjectIdentifier,
						targetPrincipal.ObjectIdentifier,
						bloodhound.EdgeKinds.ChangePassword,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            bloodhound.NodeKinds.ServerRole,
							TargetName:            targetPrincipal.Name,
							TargetType:            bloodhound.NodeKinds.Login,
							TargetTypeDescription: targetPrincipal.TypeDescription,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            "ALTER ANY LOGIN",
						},
					)
					if err := writer.WriteEdge(cpEdge); err != nil {
						return err
					}
				}
			}

		case "##MS_DatabaseConnector##":
			// SQL Server 2022+ fixed role: has CONNECT ANY DATABASE permission
			edge := c.createEdge(
				principal.ObjectIdentifier,
				serverInfo.ObjectIdentifier,
				bloodhound.EdgeKinds.ConnectAnyDatabase,
				&bloodhound.EdgeContext{
					SourceName:    principal.Name,
					SourceType:    bloodhound.NodeKinds.ServerRole,
					TargetName:    serverInfo.ServerName,
					TargetType:    bloodhound.NodeKinds.Server,
					SQLServerName: serverInfo.SQLServerName,
					SQLServerID:   serverInfo.ObjectIdentifier,
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
				// db_owner has CONTROL on the database - create both Control and ControlDB edges
				// MSSQL_Control (non-traversable) - matches PowerShell behavior
				edge := c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.Control,
					&bloodhound.EdgeContext{
						SourceName:            principal.Name,
						SourceType:            bloodhound.NodeKinds.DatabaseRole,
						TargetName:            db.Name,
						TargetType:            bloodhound.NodeKinds.Database,
						TargetTypeDescription: "DATABASE",
						SQLServerName:         serverInfo.SQLServerName,
						SQLServerID:           serverInfo.ObjectIdentifier,
						DatabaseName:          db.Name,
						IsFixedRole:           true,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// MSSQL_ControlDB (traversable)
				edge = c.createEdge(
					principal.ObjectIdentifier,
					db.ObjectIdentifier,
					bloodhound.EdgeKinds.ControlDB,
					&bloodhound.EdgeContext{
						SourceName:            principal.Name,
						SourceType:            bloodhound.NodeKinds.DatabaseRole,
						TargetName:            db.Name,
						TargetType:            bloodhound.NodeKinds.Database,
						TargetTypeDescription: "DATABASE",
						SQLServerName:         serverInfo.SQLServerName,
						SQLServerID:           serverInfo.ObjectIdentifier,
						DatabaseName:          db.Name,
						IsFixedRole:           true,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// NOTE: db_owner does NOT create explicit AddMember or ChangePassword edges
				// Its ability to add members and change passwords comes from the implicit ControlDB permission
				// PowerShell doesn't create these edges from db_owner either

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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
								SourceName:            principal.Name,
								SourceType:            bloodhound.NodeKinds.DatabaseRole,
								TargetName:            targetRole.Name,
								TargetType:            bloodhound.NodeKinds.DatabaseRole,
								TargetTypeDescription: targetRole.TypeDescription,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								IsFixedRole:           true,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}

				// db_securityadmin can change password for application roles (via ALTER ANY APPLICATION ROLE)
				for _, appRole := range db.DatabasePrincipals {
					if appRole.TypeDescription == "APPLICATION_ROLE" {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							appRole.ObjectIdentifier,
							bloodhound.EdgeKinds.ChangePassword,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            bloodhound.NodeKinds.DatabaseRole,
								TargetName:            appRole.Name,
								TargetType:            bloodhound.NodeKinds.ApplicationRole,
								TargetTypeDescription: appRole.TypeDescription,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								IsFixedRole:           true,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}

			case "db_accessadmin":
				// db_accessadmin does NOT have any special permissions that create edges
				// Its role is to manage database access (adding users), which is handled
				// through its membership in the database, not through explicit permissions
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
							SQLServerID:   serverInfo.ObjectIdentifier,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
					targetTypeDesc := ""
					isServerRole := false
					isLogin := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetTypeDesc = targetPrincipal.TypeDescription
						if targetPrincipal.TypeDescription == "SERVER_ROLE" {
							targetType = bloodhound.NodeKinds.ServerRole
							isServerRole = true
						} else {
							// It's a login type (WINDOWS_LOGIN, SQL_LOGIN, etc.)
							isLogin = true
						}
					}

					// First create non-traversable MSSQL_Control edge (matches PowerShell)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Control,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getServerPrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            targetType,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// CONTROL on login = ImpersonateLogin (MSSQL_ExecuteAs), no restrictions (even sa)
					if isLogin {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ExecuteAs,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getServerPrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            targetType,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}

					// CONTROL implies AddMember and ChangeOwner for server roles
					if isServerRole {
						// Can only add members to fixed roles if source is member (except sysadmin)
						// or to user-defined roles
						canAddMember := false
						if targetPrincipal != nil && !targetPrincipal.IsFixedRole {
							canAddMember = true
						}
						// Check if source is member of target fixed role (except sysadmin)
						if targetPrincipal != nil && targetPrincipal.IsFixedRole && targetName != "sysadmin" {
							for _, membership := range principal.MemberOf {
								if membership.Name == targetName {
									canAddMember = true
									break
								}
							}
						}

						if canAddMember {
							edge := c.createEdge(
								principal.ObjectIdentifier,
								perm.TargetObjectIdentifier,
								bloodhound.EdgeKinds.AddMember,
								&bloodhound.EdgeContext{
									SourceName:            principal.Name,
									SourceType:            c.getServerPrincipalType(principal.TypeDescription),
									TargetName:            targetName,
									TargetType:            targetType,
									TargetTypeDescription: targetTypeDesc,
									SQLServerName:         serverInfo.SQLServerName,
									SQLServerID:           serverInfo.ObjectIdentifier,
									Permission:            perm.Permission,
								},
							)
							if err := writer.WriteEdge(edge); err != nil {
								return err
							}
						}

						edge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ChangeOwner,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getServerPrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            targetType,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								Permission:            perm.Permission,
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
					targetTypeDesc := ""
					isServerRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetTypeDesc = targetPrincipal.TypeDescription
						if targetPrincipal.TypeDescription == "SERVER_ROLE" {
							targetType = bloodhound.NodeKinds.ServerRole
							isServerRole = true
						}
					}

					// Always create the MSSQL_Alter edge (matches PowerShell)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Alter,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getServerPrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            targetType,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// For server roles, also create AddMember edge if conditions are met
					if isServerRole {
						canAddMember := false
						// User-defined roles: anyone with ALTER can add members
						if targetPrincipal != nil && !targetPrincipal.IsFixedRole {
							canAddMember = true
						}
						// Fixed roles (except sysadmin): can add members if source is member of the role
						if targetPrincipal != nil && targetPrincipal.IsFixedRole && targetName != "sysadmin" {
							for _, membership := range principal.MemberOf {
								if membership.Name == targetName {
									canAddMember = true
									break
								}
							}
						}
						if canAddMember {
							addMemberEdge := c.createEdge(
								principal.ObjectIdentifier,
								perm.TargetObjectIdentifier,
								bloodhound.EdgeKinds.AddMember,
								&bloodhound.EdgeContext{
									SourceName:            principal.Name,
									SourceType:            c.getServerPrincipalType(principal.TypeDescription),
									TargetName:            targetName,
									TargetType:            targetType,
									TargetTypeDescription: targetTypeDesc,
									SQLServerName:         serverInfo.SQLServerName,
									SQLServerID:           serverInfo.ObjectIdentifier,
									Permission:            perm.Permission,
								},
							)
							if err := writer.WriteEdge(addMemberEdge); err != nil {
								return err
							}
						}
					}
				}

			case "TAKE OWNERSHIP":
				// TAKE OWNERSHIP on a server principal
				if perm.ClassDesc == "SERVER_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.Login
					targetTypeDesc := ""
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetTypeDesc = targetPrincipal.TypeDescription
						if targetPrincipal.TypeDescription == "SERVER_ROLE" {
							targetType = bloodhound.NodeKinds.ServerRole
						}
					}

					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.TakeOwnership,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getServerPrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            targetType,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// TAKE OWNERSHIP on SERVER_ROLE also grants ChangeOwner (matches PowerShell)
					if targetPrincipal != nil && targetPrincipal.TypeDescription == "SERVER_ROLE" {
						changeOwnerEdge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ChangeOwner,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getServerPrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            bloodhound.NodeKinds.ServerRole,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(changeOwnerEdge); err != nil {
							return err
						}
					}
				}

			case "IMPERSONATE":
				if perm.ClassDesc == "SERVER_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetTypeDesc := ""
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetTypeDesc = targetPrincipal.TypeDescription
					}

					// MSSQL_Impersonate edge (matches PowerShell which uses MSSQL_Impersonate at server level)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Impersonate,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getServerPrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            bloodhound.NodeKinds.Login,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            perm.Permission,
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
							SourceName:            principal.Name,
							SourceType:            c.getServerPrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            bloodhound.NodeKinds.Login,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            perm.Permission,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
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

					// Check if target has sysadmin or CONTROL SERVER (including nested)
					targetHasSysadmin := c.hasNestedRoleMembership(targetPrincipal, "sysadmin", serverInfo)
					targetHasControlServer := c.hasEffectivePermission(targetPrincipal, "CONTROL SERVER", serverInfo)

					if targetHasSysadmin || targetHasControlServer {
						continue
					}

					// Check CVE-2025-49758 patch status to determine if edge should be created
					if !c.shouldCreateChangePasswordEdge(serverInfo, targetPrincipal) {
						continue
					}

					// Create ChangePassword edge
					edge := c.createEdge(
						principal.ObjectIdentifier,
						targetPrincipal.ObjectIdentifier,
						bloodhound.EdgeKinds.ChangePassword,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getServerPrincipalType(principal.TypeDescription),
							TargetName:            targetPrincipal.Name,
							TargetType:            bloodhound.NodeKinds.Login,
							TargetTypeDescription: targetPrincipal.TypeDescription,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							Permission:            perm.Permission,
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
						SQLServerID:   serverInfo.ObjectIdentifier,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// Also create AddMember edges to each applicable server role
				// Matches PowerShell: user-defined roles always, fixed roles only if source is direct member (except sysadmin)
				for _, targetRole := range serverInfo.ServerPrincipals {
					if targetRole.TypeDescription != "SERVER_ROLE" {
						continue
					}

					canAlterRole := false
					if !targetRole.IsFixedRole {
						// User-defined role: anyone with ALTER ANY SERVER ROLE can alter it
						canAlterRole = true
					} else if targetRole.Name != "sysadmin" {
						// Fixed role (except sysadmin): can only add members if source is a direct member
						for _, membership := range principal.MemberOf {
							if membership.Name == targetRole.Name {
								canAlterRole = true
								break
							}
						}
					}

					if canAlterRole {
						addMemberEdge := c.createEdge(
							principal.ObjectIdentifier,
							targetRole.ObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getServerPrincipalType(principal.TypeDescription),
								TargetName:            targetRole.Name,
								TargetType:            bloodhound.NodeKinds.ServerRole,
								TargetTypeDescription: targetRole.TypeDescription,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(addMemberEdge); err != nil {
							return err
						}
					}
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
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            db.Name,
							TargetType:            bloodhound.NodeKinds.Database,
							TargetTypeDescription: "DATABASE",
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
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
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            db.Name,
							TargetType:            bloodhound.NodeKinds.Database,
							TargetTypeDescription: "DATABASE",
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
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
					targetTypeDesc := ""
					isRole := false
					isUser := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetType = c.getDatabasePrincipalType(targetPrincipal.TypeDescription)
						targetTypeDesc = targetPrincipal.TypeDescription
						isRole = targetPrincipal.TypeDescription == "DATABASE_ROLE"
						isUser = targetPrincipal.TypeDescription == "WINDOWS_USER" ||
							targetPrincipal.TypeDescription == "WINDOWS_GROUP" ||
							targetPrincipal.TypeDescription == "SQL_USER" ||
							targetPrincipal.TypeDescription == "ASYMMETRIC_KEY_MAPPED_USER" ||
							targetPrincipal.TypeDescription == "CERTIFICATE_MAPPED_USER"
					}

					// First create the non-traversable MSSQL_Control edge
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Control,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            targetType,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// Use specific edge type based on target
					if isRole {
						// CONTROL on role = Add members + Change owner
						edge = c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            targetType,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}

						edge = c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ChangeOwner,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            targetType,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					} else if isUser {
						// CONTROL on user = Impersonate (MSSQL_ExecuteAs)
						edge = c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ExecuteAs,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            targetType,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
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
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            db.Name,
							TargetType:            bloodhound.NodeKinds.Database,
							TargetTypeDescription: "DATABASE",
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}
				}
				break
			case "ALTER":
				if perm.ClassDesc == "DATABASE" {
					// ALTER on the database itself - use MSSQL_Alter to match PowerShell
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.Alter,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            db.Name,
							TargetType:            bloodhound.NodeKinds.Database,
							TargetTypeDescription: "DATABASE",
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// ALTER on database grants effective ALTER ANY APPLICATION ROLE and ALTER ANY ROLE
					// Create AddMember edges to roles and ChangePassword edges to application roles
					for _, targetPrincipal := range db.DatabasePrincipals {
						if targetPrincipal.ObjectIdentifier == principal.ObjectIdentifier {
							continue // Skip self
						}

						// Check if source principal is db_owner
						isDbOwner := false
						for _, role := range principal.MemberOf {
							if role.Name == "db_owner" {
								isDbOwner = true
								break
							}
						}

						switch targetPrincipal.TypeDescription {
						case "DATABASE_ROLE":
							// db_owner can alter any role, others can only alter user-defined roles
							if targetPrincipal.Name != "public" &&
								(isDbOwner || !targetPrincipal.IsFixedRole) {
								edge := c.createEdge(
									principal.ObjectIdentifier,
									targetPrincipal.ObjectIdentifier,
									bloodhound.EdgeKinds.AddMember,
									&bloodhound.EdgeContext{
										SourceName:            principal.Name,
										SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
										TargetName:            targetPrincipal.Name,
										TargetType:            bloodhound.NodeKinds.DatabaseRole,
										TargetTypeDescription: targetPrincipal.TypeDescription,
										SQLServerName:         serverInfo.SQLServerName,
										SQLServerID:           serverInfo.ObjectIdentifier,
										DatabaseName:          db.Name,
										Permission:            perm.Permission,
									},
								)
								if err := writer.WriteEdge(edge); err != nil {
									return err
								}
							}
						case "APPLICATION_ROLE":
							// ALTER on database allows changing application role passwords
							edge := c.createEdge(
								principal.ObjectIdentifier,
								targetPrincipal.ObjectIdentifier,
								bloodhound.EdgeKinds.ChangePassword,
								&bloodhound.EdgeContext{
									SourceName:            principal.Name,
									SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
									TargetName:            targetPrincipal.Name,
									TargetType:            bloodhound.NodeKinds.ApplicationRole,
									TargetTypeDescription: targetPrincipal.TypeDescription,
									SQLServerName:         serverInfo.SQLServerName,
									SQLServerID:           serverInfo.ObjectIdentifier,
									DatabaseName:          db.Name,
									Permission:            perm.Permission,
								},
							)
							if err := writer.WriteEdge(edge); err != nil {
								return err
							}
						}
					}
				} else if perm.ClassDesc == "DATABASE_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					// ALTER on a database principal - always use MSSQL_Alter to match PowerShell
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetType := bloodhound.NodeKinds.DatabaseUser
					targetTypeDesc := ""
					isRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetType = c.getDatabasePrincipalType(targetPrincipal.TypeDescription)
						targetTypeDesc = targetPrincipal.TypeDescription
						isRole = targetPrincipal.TypeDescription == "DATABASE_ROLE"
					}

					// Always create MSSQL_Alter edge (matches PowerShell)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Alter,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            targetType,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// For database roles, also create AddMember edge (matches PowerShell)
					if isRole {
						addMemberEdge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            targetName,
								TargetType:            targetType,
								TargetTypeDescription: targetTypeDesc,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(addMemberEdge); err != nil {
							return err
						}
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
						SQLServerID:   serverInfo.ObjectIdentifier,
						DatabaseName:  db.Name,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// Also create AddMember edges to each eligible database role
				// Matches PowerShell: user-defined roles always, fixed roles only if source is db_owner (except public)
				for _, targetRole := range db.DatabasePrincipals {
					if targetRole.TypeDescription != "DATABASE_ROLE" {
						continue
					}
					if targetRole.ObjectIdentifier == principal.ObjectIdentifier {
						continue // Skip self
					}
					if targetRole.Name == "public" {
						continue // public role membership cannot be changed
					}

					// Check if source principal is db_owner (member of db_owner role)
					isDbOwner := false
					for _, role := range principal.MemberOf {
						if role.Name == "db_owner" {
							isDbOwner = true
							break
						}
					}

					// db_owner can alter any role, others can only alter user-defined roles
					if isDbOwner || !targetRole.IsFixedRole {
						addMemberEdge := c.createEdge(
							principal.ObjectIdentifier,
							targetRole.ObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            targetRole.Name,
								TargetType:            bloodhound.NodeKinds.DatabaseRole,
								TargetTypeDescription: targetRole.TypeDescription,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(addMemberEdge); err != nil {
							return err
						}
					}
				}
				break
			case "ALTER ANY APPLICATION ROLE":
				// Create edge to the database since this permission affects ANY application role
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
						SQLServerID:   serverInfo.ObjectIdentifier,
						DatabaseName:  db.Name,
						Permission:    perm.Permission,
					},
				)
				if err := writer.WriteEdge(edge); err != nil {
					return err
				}

				// Create ChangePassword edges to each individual application role
				for _, appRole := range db.DatabasePrincipals {
					if appRole.TypeDescription == "APPLICATION_ROLE" &&
						appRole.ObjectIdentifier != principal.ObjectIdentifier {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							appRole.ObjectIdentifier,
							bloodhound.EdgeKinds.ChangePassword,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            appRole.Name,
								TargetType:            bloodhound.NodeKinds.ApplicationRole,
								TargetTypeDescription: appRole.TypeDescription,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}
					}
				}
				break

			case "IMPERSONATE":
				// IMPERSONATE on a database user
				if perm.ClassDesc == "DATABASE_PRINCIPAL" && perm.TargetObjectIdentifier != "" {
					targetPrincipal := principalMap[perm.TargetPrincipalID]
					targetName := perm.TargetName
					targetTypeDesc := ""
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetTypeDesc = targetPrincipal.TypeDescription
					}

					// PowerShell creates both MSSQL_Impersonate and MSSQL_ExecuteAs for database user impersonation
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Impersonate,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            bloodhound.NodeKinds.DatabaseUser,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
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
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            targetName,
							TargetType:            bloodhound.NodeKinds.DatabaseUser,
							TargetTypeDescription: targetTypeDesc,
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
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
					// Create TakeOwnership edge to the database (non-traversable)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.TakeOwnership,
						&bloodhound.EdgeContext{
							SourceName:            principal.Name,
							SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
							TargetName:            db.Name,
							TargetType:            bloodhound.NodeKinds.Database,
							TargetTypeDescription: "DATABASE",
							SQLServerName:         serverInfo.SQLServerName,
							SQLServerID:           serverInfo.ObjectIdentifier,
							DatabaseName:          db.Name,
							Permission:            perm.Permission,
						},
					)
					if err := writer.WriteEdge(edge); err != nil {
						return err
					}

					// TAKE OWNERSHIP on database also grants ChangeOwner to all database roles
					for _, targetRole := range db.DatabasePrincipals {
						if targetRole.TypeDescription == "DATABASE_ROLE" {
							changeOwnerEdge := c.createEdge(
								principal.ObjectIdentifier,
								targetRole.ObjectIdentifier,
								bloodhound.EdgeKinds.ChangeOwner,
								&bloodhound.EdgeContext{
									SourceName:            principal.Name,
									SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
									TargetName:            targetRole.Name,
									TargetType:            bloodhound.NodeKinds.DatabaseRole,
									TargetTypeDescription: targetRole.TypeDescription,
									SQLServerName:         serverInfo.SQLServerName,
									SQLServerID:           serverInfo.ObjectIdentifier,
									DatabaseName:          db.Name,
									Permission:            perm.Permission,
								},
							)
							if err := writer.WriteEdge(changeOwnerEdge); err != nil {
								return err
							}
						}
					}
				} else if perm.TargetObjectIdentifier != "" {
					// TAKE OWNERSHIP on a specific object
					// Find the target principal
					var targetPrincipal *types.DatabasePrincipal
					for idx := range db.DatabasePrincipals {
						if db.DatabasePrincipals[idx].ObjectIdentifier == perm.TargetObjectIdentifier {
							targetPrincipal = &db.DatabasePrincipals[idx]
							break
						}
					}

					if targetPrincipal != nil {
						// Create TakeOwnership edge (non-traversable)
						edge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.TakeOwnership,
							&bloodhound.EdgeContext{
								SourceName:            principal.Name,
								SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:            targetPrincipal.Name,
								TargetType:            c.getDatabasePrincipalType(targetPrincipal.TypeDescription),
								TargetTypeDescription: targetPrincipal.TypeDescription,
								SQLServerName:         serverInfo.SQLServerName,
								SQLServerID:           serverInfo.ObjectIdentifier,
								DatabaseName:          db.Name,
								Permission:            perm.Permission,
							},
						)
						if err := writer.WriteEdge(edge); err != nil {
							return err
						}

						// If target is a DATABASE_ROLE, also create ChangeOwner edge
						if targetPrincipal.TypeDescription == "DATABASE_ROLE" {
							changeOwnerEdge := c.createEdge(
								principal.ObjectIdentifier,
								perm.TargetObjectIdentifier,
								bloodhound.EdgeKinds.ChangeOwner,
								&bloodhound.EdgeContext{
									SourceName:            principal.Name,
									SourceType:            c.getDatabasePrincipalType(principal.TypeDescription),
									TargetName:            targetPrincipal.Name,
									TargetType:            bloodhound.NodeKinds.DatabaseRole,
									TargetTypeDescription: targetPrincipal.TypeDescription,
									SQLServerName:         serverInfo.SQLServerName,
									SQLServerID:           serverInfo.ObjectIdentifier,
									DatabaseName:          db.Name,
									Permission:            perm.Permission,
								},
							)
							if err := writer.WriteEdge(changeOwnerEdge); err != nil {
								return err
							}
						}
					}
				}
				break
			}
		}
	}

	return nil
}

// createEdge creates a BloodHound edge with properties.
// Returns nil if the edge is non-traversable and IncludeNontraversableEdges is false,
// matching PowerShell's Add-Edge behavior which drops non-traversable edges entirely.
func (c *Collector) createEdge(sourceID, targetID, kind string, ctx *bloodhound.EdgeContext) *bloodhound.Edge {
	// Auto-set SourceID and TargetID from parameters so callers don't need to
	if ctx != nil {
		ctx.SourceID = sourceID
		ctx.TargetID = targetID
	}
	props := bloodhound.GetEdgeProperties(kind, ctx)

	// Apply MakeInterestingEdgesTraversable overrides before filtering
	if c.config.MakeInterestingEdgesTraversable {
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

	// Drop non-traversable edges when IncludeNontraversableEdges is false
	// This matches PowerShell's Add-Edge behavior which returns early (drops the edge)
	// when the edge is non-traversable and IncludeNontraversableEdges is disabled
	if !c.config.IncludeNontraversableEdges {
		if traversable, ok := props["traversable"].(bool); ok && !traversable {
			return nil
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

// writeADFiles writes accumulated AD nodes to separate files (computers.json, users.json, groups.json)
func (c *Collector) writeADFiles() error {
	type adFileSpec struct {
		filename string
		nodes    []*bloodhound.Node
	}

	specs := []adFileSpec{
		{"computers.json", c.adComputers},
		{"users.json", c.adUsers},
		{"groups.json", c.adGroups},
	}

	var written []string
	for _, spec := range specs {
		if len(spec.nodes) == 0 {
			continue
		}

		filePath := filepath.Join(c.tempDir, spec.filename)
		writer, err := bloodhound.NewStreamingWriterNoSourceKind(filePath)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", spec.filename, err)
		}

		for _, node := range spec.nodes {
			if err := writer.WriteNode(node); err != nil {
				writer.Close()
				return fmt.Errorf("failed to write node to %s: %w", spec.filename, err)
			}
		}

		if err := writer.Close(); err != nil {
			return fmt.Errorf("failed to close %s: %w", spec.filename, err)
		}

		c.addOutputFile(filePath)
		nodes, _ := writer.Stats()
		written = append(written, fmt.Sprintf("%d nodes to %s", nodes, spec.filename))
	}

	if len(written) > 0 {
		c.config.Logger.Info("Wrote AD files", "details", strings.Join(written, ", "))
	}
	c.config.Logger.Info("Added seed_data.json")

	return nil
}

// uploadToBloodHound uploads the results zip (and optionally the schema) to BloodHound CE.
func (c *Collector) uploadToBloodHound(zipPath string) error {
	u := uploader.NewUploader(c.config.BloodHoundURL, c.config.TokenID, c.config.TokenKey, c.config.Logger)
	if u == nil {
		return fmt.Errorf("BloodHound upload requires --bloodhound-url and --token-id/--token-key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Upload schema if requested — registers custom node/edge kinds with
	// BloodHound CE via PUT /api/v2/extensions.
	if c.config.UploadSchema {
		c.config.Logger.Info("Uploading schema to BloodHound...")
		c.config.Logger.Debug("Schema PUT body", "body", string(bloodhound.SchemaJSON))
		if err := u.Client.UploadSchema(ctx, bloodhound.SchemaJSON); err != nil {
			return fmt.Errorf("schema upload failed: %w", err)
		}
		c.config.Logger.Info("Schema uploaded successfully")
	}

	// Upload results zip
	if c.config.UploadResults && zipPath != "" {
		c.config.Logger.Info("Uploading results to BloodHound...", "file", zipPath)
		summary := u.UploadFiles(ctx, []string{zipPath})
		if summary.FilesFailed > 0 {
			return fmt.Errorf("results upload failed")
		}
	}

	c.config.Logger.Info("BloodHound upload complete")
	return nil
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

	// Add embedded seed_data.json to the zip
	seedHeader := &zip.FileHeader{
		Name:   "seed_data.json",
		Method: zip.Deflate,
	}
	seedWriter, err := zipWriter.CreateHeader(seedHeader)
	if err != nil {
		return "", fmt.Errorf("failed to add seed_data.json to zip: %w", err)
	}
	if _, err := seedWriter.Write(bloodhound.SeedDataJSON); err != nil {
		return "", fmt.Errorf("failed to write seed_data.json to zip: %w", err)
	}

	return zipPath, nil
}

// createLogsZipFile creates a separate zip file containing per-target log files.
func (c *Collector) createLogsZipFile() (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	zipDir := c.config.ZipDir
	if zipDir == "" {
		zipDir = "."
	}

	zipPath := filepath.Join(zipDir, fmt.Sprintf("mssql-logs-%s.zip", timestamp))

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, filePath := range c.logFiles {
		if err := addFileToZip(zipWriter, filePath); err != nil {
			return "", fmt.Errorf("failed to add %s to logs zip: %w", filePath, err)
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

// generateFilename creates a filename matching PowerShell naming convention
// Format: mssql-{hostname}[_{port}][_{instance}].json
// - Port 1433 is omitted
// - Instance "MSSQLSERVER" is omitted
// - Uses underscore (_) as separator, not hyphen
func (c *Collector) generateFilename(server *ServerToProcess) string {
	parts := []string{server.Hostname}

	// Add port only if not 1433
	if server.Port != 1433 {
		parts = append(parts, strconv.Itoa(server.Port))
	}

	// Add instance only if not default
	if server.InstanceName != "" && server.InstanceName != "MSSQLSERVER" {
		parts = append(parts, server.InstanceName)
	}

	// Join with underscore and sanitize
	cleanedName := strings.Join(parts, "_")
	// Replace problematic filename characters with underscore (matching PS behavior)
	replacer := strings.NewReplacer(
		"\\", "_",
		"/", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	cleanedName = replacer.Replace(cleanedName)

	return fmt.Sprintf("mssql-%s.json", cleanedName)
}

// generateLogFilename creates a log filename for a server, matching the JSON naming convention.
func (c *Collector) generateLogFilename(server *ServerToProcess) string {
	return strings.TrimSuffix(c.generateFilename(server), ".json") + ".log"
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

// getMemoryUsage returns a string describing current memory usage
func (c *Collector) getMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Get allocated memory in GB
	allocatedGB := float64(m.Alloc) / 1024 / 1024 / 1024

	// Try to get system memory info (this is a rough estimate)
	// On Windows, we'd ideally use syscall but this gives a basic view
	sysGB := float64(m.Sys) / 1024 / 1024 / 1024

	return fmt.Sprintf("%.2fGB allocated (%.2fGB system)", allocatedGB, sysGB)
}
