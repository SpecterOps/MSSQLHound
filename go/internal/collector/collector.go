// Package collector orchestrates the MSSQL data collection process.
package collector

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/ad"
	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
	"github.com/SpecterOps/MSSQLHound/internal/mssql"
	"github.com/SpecterOps/MSSQLHound/internal/types"
	"github.com/SpecterOps/MSSQLHound/internal/wmi"
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
	Verbose       bool

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
}

// Collector handles the data collection process
type Collector struct {
	config                 *Config
	tempDir                string
	outputFiles            []string
	outputFilesMu          sync.Mutex // Protects outputFiles
	serversToProcess       []*ServerToProcess
	linkedServersToProcess []*ServerToProcess        // Linked servers discovered during processing
	linkedServersMu        sync.Mutex                // Protects linkedServersToProcess
	serverSPNData          map[string]*ServerSPNInfo // Track SPN data for each server, keyed by ObjectIdentifier
	serverSPNDataMu        sync.RWMutex              // Protects serverSPNData
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
func New(config *Config) *Collector {
	return &Collector{
		config:        config,
		serverSPNData: make(map[string]*ServerSPNInfo),
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
	c.logVerbose("Memory usage: %s", c.getMemoryUsage())

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
			fmt.Printf("\n[%d/%d] Processing %s...\n", i+1, len(c.serversToProcess), server.ConnectionString)
			processedServers[strings.ToLower(server.Hostname)] = true

			if err := c.processServer(server); err != nil {
				fmt.Printf("Warning: failed to process %s: %v\n", server.ConnectionString, err)
				// Continue with other servers
			}
		}
	}

	// Process linked servers recursively if enabled
	if c.config.CollectFromLinkedServers {
		c.processLinkedServersQueue(processedServers)
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

	fmt.Printf("Using %d concurrent workers\n", numWorkers)

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
	for result := range results {
		if result.err != nil {
			fmt.Printf("[%d/%d] %s: FAILED - %v\n", result.index+1, totalServers, result.server.ConnectionString, result.err)
			failCount++
		} else {
			fmt.Printf("[%d/%d] %s: OK\n", result.index+1, totalServers, result.server.ConnectionString)
			successCount++
		}
	}

	fmt.Printf("\nCompleted: %d succeeded, %d failed\n", successCount, failCount)
}

// serverWorker is a worker goroutine that processes servers from the jobs channel
func (c *Collector) serverWorker(id int, jobs <-chan serverJob, results chan<- serverResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		c.logVerbose("Worker %d: processing %s", id, job.server.ConnectionString)

		err := c.processServer(job.server)

		results <- serverResult{
			index:  job.index,
			server: job.server,
			err:    err,
		}
	}
}

// addOutputFile adds an output file to the list (thread-safe)
func (c *Collector) addOutputFile(path string) {
	c.outputFilesMu.Lock()
	defer c.outputFilesMu.Unlock()
	c.outputFiles = append(c.outputFiles, path)
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
	// From command line argument
	if c.config.ServerInstance != "" {
		server := c.parseServerString(c.config.ServerInstance)
		c.tryResolveSID(server)
		c.addServerToProcess(server)
		c.logVerbose("Added server from command line: %s", c.config.ServerInstance)
	}

	// From comma-separated list
	if c.config.ServerList != "" {
		c.logVerbose("Processing comma-separated server list")
		servers := strings.Split(c.config.ServerList, ",")
		count := 0
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s != "" {
				server := c.parseServerString(s)
				c.tryResolveSID(server)
				c.addServerToProcess(server)
				count++
			}
		}
		c.logVerbose("Added %d servers from list", count)
	}

	// From file
	if c.config.ServerListFile != "" {
		c.logVerbose("Processing server list file: %s", c.config.ServerListFile)
		data, err := os.ReadFile(c.config.ServerListFile)
		if err != nil {
			return fmt.Errorf("failed to read server list file: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		count := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				server := c.parseServerString(line)
				c.tryResolveSID(server)
				c.addServerToProcess(server)
				count++
			}
		}
		c.logVerbose("Added %d servers from file", count)
	}

	// Auto-detect domain if not provided and we have servers
	if c.config.Domain == "" && len(c.serversToProcess) > 0 {
		// Try to extract domain from server FQDNs first
		for _, server := range c.serversToProcess {
			if strings.Contains(server.Hostname, ".") {
				parts := strings.SplitN(server.Hostname, ".", 2)
				if len(parts) == 2 && parts[1] != "" {
					c.config.Domain = strings.ToLower(parts[1])
					c.logVerbose("Auto-detected domain from server FQDN: %s", c.config.Domain)
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
			fmt.Printf("No servers specified, enumerating MSSQL SPNs from Active Directory (domain: %s)...\n", domain)
			if err := c.enumerateServersFromAD(); err != nil {
				fmt.Printf("Warning: SPN enumeration failed: %v\n", err)
				fmt.Println("Hint: If LDAP authentication fails, you can:")
				fmt.Println("  1. Use --server, --server-list, or --server-list-file to specify servers manually")
				fmt.Println("  2. Use --ldap-user and --ldap-password to provide explicit credentials")
				fmt.Println("  3. Use the PowerShell version to enumerate SPNs, then provide the list to the Go version")
			}
		} else {
			fmt.Println("No servers specified and could not detect domain. Use --domain to specify a domain or --server to specify a server.")
		}
	}

	return nil
}

// tryResolveSID attempts to resolve the computer SID for a server
func (c *Collector) tryResolveSID(server *ServerToProcess) {
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

	// Try LDAP
	adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
	defer adClient.Close()

	sid, err := adClient.ResolveComputerSID(server.Hostname)
	if err == nil && sid != "" {
		server.ComputerSID = sid
	}
}

// detectDomain attempts to auto-detect the domain from environment variables or system configuration
func (c *Collector) detectDomain() string {
	// Try USERDNSDOMAIN environment variable (Windows domain-joined machines)
	if domain := os.Getenv("USERDNSDOMAIN"); domain != "" {
		c.logVerbose("Detected domain from USERDNSDOMAIN: %s", domain)
		return domain
	}

	// Try USERDOMAIN environment variable as fallback
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		c.logVerbose("Detected domain from USERDOMAIN: %s", domain)
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
						c.logVerbose("Detected domain from /etc/resolv.conf: %s", parts[1])
						return parts[1]
					}
				}
				if strings.HasPrefix(line, "domain ") {
					parts := strings.Fields(line)
					if len(parts) > 1 {
						c.logVerbose("Detected domain from /etc/resolv.conf: %s", parts[1])
						return parts[1]
					}
				}
			}
		}
	}

	return ""
}

// enumerateServersFromAD discovers MSSQL servers from Active Directory SPNs
func (c *Collector) enumerateServersFromAD() error {
	// First try native Go LDAP
	adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)

	spns, err := adClient.EnumerateMSSQLSPNs()
	adClient.Close()

	// If LDAP failed on Windows, try using PowerShell/ADSI as fallback
	if err != nil && runtime.GOOS == "windows" {
		c.logVerbose("LDAP enumeration failed, trying PowerShell/ADSI fallback...")
		spns, err = c.enumerateSPNsViaPowerShell()
	}

	if err != nil {
		return fmt.Errorf("failed to enumerate MSSQL SPNs: %w", err)
	}

	fmt.Printf("Found %d MSSQL SPNs\n", len(spns))

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

		// Try to resolve computer SID early
		c.tryResolveSID(server)

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

		fmt.Printf("  Found: %s (ObjectID: %s, service account: %s)\n", server.ConnectionString, server.ObjectIdentifier, spn.AccountName)
	}

	// If ScanAllComputers is enabled, also enumerate all domain computers
	if c.config.ScanAllComputers {
		fmt.Println("ScanAllComputers enabled, enumerating all domain computers...")
		adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
		defer adClient.Close()

		computers, err := adClient.EnumerateAllComputers()
		if err != nil && runtime.GOOS == "windows" {
			// Try PowerShell fallback on Windows
			fmt.Printf("LDAP enumeration failed (%v), trying PowerShell fallback...\n", err)
			computers, err = c.enumerateComputersViaPowerShell()
		}
		if err != nil {
			fmt.Printf("Warning: failed to enumerate domain computers: %v\n", err)
		} else {
			added := 0
			for _, computer := range computers {
				server := c.parseServerString(computer)
				c.tryResolveSID(server)
				oldLen := len(c.serversToProcess)
				c.addServerToProcess(server)
				if len(c.serversToProcess) > oldLen {
					added++
				}
			}
			fmt.Printf("Added %d additional computers to scan\n", added)
		}
	}

	fmt.Printf("\nUnique servers to process: %d\n", len(c.serversToProcess))
	return nil
}

// enumerateSPNsViaPowerShell uses PowerShell/ADSI to enumerate MSSQL SPNs (Windows fallback)
func (c *Collector) enumerateSPNsViaPowerShell() ([]types.SPN, error) {
	fmt.Println("Using PowerShell/ADSI fallback for SPN enumeration...")

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
	fmt.Println("Using PowerShell/ADSI fallback for computer enumeration...")

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

	fmt.Printf("PowerShell enumerated %d computers\n", len(computers))
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Check if we have SPN data for this server (keyed by ObjectIdentifier)
	c.serverSPNDataMu.RLock()
	spnInfo := c.serverSPNData[server.ObjectIdentifier]
	c.serverSPNDataMu.RUnlock()

	// Connect to the server
	client := mssql.NewClient(server.ConnectionString, c.config.UserID, c.config.Password)
	client.SetVerbose(c.config.Verbose)
	if err := client.Connect(ctx); err != nil {
		// If hostname doesn't have a domain but we have one from linked server discovery, try FQDN
		if server.Domain != "" && !strings.Contains(server.Hostname, ".") {
			fqdnHostname := server.Hostname + "." + server.Domain
			c.logVerbose("Connection failed, trying FQDN: %s", fqdnHostname)

			// Build FQDN connection string
			fqdnConnStr := fqdnHostname
			if server.Port != 0 && server.Port != 1433 {
				fqdnConnStr = fmt.Sprintf("%s:%d", fqdnHostname, server.Port)
			} else if server.InstanceName != "" {
				fqdnConnStr = fmt.Sprintf("%s\\%s", fqdnHostname, server.InstanceName)
			}

			fqdnClient := mssql.NewClient(fqdnConnStr, c.config.UserID, c.config.Password)
			fqdnClient.SetVerbose(c.config.Verbose)
			fqdnErr := fqdnClient.Connect(ctx)
			if fqdnErr == nil {
				// FQDN connection succeeded - update server info and continue
				fmt.Printf("  Connected using FQDN: %s\n", fqdnHostname)
				server.Hostname = fqdnHostname
				server.ConnectionString = fqdnConnStr
				client = fqdnClient
				// Fall through to continue with collection
				goto connected
			}
			fqdnClient.Close()
			c.logVerbose("FQDN connection also failed: %v", fqdnErr)
		}

		// Connection failed - check if we have SPN data to create partial output
		if spnInfo != nil {
			fmt.Printf("  Connection failed but server has SPN - creating nodes/edges from SPN data\n")
			return c.processServerFromSPNData(server, spnInfo, err)
		}

		// No SPN data available - try to look up SPNs from AD for this server
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			fmt.Printf("  Connection failed - looked up SPN from AD, creating partial output\n")
			return c.processServerFromSPNData(server, spnInfo, err)
		}

		// No SPN data - skip this server
		return fmt.Errorf("connection failed and no SPN data available: %w", err)
	}

connected:
	defer client.Close()

	c.logVerbose("Successfully connected to %s", server.ConnectionString)

	// Collect server information
	serverInfo, err := client.CollectServerInfo(ctx)
	if err != nil {
		// Collection failed after connection - try partial output if we have SPN data
		if spnInfo != nil {
			fmt.Printf("  Collection failed but server has SPN - creating nodes/edges from SPN data\n")
			return c.processServerFromSPNData(server, spnInfo, err)
		}

		// Try AD lookup for SPN data
		spnInfo = c.lookupSPNsForServer(server)
		if spnInfo != nil {
			fmt.Printf("  Collection failed - looked up SPN from AD, creating partial output\n")
			return c.processServerFromSPNData(server, spnInfo, err)
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

	// If we couldn't get the computer SID from SQL Server, try other methods
	// The resolution function will extract domain from FQDN if not provided
	if serverInfo.ComputerSID == "" {
		c.resolveComputerSIDViaLDAP(serverInfo)
	}

	// Convert built-in service accounts (LocalSystem, Local Service, Network Service)
	// to the computer account, as they authenticate on the network as the computer
	c.preprocessServiceAccounts(serverInfo)

	// Resolve service account SIDs via LDAP if they don't have SIDs
	c.resolveServiceAccountSIDsViaLDAP(serverInfo)

	// Resolve credential identity SIDs via LDAP for credential edges
	c.resolveCredentialSIDsViaLDAP(serverInfo)

	// Enumerate local Windows groups that have SQL logins and their domain members
	c.enumerateLocalGroupMembers(serverInfo)

	// Check CVE-2025-49758 patch status
	c.logCVE202549758Status(serverInfo)

	// Process discovered linked servers
	c.processLinkedServers(serverInfo, server)

	fmt.Printf("  Collected: %d principals, %d databases\n",
		len(serverInfo.ServerPrincipals), len(serverInfo.Databases))

	// Generate output filename using PowerShell naming convention
	outputFile := filepath.Join(c.tempDir, c.generateFilename(server))

	if err := c.generateOutput(serverInfo, outputFile); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	c.addOutputFile(outputFile)
	fmt.Printf("  Output: %s\n", outputFile)

	return nil
}

// processServerFromSPNData creates partial output when connection fails but SPN data exists
func (c *Collector) processServerFromSPNData(server *ServerToProcess, spnInfo *ServerSPNInfo, connErr error) error {
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

	// Create minimal server info from SPN data
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
		SPNs:             spnInfo.SPNs,
		// ServiceAccounts intentionally left empty to match PS behavior
	}

	// Check CVE-2025-49758 patch status (will show version unknown for SPN-only data)
	c.logCVE202549758Status(serverInfo)

	fmt.Printf("  Created partial output from SPN data (connection error: %v)\n", connErr)

	// Generate output using the consistent filename generation
	outputFile := filepath.Join(c.tempDir, c.generateFilename(server))

	if err := c.generateOutput(serverInfo, outputFile); err != nil {
		return fmt.Errorf("output generation failed: %w", err)
	}

	c.addOutputFile(outputFile)
	fmt.Printf("  Output: %s\n", outputFile)

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
		c.logVerbose("Using domain from linked server discovery: %s", domain)
	}

	if domain == "" {
		fmt.Println("  Cannot lookup SPN - no domain available")
		return nil
	}

	fmt.Printf("  Looking up SPNs for %s in AD (domain: %s)\n", server.Hostname, domain)

	// Try native LDAP first
	adClient := ad.NewClient(domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
	spns, err := adClient.LookupMSSQLSPNsForHost(server.Hostname)
	adClient.Close()

	// If LDAP failed on Windows, try PowerShell/ADSI
	if err != nil && runtime.GOOS == "windows" {
		fmt.Println("  LDAP lookup failed, trying PowerShell/ADSI fallback...")
		spns, err = c.lookupSPNsViaPowerShell(server.Hostname)
	}

	if err != nil {
		fmt.Printf("  AD SPN lookup failed: %v\n", err)
		return nil
	}

	if len(spns) == 0 {
		fmt.Printf("  No SPNs found in AD for %s\n", server.Hostname)
		return nil
	}

	fmt.Printf("  Found %d SPNs in AD for %s\n", len(spns), server.Hostname)

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

// resolveComputerSIDViaLDAP attempts to resolve the computer SID via multiple methods
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

	// Use the machine name (without the FQDN)
	machineName := serverInfo.Hostname
	if strings.Contains(machineName, ".") {
		machineName = strings.Split(machineName, ".")[0]
	}

	c.logVerbose("Attempting to resolve computer SID for: %s (domain: %s)", machineName, domain)

	// Method 1: Try Windows API (LookupAccountName) - most reliable on Windows
	c.logVerbose("  Method 1: Windows API LookupAccountName")
	sid, err := ad.ResolveComputerSIDWindows(machineName, domain)
	if err == nil && sid != "" {
		c.applyComputerSID(serverInfo, sid)
		c.logVerbose("  Resolved computer SID via Windows API: %s", sid)
		return
	}
	c.logVerbose("  Windows API method failed: %v", err)

	// Method 2: If we have a domain SID from SQL Server, try Windows API with that context
	if serverInfo.DomainSID != "" {
		c.logVerbose("  Method 2: Windows API with domain SID context")
		sid, err := ad.ResolveComputerSIDByDomainSID(machineName, serverInfo.DomainSID, domain)
		if err == nil && sid != "" {
			c.applyComputerSID(serverInfo, sid)
			c.logVerbose("  Resolved computer SID via Windows API (domain context): %s", sid)
			return
		}
		c.logVerbose("  Windows API with domain context failed: %v", err)
	}

	// Method 3: Try LDAP
	if domain == "" {
		c.logVerbose("  Cannot try LDAP: no domain specified (use -d flag)")
		fmt.Printf("  Note: Could not resolve computer SID (no domain specified)\n")
		return
	}

	c.logVerbose("  Method 3: LDAP query")

	// Create AD client
	adClient := ad.NewClient(domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
	defer adClient.Close()

	sid, err = adClient.ResolveComputerSID(machineName)
	if err != nil {
		fmt.Printf("  Note: Could not resolve computer SID via LDAP: %v\n", err)
		return
	}

	c.applyComputerSID(serverInfo, sid)
	c.logVerbose("  Resolved computer SID via LDAP: %s", sid)
}

// applyComputerSID applies the resolved computer SID to the server info and updates all references
func (c *Collector) applyComputerSID(serverInfo *types.ServerInfo, sid string) {
	// Store the old ObjectIdentifier to update references
	oldObjectIdentifier := serverInfo.ObjectIdentifier

	serverInfo.ComputerSID = sid
	serverInfo.ObjectIdentifier = fmt.Sprintf("%s:%d", sid, serverInfo.Port)
	fmt.Printf("  Resolved computer SID: %s\n", sid)

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
func (c *Collector) preprocessServiceAccounts(serverInfo *types.ServerInfo) {
	seenSIDs := make(map[string]bool)
	var uniqueServiceAccounts []types.ServiceAccount

	for i := range serverInfo.ServiceAccounts {
		sa := serverInfo.ServiceAccounts[i]

		// Skip NT SERVICE\* virtual service accounts entirely
		// PowerShell doesn't convert these to computer accounts - it just skips them
		// because they can't be resolved in AD (they're virtual accounts)
		if strings.HasPrefix(strings.ToUpper(sa.Name), "NT SERVICE\\") {
			c.logVerbose("Skipping NT SERVICE virtual account: %s", sa.Name)
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

			c.logVerbose("Converting built-in service account %s to computer account %s", sa.Name, computerAccount)

			sa.Name = computerAccount
			sa.ConvertedFromBuiltIn = true // Mark as converted from built-in

			// If we already have the computer SID, use it
			if serverInfo.ComputerSID != "" {
				sa.SID = serverInfo.ComputerSID
				sa.ObjectIdentifier = serverInfo.ComputerSID
				c.logVerbose("Using known computer SID: %s", serverInfo.ComputerSID)
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
			c.logVerbose("Skipping duplicate service account: %s (%s)", sa.Name, key)
		}
	}

	serverInfo.ServiceAccounts = uniqueServiceAccounts
}

// resolveServiceAccountSIDsViaLDAP resolves service account SIDs via multiple methods
func (c *Collector) resolveServiceAccountSIDsViaLDAP(serverInfo *types.ServerInfo) {
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
		if sa.SID == "" {
			// Method 1: Try Windows API first (most reliable on Windows)
			c.logVerbose("  Resolving service account %s via Windows API", sa.Name)
			sid, err := ad.ResolveAccountSIDWindows(sa.Name)
			if err == nil && sid != "" && strings.HasPrefix(sid, "S-1-5-21-") {
				sa.SID = sid
				sa.ObjectIdentifier = sid
				c.logVerbose("  Resolved service account SID via Windows API: %s", sid)
				fmt.Printf("  Resolved service account SID for %s: %s\n", sa.Name, sa.SID)
			} else {
				c.logVerbose("  Windows API failed: %v", err)
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
				c.logVerbose("  Updated computer account name from %s to %s (server's own computer account)", oldName, sa.Name)
				fmt.Printf("  Updated computer account name from %s to %s\n", oldName, sa.Name)
				continue
			}

			// For other computer accounts, try LDAP
			if c.config.Domain != "" {
				adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
				principal, err := adClient.ResolveSID(sa.SID)
				adClient.Close()
				if err == nil && principal != nil && principal.ObjectClass == "computer" {
					// Use the resolved name (which is DNSHostName for computers in our updated AD client)
					oldName := sa.Name
					sa.Name = principal.Name
					c.logVerbose("  Updated computer account name from %s to %s", oldName, sa.Name)
					fmt.Printf("  Updated computer account name from %s to %s\n", oldName, sa.Name)
				}
			}
			continue
		}

		// If we still don't have a SID and this is not a computer account, try LDAP
		if sa.SID == "" {
			if c.config.Domain == "" {
				fmt.Printf("  Note: Could not resolve service account %s (no domain specified)\n", sa.Name)
				continue
			}

			// Create AD client
			adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
			principal, err := adClient.ResolveName(sa.Name)
			adClient.Close()
			if err != nil {
				fmt.Printf("  Note: Could not resolve service account %s via LDAP: %v\n", sa.Name, err)
				continue
			}

			sa.SID = principal.SID
			sa.ObjectIdentifier = principal.SID
			// Also update the name if it's a computer
			if principal.ObjectClass == "computer" {
				sa.Name = principal.Name
			}
			fmt.Printf("  Resolved service account SID for %s: %s\n", sa.Name, sa.SID)
		}
	}
}

// resolveCredentialSIDsViaLDAP resolves credential identities to AD SIDs
// This matches PowerShell's Resolve-DomainPrincipal behavior for credential edges
func (c *Collector) resolveCredentialSIDsViaLDAP(serverInfo *types.ServerInfo) {
	if c.config.Domain == "" {
		return
	}

	// Helper to resolve a credential identity (domain\user or user@domain) to a SID
	resolveIdentity := func(identity string) string {
		if !strings.Contains(identity, "\\") && !strings.Contains(identity, "@") {
			return ""
		}
		adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
		principal, err := adClient.ResolveName(identity)
		adClient.Close()
		if err != nil || principal == nil || principal.SID == "" {
			return ""
		}
		return principal.SID
	}

	// Resolve server-level credentials (mapped via ALTER LOGIN ... WITH CREDENTIAL)
	for i := range serverInfo.ServerPrincipals {
		if serverInfo.ServerPrincipals[i].MappedCredential != nil {
			cred := serverInfo.ServerPrincipals[i].MappedCredential
			if sid := resolveIdentity(cred.CredentialIdentity); sid != "" {
				cred.ResolvedSID = sid
				c.logVerbose("  Resolved credential %s -> %s", cred.CredentialIdentity, sid)
			}
		}
	}

	// Resolve standalone credentials (for HasMappedCred edges)
	for i := range serverInfo.Credentials {
		if sid := resolveIdentity(serverInfo.Credentials[i].CredentialIdentity); sid != "" {
			serverInfo.Credentials[i].ResolvedSID = sid
			c.logVerbose("  Resolved credential %s -> %s", serverInfo.Credentials[i].CredentialIdentity, sid)
		}
	}

	// Resolve proxy account credentials
	for i := range serverInfo.ProxyAccounts {
		if sid := resolveIdentity(serverInfo.ProxyAccounts[i].CredentialIdentity); sid != "" {
			serverInfo.ProxyAccounts[i].ResolvedSID = sid
			c.logVerbose("  Resolved proxy credential %s -> %s", serverInfo.ProxyAccounts[i].CredentialIdentity, sid)
		}
	}

	// Resolve database-scoped credentials
	for i := range serverInfo.Databases {
		for j := range serverInfo.Databases[i].DBScopedCredentials {
			cred := &serverInfo.Databases[i].DBScopedCredentials[j]
			if sid := resolveIdentity(cred.CredentialIdentity); sid != "" {
				cred.ResolvedSID = sid
				c.logVerbose("  Resolved DB scoped credential %s -> %s", cred.CredentialIdentity, sid)
			}
		}
	}
}

// enumerateLocalGroupMembers finds local Windows groups that have SQL logins and enumerates their domain members via WMI
func (c *Collector) enumerateLocalGroupMembers(serverInfo *types.ServerInfo) {
	if runtime.GOOS != "windows" {
		c.logVerbose("Skipping local group enumeration (not on Windows)")
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
		members := wmi.GetLocalGroupMembersWithFallback(serverHostname, localGroupName, c.config.Verbose)

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
				adClient := ad.NewClient(c.config.Domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
				resolved, err := adClient.ResolveName(fullName)
				adClient.Close()
				if err == nil && resolved.SID != "" {
					lm.SID = resolved.SID
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
	createdLinkedServerNodes := make(map[string]bool)
	for _, linkedServer := range serverInfo.LinkedServers {
		if linkedServer.DataSource == "" || linkedServer.ResolvedObjectIdentifier == "" {
			continue
		}
		if createdLinkedServerNodes[linkedServer.ResolvedObjectIdentifier] {
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
	if info.ExtendedProtection != "" {
		props["extendedProtection"] = info.ExtendedProtection
	}

	// Add SPNs
	if len(info.SPNs) > 0 {
		props["servicePrincipalNames"] = info.SPNs
	}

	// Add service account name (first service account, matching PowerShell)
	if len(info.ServiceAccounts) > 0 {
		props["serviceAccount"] = info.ServiceAccounts[0].Name
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

	// Calculate domain principals with privileged access
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

		// Check role memberships
		for _, membership := range principal.MemberOf {
			switch membership.Name {
			case "sysadmin":
				domainPrincipalsWithSysadmin = append(domainPrincipalsWithSysadmin, principal.ObjectIdentifier)
			case "securityadmin":
				domainPrincipalsWithSecurityadmin = append(domainPrincipalsWithSecurityadmin, principal.ObjectIdentifier)
			}
		}

		// Check explicit permissions
		for _, perm := range principal.Permissions {
			if perm.State != "GRANT" && perm.State != "GRANT_WITH_GRANT_OPTION" {
				continue
			}
			switch perm.Permission {
			case "CONTROL SERVER":
				domainPrincipalsWithControlServer = append(domainPrincipalsWithControlServer, principal.ObjectIdentifier)
			case "IMPERSONATE ANY LOGIN":
				domainPrincipalsWithImpersonateAnyLogin = append(domainPrincipalsWithImpersonateAnyLogin, principal.ObjectIdentifier)
			}
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

	// Create Computer node for the server's host computer (matching PowerShell behavior)
	if serverInfo.ComputerSID != "" {
		// Build display name with domain
		displayName := serverInfo.Hostname
		if c.config.Domain != "" && !strings.Contains(displayName, "@") {
			displayName = serverInfo.Hostname + "@" + c.config.Domain
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
		if err := writer.WriteNode(node); err != nil {
			return err
		}
		createdNodes[serverInfo.ComputerSID] = true
	}

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

	// Create nodes for well-known local groups (S-1-5-32-*) with SQL logins
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.SecurityIdentifier == "" {
			continue
		}

		// Only process well-known local group SIDs (S-1-5-32-*)
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-32-") {
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
		if err := writer.WriteNode(node); err != nil {
			return err
		}
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

	// Linked servers - one edge per login mapping (matching PowerShell behavior)
	for _, linked := range serverInfo.LinkedServers {
		// Determine target ObjectIdentifier for linked server
		targetID := linked.DataSource
		if linked.ResolvedObjectIdentifier != "" {
			targetID = linked.ResolvedObjectIdentifier
		}

		// MSSQL_LinkedTo edge with all properties matching PowerShell
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
		// Add linked server specific properties (matching PowerShell)
		edge.Properties["dataAccess"] = linked.IsDataAccessEnabled
		edge.Properties["dataSource"] = linked.DataSource
		edge.Properties["localLogin"] = linked.LocalLogin
		edge.Properties["product"] = linked.Product
		edge.Properties["provider"] = linked.Provider
		edge.Properties["remoteHasControlServer"] = linked.RemoteHasControlServer
		edge.Properties["remoteHasImpersonateAnyLogin"] = linked.RemoteHasImpersonateAnyLogin
		edge.Properties["remoteIsMixedMode"] = linked.RemoteIsMixedMode
		edge.Properties["remoteIsSecurityAdmin"] = linked.RemoteIsSecurityAdmin
		edge.Properties["remoteIsSysadmin"] = linked.RemoteIsSysadmin
		edge.Properties["remoteLogin"] = linked.RemoteLogin
		edge.Properties["rpcOut"] = linked.IsRPCOutEnabled
		edge.Properties["usesImpersonation"] = linked.UsesImpersonation
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
			// Add linked server specific properties (matching PowerShell)
			edge.Properties["dataAccess"] = linked.IsDataAccessEnabled
			edge.Properties["dataSource"] = linked.DataSource
			edge.Properties["localLogin"] = linked.LocalLogin
			edge.Properties["product"] = linked.Product
			edge.Properties["provider"] = linked.Provider
			edge.Properties["remoteHasControlServer"] = linked.RemoteHasControlServer
			edge.Properties["remoteHasImpersonateAnyLogin"] = linked.RemoteHasImpersonateAnyLogin
			edge.Properties["remoteIsMixedMode"] = linked.RemoteIsMixedMode
			edge.Properties["remoteIsSecurityAdmin"] = linked.RemoteIsSecurityAdmin
			edge.Properties["remoteIsSysadmin"] = linked.RemoteIsSysadmin
			edge.Properties["remoteLogin"] = linked.RemoteLogin
			edge.Properties["rpcOut"] = linked.IsRPCOutEnabled
			edge.Properties["usesImpersonation"] = linked.UsesImpersonation
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

			// Check if database owner has high privileges
			// (sysadmin, securityadmin, CONTROL SERVER, or IMPERSONATE ANY LOGIN)
			if db.OwnerObjectIdentifier != "" {
				// Find the owner in server principals
				var ownerHasSysadmin, ownerHasSecurityadmin, ownerHasControlServer, ownerHasImpersonateAnyLogin bool
				for _, owner := range serverInfo.ServerPrincipals {
					if owner.ObjectIdentifier == db.OwnerObjectIdentifier {
						// Check if owner is a member of sysadmin or securityadmin
						for _, role := range owner.MemberOf {
							if role.Name == "sysadmin" {
								ownerHasSysadmin = true
							}
							if role.Name == "securityadmin" {
								ownerHasSecurityadmin = true
							}
						}
						// Check explicit permissions
						for _, perm := range owner.Permissions {
							if perm.Permission == "CONTROL SERVER" && (perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
								ownerHasControlServer = true
							}
							if perm.Permission == "IMPERSONATE ANY LOGIN" && (perm.State == "GRANT" || perm.State == "GRANT_WITH_GRANT_OPTION") {
								ownerHasImpersonateAnyLogin = true
							}
						}
						break
					}
				}

				if ownerHasSysadmin || ownerHasSecurityadmin || ownerHasControlServer || ownerHasImpersonateAnyLogin {
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
	// Match PowerShell logic: create only for enabled logins with domain SIDs that have CONNECT SQL permission
	principalsWithLogin := make(map[string]bool)
	for _, principal := range serverInfo.ServerPrincipals {
		if !principal.IsActiveDirectoryPrincipal || principal.SecurityIdentifier == "" {
			continue
		}

		// Skip disabled logins
		if principal.IsDisabled {
			continue
		}

		// Only process domain SIDs (S-1-5-21-*), skip NT AUTHORITY, NT SERVICE, local accounts, etc.
		// PowerShell checks: $principal.SecurityIdentifier -like "S-1-5-21-*"
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-21-") {
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

	// Create HasLogin edges for well-known local groups (S-1-5-32-*)
	// These are BUILTIN groups like BUILTIN\Users, BUILTIN\Administrators, etc.
	for _, principal := range serverInfo.ServerPrincipals {
		if principal.SecurityIdentifier == "" {
			continue
		}

		// Only process well-known local group SIDs (S-1-5-32-*)
		if !strings.HasPrefix(principal.SecurityIdentifier, "S-1-5-32-") {
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
			},
		)
		if err := writer.WriteEdge(edge); err != nil {
			return err
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
				},
			)
			if err := writer.WriteEdge(edge); err != nil {
				return err
			}
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

		// Use ResolvedSID if available, fall back to CredentialIdentity
		// PowerShell uses the resolved SID as the edge target
		targetID := cred.CredentialIdentity
		if cred.ResolvedSID != "" {
			targetID = cred.ResolvedSID
		}

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

			// Use ResolvedSID if available, fall back to CredentialIdentity
			proxyTargetID := proxy.CredentialIdentity
			if proxy.ResolvedSID != "" {
				proxyTargetID = proxy.ResolvedSID
			}

			// HasProxyCred: Login -> AD Principal (resolved SID or credential identity)
			edge := c.createEdge(
				loginObjectID,
				proxyTargetID,
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

			// Use ResolvedSID if available, fall back to CredentialIdentity
			dbCredTargetID := cred.CredentialIdentity
			if cred.ResolvedSID != "" {
				dbCredTargetID = cred.ResolvedSID
			}

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

// hasSecurityadminRole checks if a principal is a member of the securityadmin role (directly or through nesting)
func (c *Collector) hasSecurityadminRole(principal types.ServerPrincipal) bool {
	for _, m := range principal.MemberOf {
		if m.Name == "securityadmin" {
			return true
		}
	}
	return false
}

// hasImpersonateAnyLogin checks if a principal has IMPERSONATE ANY LOGIN permission
func (c *Collector) hasImpersonateAnyLogin(principal types.ServerPrincipal) bool {
	for _, p := range principal.Permissions {
		if p.Permission == "IMPERSONATE ANY LOGIN" && (p.State == "GRANT" || p.State == "GRANT_WITH_GRANT_OPTION") {
			return true
		}
	}
	return false
}

// shouldCreateChangePasswordEdge determines if a ChangePassword edge should be created for a target SQL login
// based on CVE-2025-49758 patch status. If the server is patched, the edge is only created if the target
// does NOT have securityadmin role or IMPERSONATE ANY LOGIN permission.
func (c *Collector) shouldCreateChangePasswordEdge(serverInfo *types.ServerInfo, targetPrincipal types.ServerPrincipal) bool {
	// Check if server is patched for CVE-2025-49758
	if IsPatchedForCVE202549758(serverInfo.VersionNumber, serverInfo.Version) {
		// Patched - check if target has securityadmin or IMPERSONATE ANY LOGIN
		// If target has either, the patch prevents changing their password without current password
		if c.hasSecurityadminRole(targetPrincipal) || c.hasImpersonateAnyLogin(targetPrincipal) {
			c.logVerbose("Skipping ChangePassword edge to %s - server is patched for CVE-2025-49758 and target has securityadmin role or IMPERSONATE ANY LOGIN permission", targetPrincipal.Name)
			return false
		}
	}
	// Unpatched or target doesn't have protected permissions - create the edge
	return true
}

// logCVE202549758Status logs the CVE-2025-49758 vulnerability status for a server
func (c *Collector) logCVE202549758Status(serverInfo *types.ServerInfo) {
	if serverInfo.VersionNumber == "" && serverInfo.Version == "" {
		fmt.Println("  Skipping CVE-2025-49758 patch status check - server version unknown")
		return
	}

	c.logVerbose("Checking for CVE-2025-49758 patch status...")
	result := CheckCVE202549758(serverInfo.VersionNumber, serverInfo.Version)
	if result == nil {
		fmt.Println("  Unable to parse SQL version for CVE-2025-49758 check")
		return
	}

	c.logVerbose("Detected SQL version: %s", result.VersionDetected)
	if result.IsVulnerable {
		fmt.Printf("  CVE-2025-49758: VULNERABLE (version %s, requires %s)\n", result.VersionDetected, result.RequiredVersion)
	} else if result.IsPatched {
		fmt.Printf("  CVE-2025-49758: NOT vulnerable (version %s)\n", result.VersionDetected)
	}
}

// processLinkedServers handles discovered linked servers with verbose output
func (c *Collector) processLinkedServers(serverInfo *types.ServerInfo, server *ServerToProcess) {
	if len(serverInfo.LinkedServers) == 0 {
		return
	}

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

		// Log status for this linked server
		if c.config.CollectFromLinkedServers {
			if isAlreadyQueued {
				fmt.Printf("        %s: already in queue for processing\n", resolvedHost)
			} else {
				fmt.Printf("        %s: will be added to processing queue (domain: %s)\n", resolvedHost, sourceDomain)
				// Add to linked servers queue for later processing
				c.addLinkedServerToQueue(resolvedHost, serverInfo.Hostname, sourceDomain)
			}
		} else {
			c.logVerbose("        %s: skipped (use --collect-from-linked to enable collection)", resolvedHost)
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
		adClient := ad.NewClient(domain, c.config.DomainController, c.config.SkipPrivateAddress, c.config.LDAPUser, c.config.LDAPPassword)
		defer adClient.Close()

		sid, err = adClient.ResolveComputerSID(machineName)
		if err == nil && sid != "" {
			if instanceName != "" {
				return fmt.Sprintf("%s:%s", sid, instanceName)
			}
			return fmt.Sprintf("%s:%s", sid, port)
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
	c.tryResolveSID(server)
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
				c.logVerbose("Skipping already processed linked server: %s", server.Hostname)
			}
		}

		if len(serversToProcess) == 0 {
			continue
		}

		iteration++
		fmt.Printf("\n=== Processing %d linked server(s) (iteration %d) ===\n", len(serversToProcess), iteration)

		// Process this batch
		for i, server := range serversToProcess {
			discoveredInfo := ""
			if server.DiscoveredFrom != "" {
				discoveredInfo = fmt.Sprintf(" (discovered from %s)", server.DiscoveredFrom)
			}
			fmt.Printf("\n[Linked %d/%d] Processing %s%s...\n", i+1, len(serversToProcess), server.ConnectionString, discoveredInfo)

			if err := c.processServer(server); err != nil {
				fmt.Printf("Warning: failed to process linked server %s: %v\n", server.ConnectionString, err)
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

				// Check if target has sysadmin or CONTROL SERVER
				targetHasSysadmin := false
				for _, m := range targetPrincipal.MemberOf {
					if m.Name == "sysadmin" {
						targetHasSysadmin = true
						break
					}
				}
				targetHasControlServer := false
				for _, p := range targetPrincipal.Permissions {
					if p.Permission == "CONTROL SERVER" && (p.State == "GRANT" || p.State == "GRANT_WITH_GRANT_OPTION") {
						targetHasControlServer = true
						break
					}
				}

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
							SourceName:    principal.Name,
							SourceType:    bloodhound.NodeKinds.ServerRole,
							TargetName:    targetPrincipal.Name,
							TargetType:    bloodhound.NodeKinds.Login,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    "ALTER ANY LOGIN",
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

				targetHasSysadmin := false
				for _, m := range targetPrincipal.MemberOf {
					if m.Name == "sysadmin" {
						targetHasSysadmin = true
						break
					}
				}
				targetHasControlServer := false
				for _, p := range targetPrincipal.Permissions {
					if p.Permission == "CONTROL SERVER" && (p.State == "GRANT" || p.State == "GRANT_WITH_GRANT_OPTION") {
						targetHasControlServer = true
						break
					}
				}

				if !targetHasSysadmin && !targetHasControlServer {
					if !c.shouldCreateChangePasswordEdge(serverInfo, targetPrincipal) {
						continue
					}

					cpEdge := c.createEdge(
						principal.ObjectIdentifier,
						targetPrincipal.ObjectIdentifier,
						bloodhound.EdgeKinds.ChangePassword,
						&bloodhound.EdgeContext{
							SourceName:    principal.Name,
							SourceType:    bloodhound.NodeKinds.ServerRole,
							TargetName:    targetPrincipal.Name,
							TargetType:    bloodhound.NodeKinds.Login,
							SQLServerName: serverInfo.SQLServerName,
							Permission:    "ALTER ANY LOGIN",
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

				// MSSQL_ControlDB (traversable)
				edge = c.createEdge(
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

				// db_securityadmin can change password for application roles (via ALTER ANY APPLICATION ROLE)
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
					isLogin := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
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

					// CONTROL on login = ImpersonateLogin (MSSQL_ExecuteAs), no restrictions (even sa)
					if isLogin {
						edge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ExecuteAs,
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

					// Always create the MSSQL_Alter edge (matches PowerShell)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Alter,
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
									SourceName:    principal.Name,
									SourceType:    c.getServerPrincipalType(principal.TypeDescription),
									TargetName:    targetName,
									TargetType:    targetType,
									SQLServerName: serverInfo.SQLServerName,
									Permission:    perm.Permission,
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

					// TAKE OWNERSHIP on SERVER_ROLE also grants ChangeOwner (matches PowerShell)
					if targetPrincipal != nil && targetPrincipal.TypeDescription == "SERVER_ROLE" {
						changeOwnerEdge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ChangeOwner,
							&bloodhound.EdgeContext{
								SourceName:    principal.Name,
								SourceType:    c.getServerPrincipalType(principal.TypeDescription),
								TargetName:    targetName,
								TargetType:    bloodhound.NodeKinds.ServerRole,
								SQLServerName: serverInfo.SQLServerName,
								Permission:    perm.Permission,
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
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
					}

					// MSSQL_Impersonate edge (matches PowerShell which uses MSSQL_Impersonate at server level)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Impersonate,
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
								SourceName:    principal.Name,
								SourceType:    c.getServerPrincipalType(principal.TypeDescription),
								TargetName:    targetRole.Name,
								TargetType:    bloodhound.NodeKinds.ServerRole,
								SQLServerName: serverInfo.SQLServerName,
								Permission:    perm.Permission,
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
					isUser := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetType = c.getDatabasePrincipalType(targetPrincipal.TypeDescription)
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

					// Use specific edge type based on target
					if isRole {
						// CONTROL on role = Add members + Change owner
						edge = c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
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

						edge = c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ChangeOwner,
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
					} else if isUser {
						// CONTROL on user = Impersonate (MSSQL_ExecuteAs)
						edge = c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.ExecuteAs,
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
					// ALTER on the database itself - use MSSQL_Alter to match PowerShell
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.Alter,
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
										SourceName:    principal.Name,
										SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
										TargetName:    targetPrincipal.Name,
										TargetType:    bloodhound.NodeKinds.DatabaseRole,
										SQLServerName: serverInfo.SQLServerName,
										DatabaseName:  db.Name,
										Permission:    perm.Permission,
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
									SourceName:    principal.Name,
									SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
									TargetName:    targetPrincipal.Name,
									TargetType:    bloodhound.NodeKinds.ApplicationRole,
									SQLServerName: serverInfo.SQLServerName,
									DatabaseName:  db.Name,
									Permission:    perm.Permission,
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
					isRole := false
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
						targetType = c.getDatabasePrincipalType(targetPrincipal.TypeDescription)
						isRole = targetPrincipal.TypeDescription == "DATABASE_ROLE"
					}

					// Always create MSSQL_Alter edge (matches PowerShell)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Alter,
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

					// For database roles, also create AddMember edge (matches PowerShell)
					if isRole {
						addMemberEdge := c.createEdge(
							principal.ObjectIdentifier,
							perm.TargetObjectIdentifier,
							bloodhound.EdgeKinds.AddMember,
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
								SourceName:    principal.Name,
								SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:    targetRole.Name,
								TargetType:    bloodhound.NodeKinds.DatabaseRole,
								SQLServerName: serverInfo.SQLServerName,
								DatabaseName:  db.Name,
								Permission:    perm.Permission,
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
								SourceName:    principal.Name,
								SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:    appRole.Name,
								TargetType:    bloodhound.NodeKinds.ApplicationRole,
								SQLServerName: serverInfo.SQLServerName,
								DatabaseName:  db.Name,
								Permission:    perm.Permission,
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
					if targetPrincipal != nil {
						targetName = targetPrincipal.Name
					}

					// PowerShell creates both MSSQL_Impersonate and MSSQL_ExecuteAs for database user impersonation
					edge := c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.Impersonate,
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

					// Also create ExecuteAs edge (PowerShell creates both)
					edge = c.createEdge(
						principal.ObjectIdentifier,
						perm.TargetObjectIdentifier,
						bloodhound.EdgeKinds.ExecuteAs,
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
					// Create TakeOwnership edge to the database (non-traversable)
					edge := c.createEdge(
						principal.ObjectIdentifier,
						db.ObjectIdentifier,
						bloodhound.EdgeKinds.TakeOwnership,
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

					// TAKE OWNERSHIP on database also grants ChangeOwner to all database roles
					for _, targetRole := range db.DatabasePrincipals {
						if targetRole.TypeDescription == "DATABASE_ROLE" {
							changeOwnerEdge := c.createEdge(
								principal.ObjectIdentifier,
								targetRole.ObjectIdentifier,
								bloodhound.EdgeKinds.ChangeOwner,
								&bloodhound.EdgeContext{
									SourceName:    principal.Name,
									SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
									TargetName:    targetRole.Name,
									TargetType:    bloodhound.NodeKinds.DatabaseRole,
									SQLServerName: serverInfo.SQLServerName,
									DatabaseName:  db.Name,
									Permission:    perm.Permission,
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
								SourceName:    principal.Name,
								SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
								TargetName:    targetPrincipal.Name,
								TargetType:    c.getDatabasePrincipalType(targetPrincipal.TypeDescription),
								SQLServerName: serverInfo.SQLServerName,
								DatabaseName:  db.Name,
								Permission:    perm.Permission,
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
									SourceName:    principal.Name,
									SourceType:    c.getDatabasePrincipalType(principal.TypeDescription),
									TargetName:    targetPrincipal.Name,
									TargetType:    bloodhound.NodeKinds.DatabaseRole,
									SQLServerName: serverInfo.SQLServerName,
									DatabaseName:  db.Name,
									Permission:    perm.Permission,
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

// logVerbose logs a message only if verbose mode is enabled
func (c *Collector) logVerbose(format string, args ...interface{}) {
	if c.config.Verbose {
		fmt.Printf(format+"\n", args...)
	}
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
