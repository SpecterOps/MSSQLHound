package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/collector"
	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/SpecterOps/MSSQLHound/internal/proxydialer"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	version = "2.0.0"

	// Shared connection options (persistent - inherited by subcommands)
	serverInstance string
	userID         string
	password       string
	ntHash         string // NT hash for pass-the-hash authentication
	domain         string
	dc             string
	dnsResolver    string
	ldapUser       string
	ldapPassword   string
	useKerberos    bool   // Use Kerberos authentication
	krb5ConfigFile string // Path to krb5.conf
	krb5CCacheFile string // Path to ccache file
	krb5KeytabFile string // Path to keytab file
	krb5Realm      string // Kerberos realm
	verbose        bool
	debug          bool
	proxyAddr      string

	// Collection-specific options (local to root command)
	outputFormat string
	tempDir        string
	zipDir         string
	fileSizeLimit  string

	logPerTarget bool

	domainEnumOnly                  bool
	skipLinkedServerEnum            bool
	collectFromLinkedServers        bool
	skipPrivateAddress              bool
	scanAllComputers                bool
	skipADNodeCreation              bool
	includeNontraversableEdges      bool
	makeInterestingEdgesTraversable bool

	linkedServerTimeout    int
	memoryThresholdPercent int
	fileSizeUpdateInterval int
	workers                int

	// BloodHound upload options
	bloodhoundUpload string // -B shorthand: <token-id>:<token_key>@<bloodhound_url>
	bloodhoundURL    string
	tokenID          string
	tokenKey         string
	uploadSchema     bool
	uploadResults    bool
	skipCollection   bool
)

var (
	logLevel slog.LevelVar
	logger   *slog.Logger
)

func main() {
	logger = slog.New(logging.NewHandler(os.Stderr, &logging.Options{Level: &logLevel}))

	rootCmd := &cobra.Command{
		Use:   "mssqlhound",
		Short: "MSSQLHound: Collector for adding MSSQL attack paths to BloodHound",
		Long: `MSSQLHound: Collector for adding MSSQL attack paths to BloodHound with OpenGraph

Authors: Chris Thompson (@_Mayyhem) at SpecterOps and Javier Azofra at Siemens Healthineers

Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual files, then zips them.`,
		Version: version,
		RunE:    run,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case debug:
				logLevel.Set(slog.LevelDebug)
			case verbose:
				logLevel.Set(logging.LevelVerbose)
			}
			return nil
		},
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add -V shorthand for --version
	rootCmd.Flags().BoolP("version", "V", false, "Print version information")

	// Shared connection flags (persistent - available to subcommands)
	rootCmd.PersistentFlags().StringVarP(&serverInstance, "targets", "t", "", "SQL Server targets: [user:pass@]host, host:port, host\\instance, MSSQLSvc/host:port, comma-separated list, or file path (default: enumerate domain MSSQLSvc SPNs)")
	rootCmd.PersistentFlags().StringVarP(&userID, "user", "u", "", "SQL Server login username (used to connect and enumerate)")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "SQL Server login password")
	rootCmd.PersistentFlags().StringVar(&ntHash, "nt-hash", "", "NT hash for pass-the-hash SQL auth (32 hex chars; mutually exclusive with -p)")
	rootCmd.PersistentFlags().StringVar(&ldapUser, "ldap-user", "", "Domain user for LDAP queries and EPA testing (DOMAIN\\user or user@domain); not used for SQL login")
	rootCmd.PersistentFlags().StringVar(&ldapPassword, "ldap-password", "", "Password for --ldap-user (LDAP bind and EPA NTLM; not used for SQL login)")
	rootCmd.PersistentFlags().BoolVarP(&useKerberos, "kerberos", "k", false, "Use Kerberos for SQL Server authentication (reads ccache from KRB5CCNAME or --krb5-credcachefile)")
	rootCmd.PersistentFlags().StringVar(&krb5ConfigFile, "krb5-configfile", "", "Path to krb5.conf (default: /etc/krb5.conf or KRB5_CONFIG env var)")
	rootCmd.PersistentFlags().StringVar(&krb5CCacheFile, "krb5-credcachefile", "", "Path to Kerberos credential cache file (overrides KRB5CCNAME env var)")
	rootCmd.PersistentFlags().StringVar(&krb5KeytabFile, "krb5-keytabfile", "", "Path to Kerberos keytab file")
	rootCmd.PersistentFlags().StringVar(&krb5Realm, "krb5-realm", "", "Kerberos realm (default: derived from domain or krb5.conf)")
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Domain to use for name and SID resolution")
	rootCmd.PersistentFlags().StringVar(&dc, "dc", "", "Domain controller hostname or IP (used for LDAP and as DNS resolver if --dns-resolver not specified)")
	rootCmd.PersistentFlags().StringVar(&dnsResolver, "dns-resolver", "", "DNS resolver IP address for domain lookups")
	rootCmd.PersistentFlags().StringVarP(&proxyAddr, "proxy", "x", "", "SOCKS5 proxy address (host:port or socks5://[user:pass@]host:port)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output showing detailed collection progress")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output (includes EPA/TLS/NTLM diagnostics)")

	// Collection-specific flags (local to root command only)
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "BloodHound", "Output format: BloodHound, BHGeneric")
	rootCmd.Flags().StringVar(&tempDir, "temp-dir", "", "Temporary directory for output files")
	rootCmd.Flags().StringVar(&zipDir, "zip-dir", ".", "Directory for final zip file")
	rootCmd.Flags().StringVar(&fileSizeLimit, "file-size-limit", "1GB", "Stop enumeration after files exceed this size")
	rootCmd.Flags().BoolVar(&logPerTarget, "log-per-target", false, "Save per-target log files in a separate zip")
	rootCmd.Flags().BoolVar(&domainEnumOnly, "domain-enum-only", false, "Only enumerate SPNs, skip MSSQL collection")
	rootCmd.Flags().BoolVar(&skipLinkedServerEnum, "skip-linked-servers", false, "Don't enumerate linked servers")
	rootCmd.Flags().BoolVar(&collectFromLinkedServers, "collect-from-linked", false, "Perform full collection on discovered linked servers")
	rootCmd.Flags().BoolVar(&skipPrivateAddress, "skip-private-address", false, "Skip private IP check when resolving domains")
	rootCmd.Flags().BoolVarP(&scanAllComputers, "scan-all-computers", "A", false, "Scan all domain computers, not just those with SPNs")
	rootCmd.Flags().BoolVar(&skipADNodeCreation, "skip-ad-nodes", false, "Skip creating User, Group, Computer nodes")
	rootCmd.Flags().BoolVar(&includeNontraversableEdges, "include-nontraversable", false, "Include non-traversable edges")
	rootCmd.Flags().BoolVar(&makeInterestingEdgesTraversable, "make-interesting-traversable", true, "Make interesting edges traversable")
	rootCmd.Flags().IntVar(&linkedServerTimeout, "linked-timeout", 300, "Linked server enumeration timeout (seconds)")
	rootCmd.Flags().IntVar(&memoryThresholdPercent, "memory-threshold", 90, "Stop when memory exceeds this percentage")
	rootCmd.Flags().IntVar(&fileSizeUpdateInterval, "size-update-interval", 5, "Interval for file size updates (seconds)")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 0, "Number of concurrent workers (0 = sequential processing)")

	// BloodHound upload flags (uses local DNS, bypasses --proxy)
	rootCmd.Flags().StringVarP(&bloodhoundUpload, "bloodhound", "B", "", "BloodHound CE credentials: <token-id>:<token_key>@<bloodhound_url> (requires --upload-schema and/or --upload-results)")
	rootCmd.Flags().StringVar(&bloodhoundURL, "bloodhound-url", "", "BloodHound CE instance URL, uses local DNS (env: BLOODHOUND_URL)")
	rootCmd.Flags().StringVar(&tokenID, "token-id", "", "BloodHound API token ID (env: BLOODHOUND_TOKEN_ID)")
	rootCmd.Flags().StringVar(&tokenKey, "token-key", "", "BloodHound API token key (env: BLOODHOUND_TOKEN_KEY)")
	rootCmd.Flags().BoolVar(&uploadSchema, "upload-schema", false, "Upload schema definitions to BloodHound (PUT /api/v2/extensions)")
	rootCmd.Flags().BoolVar(&uploadResults, "upload-results", false, "Upload collection results to BloodHound after collection")
	rootCmd.Flags().BoolVar(&skipCollection, "skip-collection", false, "Skip data collection (use with --upload-schema to only upload schema)")

	// Annotate flags with display groups for --help output
	for _, name := range []string{"user", "password", "nt-hash", "ldap-user", "ldap-password",
		"kerberos", "krb5-configfile", "krb5-credcachefile", "krb5-keytabfile", "krb5-realm"} {
		rootCmd.PersistentFlags().SetAnnotation(name, "group", []string{"Authentication"}) //nolint:errcheck
	}
	for _, name := range []string{"targets", "domain", "dc", "dns-resolver", "proxy"} {
		rootCmd.PersistentFlags().SetAnnotation(name, "group", []string{"Collection"}) //nolint:errcheck
	}
	for _, name := range []string{"scan-all-computers", "skip-private-address",
		"domain-enum-only", "skip-linked-servers", "collect-from-linked",
		"skip-ad-nodes", "include-nontraversable", "make-interesting-traversable"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"Collection"}) //nolint:errcheck
	}
	for _, name := range []string{"linked-timeout", "workers", "file-size-limit",
		"memory-threshold", "size-update-interval"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"Performance"}) //nolint:errcheck
	}
	for _, name := range []string{"output-format", "temp-dir", "zip-dir", "log-per-target"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"Output"}) //nolint:errcheck
	}
	for _, name := range []string{"bloodhound", "bloodhound-url", "token-id", "token-key", "upload-results", "upload-schema", "skip-collection"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"BloodHound Upload"}) //nolint:errcheck
	}

	// Shared grouped usage display used by both --help and error usage
	groupOrder := []string{
		"Authentication",
		"Collection",
		"Performance",
		"Output",
		"BloodHound Upload",
	}
	printUsage := func(cmd *cobra.Command, out interface{ Write([]byte) (int, error) }) {
		fmt.Fprintf(out, "Usage:\n  %s\n\n", cmd.UseLine())

		// Merge all applicable flag sets
		allFS := pflag.NewFlagSet("", pflag.ContinueOnError)
		allFS.AddFlagSet(cmd.LocalFlags())
		allFS.AddFlagSet(cmd.PersistentFlags())
		allFS.AddFlagSet(cmd.InheritedFlags())

		// Print flags in defined group order
		printed := map[string]bool{}
		for _, gName := range groupOrder {
			groupFS := pflag.NewFlagSet("", pflag.ContinueOnError)
			allFS.VisitAll(func(f *pflag.Flag) {
				if printed[f.Name] {
					return
				}
				if vals, ok := f.Annotations["group"]; ok {
					for _, v := range vals {
						if v == gName {
							groupFS.AddFlag(f)
							printed[f.Name] = true
						}
					}
				}
			})
			if groupFS.HasFlags() {
				fmt.Fprintf(out, "%s:\n", gName)
				fmt.Fprint(out, groupFS.FlagUsages())
				fmt.Fprintln(out)
			}
		}

		// Print any ungrouped flags (e.g., subcommand-specific options)
		ungroupedFS := pflag.NewFlagSet("", pflag.ContinueOnError)
		allFS.VisitAll(func(f *pflag.Flag) {
			if !printed[f.Name] && f.Name != "help" {
				ungroupedFS.AddFlag(f)
				printed[f.Name] = true
			}
		})
		if ungroupedFS.HasFlags() {
			fmt.Fprintf(out, "Options:\n")
			fmt.Fprint(out, ungroupedFS.FlagUsages())
			fmt.Fprintln(out)
		}

		if cmd.HasAvailableSubCommands() {
			fmt.Fprintln(out, "Available Commands:")
			for _, sub := range cmd.Commands() {
				if sub.IsAvailableCommand() {
					fmt.Fprintf(out, "  %-20s %s\n", sub.Name(), sub.Short)
				}
			}
			fmt.Fprintln(out)
			fmt.Fprintf(out, "Use \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		}
	}

	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		if cmd.Long != "" {
			fmt.Fprintln(out, cmd.Long)
			fmt.Fprintln(out)
		}
		printUsage(cmd, out)
	})
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		printUsage(cmd, cmd.OutOrStderr())
		return nil
	})

	// Register subcommands
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newTestEPAMatrixCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	logger.Info("MSSQLHound starting", "version", version)

	// Validate mutually exclusive auth options
	if ntHash != "" && password != "" {
		return fmt.Errorf("--nt-hash and --password are mutually exclusive")
	}
	if useKerberos && password != "" {
		return fmt.Errorf("--kerberos and --password are mutually exclusive")
	}
	if useKerberos && ntHash != "" {
		return fmt.Errorf("--kerberos and --nt-hash are mutually exclusive")
	}

	// Extract inline credentials from targets if present: user:pass@target
	// Only extract if -u was not explicitly provided
	if serverInstance != "" && !cmd.Flags().Changed("user") {
		serverInstance = extractAndApplyCredentials(serverInstance)
	}

	// Smart server target detection: file path, comma-separated list, or single instance
	serverInstance, serverListFile, serverList := classifyTarget(serverInstance)

	// Auto-resolve domain controller from domain if not explicitly specified
	if dc == "" && domain != "" {
		if _, addrs, srvErr := net.DefaultResolver.LookupSRV(context.Background(), "ldap", "tcp", domain); srvErr == nil && len(addrs) > 0 {
			dc = strings.TrimSuffix(addrs[0].Target, ".")
			logger.Info("Auto-resolved domain controller via SRV", "dc", dc)
		} else if ips, lookupErr := net.DefaultResolver.LookupHost(context.Background(), domain); lookupErr == nil && len(ips) > 0 {
			dc = domain
			logger.Info("Auto-resolved domain controller from domain name", "dc", dc)
		}
	}

	// Configure DNS resolver if specified
	// If --dc is specified but --dns-resolver is not, use dc as the resolver
	resolver := dnsResolver
	if resolver == "" && dc != "" {
		resolver = dc
	}

	if resolver != "" {
		logger.Info("Using DNS resolver", "resolver", resolver)
		var dnsDialFunc func(ctx context.Context, network, address string) (net.Conn, error)
		if proxyAddr != "" {
			pd, err := proxydialer.New(proxyAddr)
			if err != nil {
				return fmt.Errorf("failed to create proxy dialer for DNS: %w", err)
			}
			dnsDialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				// Force TCP: SOCKS5 doesn't support UDP, and DNS works fine over TCP
				return pd.DialContext(ctx, "tcp", net.JoinHostPort(resolver, "53"))
			}
		} else {
			dnsDialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, net.JoinHostPort(resolver, "53"))
			}
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial:     dnsDialFunc,
		}
	}

	// If LDAP credentials not specified but SQL credentials look like domain credentials,
	// use the SQL credentials for LDAP authentication as a fallback
	effectiveLDAPUser := ldapUser
	effectiveLDAPPassword := ldapPassword
	if effectiveLDAPUser == "" && effectiveLDAPPassword == "" && userID != "" {
		if strings.Contains(userID, "\\") || strings.Contains(userID, "@") {
			effectiveLDAPUser = userID
			if password != "" {
				effectiveLDAPPassword = password
			}
			// When using --nt-hash, password is empty but LDAP can still auth via NTLMBindWithHash
		} else if domain != "" {
			// Bare username with no domain prefix — derive UPN from -d flag
			effectiveLDAPUser = userID + "@" + domain
			if password != "" {
				effectiveLDAPPassword = password
			}
		}
	}

	// Parse -B shorthand: <token-id>:<token_key>@<bloodhound_url>
	if bloodhoundUpload != "" {
		atIdx := strings.Index(bloodhoundUpload, "@")
		if atIdx < 0 {
			return fmt.Errorf("-B format must be <token-id>:<token_key>@<bloodhound_url>")
		}
		credentials := bloodhoundUpload[:atIdx]
		url := bloodhoundUpload[atIdx+1:]

		colonIdx := strings.Index(credentials, ":")
		if colonIdx < 0 {
			return fmt.Errorf("-B format must be <token-id>:<token_key>@<bloodhound_url>")
		}

		tokenID = credentials[:colonIdx]
		tokenKey = credentials[colonIdx+1:]
		bloodhoundURL = url
	}

	// Apply environment variable defaults for BloodHound upload options
	if bloodhoundURL == "" {
		bloodhoundURL = os.Getenv("BLOODHOUND_URL")
	}
	if tokenID == "" {
		tokenID = os.Getenv("BLOODHOUND_TOKEN_ID")
	}
	if tokenKey == "" {
		tokenKey = os.Getenv("BLOODHOUND_TOKEN_KEY")
	}

	// Validate that at least one upload action is specified when credentials are provided
	if bloodhoundURL != "" && !uploadSchema && !uploadResults {
		return fmt.Errorf("--upload-schema and/or --upload-results must be specified with BloodHound credentials")
	}

	// Build configuration from flags
	config := &collector.Config{
		ServerInstance:                  serverInstance,
		ServerListFile:                  serverListFile,
		ServerList:                      serverList,
		UserID:                          userID,
		Password:                        password,
		NTHash:                          ntHash,
		UseKerberos:                     useKerberos,
		Krb5ConfigFile:                  krb5ConfigFile,
		Krb5CCacheFile:                  krb5CCacheFile,
		Krb5KeytabFile:                  krb5KeytabFile,
		Krb5Realm:                       krb5Realm,
		Domain:                          strings.ToUpper(domain),
		DC:                              dc,
		DNSResolver:                     dnsResolver,
		LDAPUser:                        effectiveLDAPUser,
		LDAPPassword:                    effectiveLDAPPassword,
		OutputFormat:                    outputFormat,
		TempDir:                         tempDir,
		ZipDir:                          zipDir,
		FileSizeLimit:                   fileSizeLimit,
		Verbose:                         verbose,
		Debug:                           debug,
		DomainEnumOnly:                  domainEnumOnly,
		SkipLinkedServerEnum:            skipLinkedServerEnum,
		CollectFromLinkedServers:        collectFromLinkedServers,
		SkipPrivateAddress:              skipPrivateAddress,
		ScanAllComputers:                scanAllComputers,
		SkipADNodeCreation:              skipADNodeCreation,
		IncludeNontraversableEdges:      includeNontraversableEdges,
		MakeInterestingEdgesTraversable: makeInterestingEdgesTraversable,
		LinkedServerTimeout:             linkedServerTimeout,
		MemoryThresholdPercent:          memoryThresholdPercent,
		FileSizeUpdateInterval:          fileSizeUpdateInterval,
		Workers:                         workers,
		ProxyAddr:                       proxyAddr,
		Logger:                          logger,
		LogPerTarget:                    logPerTarget,
		LogLevel:                        &logLevel,
		BloodHoundURL:                   bloodhoundURL,
		TokenID:                         tokenID,
		TokenKey:                        tokenKey,
		UploadSchema:                    uploadSchema,
		UploadResults:                   uploadResults,
		SkipCollection:                  skipCollection,
	}

	if proxyAddr != "" {
		logger.Info("SOCKS5 proxy configured", "addr", proxyAddr)
		logger.Info("SQL Browser (UDP) resolution is not supported through SOCKS5. Named instances must include an explicit port (e.g., host\\instance:1433).")
		if resolver == "" {
			logger.Warn("No DNS resolver specified. DNS will resolve locally, not through the proxy. Consider using --dns-resolver or --dc for remote DNS resolution.")
		}
	}

	// Create and run collector
	c, err := collector.New(config)
	if err != nil {
		return err
	}
	return c.Run()
}

// classifyTarget determines how to interpret the -t/--targets value.
// Returns (serverInstance, serverListFile, serverList).
func classifyTarget(target string) (string, string, string) {
	if target == "" {
		return "", "", ""
	}
	// If it's an existing file, treat as server list file
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return "", target, ""
	}
	// If it contains commas, treat as comma-separated list
	if strings.Contains(target, ",") {
		return "", "", target
	}
	// Otherwise it's a single server instance (host, host:port, host\instance, SPN)
	return target, "", ""
}

// extractTargetCredentials parses user:password@target from a target string.
// Splits on the last '@' (so UPN usernames like user@domain work) and the
// first ':' in the credentials portion. Returns (user, password, cleanTarget, ok).
func extractTargetCredentials(target string) (string, string, string, bool) {
	atIdx := strings.LastIndex(target, "@")
	if atIdx < 0 {
		return "", "", target, false
	}

	credentials := target[:atIdx]
	cleanTarget := target[atIdx+1:]

	// Credentials must contain a colon separating user from password
	colonIdx := strings.Index(credentials, ":")
	if colonIdx < 0 {
		return "", "", target, false
	}

	user := credentials[:colonIdx]
	pass := credentials[colonIdx+1:]

	// Sanity: both user and target must be non-empty
	if user == "" || cleanTarget == "" {
		return "", "", target, false
	}

	return user, pass, cleanTarget, true
}

// extractAndApplyCredentials strips user:pass@ from one or more comma-separated
// targets, sets the package-level userID/password from the first entry that has
// credentials, and returns the cleaned target string (credentials removed).
func extractAndApplyCredentials(targets string) string {
	// Don't touch file paths — they'll be detected by classifyTarget later
	if info, err := os.Stat(targets); err == nil && !info.IsDir() {
		return targets
	}

	parts := strings.Split(targets, ",")
	cleaned := make([]string, 0, len(parts))
	var credUser, credPass string
	credSet := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if extractedUser, extractedPass, cleanTarget, ok := extractTargetCredentials(part); ok {
			if !credSet {
				credUser = extractedUser
				credPass = extractedPass
				credSet = true
			}
			cleaned = append(cleaned, cleanTarget)
		} else {
			cleaned = append(cleaned, part)
		}
	}

	if credSet {
		userID = credUser
		password = credPass
		logger.Info("Parsed inline credentials from target", "user", userID)
	}

	if len(cleaned) == 1 {
		return cleaned[0]
	}
	return strings.Join(cleaned, ",")
}
