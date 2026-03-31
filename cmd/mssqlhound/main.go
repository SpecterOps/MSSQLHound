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
	dcIP           string
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
	serverListFile string
	serverList     string
	outputFormat   string
	tempDir        string
	zipDir         string
	fileSizeLimit  string

	logPerTarget                    bool

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
	bloodhoundURL string
	tokenID       string
	tokenKey      string
	uploadSchema  bool
	uploadResults bool
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

	// Shared connection flags (persistent - available to subcommands)
	rootCmd.PersistentFlags().StringVarP(&serverInstance, "server", "s", "", "SQL Server instance to collect from (host, host:port, or host\\instance)")
	rootCmd.PersistentFlags().StringVarP(&userID, "user", "u", "", "SQL login username")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "SQL login password")
	rootCmd.PersistentFlags().StringVar(&ntHash, "nt-hash", "", "NT hash (32 hex chars) for pass-the-hash authentication (mutually exclusive with --password)")
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Domain to use for name and SID resolution")
	rootCmd.PersistentFlags().StringVar(&dcIP, "dc-ip", "", "Domain controller hostname or IP (used for LDAP and as DNS resolver if --dns-resolver not specified)")
	rootCmd.PersistentFlags().StringVar(&dnsResolver, "dns-resolver", "", "DNS resolver IP address for domain lookups")
	rootCmd.PersistentFlags().StringVar(&ldapUser, "ldap-user", "", "LDAP user (DOMAIN\\user or user@domain) for GSSAPI/Kerberos bind")
	rootCmd.PersistentFlags().StringVar(&ldapPassword, "ldap-password", "", "LDAP password for GSSAPI/Kerberos bind")
	rootCmd.PersistentFlags().BoolVarP(&useKerberos, "kerberos", "k", false, "Use Kerberos authentication (reads ccache from KRB5CCNAME or --krb5-credcachefile)")
	rootCmd.PersistentFlags().StringVar(&krb5ConfigFile, "krb5-configfile", "", "Path to krb5.conf (default: /etc/krb5.conf or KRB5_CONFIG env var)")
	rootCmd.PersistentFlags().StringVar(&krb5CCacheFile, "krb5-credcachefile", "", "Path to Kerberos credential cache file (overrides KRB5CCNAME env var)")
	rootCmd.PersistentFlags().StringVar(&krb5KeytabFile, "krb5-keytabfile", "", "Path to Kerberos keytab file")
	rootCmd.PersistentFlags().StringVar(&krb5Realm, "krb5-realm", "", "Kerberos realm (default: derived from domain or krb5.conf)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output showing detailed collection progress")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output (includes EPA/TLS/NTLM diagnostics)")
	rootCmd.PersistentFlags().StringVar(&proxyAddr, "proxy", "", "SOCKS5 proxy address (host:port or socks5://[user:pass@]host:port)")

	// Collection-specific flags (local to root command only)
	rootCmd.Flags().StringVar(&serverListFile, "server-list-file", "", "File containing list of servers (one per line)")
	rootCmd.Flags().StringVar(&serverList, "server-list", "", "Comma-separated list of servers")
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "BloodHound", "Output format: BloodHound, BHGeneric")
	rootCmd.Flags().StringVar(&tempDir, "temp-dir", "", "Temporary directory for output files")
	rootCmd.Flags().StringVar(&zipDir, "zip-dir", ".", "Directory for final zip file")
	rootCmd.Flags().StringVar(&fileSizeLimit, "file-size-limit", "1GB", "Stop enumeration after files exceed this size")
	rootCmd.Flags().BoolVar(&logPerTarget, "log-per-target", false, "Save per-target log files in a separate zip")
	rootCmd.Flags().BoolVar(&domainEnumOnly, "domain-enum-only", false, "Only enumerate SPNs, skip MSSQL collection")
	rootCmd.Flags().BoolVar(&skipLinkedServerEnum, "skip-linked-servers", false, "Don't enumerate linked servers")
	rootCmd.Flags().BoolVar(&collectFromLinkedServers, "collect-from-linked", false, "Perform full collection on discovered linked servers")
	rootCmd.Flags().BoolVar(&skipPrivateAddress, "skip-private-address", false, "Skip private IP check when resolving domains")
	rootCmd.Flags().BoolVar(&scanAllComputers, "scan-all-computers", false, "Scan all domain computers, not just those with SPNs")
	rootCmd.Flags().BoolVar(&skipADNodeCreation, "skip-ad-nodes", false, "Skip creating User, Group, Computer nodes")
	rootCmd.Flags().BoolVar(&includeNontraversableEdges, "include-nontraversable", false, "Include non-traversable edges")
	rootCmd.Flags().BoolVar(&makeInterestingEdgesTraversable, "make-interesting-traversable", true, "Make interesting edges traversable (default true)")
	rootCmd.Flags().IntVar(&linkedServerTimeout, "linked-timeout", 300, "Linked server enumeration timeout (seconds)")
	rootCmd.Flags().IntVar(&memoryThresholdPercent, "memory-threshold", 90, "Stop when memory exceeds this percentage")
	rootCmd.Flags().IntVar(&fileSizeUpdateInterval, "size-update-interval", 5, "Interval for file size updates (seconds)")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 0, "Number of concurrent workers (0 = sequential processing)")

	// BloodHound upload flags (uses local DNS, bypasses --proxy)
	rootCmd.Flags().StringVar(&bloodhoundURL, "bloodhound-url", "", "BloodHound CE instance URL, uses local DNS (env: BLOODHOUND_URL)")
	rootCmd.Flags().StringVar(&tokenID, "token-id", "", "BloodHound API token ID (env: BLOODHOUND_TOKEN_ID)")
	rootCmd.Flags().StringVar(&tokenKey, "token-key", "", "BloodHound API token key (env: BLOODHOUND_TOKEN_KEY)")
	rootCmd.Flags().BoolVar(&uploadSchema, "upload-schema", false, "Upload schema definitions (SCHEMA.json) to BloodHound")
	rootCmd.Flags().BoolVar(&uploadResults, "upload-results", false, "Upload collection results to BloodHound after collection")

	// Annotate flags with display groups for --help output
	for _, name := range []string{"server", "user", "password", "nt-hash", "kerberos",
		"krb5-configfile", "krb5-credcachefile", "krb5-keytabfile", "krb5-realm"} {
		rootCmd.PersistentFlags().SetAnnotation(name, "group", []string{"Authentication"}) //nolint:errcheck
	}
	for _, name := range []string{"domain", "dc-ip", "dns-resolver", "ldap-user", "ldap-password"} {
		rootCmd.PersistentFlags().SetAnnotation(name, "group", []string{"Domain / LDAP"}) //nolint:errcheck
	}
	for _, name := range []string{"server-list-file", "server-list", "scan-all-computers", "skip-private-address"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"Target Selection"}) //nolint:errcheck
	}
	for _, name := range []string{"domain-enum-only", "skip-linked-servers", "collect-from-linked",
		"linked-timeout", "skip-ad-nodes", "include-nontraversable", "make-interesting-traversable", "workers"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"Collection"}) //nolint:errcheck
	}
	for _, name := range []string{"output-format", "temp-dir", "zip-dir", "file-size-limit",
		"log-per-target", "memory-threshold", "size-update-interval"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"Output / Storage"}) //nolint:errcheck
	}
	for _, name := range []string{"bloodhound-url", "token-id", "token-key", "upload-results", "upload-schema"} {
		rootCmd.Flags().SetAnnotation(name, "group", []string{"BloodHound Upload"}) //nolint:errcheck
	}
	for _, name := range []string{"verbose", "debug", "proxy"} {
		rootCmd.PersistentFlags().SetAnnotation(name, "group", []string{"Diagnostics"}) //nolint:errcheck
	}

	// Custom help function with grouped flag display
	groupOrder := []string{
		"Authentication",
		"Domain / LDAP",
		"Target Selection",
		"Collection",
		"Output / Storage",
		"BloodHound Upload",
		"Diagnostics",
	}
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()

		if cmd.Long != "" {
			fmt.Fprintln(out, cmd.Long)
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "Usage:\n  %s\n\n", cmd.UseLine())

		if cmd.HasAvailableSubCommands() {
			fmt.Fprintln(out, "Available Commands:")
			for _, sub := range cmd.Commands() {
				if sub.IsAvailableCommand() {
					fmt.Fprintf(out, "  %-20s %s\n", sub.Name(), sub.Short)
				}
			}
			fmt.Fprintln(out)
		}

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
			fmt.Fprintf(out, "Use \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		}
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

	// Configure DNS resolver if specified
	// If --dc-ip is specified but --dns-resolver is not, use dc-ip as the resolver
	resolver := dnsResolver
	if resolver == "" && dcIP != "" {
		resolver = dcIP
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
		DCIP:                            dcIP,
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
	}

	if proxyAddr != "" {
		logger.Info("SOCKS5 proxy configured", "addr", proxyAddr)
		logger.Info("SQL Browser (UDP) resolution is not supported through SOCKS5. Named instances must include an explicit port (e.g., host\\instance:1433).")
		if resolver == "" {
			logger.Warn("No DNS resolver specified. DNS will resolve locally, not through the proxy. Consider using --dns-resolver or --dc-ip for remote DNS resolution.")
		}
	}

	// Create and run collector
	c, err := collector.New(config)
	if err != nil {
		return err
	}
	return c.Run()
}
