package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/collector"
	"github.com/SpecterOps/MSSQLHound/internal/proxydialer"
	"github.com/spf13/cobra"
)

var (
	version = "2.0.0"

	// Shared connection options (persistent - inherited by subcommands)
	serverInstance string
	userID         string
	password       string
	domain         string
	dcIP           string
	dnsResolver    string
	ldapUser       string
	ldapPassword   string
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
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mssqlhound",
		Short: "MSSQLHound: Collector for adding MSSQL attack paths to BloodHound",
		Long: `MSSQLHound: Collector for adding MSSQL attack paths to BloodHound with OpenGraph

Authors: Chris Thompson (@_Mayyhem) at SpecterOps and Javier Azofra at Siemens Healthineers

Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual files, then zips them.`,
		Version: version,
		RunE:    run,
	}

	// Shared connection flags (persistent - available to subcommands)
	rootCmd.PersistentFlags().StringVarP(&serverInstance, "server", "s", "", "SQL Server instance to collect from (host, host:port, or host\\instance)")
	rootCmd.PersistentFlags().StringVarP(&userID, "user", "u", "", "SQL login username")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "SQL login password")
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Domain to use for name and SID resolution")
	rootCmd.PersistentFlags().StringVar(&dcIP, "dc-ip", "", "Domain controller hostname or IP (used for LDAP and as DNS resolver if --dns-resolver not specified)")
	rootCmd.PersistentFlags().StringVar(&dnsResolver, "dns-resolver", "", "DNS resolver IP address for domain lookups")
	rootCmd.PersistentFlags().StringVar(&ldapUser, "ldap-user", "", "LDAP user (DOMAIN\\user or user@domain) for GSSAPI/Kerberos bind")
	rootCmd.PersistentFlags().StringVar(&ldapPassword, "ldap-password", "", "LDAP password for GSSAPI/Kerberos bind")
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

	// Register subcommands
	rootCmd.AddCommand(newTestEPAMatrixCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	fmt.Printf("MSSQLHound v%s\n", version)
	fmt.Println("Authors: Chris Thompson (@_Mayyhem) at SpecterOps and Javier Azofra at Siemens Healthineers")
	fmt.Println()

	// Configure custom DNS resolver if specified
	// If --dc-ip is specified but --dns-resolver is not, use dc-ip as the resolver
	resolver := dnsResolver
	if resolver == "" && dcIP != "" {
		resolver = dcIP
	}

	if resolver != "" {
		fmt.Printf("Using custom DNS resolver: %s\n", resolver)
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
	if effectiveLDAPUser == "" && effectiveLDAPPassword == "" && userID != "" && password != "" {
		if strings.Contains(userID, "\\") || strings.Contains(userID, "@") {
			effectiveLDAPUser = userID
			effectiveLDAPPassword = password
		}
	}

	// Build configuration from flags
	config := &collector.Config{
		ServerInstance:                  serverInstance,
		ServerListFile:                  serverListFile,
		ServerList:                      serverList,
		UserID:                          userID,
		Password:                        password,
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
	}

	if proxyAddr != "" {
		fmt.Printf("SOCKS5 proxy configured: %s\n", proxyAddr)
		fmt.Println("  Note: SQL Browser (UDP) resolution is not supported through SOCKS5.")
		fmt.Println("  Named instances must include an explicit port (e.g., host\\instance:1433).")
		if resolver == "" {
			fmt.Println("  Warning: No DNS resolver specified. DNS will resolve locally, not through the proxy.")
			fmt.Println("  Consider using --dns-resolver or --dc-ip for remote DNS resolution.")
		}
		fmt.Println()
	}

	// Create and run collector
	c := collector.New(config)
	return c.Run()
}
