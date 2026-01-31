package main

import (
	"fmt"
	"os"

	"github.com/SpecterOps/MSSQLHound/internal/collector"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"

	// Connection options
	serverInstance   string
	serverListFile   string
	serverList       string
	userID           string
	password         string
	domain           string
	domainController string
	ldapUser         string
	ldapPassword     string

	// Output options
	outputFormat  string
	tempDir       string
	zipDir        string
	fileSizeLimit string

	// Collection options
	domainEnumOnly                  bool
	skipLinkedServerEnum            bool
	collectFromLinkedServers        bool
	skipPrivateAddress              bool
	scanAllComputers                bool
	skipADNodeCreation              bool
	includeNontraversableEdges      bool
	makeInterestingEdgesTraversable bool

	// Timeouts and limits
	linkedServerTimeout    int
	memoryThresholdPercent int
	fileSizeUpdateInterval int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mssqlhound",
		Short: "MSSQLHound: Collector for adding MSSQL attack paths to BloodHound",
		Long: `MSSQLHound: PowerShell collector for adding MSSQL attack paths to BloodHound with OpenGraph

Author: Chris Thompson (@_Mayyhem) at SpecterOps

Collects BloodHound OpenGraph compatible data from one or more MSSQL servers into individual files, then zips them.`,
		Version: version,
		RunE:    run,
	}

	// Connection flags
	rootCmd.Flags().StringVarP(&serverInstance, "server", "s", "", "SQL Server instance to collect from (host, host:port, or host\\instance)")
	rootCmd.Flags().StringVar(&serverListFile, "server-list-file", "", "File containing list of servers (one per line)")
	rootCmd.Flags().StringVar(&serverList, "server-list", "", "Comma-separated list of servers")
	rootCmd.Flags().StringVarP(&userID, "user", "u", "", "SQL login username")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "SQL login password")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to use for name and SID resolution")
	rootCmd.Flags().StringVar(&domainController, "dc", "", "Domain controller to use for resolution")
	rootCmd.Flags().StringVar(&ldapUser, "ldap-user", "", "LDAP user (DOMAIN\\user or user@domain) for GSSAPI/Kerberos bind")
	rootCmd.Flags().StringVar(&ldapPassword, "ldap-password", "", "LDAP password for GSSAPI/Kerberos bind")

	// Output flags
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "BloodHound", "Output format: BloodHound, BHGeneric")
	rootCmd.Flags().StringVar(&tempDir, "temp-dir", "", "Temporary directory for output files")
	rootCmd.Flags().StringVar(&zipDir, "zip-dir", ".", "Directory for final zip file")
	rootCmd.Flags().StringVar(&fileSizeLimit, "file-size-limit", "1GB", "Stop enumeration after files exceed this size")

	// Collection flags
	rootCmd.Flags().BoolVar(&domainEnumOnly, "domain-enum-only", false, "Only enumerate SPNs, skip MSSQL collection")
	rootCmd.Flags().BoolVar(&skipLinkedServerEnum, "skip-linked-servers", false, "Don't enumerate linked servers")
	rootCmd.Flags().BoolVar(&collectFromLinkedServers, "collect-from-linked", false, "Perform full collection on discovered linked servers")
	rootCmd.Flags().BoolVar(&skipPrivateAddress, "skip-private-address", false, "Skip private IP check when resolving domains")
	rootCmd.Flags().BoolVar(&scanAllComputers, "scan-all-computers", false, "Scan all domain computers, not just those with SPNs")
	rootCmd.Flags().BoolVar(&skipADNodeCreation, "skip-ad-nodes", false, "Skip creating User, Group, Computer nodes")
	rootCmd.Flags().BoolVar(&includeNontraversableEdges, "include-nontraversable", false, "Include non-traversable edges")
	rootCmd.Flags().BoolVar(&makeInterestingEdgesTraversable, "make-interesting-traversable", true, "Make interesting edges traversable (default true)")

	// Timeout/limit flags
	rootCmd.Flags().IntVar(&linkedServerTimeout, "linked-timeout", 300, "Linked server enumeration timeout (seconds)")
	rootCmd.Flags().IntVar(&memoryThresholdPercent, "memory-threshold", 90, "Stop when memory exceeds this percentage")
	rootCmd.Flags().IntVar(&fileSizeUpdateInterval, "size-update-interval", 5, "Interval for file size updates (seconds)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	fmt.Printf("MSSQLHound v%s\n", version)
	fmt.Println("Author: Chris Thompson (@_Mayyhem) at SpecterOps")
	fmt.Println()

	// Build configuration from flags
	config := &collector.Config{
		ServerInstance:                  serverInstance,
		ServerListFile:                  serverListFile,
		ServerList:                      serverList,
		UserID:                          userID,
		Password:                        password,
		Domain:                          domain,
		DomainController:                domainController,
		LDAPUser:                        ldapUser,
		LDAPPassword:                    ldapPassword,
		OutputFormat:                    outputFormat,
		TempDir:                         tempDir,
		ZipDir:                          zipDir,
		FileSizeLimit:                   fileSizeLimit,
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
	}

	// Create and run collector
	c := collector.New(config)
	return c.Run()
}
