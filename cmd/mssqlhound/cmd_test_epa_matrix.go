package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/epamatrix"
	"github.com/SpecterOps/MSSQLHound/internal/proxydialer"
	"github.com/SpecterOps/MSSQLHound/internal/winrmclient"
	"github.com/spf13/cobra"
)

// epaMatrixLogger returns a logger tagged with the EPA matrix target.
func epaMatrixLogger() *slog.Logger {
	return logger.With("target", serverInstance)
}

var (
	winrmHost             string
	winrmPort             int
	winrmHTTPS            bool
	winrmBasic            bool
	sqlInstanceName       string
	serviceRestartWaitSec int
	postRestartDelaySec   int
	skipStrictEncryption  bool
)

func newTestEPAMatrixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-epa-matrix",
		Short: "Test all EPA setting combinations against a SQL Server",
		Long: `Connects to a SQL Server host via WinRM to configure registry settings,
then tests all 12 combinations of Force Encryption, Force Strict Encryption,
and Extended Protection. For each combination, restarts the SQL Server service
and runs MSSQLHound's EPA detection to verify correctness.

Requires WinRM access (PowerShell Remoting) to the SQL Server host and
domain credentials (--user/--password in DOMAIN\user format) for both
WinRM and NTLM-based EPA testing.

WARNING: This command modifies SQL Server registry settings and restarts the
SQL Server service. Original settings are restored when testing completes
or if interrupted (Ctrl+C).`,
		RunE: runTestEPAMatrix,
	}

	cmd.Flags().StringVar(&winrmHost, "winrm-host", "", "WinRM target host (defaults to SQL Server hostname)")
	cmd.Flags().IntVar(&winrmPort, "winrm-port", 5985, "WinRM port")
	cmd.Flags().BoolVar(&winrmHTTPS, "winrm-https", false, "Use HTTPS for WinRM (port 5986)")
	cmd.Flags().BoolVar(&winrmBasic, "winrm-basic", false, "Use Basic auth instead of NTLM for WinRM (requires AllowUnencrypted on server)")
	cmd.Flags().StringVar(&sqlInstanceName, "sql-instance-name", "MSSQLSERVER", "SQL Server instance name for registry lookup")
	cmd.Flags().IntVar(&serviceRestartWaitSec, "restart-wait", 60, "Max seconds to wait for SQL Server service restart")
	cmd.Flags().IntVar(&postRestartDelaySec, "post-restart-delay", 5, "Seconds to wait after service reports Running before testing")
	cmd.Flags().BoolVar(&skipStrictEncryption, "skip-strict", false, "Skip ForceStrictEncryption=1 combinations (for pre-SQL Server 2022)")

	return cmd
}

func runTestEPAMatrix(cmd *cobra.Command, args []string) error {
	if serverInstance == "" {
		return fmt.Errorf("--server is required")
	}
	if userID == "" || (password == "" && ntHash == "") {
		return fmt.Errorf("--user and (--password or --nt-hash) are required (DOMAIN\\user format)")
	}

	// Configure DNS resolver (same logic as root command)
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
				return pd.DialContext(ctx, "tcp", net.JoinHostPort(resolver, "53"))
			}
		} else {
			dnsDialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(resolver, "53"))
			}
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial:     dnsDialFunc,
		}
	}

	// Determine WinRM host - default to SQL server hostname
	effectiveWinRMHost := winrmHost
	if effectiveWinRMHost == "" {
		effectiveWinRMHost = extractHostname(serverInstance)
	}

	log := epaMatrixLogger()
	operationalTimeout := time.Duration(serviceRestartWaitSec+30) * time.Second

	// If the user explicitly set any WinRM transport flag, use those values directly.
	// Otherwise, auto-discover by probing HTTP/HTTPS + NTLM/Basic on 5985/5986.
	transportExplicit := cmd.Flags().Changed("winrm-port") ||
		cmd.Flags().Changed("winrm-https") ||
		cmd.Flags().Changed("winrm-basic")

	var executor winrmclient.Executor
	var winrmCfg winrmclient.Config

	if transportExplicit {
		winrmCfg = winrmclient.Config{
			Host:     effectiveWinRMHost,
			Port:     winrmPort,
			Username: userID,
			Password: password,
			UseHTTPS: winrmHTTPS,
			UseBasic: winrmBasic,
			Timeout:  operationalTimeout,
		}
		client, err := winrmclient.New(winrmCfg)
		if err != nil {
			return fmt.Errorf("failed to create WinRM client: %w", err)
		}
		executor = client
	} else {
		log.Info("No WinRM transport flags specified, auto-discovering configuration")
		discoverCfg := winrmclient.DiscoverConfig{
			Host:     effectiveWinRMHost,
			Username: userID,
			Password: password,
			Timeout:  operationalTimeout,
		}
		client, discovered, err := winrmclient.Discover(cmd.Context(), discoverCfg, log)
		if err != nil {
			return fmt.Errorf("WinRM auto-discovery failed: %w", err)
		}
		executor = client
		winrmCfg = discovered
	}

	// Parse NT hash if provided
	var parsedNTHash []byte
	if ntHash != "" {
		var err error
		parsedNTHash, err = hex.DecodeString(ntHash)
		if err != nil || len(parsedNTHash) != 16 {
			return fmt.Errorf("--nt-hash must be exactly 32 hex characters (16 bytes)")
		}
	}

	// Use same credentials for EPA testing (NTLM auth)
	matrixCfg := &epamatrix.MatrixConfig{
		ServerInstance:        serverInstance,
		Domain:               strings.ToUpper(domain),
		LDAPUser:             userID,
		LDAPPassword:         password,
		NTHash:               parsedNTHash,
		Verbose:              verbose,
		Debug:                debug,
		SQLInstanceName:      sqlInstanceName,
		ServiceRestartWaitSec: serviceRestartWaitSec,
		PostRestartDelaySec:  postRestartDelaySec,
		SkipStrictEncryption: skipStrictEncryption,
		ProxyAddr:            proxyAddr,
		Logger:               logger,
	}

	totalCombos := 12
	if skipStrictEncryption {
		totalCombos = 6
	}

	authType := "NTLM"
	if winrmCfg.UseBasic {
		authType = "Basic"
	}

	log.Info("MSSQLHound EPA Matrix Test", "version", version)
	log.Info("Configuration",
		"winrm_host", fmt.Sprintf("%s:%d", winrmCfg.Host, winrmCfg.Port),
		"winrm_https", winrmCfg.UseHTTPS,
		"winrm_auth", authType,
		"sql_instance", sqlInstanceName,
		"combinations", totalCombos,
	)

	ctx := context.Background()
	results, runErr := epamatrix.RunMatrix(ctx, matrixCfg, executor)

	// Always print results table even if interrupted
	if len(results) > 0 {
		epamatrix.PrintResultsTable(os.Stdout, results)
		epamatrix.Summarize(os.Stdout, results)
	}

	return runErr
}

func extractHostname(serverInstance string) string {
	host := serverInstance
	// Strip instance name
	if idx := strings.Index(host, "\\"); idx != -1 {
		host = host[:idx]
	}
	// Strip port
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}
