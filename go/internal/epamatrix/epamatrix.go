// Package epamatrix orchestrates EPA test matrix runs by configuring SQL Server
// settings via WinRM, restarting the service, and running EPA detection for each
// combination of Force Encryption, Force Strict Encryption, and Extended Protection.
package epamatrix

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/mssql"
	"github.com/SpecterOps/MSSQLHound/internal/proxydialer"
	"github.com/SpecterOps/MSSQLHound/internal/winrmclient"
)

// MatrixConfig holds parameters for the EPA matrix test.
type MatrixConfig struct {
	ServerInstance string
	Domain         string
	LDAPUser       string
	LDAPPassword   string
	Verbose        bool
	Debug          bool

	SQLInstanceName       string // default "MSSQLSERVER"
	ServiceRestartWaitSec int    // default 60
	PostRestartDelaySec   int    // default 5
	SkipStrictEncryption  bool   // for pre-SQL Server 2022

	ProxyAddr string
}

// MatrixResult holds one row of the output table.
type MatrixResult struct {
	Index                 int
	ForceEncryption       int
	ForceStrictEncryption int
	ExtendedProtection    int
	EPAResult             *mssql.EPATestResult
	Verdict               string
	Error                 error
}

// RunMatrix executes the full EPA test matrix.
func RunMatrix(ctx context.Context, cfg *MatrixConfig, executor winrmclient.Executor) ([]MatrixResult, error) {
	// Set defaults
	if cfg.SQLInstanceName == "" {
		cfg.SQLInstanceName = "MSSQLSERVER"
	}
	if cfg.ServiceRestartWaitSec == 0 {
		cfg.ServiceRestartWaitSec = 60
	}
	if cfg.PostRestartDelaySec == 0 {
		cfg.PostRestartDelaySec = 5
	}

	// Step 1: Detect instance registry path
	fmt.Println("Detecting SQL Server instance registry path...")
	instanceInfo, err := detectInstance(ctx, executor, cfg.SQLInstanceName)
	if err != nil {
		return nil, fmt.Errorf("instance detection failed: %w", err)
	}
	fmt.Printf("  Instance: %s\n", instanceInfo.RegistryRoot)
	fmt.Printf("  Registry: %s\n", instanceInfo.RegistryPath)
	fmt.Printf("  Service:  %s\n", instanceInfo.ServiceName)

	// Step 2: Read and save original settings
	fmt.Println("\nReading current settings...")
	originalSettings, err := readSettings(ctx, executor, instanceInfo.RegistryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read current settings: %w", err)
	}
	fmt.Printf("  ForceEncryption:       %d\n", originalSettings.ForceEncryption)
	fmt.Printf("  ForceStrictEncryption: %d\n", originalSettings.ForceStrictEncryption)
	fmt.Printf("  ExtendedProtection:    %d (%s)\n", originalSettings.ExtendedProtection, epIntToLabel(originalSettings.ExtendedProtection))

	// Step 3: Set up signal handler for restore on interrupt
	sigCtx, sigCancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer sigCancel()

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		fmt.Println("\nRestoring original SQL Server settings...")
		script := BuildWriteSettingsScript(instanceInfo.RegistryPath, *originalSettings)
		_, _, restoreErr := executor.RunPowerShell(context.Background(), script)
		if restoreErr != nil {
			fmt.Printf("WARNING: Failed to restore settings: %v\n", restoreErr)
			fmt.Printf("Manual restore needed at %s:\n", instanceInfo.RegistryPath)
			fmt.Printf("  ForceEncryption=%d, ForceStrictEncryption=%d, ExtendedProtection=%d\n",
				originalSettings.ForceEncryption, originalSettings.ForceStrictEncryption,
				originalSettings.ExtendedProtection)
			return
		}
		restartScript := BuildRestartServiceScript(instanceInfo.ServiceName, cfg.ServiceRestartWaitSec)
		_, _, _ = executor.RunPowerShell(context.Background(), restartScript)
		fmt.Println("Original settings restored successfully.")
	}
	defer restore()

	// Step 4: Build proxy dialer if configured
	var pd proxydialer.ContextDialer
	if cfg.ProxyAddr != "" {
		pd, err = proxydialer.New(cfg.ProxyAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}
	}

	// Step 5: Run matrix
	combos := allCombinations(cfg.SkipStrictEncryption)
	var results []MatrixResult

	// Extract host:port for TCP readiness checks
	sqlHost, sqlPort := extractHostPort(cfg.ServerInstance)

	fmt.Printf("\nRunning %d EPA test combinations...\n", len(combos))

	for i, combo := range combos {
		// Check for interruption
		select {
		case <-sigCtx.Done():
			fmt.Printf("\nInterrupted after %d/%d combinations.\n", i, len(combos))
			return results, fmt.Errorf("interrupted by signal")
		default:
		}

		epLabel := epIntToLabel(combo.ExtendedProtection)
		fmt.Printf("\n[%d/%d] ForceEncryption=%s, ForceStrictEncryption=%s, ExtendedProtection=%s\n",
			i+1, len(combos),
			intToYesNo(combo.ForceEncryption),
			intToYesNo(combo.ForceStrictEncryption),
			epLabel,
		)

		result := MatrixResult{
			Index:                 i + 1,
			ForceEncryption:       combo.ForceEncryption,
			ForceStrictEncryption: combo.ForceStrictEncryption,
			ExtendedProtection:    combo.ExtendedProtection,
		}

		// a. Write settings
		writeScript := BuildWriteSettingsScript(instanceInfo.RegistryPath, combo)
		if _, _, writeErr := executor.RunPowerShell(sigCtx, writeScript); writeErr != nil {
			result.Error = fmt.Errorf("write settings: %w", writeErr)
			result.Verdict = fmt.Sprintf("Error: write settings failed")
			results = append(results, result)
			fmt.Printf("  ERROR: %v\n", writeErr)
			continue
		}
		fmt.Println("  Registry updated")

		// b. Restart service
		restartScript := BuildRestartServiceScript(instanceInfo.ServiceName, cfg.ServiceRestartWaitSec)
		if _, _, restartErr := executor.RunPowerShell(sigCtx, restartScript); restartErr != nil {
			result.Error = fmt.Errorf("restart service: %w", restartErr)
			result.Verdict = "Error: service restart failed"
			results = append(results, result)
			fmt.Printf("  ERROR: service restart failed: %v\n", restartErr)
			continue
		}
		fmt.Println("  Service restarted")

		// c. Wait for SQL Server to be ready (TCP port reachable)
		if waitErr := waitForPort(sigCtx, sqlHost, sqlPort, cfg.PostRestartDelaySec); waitErr != nil {
			result.Error = fmt.Errorf("port readiness: %w", waitErr)
			result.Verdict = "Error: SQL Server port not reachable"
			results = append(results, result)
			fmt.Printf("  ERROR: port not reachable: %v\n", waitErr)
			continue
		}
		fmt.Println("  SQL Server port reachable")

		// d. Create client and run TestEPA
		client := mssql.NewClient(cfg.ServerInstance, "", "")
		client.SetDomain(cfg.Domain)
		client.SetLDAPCredentials(cfg.LDAPUser, cfg.LDAPPassword)
		client.SetVerbose(cfg.Verbose)
		client.SetDebug(cfg.Debug)
		if pd != nil {
			client.SetProxyDialer(pd)
		}

		epaResult, epaErr := client.TestEPA(sigCtx)
		if epaErr != nil {
			result.Error = epaErr
			if mssql.IsEPAPrereqError(epaErr) {
				result.Verdict = fmt.Sprintf("Error: EPA prereq failed - %v", epaErr)
			} else {
				result.Verdict = fmt.Sprintf("Error: %v", epaErr)
			}
			fmt.Printf("  EPA test error: %v\n", epaErr)
		} else {
			result.EPAResult = epaResult
			expected := expectedEPAStatus(combo)
			result.Verdict = computeVerdict(expected, epaResult)
			fmt.Printf("  Detected: %s (expected: %s) -> %s\n", epaResult.EPAStatus, expected, result.Verdict)
		}

		results = append(results, result)
	}

	return results, nil
}

// allCombinations returns the test matrix (12 or 6 combinations).
func allCombinations(skipStrict bool) []RegistrySettings {
	var combos []RegistrySettings
	for _, fe := range []int{0, 1} {
		for _, fse := range []int{0, 1} {
			if skipStrict && fse == 1 {
				continue
			}
			for _, ep := range []int{0, 1, 2} {
				combos = append(combos, RegistrySettings{
					ForceEncryption:       fe,
					ForceStrictEncryption: fse,
					ExtendedProtection:    ep,
				})
			}
		}
	}
	return combos
}

func expectedEPAStatus(settings RegistrySettings) string {
	switch settings.ExtendedProtection {
	case 0:
		return "Off"
	case 1:
		return "Allowed"
	case 2:
		return "Required"
	default:
		return "Unknown"
	}
}

func computeVerdict(expected string, actual *mssql.EPATestResult) string {
	if actual == nil {
		return "Error"
	}
	if actual.EPAStatus == expected {
		return "Correct"
	}
	return fmt.Sprintf("Incorrect - detected %s, expected %s", actual.EPAStatus, expected)
}

func detectInstance(ctx context.Context, executor winrmclient.Executor, instanceName string) (*SQLInstanceInfo, error) {
	script := BuildDetectInstanceScript(instanceName)
	stdout, _, err := executor.RunPowerShell(ctx, script)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(strings.TrimSpace(stdout), "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("unexpected detection output: %q", stdout)
	}

	return &SQLInstanceInfo{
		InstanceName: instanceName,
		RegistryRoot: parts[0],
		RegistryPath: parts[1],
		ServiceName:  parts[2],
	}, nil
}

func readSettings(ctx context.Context, executor winrmclient.Executor, registryPath string) (*RegistrySettings, error) {
	script := BuildReadSettingsScript(registryPath)
	stdout, _, err := executor.RunPowerShell(ctx, script)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(strings.TrimSpace(stdout), "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("unexpected settings output: %q", stdout)
	}

	fe, err1 := strconv.Atoi(parts[0])
	fse, err2 := strconv.Atoi(parts[1])
	ep, err3 := strconv.Atoi(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}

	return &RegistrySettings{
		ForceEncryption:       fe,
		ForceStrictEncryption: fse,
		ExtendedProtection:    ep,
	}, nil
}

func extractHostPort(serverInstance string) (string, string) {
	host := serverInstance
	port := "1433"

	// Strip instance name (host\instance or host\instance:port)
	if idx := strings.Index(host, "\\"); idx != -1 {
		host = host[:idx]
	}
	// Extract port
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}
	return host, port
}

func waitForPort(ctx context.Context, host, port string, extraDelaySec int) error {
	addr := net.JoinHostPort(host, port)
	for attempt := 0; attempt < 6; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			conn.Close()
			// Extra delay for SQL Server to fully initialize after port is open
			if extraDelaySec > 0 {
				time.Sleep(time.Duration(extraDelaySec) * time.Second)
			}
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("port %s not reachable after 30 seconds", addr)
}
