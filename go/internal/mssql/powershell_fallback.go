// Package mssql provides SQL Server connection and data collection functionality.
package mssql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// extractPowerShellError extracts the meaningful error message from PowerShell stderr output
// PowerShell stderr includes the full script and verbose error info - we just want the exception message
func extractPowerShellError(stderr string) string {
	// Look for the exception message pattern from Write-Error output
	// Example: 'Exception calling "Open" with "0" argument(s): "Login failed for user 'AD005\Z004HYMU-A01'."'

	// Try to find the actual exception message
	if idx := strings.Index(stderr, "Exception calling"); idx != -1 {
		// Extract from "Exception calling" to the end of that line or next major section
		rest := stderr[idx:]
		// Find the quoted error message
		re := regexp.MustCompile(`"([^"]+)"[^"]*$`)
		if matches := re.FindStringSubmatch(strings.Split(rest, "\n")[0]); len(matches) > 1 {
			return matches[1]
		}
		// Just return the first line
		if nlIdx := strings.Index(rest, "\n"); nlIdx != -1 {
			return strings.TrimSpace(rest[:nlIdx])
		}
		return strings.TrimSpace(rest)
	}

	// Look for common SQL error patterns
	if idx := strings.Index(stderr, "Login failed"); idx != -1 {
		rest := stderr[idx:]
		if nlIdx := strings.Index(rest, "\n"); nlIdx != -1 {
			return strings.TrimSpace(rest[:nlIdx])
		}
		return strings.TrimSpace(rest)
	}

	// Fallback: return first non-empty line that doesn't look like script content
	lines := strings.Split(stderr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip lines that look like script content
		if strings.HasPrefix(line, "$") || strings.HasPrefix(line, "try") ||
			strings.HasPrefix(line, "}") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "if") || strings.HasPrefix(line, "foreach") {
			continue
		}
		return line
	}

	return strings.TrimSpace(stderr)
}

// PowerShellClient provides SQL Server connectivity using PowerShell and System.Data.SqlClient
// as a fallback when go-mssqldb fails with SSPI/Kerberos authentication issues.
type PowerShellClient struct {
	serverInstance string
	hostname       string
	port           int
	instanceName   string
	userID         string
	password       string
	useWindowsAuth bool
	verbose        bool
}

// NewPowerShellClient creates a new PowerShell-based SQL client
func NewPowerShellClient(serverInstance, userID, password string) *PowerShellClient {
	hostname, port, instanceName := parseServerInstance(serverInstance)

	return &PowerShellClient{
		serverInstance: serverInstance,
		hostname:       hostname,
		port:           port,
		instanceName:   instanceName,
		userID:         userID,
		password:       password,
		useWindowsAuth: userID == "" && password == "",
	}
}

// SetVerbose enables or disables verbose logging
func (p *PowerShellClient) SetVerbose(verbose bool) {
	p.verbose = verbose
}

// logVerbose logs a message only if verbose mode is enabled
func (p *PowerShellClient) logVerbose(format string, args ...interface{}) {
	if p.verbose {
		fmt.Printf(format+"\n", args...)
	}
}

// buildConnectionString creates the .NET SqlClient connection string
func (p *PowerShellClient) buildConnectionString() string {
	var parts []string

	// Build server string
	server := p.hostname
	if p.instanceName != "" {
		server = fmt.Sprintf("%s\\%s", p.hostname, p.instanceName)
	} else if p.port > 0 && p.port != 1433 {
		server = fmt.Sprintf("%s,%d", p.hostname, p.port)
	}
	parts = append(parts, fmt.Sprintf("Server=%s", server))

	if p.useWindowsAuth {
		parts = append(parts, "Integrated Security=True")
	} else {
		parts = append(parts, fmt.Sprintf("User Id=%s", p.userID))
		parts = append(parts, fmt.Sprintf("Password=%s", p.password))
	}

	parts = append(parts, "TrustServerCertificate=True")
	parts = append(parts, "Application Name=MSSQLHound")

	return strings.Join(parts, ";")
}

// TestConnection tests if PowerShell can connect to the server
func (p *PowerShellClient) TestConnection(ctx context.Context) error {
	query := "SELECT 1 AS test"
	_, err := p.ExecuteQuery(ctx, query)
	return err
}

// QueryResult represents a row of query results
type QueryResult map[string]interface{}

// QueryResponse includes both results and column order
type QueryResponse struct {
	Columns []string      `json:"columns"`
	Rows    []QueryResult `json:"rows"`
}

// ExecuteQuery executes a SQL query using PowerShell and returns the results as JSON
func (p *PowerShellClient) ExecuteQuery(ctx context.Context, query string) (*QueryResponse, error) {
	connStr := p.buildConnectionString()

	// PowerShell script that executes the query and returns JSON with column order preserved
	// Note: The SQL query is placed in a here-string (@' ... '@) which preserves
	// content literally - no escaping needed. Only the connection string needs escaping.
	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
try {
    $conn = New-Object System.Data.SqlClient.SqlConnection
    $conn.ConnectionString = '%s'
    $conn.Open()
    
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = @'
%s
'@
    $cmd.CommandTimeout = 120
    
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $dataset = New-Object System.Data.DataSet
    [void]$adapter.Fill($dataset)
    
    $response = @{
        columns = @()
        rows = @()
    }
    
    if ($dataset.Tables.Count -gt 0) {
        # Get column names in order
        foreach ($col in $dataset.Tables[0].Columns) {
            $response.columns += $col.ColumnName
        }
        
        foreach ($row in $dataset.Tables[0].Rows) {
            $obj = @{}
            foreach ($col in $dataset.Tables[0].Columns) {
                $val = $row[$col.ColumnName]
                if ($val -is [DBNull]) {
                    $obj[$col.ColumnName] = $null
                } elseif ($val -is [byte[]]) {
                    $obj[$col.ColumnName] = "0x" + [BitConverter]::ToString($val).Replace("-", "")
                } else {
                    $obj[$col.ColumnName] = $val
                }
            }
            $response.rows += $obj
        }
    }
    
    $conn.Close()
    $response | ConvertTo-Json -Depth 10 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, strings.ReplaceAll(connStr, "'", "''"), query)

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		errMsg := extractPowerShellError(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("PowerShell: %s", errMsg)
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" || output == "null" {
		return &QueryResponse{Columns: []string{}, Rows: []QueryResult{}}, nil
	}

	// Parse JSON result - now expects {columns: [...], rows: [...]}
	var response QueryResponse
	err = json.Unmarshal([]byte(output), &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PowerShell output: %w", err)
	}

	return &response, nil
}

// ExecuteScalar executes a query and returns a single value
func (p *PowerShellClient) ExecuteScalar(ctx context.Context, query string) (interface{}, error) {
	response, err := p.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(response.Rows) == 0 || len(response.Columns) == 0 {
		return nil, nil
	}
	// Return first column of first row (using column order)
	firstCol := response.Columns[0]
	return response.Rows[0][firstCol], nil
}

// GetString helper to get string value from QueryResult
func (r QueryResult) GetString(key string) string {
	if v, ok := r[key]; ok && v != nil {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%.0f", val)
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}

// GetInt helper to get int value from QueryResult
func (r QueryResult) GetInt(key string) int {
	if v, ok := r[key]; ok && v != nil {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		case int64:
			return int(val)
		case string:
			i, _ := fmt.Sscanf(val, "%d", new(int))
			return i
		}
	}
	return 0
}

// GetBool helper to get bool value from QueryResult
func (r QueryResult) GetBool(key string) bool {
	if v, ok := r[key]; ok && v != nil {
		switch val := v.(type) {
		case bool:
			return val
		case float64:
			return val != 0
		case int:
			return val != 0
		case string:
			return strings.ToLower(val) == "true" || val == "1"
		}
	}
	return false
}

// IsUntrustedDomainError checks if the error is the "untrusted domain" SSPI error
func IsUntrustedDomainError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "untrusted domain") ||
		strings.Contains(errStr, "cannot be used with windows authentication") ||
		strings.Contains(errStr, "cannot be used with integrated authentication")
}
