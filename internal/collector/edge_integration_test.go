//go:build integration

package collector

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
)

// =============================================================================
// INTEGRATION TEST FUNCTIONS
// =============================================================================

// TestIntegrationAll runs the full integration test flow: setup -> test -> coverage -> teardown.
func TestIntegrationAll(t *testing.T) {
	cfg := loadIntegrationConfig()

	switch strings.ToLower(cfg.Action) {
	case "setup":
		runSetup(t, cfg)
	case "test":
		runIntegrationEdgeTests(t, cfg)
	case "teardown":
		runTeardown(t, cfg)
	case "coverage":
		runIntegrationCoverage(t, cfg)
	case "validate":
		runValidateZip(t, cfg)
	case "all":
		t.Run("Setup", func(t *testing.T) {
			runSetup(t, cfg)
		})
		t.Run("Edges", func(t *testing.T) {
			runIntegrationEdgeTests(t, cfg)
		})
		t.Run("Coverage", func(t *testing.T) {
			runIntegrationCoverage(t, cfg)
		})
		if !t.Failed() {
			t.Run("Report", func(t *testing.T) {
				runIntegrationReport(t, cfg)
			})
		}
		t.Run("Teardown", func(t *testing.T) {
			runTeardown(t, cfg)
		})
	default:
		t.Fatalf("Unknown action: %s (valid: all, setup, test, teardown, coverage, validate)", cfg.Action)
	}
}

// TestIntegrationSetup runs only the setup phase.
func TestIntegrationSetup(t *testing.T) {
	cfg := loadIntegrationConfig()
	runSetup(t, cfg)
}

// TestIntegrationEdges runs only the edge validation phase (assumes setup was already done).
func TestIntegrationEdges(t *testing.T) {
	cfg := loadIntegrationConfig()
	runIntegrationEdgeTests(t, cfg)
}

// TestIntegrationCoverage runs only the coverage analysis phase.
func TestIntegrationCoverage(t *testing.T) {
	cfg := loadIntegrationConfig()
	runIntegrationCoverage(t, cfg)
}

// TestIntegrationTeardown runs only the teardown phase.
func TestIntegrationTeardown(t *testing.T) {
	cfg := loadIntegrationConfig()
	runTeardown(t, cfg)
}

// TestIntegrationValidateZip validates edges from an existing MSSQLHound .zip output file.
// Usage:
//
//	MSSQL_ZIP=/path/to/output.zip go test -tags integration -v -run TestIntegrationValidateZip
//	MSSQL_ZIP=/path/to/output.zip MSSQL_LIMIT_EDGE=MemberOf go test -tags integration -v -run TestIntegrationValidateZip
func TestIntegrationValidateZip(t *testing.T) {
	cfg := loadIntegrationConfig()
	runValidateZip(t, cfg)
}

// runValidateZip reads edges from a .zip file and validates them against test cases.
func runValidateZip(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	if cfg.ZipFile == "" {
		t.Fatal("MSSQL_ZIP environment variable must be set to a .zip file path")
	}

	edges, nodes, err := readBloodHoundZip(cfg.ZipFile)
	if err != nil {
		t.Fatalf("Failed to read zip file %s: %v", cfg.ZipFile, err)
	}

	t.Logf("Loaded %d edges and %d nodes from %s", len(edges), len(nodes), cfg.ZipFile)

	allTestCases := getAllTestCases()

	// Filter by edge type if specified
	if cfg.LimitToEdge != "" {
		var filtered []edgeTestCase
		for _, tc := range allTestCases {
			if strings.EqualFold(tc.EdgeType, cfg.LimitToEdge) ||
				strings.EqualFold(tc.EdgeType, "MSSQL_"+cfg.LimitToEdge) {
				filtered = append(filtered, tc)
			}
		}
		if len(filtered) == 0 {
			t.Fatalf("No test cases found for edge type %q", cfg.LimitToEdge)
		}
		allTestCases = filtered
	}

	var run integrationTestRun
	run.Edges = edges
	run.Nodes = nodes

	passed, failed := 0, 0
	for _, tc := range allTestCases {
		t.Run(tc.Description, func(t *testing.T) {
			result := integrationTestResult{TestCase: tc}
			ok := runSingleTestCaseWithResult(t, edges, tc)
			result.Passed = ok
			if ok {
				passed++
			} else {
				failed++
				result.Message = fmt.Sprintf("Failed: %s -> %s", tc.SourcePattern, tc.TargetPattern)
			}
			run.Results = append(run.Results, result)
		})
	}

	t.Logf("Results: %d passed, %d failed", passed, failed)

	// Store for coverage/report if desired
	storeTestRuns(t, []integrationTestRun{run})
}

// readBloodHoundZip extracts and reads all JSON files from a MSSQLHound .zip output.
func readBloodHoundZip(zipPath string) ([]bloodhound.Edge, []bloodhound.Node, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	var allEdges []bloodhound.Edge
	var allNodes []bloodhound.Node

	for _, f := range r.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("open %s in zip: %w", f.Name, err)
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("read %s in zip: %w", f.Name, err)
		}

		edges, nodes, err := parseBloodHoundJSON(data)
		if err != nil {
			continue // skip unparseable files
		}
		allEdges = append(allEdges, edges...)
		allNodes = append(allNodes, nodes...)
	}

	return allEdges, allNodes, nil
}

// parseBloodHoundJSON tries multiple BloodHound JSON formats:
// 1. Graph format: {"graph": {"nodes": [...], "edges": [...]}} (MSSQLHound output)
// 2. Data format: {"data": [...]} (OpenGraph ingest format)
// 3. Line-delimited JSON
func parseBloodHoundJSON(data []byte) ([]bloodhound.Edge, []bloodhound.Node, error) {
	// Strip UTF-8 BOM if present
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}

	// Try graph format (MSSQLHound output): {"graph": {"nodes": [...], "edges": [...]}}
	var graphDoc struct {
		Graph struct {
			Nodes []bloodhound.Node `json:"nodes"`
			Edges []bloodhound.Edge `json:"edges"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(data, &graphDoc); err == nil {
		if len(graphDoc.Graph.Nodes) > 0 || len(graphDoc.Graph.Edges) > 0 {
			return graphDoc.Graph.Edges, graphDoc.Graph.Nodes, nil
		}
	}

	// Try data format: {"data": [...]}
	var dataDoc struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &dataDoc); err == nil && len(dataDoc.Data) > 0 {
		var edges []bloodhound.Edge
		var nodes []bloodhound.Node
		for _, raw := range dataDoc.Data {
			var probe struct {
				Kind  string `json:"kind"`
				Start *struct{}  `json:"start"`
			}
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.Start != nil {
				var edge bloodhound.Edge
				if err := json.Unmarshal(raw, &edge); err == nil {
					edges = append(edges, edge)
				}
			} else if probe.Kind != "" {
				var node bloodhound.Node
				if err := json.Unmarshal(raw, &node); err == nil {
					nodes = append(nodes, node)
				}
			}
		}
		return edges, nodes, nil
	}

	// Try line-delimited format
	return readBloodHoundJSONLines(data)
}

// =============================================================================
// EDGE TESTING
// =============================================================================

// integrationTestRun holds results from a test run.
type integrationTestRun struct {
	Edges       []bloodhound.Edge
	Nodes       []bloodhound.Node
	OutputFile  string
	Results     []integrationTestResult
}

type integrationTestResult struct {
	TestCase edgeTestCase
	Passed   bool
	Message  string
}

// runIntegrationEdgeTests runs the MSSQLHound collector against a live SQL Server
// and validates the created edges against expected patterns.
func runIntegrationEdgeTests(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	run := runEnumerationAndValidate(t, cfg, true)

	// Store test runs for coverage/reporting
	storeTestRuns(t, []integrationTestRun{run})
}

// runEnumerationAndValidate runs the collector and validates edges against test case data.
func runEnumerationAndValidate(t *testing.T, cfg *integrationConfig, includeNontraversable bool) integrationTestRun {
	t.Helper()

	run := integrationTestRun{}

	// Run MSSQLHound enumeration
	tempDir := t.TempDir()
	collectorCfg := &Config{
		ServerInstance:             cfg.ServerInstance,
		UserID:                    cfg.EnumUserID,
		Password:                  cfg.EnumPassword,
		Domain:                    cfg.Domain,
		DC:                        cfg.DC,
		DNSResolver:               cfg.DC, // Use DC as DNS resolver when no explicit resolver is set
		LDAPUser:                  cfg.LDAPUser,
		LDAPPassword:              cfg.LDAPPassword,
		OutputFormat:              "BloodHound",
		TempDir:                   tempDir,
		Verbose:                   true,
		IncludeNontraversableEdges: includeNontraversable,
		SkipLinkedServerEnum:      false,
	}

	t.Logf("Running enumeration as %s (nontraversable: %v)...",
		cfg.EnumUserID, includeNontraversable)

	collector, err := New(collectorCfg)
	if err != nil {
		t.Fatalf("Failed to create collector: %v", err)
	}
	if err := collector.Run(); err != nil {
		t.Fatalf("Collector failed: %v", err)
	}

	// Find and read the BloodHound output file
	outputFiles, err := filepath.Glob(filepath.Join(tempDir, "*.json"))
	if err != nil || len(outputFiles) == 0 {
		t.Fatal("No BloodHound JSON output files found")
	}

	// Read edges and nodes from all output files
	for _, f := range outputFiles {
		edges, nodes, err := readBloodHoundJSON(f)
		if err != nil {
			t.Fatalf("Failed to read BloodHound output %s: %v", f, err)
		}
		run.Edges = append(run.Edges, edges...)
		run.Nodes = append(run.Nodes, nodes...)
	}

	t.Logf("Enumeration produced %d edges and %d nodes", len(run.Edges), len(run.Nodes))

	// Get all test cases
	allTestCases := getAllTestCases()

	// Filter by edge type if specified
	if cfg.LimitToEdge != "" {
		var filtered []edgeTestCase
		for _, tc := range allTestCases {
			if strings.EqualFold(tc.EdgeType, cfg.LimitToEdge) ||
				strings.EqualFold(tc.EdgeType, "MSSQL_"+cfg.LimitToEdge) {
				filtered = append(filtered, tc)
			}
		}
		allTestCases = filtered
	}

	// Run test cases
	for _, tc := range allTestCases {
		t.Run(tc.Description, func(t *testing.T) {
			result := integrationTestResult{TestCase: tc}
			passed := runSingleTestCaseWithResult(t, run.Edges, tc)
			result.Passed = passed
			if !passed {
				result.Message = fmt.Sprintf("Failed: %s -> %s", tc.SourcePattern, tc.TargetPattern)
			}
			run.Results = append(run.Results, result)
		})
	}

	return run
}

// getAllTestCases collects all test cases from the test data file.
func getAllTestCases() []edgeTestCase {
	var all []edgeTestCase
	all = append(all, addMemberTestCases...)
	all = append(all, alterTestCases...)
	all = append(all, alterAnyAppRoleTestCases...)
	all = append(all, alterAnyDBRoleTestCases...)
	all = append(all, alterAnyLoginTestCases...)
	all = append(all, alterAnyServerRoleTestCases...)
	all = append(all, changeOwnerTestCases...)
	all = append(all, changePasswordTestCases...)
	all = append(all, coerceAndRelayTestCases...)
	all = append(all, connectTestCases...)
	all = append(all, connectAnyDatabaseTestCases...)
	all = append(all, containsTestCases...)
	all = append(all, controlTestCases...)
	all = append(all, controlDBTestCases...)
	all = append(all, controlServerTestCases...)
	all = append(all, executeAsTestCases...)
	all = append(all, executeAsOwnerTestCases...)
	all = append(all, executeOnHostTestCases...)
	all = append(all, getAdminTGSTestCases...)
	all = append(all, getTGSTestCases...)
	all = append(all, grantAnyDBPermTestCases...)
	all = append(all, grantAnyPermTestCases...)
	all = append(all, hasDBScopedCredTestCases...)
	all = append(all, hasLoginTestCases...)
	all = append(all, hasMappedCredTestCases...)
	all = append(all, hasProxyCredTestCases...)
	all = append(all, impersonateTestCases...)
	all = append(all, impersonateAnyLoginTestCases...)
	all = append(all, isMappedToTestCases...)
	all = append(all, linkedAsAdminTestCases...)
	all = append(all, linkedToTestCases...)
	all = append(all, memberOfTestCases...)
	all = append(all, ownsTestCases...)
	all = append(all, serviceAccountForTestCases...)
	all = append(all, takeOwnershipTestCases...)
	return all
}

// runSingleTestCaseWithResult is like runSingleTestCase but returns pass/fail.
func runSingleTestCaseWithResult(t *testing.T, edges []bloodhound.Edge, tc edgeTestCase) bool {
	t.Helper()

	matching := findEdges(edges, tc.EdgeType, tc.SourcePattern, tc.TargetPattern)

	if tc.ExpectedCount > 0 {
		if len(matching) != tc.ExpectedCount {
			t.Errorf("Expected %d %s edges matching %s -> %s, got %d",
				tc.ExpectedCount, tc.EdgeType, tc.SourcePattern, tc.TargetPattern, len(matching))
			logActualEdgesOfType(t, edges, tc.EdgeType)
			return false
		}
		return true
	}

	if tc.Negative {
		if len(matching) > 0 {
			t.Errorf("Expected NO %s edge from %s to %s, but found %d:",
				tc.EdgeType, tc.SourcePattern, tc.TargetPattern, len(matching))
			for _, e := range matching {
				t.Errorf("  actual: %s -> %s", e.Start.Value, e.End.Value)
			}
			return false
		}
		return true
	}

	// Positive test case
	if len(matching) == 0 {
		t.Errorf("Expected %s edge from %s to %s, but none found",
			tc.EdgeType, tc.SourcePattern, tc.TargetPattern)
		logActualEdgesOfType(t, edges, tc.EdgeType)
		return false
	}

	// Check edge properties if specified
	if len(tc.EdgeProperties) > 0 {
		for _, edge := range matching {
			for propName, expectedValue := range tc.EdgeProperties {
				actualValue, exists := edge.Properties[propName]
				if !exists {
					t.Errorf("Edge property %q missing on %s -> %s",
						propName, edge.Start.Value, edge.End.Value)
					return false
				}
				if fmt.Sprintf("%v", actualValue) != fmt.Sprintf("%v", expectedValue) {
					t.Errorf("Edge property %q on %s -> %s: expected %v, got %v",
						propName, edge.Start.Value, edge.End.Value, expectedValue, actualValue)
					return false
				}
			}
		}
	}

	return true
}

// logActualEdgesOfType logs all edges of the given type to help diagnose failures.
func logActualEdgesOfType(t *testing.T, edges []bloodhound.Edge, edgeType string) {
	t.Helper()
	var actual []bloodhound.Edge
	for _, e := range edges {
		if e.Kind == edgeType {
			actual = append(actual, e)
		}
	}
	if len(actual) == 0 {
		t.Logf("  no %s edges exist in output", edgeType)
		return
	}
	t.Logf("  actual %s edges (%d total):", edgeType, len(actual))
	for _, e := range actual {
		if path, ok := e.Properties["path"].(string); ok && path != "" {
			t.Logf("    %s -> %s (path=%s)", e.Start.Value, e.End.Value, path)
		} else {
			t.Logf("    %s -> %s", e.Start.Value, e.End.Value)
		}
	}
}

// =============================================================================
// BLOODHOUND JSON READING
// =============================================================================

// readBloodHoundJSON reads edges and nodes from a BloodHound JSON file.
func readBloodHoundJSON(path string) ([]bloodhound.Edge, []bloodhound.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return parseBloodHoundJSON(data)
}

// readBloodHoundJSONLines reads line-delimited JSON format.
func readBloodHoundJSONLines(data []byte) ([]bloodhound.Edge, []bloodhound.Node, error) {
	var edges []bloodhound.Edge
	var nodes []bloodhound.Node

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" {
			continue
		}
		line = strings.TrimSuffix(line, ",")

		var probe struct {
			Kind      string `json:"kind"`
			StartNode string `json:"start_node"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			continue
		}

		if probe.StartNode != "" {
			var edge bloodhound.Edge
			if err := json.Unmarshal([]byte(line), &edge); err == nil {
				edges = append(edges, edge)
			}
		} else if probe.Kind != "" {
			var node bloodhound.Node
			if err := json.Unmarshal([]byte(line), &node); err == nil {
				nodes = append(nodes, node)
			}
		}
	}

	return edges, nodes, nil
}

// =============================================================================
// COVERAGE ANALYSIS
// =============================================================================

// runIntegrationCoverage analyzes which edge types were found in test runs.
func runIntegrationCoverage(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	testRuns := loadTestRuns(t)
	if len(testRuns) == 0 {
		t.Skip("No test runs found - run edges test first")
	}

	report := analyzeCoverage(testRuns)

	t.Logf("Edge Type Coverage Analysis:")
	t.Logf("========================================")

	missingCount := 0
	for _, entry := range report {
		status := entry.Status
		t.Logf("  %s: %s", entry.EdgeType, status)
		if status == "MISSING" {
			missingCount++
		}
	}

	t.Logf("========================================")
	t.Logf("Missing edge types: %d", missingCount)

	if missingCount > 0 {
		t.Errorf("%d edge types are missing from test results", missingCount)
	}
}

// =============================================================================
// TEST RUN STORAGE
// =============================================================================

var integrationTestRunsFile = ""

func storeTestRuns(t *testing.T, runs []integrationTestRun) {
	t.Helper()

	data, err := json.MarshalIndent(runs, "", "  ")
	if err != nil {
		t.Logf("Warning: Failed to marshal test runs: %v", err)
		return
	}

	file := filepath.Join(os.TempDir(), fmt.Sprintf("mssqlhound-integration-runs-%d.json", time.Now().Unix()))
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Logf("Warning: Failed to write test runs: %v", err)
		return
	}

	integrationTestRunsFile = file
	t.Logf("Test runs stored at: %s", file)
}

func loadTestRuns(t *testing.T) []integrationTestRun {
	t.Helper()

	if integrationTestRunsFile == "" {
		// Try to find the most recent runs file
		pattern := filepath.Join(os.TempDir(), "mssqlhound-integration-runs-*.json")
		files, err := filepath.Glob(pattern)
		if err != nil || len(files) == 0 {
			return nil
		}
		integrationTestRunsFile = files[len(files)-1]
	}

	data, err := os.ReadFile(integrationTestRunsFile)
	if err != nil {
		return nil
	}

	var runs []integrationTestRun
	if err := json.Unmarshal(data, &runs); err != nil {
		return nil
	}

	return runs
}
