//go:build integration

package collector

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/SpecterOps/MSSQLHound/internal/bloodhound"
)

// =============================================================================
// COVERAGE ANALYSIS (ports PS1 Get-EdgeCoverage)
// =============================================================================

// coverageEntry represents coverage status for a single edge type.
type coverageEntry struct {
	EdgeType string `json:"edgeType"`
	Found    bool   `json:"found"`
	Status   string `json:"status"`
}

// knownEdgeTypes lists all edge types that MSSQLHound can produce.
var knownEdgeTypes = []string{
	"CoerceAndRelayToMSSQL",
	"HasSession",
	"MSSQL_AddMember",
	"MSSQL_Alter",
	"MSSQL_AlterAnyAppRole",
	"MSSQL_AlterAnyDBRole",
	"MSSQL_AlterAnyLogin",
	"MSSQL_AlterAnyServerRole",
	"MSSQL_ChangeOwner",
	"MSSQL_ChangePassword",
	"MSSQL_Connect",
	"MSSQL_ConnectAnyDatabase",
	"MSSQL_Contains",
	"MSSQL_Control",
	"MSSQL_ControlDB",
	"MSSQL_ControlServer",
	"MSSQL_ExecuteAs",
	"MSSQL_ExecuteAsOwner",
	"MSSQL_ExecuteOnHost",
	"MSSQL_GetAdminTGS",
	"MSSQL_GetTGS",
	"MSSQL_GrantAnyDBPermission",
	"MSSQL_GrantAnyPermission",
	"MSSQL_HasDBScopedCred",
	"MSSQL_HasLogin",
	"MSSQL_HasMappedCred",
	"MSSQL_HasProxyCred",
	"MSSQL_HostFor",
	"MSSQL_Impersonate",
	"MSSQL_ImpersonateAnyLogin",
	"MSSQL_IsMappedTo",
	"MSSQL_IsTrustedBy",
	"MSSQL_LinkedAsAdmin",
	"MSSQL_LinkedTo",
	"MSSQL_MemberOf",
	"MSSQL_Owns",
	"MSSQL_ServiceAccountFor",
	"MSSQL_TakeOwnership",
}

func getAllEdgeTypes() []string {
	result := make([]string, len(knownEdgeTypes))
	copy(result, knownEdgeTypes)
	sort.Strings(result)
	return result
}

// analyzeCoverage analyzes which edge types were found in test runs.
func analyzeCoverage(runs []integrationTestRun) []coverageEntry {
	foundEdges := make(map[string]bool)

	for _, run := range runs {
		for _, edge := range run.Edges {
			foundEdges[edge.Kind] = true
		}
	}

	allEdgeTypes := getAllEdgeTypes()
	var report []coverageEntry

	for _, edgeType := range allEdgeTypes {
		found := foundEdges[edgeType]

		var status string
		if found {
			status = "Found"
		} else {
			status = "MISSING"
		}

		report = append(report, coverageEntry{
			EdgeType: edgeType,
			Found:    found,
			Status:   status,
		})
	}

	return report
}

// =============================================================================
// MISSING TESTS ANALYSIS (ports PS1 Get-MissingTests)
// =============================================================================

type missingTestsResult struct {
	EdgeTypesWithTests    []string `json:"edgeTypesWithTests"`
	EdgeTypesWithoutTests []string `json:"edgeTypesWithoutTests"`
	UnknownEdgeTypes      []string `json:"unknownEdgeTypes"`
}

func analyzeMissingTests() missingTestsResult {
	allTestCases := getAllTestCases()

	// Collect unique edge types that have test cases
	edgeTypesWithTests := make(map[string]bool)
	for _, tc := range allTestCases {
		edgeTypesWithTests[tc.EdgeType] = true
	}

	allEdgeTypes := getAllEdgeTypes()

	var withTests, withoutTests, unknown []string

	edgeTypeSet := make(map[string]bool)
	for _, e := range allEdgeTypes {
		edgeTypeSet[e] = true
	}

	for edgeType := range edgeTypesWithTests {
		if edgeTypeSet[edgeType] {
			withTests = append(withTests, edgeType)
		} else {
			unknown = append(unknown, edgeType)
		}
	}

	for _, edgeType := range allEdgeTypes {
		if !edgeTypesWithTests[edgeType] {
			withoutTests = append(withoutTests, edgeType)
		}
	}

	sort.Strings(withTests)
	sort.Strings(withoutTests)
	sort.Strings(unknown)

	return missingTestsResult{
		EdgeTypesWithTests:    withTests,
		EdgeTypesWithoutTests: withoutTests,
		UnknownEdgeTypes:      unknown,
	}
}

// =============================================================================
// REPORT GENERATION
// =============================================================================

// testReport is the JSON report structure.
type testReport struct {
	Timestamp      time.Time            `json:"timestamp"`
	ServerInstance string               `json:"serverInstance"`
	Domain         string               `json:"domain"`
	TestRuns       []testRunSummary     `json:"testRuns"`
	Coverage       []coverageEntry      `json:"coverage"`
	MissingTests   missingTestsResult   `json:"missingTests"`
	Summary        testReportSummary    `json:"summary"`
}

type testRunSummary struct {
	TotalTests  int    `json:"totalTests"`
	Passed      int    `json:"passed"`
	Failed      int    `json:"failed"`
	PassRate    string `json:"passRate"`
	EdgeCount   int    `json:"edgeCount"`
	NodeCount   int    `json:"nodeCount"`
}

type testReportSummary struct {
	TotalEdgeTypes    int `json:"totalEdgeTypes"`
	CoveredEdgeTypes  int `json:"coveredEdgeTypes"`
	MissingEdgeTypes  int `json:"missingEdgeTypes"`
	TotalTests        int `json:"totalTests"`
	TotalPassed       int `json:"totalPassed"`
	TotalFailed       int `json:"totalFailed"`
}

// runIntegrationReport generates JSON and HTML reports.
func runIntegrationReport(t *testing.T, cfg *integrationConfig) {
	t.Helper()

	testRuns := loadTestRuns(t)
	if len(testRuns) == 0 {
		t.Skip("No test runs found - run edges test first")
	}

	coverage := analyzeCoverage(testRuns)
	missingTests := analyzeMissingTests()

	// Build report
	report := testReport{
		Timestamp:      time.Now(),
		ServerInstance: cfg.ServerInstance,
		Domain:         cfg.Domain,
		Coverage:       coverage,
		MissingTests:   missingTests,
	}

	totalTests := 0
	totalPassed := 0
	totalFailed := 0

	for _, run := range testRuns {
		passed := 0
		failed := 0
		for _, result := range run.Results {
			if result.Passed {
				passed++
			} else {
				failed++
			}
		}

		total := passed + failed
		passRate := "0%"
		if total > 0 {
			passRate = fmt.Sprintf("%.1f%%", float64(passed)/float64(total)*100)
		}

		report.TestRuns = append(report.TestRuns, testRunSummary{
			TotalTests:  total,
			Passed:      passed,
			Failed:      failed,
			PassRate:    passRate,
			EdgeCount:   len(run.Edges),
			NodeCount:   len(run.Nodes),
		})

		totalTests += total
		totalPassed += passed
		totalFailed += failed
	}

	coveredCount := 0
	missingCount := 0
	for _, entry := range coverage {
		if entry.Status == "MISSING" {
			missingCount++
		} else if entry.Status != "Not Tested" && !strings.HasPrefix(entry.Status, "N/A") {
			coveredCount++
		}
	}

	report.Summary = testReportSummary{
		TotalEdgeTypes:   len(getAllEdgeTypes()),
		CoveredEdgeTypes: coveredCount,
		MissingEdgeTypes: missingCount,
		TotalTests:       totalTests,
		TotalPassed:      totalPassed,
		TotalFailed:      totalFailed,
	}

	// Generate JSON report
	outputDir := filepath.Join(os.TempDir(), "mssqlhound-reports")
	os.MkdirAll(outputDir, 0755)

	jsonPath := filepath.Join(outputDir,
		fmt.Sprintf("integration-report-%s.json", time.Now().Format("20060102-150405")))
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(jsonPath, jsonData, 0644)
	t.Logf("JSON report: %s", jsonPath)

	// Generate HTML report
	if !cfg.SkipHTMLReport {
		htmlPath := filepath.Join(outputDir,
			fmt.Sprintf("integration-report-%s.html", time.Now().Format("20060102-150405")))
		if err := generateHTMLReport(report, htmlPath); err != nil {
			t.Logf("Warning: Failed to generate HTML report: %v", err)
		} else {
			t.Logf("HTML report: %s", htmlPath)
		}
	}
}

// =============================================================================
// HTML REPORT (ports PS1 Generate-HTMLReport)
// =============================================================================

func generateHTMLReport(report testReport, path string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"statusColor": func(status string) string {
			switch {
			case strings.Contains(status, "Expected") || strings.HasPrefix(status, "Found"):
				return "#28a745"
			case status == "MISSING":
				return "#dc3545"
			case strings.HasPrefix(status, "Partial"):
				return "#ffc107"
			default:
				return "#6c757d"
			}
		},
		"resultColor": func(passed bool) string {
			if passed {
				return "#28a745"
			}
			return "#dc3545"
		},
	}).Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, report)
}

// edgeKindDisplayName returns a display-friendly name for an edge type.
func edgeKindDisplayName(kind string) string {
	return strings.TrimPrefix(kind, "MSSQL_")
}

var htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSSQLHound Integration Test Report</title>
    <style>
        :root {
            --primary: #6f42c1;
            --success: #28a745;
            --danger: #dc3545;
            --warning: #ffc107;
            --info: #17a2b8;
            --secondary: #6c757d;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header {
            background: linear-gradient(135deg, var(--primary), #3f51b5);
            color: white; padding: 2rem; text-align: center;
        }
        .header h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
        .header p { opacity: 0.9; }
        .container { max-width: 1200px; margin: 0 auto; padding: 1rem; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }
        .card {
            background: white; border-radius: 8px; padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;
        }
        .card h3 { font-size: 2rem; margin-bottom: 0.25rem; }
        .card p { color: var(--secondary); font-size: 0.9rem; }
        .section { background: white; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { font-size: 1.3rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #eee; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f1f3f5; padding: 0.75rem; text-align: left; font-weight: 600; }
        td { padding: 0.75rem; border-bottom: 1px solid #eee; }
        .badge {
            display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px;
            font-size: 0.8rem; font-weight: 500; color: white;
        }
        .coverage-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 0.5rem; }
        .coverage-item {
            padding: 0.5rem 0.75rem; border-radius: 4px; font-size: 0.85rem;
            border-left: 4px solid; background: #f8f9fa;
        }
        .pass { color: var(--success); }
        .fail { color: var(--danger); }
    </style>
</head>
<body>
<div class="header">
    <h1>MSSQLHound Integration Test Report</h1>
    <p>Server: {{.ServerInstance}} | Domain: {{.Domain}} | {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
</div>
<div class="container">
    <div class="cards">
        <div class="card">
            <h3>{{.Summary.TotalTests}}</h3>
            <p>Total Tests</p>
        </div>
        <div class="card">
            <h3 class="pass">{{.Summary.TotalPassed}}</h3>
            <p>Passed</p>
        </div>
        <div class="card">
            <h3 class="fail">{{.Summary.TotalFailed}}</h3>
            <p>Failed</p>
        </div>
        <div class="card">
            <h3>{{.Summary.CoveredEdgeTypes}}/{{.Summary.TotalEdgeTypes}}</h3>
            <p>Edge Types Covered</p>
        </div>
    </div>

    {{range .TestRuns}}
    <div class="section">
        <h2>Test Run</h2>
        <p>{{.TotalTests}} tests | {{.Passed}} passed | {{.Failed}} failed | {{.PassRate}} pass rate | {{.EdgeCount}} edges | {{.NodeCount}} nodes</p>
    </div>
    {{end}}

    <div class="section">
        <h2>Edge Type Coverage</h2>
        <div class="coverage-grid">
            {{range .Coverage}}
            <div class="coverage-item" style="border-color: {{statusColor .Status}}">
                <strong>{{.EdgeType}}</strong><br>
                <span style="color: {{statusColor .Status}}">{{.Status}}</span>
            </div>
            {{end}}
        </div>
    </div>

    {{if .MissingTests.EdgeTypesWithoutTests}}
    <div class="section">
        <h2>Edge Types Without Tests</h2>
        <ul>
            {{range .MissingTests.EdgeTypesWithoutTests}}
            <li>{{.}}</li>
            {{end}}
        </ul>
    </div>
    {{end}}
</div>
</body>
</html>
`

// Ensure bloodhound types are used (they're referenced in integrationTestRun)
var _ = bloodhound.Edge{}
