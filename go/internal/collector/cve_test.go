package collector

import (
	"testing"
)

func TestParseSQLVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  *SQLVersion
		wantError bool
	}{
		{
			name:     "SQL Server 2019 full version",
			input:    "15.0.4435.7",
			expected: &SQLVersion{15, 0, 4435, 7},
		},
		{
			name:     "SQL Server 2022 version",
			input:    "16.0.4210.1",
			expected: &SQLVersion{16, 0, 4210, 1},
		},
		{
			name:     "Short version",
			input:    "15.0.4435",
			expected: &SQLVersion{15, 0, 4435, 0},
		},
		{
			name:     "Two part version",
			input:    "15.0",
			expected: &SQLVersion{15, 0, 0, 0},
		},
		{
			name:      "Empty string",
			input:     "",
			wantError: true,
		},
		{
			name:      "Invalid version",
			input:     "invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSQLVersion(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result.Major != tt.expected.Major || result.Minor != tt.expected.Minor ||
				result.Build != tt.expected.Build || result.Revision != tt.expected.Revision {
				t.Errorf("Expected %v but got %v", tt.expected, result)
			}
		})
	}
}

func TestSQLVersionCompare(t *testing.T) {
	tests := []struct {
		name     string
		v1       SQLVersion
		v2       SQLVersion
		expected int
	}{
		{
			name:     "Equal versions",
			v1:       SQLVersion{15, 0, 4435, 7},
			v2:       SQLVersion{15, 0, 4435, 7},
			expected: 0,
		},
		{
			name:     "v1 less than v2 (major)",
			v1:       SQLVersion{14, 0, 0, 0},
			v2:       SQLVersion{15, 0, 0, 0},
			expected: -1,
		},
		{
			name:     "v1 greater than v2 (minor)",
			v1:       SQLVersion{15, 1, 0, 0},
			v2:       SQLVersion{15, 0, 0, 0},
			expected: 1,
		},
		{
			name:     "v1 less than v2 (build)",
			v1:       SQLVersion{15, 0, 4435, 0},
			v2:       SQLVersion{15, 0, 4440, 0},
			expected: -1,
		},
		{
			name:     "v1 greater than v2 (revision)",
			v1:       SQLVersion{15, 0, 4435, 8},
			v2:       SQLVersion{15, 0, 4435, 7},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.v1.Compare(tt.v2)
			if result != tt.expected {
				t.Errorf("Expected %d but got %d", tt.expected, result)
			}
		})
	}
}

func TestCheckCVE202549758(t *testing.T) {
	tests := []struct {
		name          string
		versionNumber string
		fullVersion   string
		isVulnerable  bool
		isPatched     bool
	}{
		{
			name:          "SQL 2019 vulnerable version",
			versionNumber: "15.0.4435.7",
			isVulnerable:  true,
			isPatched:     false,
		},
		{
			name:          "SQL 2019 patched version",
			versionNumber: "15.0.4440.1",
			isVulnerable:  false,
			isPatched:     true,
		},
		{
			name:          "SQL 2022 vulnerable version",
			versionNumber: "16.0.4205.1",
			isVulnerable:  true,
			isPatched:     false,
		},
		{
			name:          "SQL 2022 patched version",
			versionNumber: "16.0.4210.1",
			isVulnerable:  false,
			isPatched:     true,
		},
		{
			name:          "SQL 2017 vulnerable version",
			versionNumber: "14.0.3495.9",
			isVulnerable:  true,
			isPatched:     false,
		},
		{
			name:          "SQL 2016 vulnerable version",
			versionNumber: "13.0.6460.7",
			isVulnerable:  true,
			isPatched:     false,
		},
		{
			name:          "SQL 2014 (pre-2016) - vulnerable",
			versionNumber: "12.0.5000.0",
			isVulnerable:  true,
			isPatched:     false,
		},
		{
			name:         "Full @@VERSION string",
			fullVersion:  "Microsoft SQL Server 2019 (RTM-CU32) (KB5029378) - 15.0.4435.7 (X64)",
			isVulnerable: true,
			isPatched:    false,
		},
		{
			name:          "Newer version not in affected ranges (assume patched)",
			versionNumber: "16.0.5000.0",
			isVulnerable:  false,
			isPatched:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckCVE202549758(tt.versionNumber, tt.fullVersion)
			if result == nil {
				t.Error("Expected result but got nil")
				return
			}
			if result.IsVulnerable != tt.isVulnerable {
				t.Errorf("IsVulnerable: expected %v but got %v", tt.isVulnerable, result.IsVulnerable)
			}
			if result.IsPatched != tt.isPatched {
				t.Errorf("IsPatched: expected %v but got %v", tt.isPatched, result.IsPatched)
			}
		})
	}
}

func TestIsVulnerableToCVE202549758(t *testing.T) {
	// Vulnerable version
	if !IsVulnerableToCVE202549758("15.0.4435.7", "") {
		t.Error("Expected 15.0.4435.7 to be vulnerable")
	}

	// Patched version
	if IsVulnerableToCVE202549758("15.0.4440.1", "") {
		t.Error("Expected 15.0.4440.1 to not be vulnerable")
	}

	// Empty version - should return false (assume not vulnerable)
	if IsVulnerableToCVE202549758("", "") {
		t.Error("Expected empty version to return false (not vulnerable)")
	}
}

func TestIsPatchedForCVE202549758(t *testing.T) {
	// Patched version
	if !IsPatchedForCVE202549758("15.0.4440.1", "") {
		t.Error("Expected 15.0.4440.1 to be patched")
	}

	// Vulnerable version
	if IsPatchedForCVE202549758("15.0.4435.7", "") {
		t.Error("Expected 15.0.4435.7 to not be patched")
	}

	// Empty version - should return true (assume patched to reduce false positives)
	if !IsPatchedForCVE202549758("", "") {
		t.Error("Expected empty version to return true (assume patched)")
	}
}

func TestExtractVersionFromFullVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard @@VERSION output",
			input:    "Microsoft SQL Server 2019 (RTM-CU32) (KB5029378) - 15.0.4435.7 (X64)",
			expected: "15.0.4435.7",
		},
		{
			name:     "SQL 2022 @@VERSION",
			input:    "Microsoft SQL Server 2022 (RTM-CU20-GDR) - 16.0.4210.1 (X64)",
			expected: "16.0.4210.1",
		},
		{
			name:     "Three part version",
			input:    "Microsoft SQL Server 2019 - 15.0.4435",
			expected: "15.0.4435",
		},
		{
			name:     "No version found",
			input:    "Invalid string",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractVersionFromFullVersion(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q but got %q", tt.expected, result)
			}
		})
	}
}
