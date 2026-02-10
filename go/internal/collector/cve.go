// Package collector provides CVE vulnerability checking for SQL Server.
package collector

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SQLVersion represents a parsed SQL Server version
type SQLVersion struct {
	Major    int
	Minor    int
	Build    int
	Revision int
}

// Compare compares two SQLVersions. Returns -1 if v < other, 0 if equal, 1 if v > other
func (v SQLVersion) Compare(other SQLVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Build != other.Build {
		if v.Build < other.Build {
			return -1
		}
		return 1
	}
	if v.Revision != other.Revision {
		if v.Revision < other.Revision {
			return -1
		}
		return 1
	}
	return 0
}

func (v SQLVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Build, v.Revision)
}

// LessThan returns true if v < other
func (v SQLVersion) LessThan(other SQLVersion) bool {
	return v.Compare(other) < 0
}

// LessThanOrEqual returns true if v <= other
func (v SQLVersion) LessThanOrEqual(other SQLVersion) bool {
	return v.Compare(other) <= 0
}

// GreaterThanOrEqual returns true if v >= other
func (v SQLVersion) GreaterThanOrEqual(other SQLVersion) bool {
	return v.Compare(other) >= 0
}

// SecurityUpdate represents a SQL Server security update for CVE-2025-49758
type SecurityUpdate struct {
	Name        string
	KB          string
	MinAffected SQLVersion
	MaxAffected SQLVersion
	PatchedAt   SQLVersion
}

// CVE202549758Updates contains the security updates that fix CVE-2025-49758
var CVE202549758Updates = []SecurityUpdate{
	// SQL Server 2022
	{
		Name:        "SQL 2022 CU20+GDR",
		KB:          "5063814",
		MinAffected: SQLVersion{16, 0, 4003, 1},
		MaxAffected: SQLVersion{16, 0, 4205, 1},
		PatchedAt:   SQLVersion{16, 0, 4210, 1},
	},
	{
		Name:        "SQL 2022 RTM+GDR",
		KB:          "5063756",
		MinAffected: SQLVersion{16, 0, 1000, 6},
		MaxAffected: SQLVersion{16, 0, 1140, 6},
		PatchedAt:   SQLVersion{16, 0, 1145, 1},
	},

	// SQL Server 2019
	{
		Name:        "SQL 2019 CU32+GDR",
		KB:          "5063757",
		MinAffected: SQLVersion{15, 0, 4003, 23},
		MaxAffected: SQLVersion{15, 0, 4435, 7},
		PatchedAt:   SQLVersion{15, 0, 4440, 1},
	},
	{
		Name:        "SQL 2019 RTM+GDR",
		KB:          "5063758",
		MinAffected: SQLVersion{15, 0, 2000, 5},
		MaxAffected: SQLVersion{15, 0, 2135, 5},
		PatchedAt:   SQLVersion{15, 0, 2140, 1},
	},

	// SQL Server 2017
	{
		Name:        "SQL 2017 CU31+GDR",
		KB:          "5063759",
		MinAffected: SQLVersion{14, 0, 3006, 16},
		MaxAffected: SQLVersion{14, 0, 3495, 9},
		PatchedAt:   SQLVersion{14, 0, 3500, 1},
	},
	{
		Name:        "SQL 2017 RTM+GDR",
		KB:          "5063760",
		MinAffected: SQLVersion{14, 0, 1000, 169},
		MaxAffected: SQLVersion{14, 0, 2075, 8},
		PatchedAt:   SQLVersion{14, 0, 2080, 1},
	},

	// SQL Server 2016
	{
		Name:        "SQL 2016 Azure Connect Feature Pack",
		KB:          "5063761",
		MinAffected: SQLVersion{13, 0, 7000, 253},
		MaxAffected: SQLVersion{13, 0, 7055, 9},
		PatchedAt:   SQLVersion{13, 0, 7060, 1},
	},
	{
		Name:        "SQL 2016 SP3 RTM+GDR",
		KB:          "5063762",
		MinAffected: SQLVersion{13, 0, 6300, 2},
		MaxAffected: SQLVersion{13, 0, 6460, 7},
		PatchedAt:   SQLVersion{13, 0, 6465, 1},
	},
}

// CVECheckResult holds the result of a CVE vulnerability check
type CVECheckResult struct {
	VersionDetected string
	IsVulnerable    bool
	IsPatched       bool
	UpdateName      string
	KB              string
	RequiredVersion string
}

// ParseSQLVersion parses a SQL Server version string (e.g., "15.0.2000.5") into SQLVersion
func ParseSQLVersion(versionStr string) (*SQLVersion, error) {
	// Clean up the version string
	versionStr = strings.TrimSpace(versionStr)
	if versionStr == "" {
		return nil, fmt.Errorf("empty version string")
	}

	// Split by dots
	parts := strings.Split(versionStr, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid version format: %s", versionStr)
	}

	v := &SQLVersion{}
	var err error

	// Parse major version
	v.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	// Parse minor version
	v.Minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	// Parse build number (optional)
	if len(parts) >= 3 {
		v.Build, err = strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid build version: %s", parts[2])
		}
	}

	// Parse revision (optional)
	if len(parts) >= 4 {
		v.Revision, err = strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid revision: %s", parts[3])
		}
	}

	return v, nil
}

// ExtractVersionFromFullVersion extracts numeric version from @@VERSION output
// e.g., "Microsoft SQL Server 2019 (RTM-CU32) ... - 15.0.4435.7 ..." -> "15.0.4435.7"
func ExtractVersionFromFullVersion(fullVersion string) string {
	// Try to find version pattern like "15.0.4435.7"
	re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(fullVersion)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Try simpler pattern like "15.0.4435"
	re = regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	matches = re.FindStringSubmatch(fullVersion)
	if len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// CheckCVE202549758 checks if a SQL Server version is vulnerable to CVE-2025-49758
// Reference: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-49758
func CheckCVE202549758(versionNumber string, fullVersion string) *CVECheckResult {
	// Try to get version from versionNumber first, then fullVersion
	versionStr := versionNumber
	if versionStr == "" && fullVersion != "" {
		versionStr = ExtractVersionFromFullVersion(fullVersion)
	}

	if versionStr == "" {
		return nil
	}

	sqlVersion, err := ParseSQLVersion(versionStr)
	if err != nil {
		return nil
	}

	result := &CVECheckResult{
		VersionDetected: sqlVersion.String(),
		IsVulnerable:    false,
		IsPatched:       false,
	}

	// Check if version is lower than SQL 2016 (version 13.x)
	// These versions are out of support and vulnerable
	sql2016Min := SQLVersion{13, 0, 0, 0}
	if sqlVersion.LessThan(sql2016Min) {
		result.IsVulnerable = true
		result.UpdateName = "SQL Server < 2016"
		result.KB = "N/A"
		result.RequiredVersion = "13.0.6300.2 (SQL 2016 SP3)"
		return result
	}

	// Check against each security update
	for _, update := range CVE202549758Updates {
		// Check if version is in the affected range
		if sqlVersion.GreaterThanOrEqual(update.MinAffected) && sqlVersion.LessThanOrEqual(update.MaxAffected) {
			// Version is in affected range - check if patched
			if sqlVersion.GreaterThanOrEqual(update.PatchedAt) {
				result.IsPatched = true
				result.UpdateName = update.Name
				result.KB = update.KB
				result.RequiredVersion = update.PatchedAt.String()
			} else {
				result.IsVulnerable = true
				result.UpdateName = update.Name
				result.KB = update.KB
				result.RequiredVersion = update.PatchedAt.String()
			}
			return result
		}
	}

	// Version not in any known affected range - assume patched (newer version)
	result.IsPatched = true
	return result
}

// IsVulnerableToCVE202549758 is a convenience function that returns true if the server is vulnerable
func IsVulnerableToCVE202549758(versionNumber string, fullVersion string) bool {
	result := CheckCVE202549758(versionNumber, fullVersion)
	if result == nil {
		// Unable to determine - assume not vulnerable to reduce false positives
		return false
	}
	return result.IsVulnerable
}

// IsPatchedForCVE202549758 is a convenience function that returns true if the server is patched
func IsPatchedForCVE202549758(versionNumber string, fullVersion string) bool {
	result := CheckCVE202549758(versionNumber, fullVersion)
	if result == nil {
		// Unable to determine - assume patched to reduce false positives
		return true
	}
	return result.IsPatched
}
