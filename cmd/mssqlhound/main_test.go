package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyTarget(t *testing.T) {
	// Create a temp file to test file detection
	tmpDir := t.TempDir()
	serverFile := filepath.Join(tmpDir, "servers.txt")
	if err := os.WriteFile(serverFile, []byte("host1\nhost2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		input            string
		wantInstance     string
		wantListFile     string
		wantList         string
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:         "single hostname",
			input:        "sqlserver1",
			wantInstance: "sqlserver1",
		},
		{
			name:         "hostname with port (colon)",
			input:        "sqlserver1:1433",
			wantInstance: "sqlserver1:1433",
		},
		{
			name:         "hostname with named instance",
			input:        "sqlserver1\\SQLEXPRESS",
			wantInstance: "sqlserver1\\SQLEXPRESS",
		},
		{
			name:         "SPN format",
			input:        "MSSQLSvc/sqlserver1.domain.com:1433",
			wantInstance: "MSSQLSvc/sqlserver1.domain.com:1433",
		},
		{
			name:         "SPN format with instance name",
			input:        "MSSQLSvc/sqlserver1.domain.com:SQLEXPRESS",
			wantInstance: "MSSQLSvc/sqlserver1.domain.com:SQLEXPRESS",
		},
		{
			name:         "FQDN",
			input:        "sqlserver1.domain.com",
			wantInstance: "sqlserver1.domain.com",
		},
		{
			name:         "FQDN with port",
			input:        "sqlserver1.domain.com:1434",
			wantInstance: "sqlserver1.domain.com:1434",
		},
		{
			name:     "comma-separated list",
			input:    "host1,host2,host3",
			wantList: "host1,host2,host3",
		},
		{
			name:     "comma-separated with ports",
			input:    "host1:1433,host2:1434",
			wantList: "host1:1433,host2:1434",
		},
		{
			name:         "file path",
			input:        serverFile,
			wantListFile: serverFile,
		},
		{
			name:         "non-existent file path treated as hostname",
			input:        "/no/such/file.txt",
			wantInstance: "/no/such/file.txt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotInstance, gotListFile, gotList := classifyTarget(tc.input)
			if gotInstance != tc.wantInstance {
				t.Errorf("instance: got %q, want %q", gotInstance, tc.wantInstance)
			}
			if gotListFile != tc.wantListFile {
				t.Errorf("listFile: got %q, want %q", gotListFile, tc.wantListFile)
			}
			if gotList != tc.wantList {
				t.Errorf("list: got %q, want %q", gotList, tc.wantList)
			}
		})
	}
}

func TestExtractTargetCredentials(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantUser   string
		wantPass   string
		wantTarget string
		wantOK     bool
	}{
		{
			name:       "simple hostname",
			input:      "sa:password@sqlserver1",
			wantUser:   "sa",
			wantPass:   "password",
			wantTarget: "sqlserver1",
			wantOK:     true,
		},
		{
			name:       "hostname with port",
			input:      "sa:password@sqlserver1:1433",
			wantUser:   "sa",
			wantPass:   "password",
			wantTarget: "sqlserver1:1433",
			wantOK:     true,
		},
		{
			name:       "FQDN",
			input:      "sa:password@sqlserver1.domain.com",
			wantUser:   "sa",
			wantPass:   "password",
			wantTarget: "sqlserver1.domain.com",
			wantOK:     true,
		},
		{
			name:       "named instance",
			input:      `sa:password@sqlserver1\SQLEXPRESS`,
			wantUser:   "sa",
			wantPass:   "password",
			wantTarget: `sqlserver1\SQLEXPRESS`,
			wantOK:     true,
		},
		{
			name:       "SPN format",
			input:      "sa:password@MSSQLSvc/sqlserver1.domain.com:1433",
			wantUser:   "sa",
			wantPass:   "password",
			wantTarget: "MSSQLSvc/sqlserver1.domain.com:1433",
			wantOK:     true,
		},
		{
			name:       "domain backslash user",
			input:      `DOMAIN\admin:P@ssw0rd@sqlserver1`,
			wantUser:   `DOMAIN\admin`,
			wantPass:   "P@ssw0rd",
			wantTarget: "sqlserver1",
			wantOK:     true,
		},
		{
			name:       "UPN user (user@domain)",
			input:      "admin@domain.com:secret@sqlserver1",
			wantUser:   "admin@domain.com",
			wantPass:   "secret",
			wantTarget: "sqlserver1",
			wantOK:     true,
		},
		{
			name:       "password with special chars",
			input:      "sa:p@ss:w0rd!@sqlserver1",
			wantUser:   "sa",
			wantPass:   "p@ss:w0rd!",
			wantTarget: "sqlserver1",
			wantOK:     true,
		},
		{
			name:       "empty password",
			input:      "sa:@sqlserver1",
			wantUser:   "sa",
			wantPass:   "",
			wantTarget: "sqlserver1",
			wantOK:     true,
		},
		{
			name:       "no credentials - plain hostname",
			input:      "sqlserver1",
			wantTarget: "sqlserver1",
			wantOK:     false,
		},
		{
			name:       "no colon - not credentials",
			input:      "user@sqlserver1",
			wantTarget: "user@sqlserver1",
			wantOK:     false,
		},
		{
			name:       "empty user",
			input:      ":password@sqlserver1",
			wantTarget: ":password@sqlserver1",
			wantOK:     false,
		},
		{
			name:       "empty target",
			input:      "sa:password@",
			wantTarget: "sa:password@",
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotUser, gotPass, gotTarget, gotOK := extractTargetCredentials(tc.input)
			if gotOK != tc.wantOK {
				t.Fatalf("ok: got %v, want %v", gotOK, tc.wantOK)
			}
			if gotUser != tc.wantUser {
				t.Errorf("user: got %q, want %q", gotUser, tc.wantUser)
			}
			if gotPass != tc.wantPass {
				t.Errorf("pass: got %q, want %q", gotPass, tc.wantPass)
			}
			if gotTarget != tc.wantTarget {
				t.Errorf("target: got %q, want %q", gotTarget, tc.wantTarget)
			}
		})
	}
}

func TestParseBloodhoundUploadFlag(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantID    string
		wantKey   string
		wantURL   string
		wantErr   string
	}{
		{
			name:    "valid full URL",
			input:   "abc123:secretkey@https://bloodhound.corp.local",
			wantID:  "abc123",
			wantKey: "secretkey",
			wantURL: "https://bloodhound.corp.local",
		},
		{
			name:    "valid with port",
			input:   "myid:mykey@https://bh.local:8443",
			wantID:  "myid",
			wantKey: "mykey",
			wantURL: "https://bh.local:8443",
		},
		{
			name:    "missing @ separator",
			input:   "abc123:secretkey",
			wantErr: "-B format must be",
		},
		{
			name:    "missing colon in credentials",
			input:   "abc123@https://bh.local",
			wantErr: "-B format must be",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			atIdx := strings.Index(tc.input, "@")
			if atIdx < 0 {
				if tc.wantErr == "" {
					t.Fatalf("unexpected parse failure: no @ in %q", tc.input)
				}
				return
			}
			credentials := tc.input[:atIdx]
			url := tc.input[atIdx+1:]

			colonIdx := strings.Index(credentials, ":")
			if colonIdx < 0 {
				if tc.wantErr == "" {
					t.Fatalf("unexpected parse failure: no : in credentials %q", credentials)
				}
				return
			}

			if tc.wantErr != "" {
				t.Fatalf("expected error but parsed successfully")
			}

			gotID := credentials[:colonIdx]
			gotKey := credentials[colonIdx+1:]

			if gotID != tc.wantID {
				t.Errorf("tokenID: got %q, want %q", gotID, tc.wantID)
			}
			if gotKey != tc.wantKey {
				t.Errorf("tokenKey: got %q, want %q", gotKey, tc.wantKey)
			}
			if url != tc.wantURL {
				t.Errorf("URL: got %q, want %q", url, tc.wantURL)
			}
		})
	}
}
