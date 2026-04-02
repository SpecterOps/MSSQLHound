package main

import (
	"os"
	"path/filepath"
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
