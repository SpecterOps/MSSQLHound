// MSSQLHound - BloodHound collector for MSSQL attack paths
// Copyright (C) 2024  SpecterOps
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build integration

package uploader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests require a running BloodHound CE instance.
// Run with: go test -tags integration -v ./internal/uploader/
//
// Required environment variables (from .env):
//   BLOODHOUND_URL, BLOODHOUND_KEY_ID, BLOODHOUND_KEY

func getEnvOrSkip(t *testing.T, key string) string {
	t.Helper()
	val := os.Getenv(key)
	if val == "" {
		t.Skipf("skipping: %s not set", key)
	}
	return val
}

func testClient(t *testing.T) *Client {
	t.Helper()
	url := getEnvOrSkip(t, "BLOODHOUND_URL")
	keyID := getEnvOrSkip(t, "BLOODHOUND_KEY_ID")
	key := getEnvOrSkip(t, "BLOODHOUND_KEY")

	auth := &HMACAuth{TokenID: keyID, TokenKey: key}
	return NewClient(url, auth)
}

func TestIntegration_StartUpload(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jobID, err := c.StartUpload(ctx)
	if err != nil {
		t.Fatalf("StartUpload() error: %v", err)
	}
	t.Logf("Upload job started: ID=%s", jobID)

	if jobID == "" || jobID == "0" {
		t.Fatal("received empty or zero job ID")
	}
}

func TestIntegration_FullUpload(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a minimal BloodHound CE ingest JSON file.
	// BH CE expects a "meta" tag with "type" and "version" at minimum.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-output.json")
	data := []byte(`{
		"meta": {
			"methods": 0,
			"type": "computers",
			"count": 0,
			"version": 6
		},
		"data": []
	}`)
	if err := os.WriteFile(testFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Phase 1: Start upload.
	jobID, err := c.StartUpload(ctx)
	if err != nil {
		t.Fatalf("StartUpload() error: %v", err)
	}
	t.Logf("Job ID: %s", jobID)

	// Phase 2: Upload file.
	if err := c.UploadFile(ctx, jobID, testFile); err != nil {
		t.Fatalf("UploadFile() error: %v", err)
	}
	t.Log("File uploaded successfully")

	// Phase 3: End upload.
	if err := c.EndUpload(ctx, jobID); err != nil {
		t.Fatalf("EndUpload() error: %v", err)
	}
	t.Log("Upload job ended successfully")
}
