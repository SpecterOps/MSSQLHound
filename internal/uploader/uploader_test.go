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

package uploader

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewUploader_NilWhenNoURL(t *testing.T) {
	u := NewUploader("", "key-id", "secret", discardLogger())
	if u != nil {
		t.Error("expected nil Uploader when BloodHound URL is empty")
	}
}

func TestNewUploader_NilWhenNoAuth(t *testing.T) {
	u := NewUploader("https://bh.example.com", "", "", discardLogger())
	if u != nil {
		t.Error("expected nil Uploader when no auth credentials provided")
	}
}

func TestNewUploader_HMACAuth(t *testing.T) {
	u := NewUploader("https://bh.example.com", "key-id", "secret", discardLogger())
	if u == nil {
		t.Fatal("expected non-nil Uploader")
	}
	if _, ok := u.Client.Auth.(*HMACAuth); !ok {
		t.Errorf("expected HMACAuth, got %T", u.Client.Auth)
	}
}

func TestNewUploader_BearerFallback(t *testing.T) {
	u := NewUploader("https://bh.example.com", "jwt-token-here", "", discardLogger())
	if u == nil {
		t.Fatal("expected non-nil Uploader")
	}
	if _, ok := u.Client.Auth.(*BearerAuth); !ok {
		t.Errorf("expected BearerAuth, got %T", u.Client.Auth)
	}
}

func TestUploader_UploadFiles_EmptyList(t *testing.T) {
	u := &Uploader{
		Client: NewClient("http://unused", &fakeAuth{}),
		Logger: discardLogger(),
	}

	summary := u.UploadFiles(context.Background(), nil)
	if summary.FilesUploaded != 0 {
		t.Errorf("FilesUploaded = %d, want 0", summary.FilesUploaded)
	}
	if summary.FilesFailed != 0 {
		t.Errorf("FilesFailed = %d, want 0", summary.FilesFailed)
	}
}

func TestUploader_UploadFiles_Success(t *testing.T) {
	var uploadedFiles atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/file-upload/start":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"data":{"id":1}}`)
		case strings.HasSuffix(r.URL.Path, "/end"):
			w.WriteHeader(http.StatusOK)
		default:
			uploadedFiles.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	// Create temp output files.
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "graph1.json")
	file2 := filepath.Join(tmpDir, "graph2.json")
	os.WriteFile(file1, []byte(`{"graph":{}}`), 0o644)
	os.WriteFile(file2, []byte(`{"graph":{}}`), 0o644)

	u := &Uploader{
		Client: NewClient(srv.URL, &fakeAuth{}),
		Logger: discardLogger(),
	}

	summary := u.UploadFiles(context.Background(), []string{file1, file2})
	if summary.FilesUploaded != 2 {
		t.Errorf("FilesUploaded = %d, want 2", summary.FilesUploaded)
	}
	if summary.FilesFailed != 0 {
		t.Errorf("FilesFailed = %d, want 0", summary.FilesFailed)
	}
	if got := uploadedFiles.Load(); got != 2 {
		t.Errorf("uploaded files = %d, want 2", got)
	}
}

func TestUploader_UploadFiles_StartUploadFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "forbidden")
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "output.json")
	os.WriteFile(tmpFile, []byte(`{}`), 0o644)

	u := &Uploader{
		Client: NewClient(srv.URL, &fakeAuth{}),
		Logger: discardLogger(),
	}

	summary := u.UploadFiles(context.Background(), []string{tmpFile})
	if summary.FilesFailed != 1 {
		t.Errorf("FilesFailed = %d, want 1", summary.FilesFailed)
	}
	if len(summary.Errors) == 0 {
		t.Error("expected errors in summary")
	}
}

func TestUploader_UploadFiles_MultipleFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/file-upload/start":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"data":{"id":1}}`)
		case strings.HasSuffix(r.URL.Path, "/end"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "a.json")
	file2 := filepath.Join(tmpDir, "b.json")
	file3 := filepath.Join(tmpDir, "c.zip")
	os.WriteFile(file1, []byte(`{}`), 0o644)
	os.WriteFile(file2, []byte(`{}`), 0o644)
	os.WriteFile(file3, []byte("PK\x03\x04fake"), 0o644)

	u := &Uploader{
		Client: NewClient(srv.URL, &fakeAuth{}),
		Logger: discardLogger(),
	}

	summary := u.UploadFiles(context.Background(), []string{file1, file2, file3})
	if summary.FilesUploaded != 3 {
		t.Errorf("FilesUploaded = %d, want 3", summary.FilesUploaded)
	}
	if summary.FilesFailed != 0 {
		t.Errorf("FilesFailed = %d, want 0", summary.FilesFailed)
	}
}
