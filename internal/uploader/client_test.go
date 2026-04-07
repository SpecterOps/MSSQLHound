package uploader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAuth is a test Authenticator that does nothing.
type fakeAuth struct{}

func (f *fakeAuth) Authenticate(req *http.Request, _ []byte) error {
	req.Header.Set("Authorization", "Bearer fake-token")
	return nil
}

func TestClient_StartUpload_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/file-upload/start" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"data":{"id":42}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	jobID, err := c.StartUpload(context.Background())
	if err != nil {
		t.Fatalf("StartUpload() error: %v", err)
	}
	if jobID != "42" {
		t.Errorf("jobID = %q, want %q", jobID, "42")
	}
}

func TestClient_StartUpload_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"message":"invalid credentials"}]}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	_, err := c.StartUpload(context.Background())
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should contain status code: %v", err)
	}
}

func TestClient_StartUpload_RetryOn500(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "server error")
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"data":{"id":99}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.RetryDelay = 10 * time.Millisecond // Speed up test.

	jobID, err := c.StartUpload(context.Background())
	if err != nil {
		t.Fatalf("StartUpload() error after retries: %v", err)
	}
	if jobID != "99" {
		t.Errorf("jobID = %q, want %q", jobID, "99")
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestClient_StartUpload_RetryExhausted(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "always failing")
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.MaxRetries = 2
	c.RetryDelay = 10 * time.Millisecond

	_, err := c.StartUpload(context.Background())
	if err == nil {
		t.Fatal("expected error after exhausted retries, got nil")
	}
	if got := attempts.Load(); got != 3 { // 1 initial + 2 retries
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestClient_StartUpload_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	c := NewClient(srv.URL, &fakeAuth{})
	c.RetryDelay = 10 * time.Millisecond

	_, err := c.StartUpload(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestClient_UploadFile_Success(t *testing.T) {
	var receivedContentType string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/file-upload/42" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		receivedContentType = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Create a temp JSON file to upload.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "output.json")
	content := `{"graph":{"nodes":[],"edges":[]}}`
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewClient(srv.URL, &fakeAuth{})
	if err := c.UploadFile(context.Background(), "42", tmpFile); err != nil {
		t.Fatalf("UploadFile() error: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedContentType)
	}
	if string(receivedBody) != content {
		t.Errorf("body mismatch: got %q", string(receivedBody))
	}
}

func TestClient_UploadFile_ZipContentType(t *testing.T) {
	var receivedContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		receivedContentType = w.Header().Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Capture the content type from the request, not response.
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "output.zip")
	os.WriteFile(tmpFile, []byte("PK\x03\x04fake"), 0o644)

	c := NewClient(srv.URL, &fakeAuth{})
	if err := c.UploadFile(context.Background(), "42", tmpFile); err != nil {
		t.Fatalf("UploadFile() error: %v", err)
	}

	if receivedContentType != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", receivedContentType)
	}
}

func TestClient_UploadFile_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	err := c.UploadFile(context.Background(), "42", "/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestClient_EndUpload_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/file-upload/42/end" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	if err := c.EndUpload(context.Background(), "42"); err != nil {
		t.Fatalf("EndUpload() error: %v", err)
	}
}

func TestClient_RetryOn429(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "rate limited")
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"data":{"id":7}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.RetryDelay = 10 * time.Millisecond

	jobID, err := c.StartUpload(context.Background())
	if err != nil {
		t.Fatalf("StartUpload() error: %v", err)
	}
	if jobID != "7" {
		t.Errorf("jobID = %q, want %q", jobID, "7")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is..."},
		{"  padded  ", 20, "padded"},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}
