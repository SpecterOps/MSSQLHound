package uploader

import (
	"context"
	"encoding/json"
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

func TestClient_ListSavedQueries_Pagination(t *testing.T) {
	// Two pages: page 1 returns 1000 (full page), page 2 returns 2.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/saved-queries" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		skip := r.URL.Query().Get("skip")
		w.WriteHeader(http.StatusOK)
		switch skip {
		case "0":
			data := make([]map[string]any, 0, 1000)
			for i := range 1000 {
				data = append(data, map[string]any{"id": i + 1, "name": fmt.Sprintf("Query%04d", i+1)})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "1000":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": 1001, "name": "QueryA"},
					{"id": 1002, "name": "QueryB"},
				},
			})
		default:
			t.Errorf("unexpected skip=%s", skip)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	got, err := c.ListSavedQueries(context.Background())
	if err != nil {
		t.Fatalf("ListSavedQueries() error: %v", err)
	}
	if len(got) != 1002 {
		t.Errorf("got %d queries, want 1002", len(got))
	}
	if got["QueryA"] != 1001 {
		t.Errorf("QueryA id = %d, want 1001", got["QueryA"])
	}
	if got["QueryB"] != 1002 {
		t.Errorf("QueryB id = %d, want 1002", got["QueryB"])
	}
}

func TestClient_CreateSavedQuery_Success(t *testing.T) {
	var receivedBody []byte
	var receivedMethod, receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/saved-queries" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		receivedMethod = r.Method
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	q := SavedQuery{Name: "Smoke", Query: "MATCH (n) RETURN n", Description: "doc"}
	if err := c.CreateSavedQuery(context.Background(), q); err != nil {
		t.Fatalf("CreateSavedQuery() error: %v", err)
	}

	if receivedMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", receivedMethod)
	}
	if receivedAuth == "" {
		t.Error("expected Authorization header to be set by Authenticator")
	}
	want := `{"name":"Smoke","query":"MATCH (n) RETURN n","description":"doc"}`
	if string(receivedBody) != want {
		t.Errorf("body =\n  %s\nwant\n  %s", receivedBody, want)
	}
}

func TestClient_CreateSavedQuery_NonCreatedFails(t *testing.T) {
	// BH CE returns 200 instead of 201 — should be treated as failure to
	// match the documented contract and the gophlare reference.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	err := c.CreateSavedQuery(context.Background(), SavedQuery{Name: "X", Query: "MATCH (n) RETURN n"})
	if err == nil {
		t.Fatal("expected error when server returns 200 instead of 201")
	}
	if !strings.Contains(err.Error(), "200") {
		t.Errorf("error should mention HTTP 200: %v", err)
	}
}

func TestClient_UpdateSavedQuery_Success(t *testing.T) {
	var receivedPath, receivedMethod string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	q := SavedQuery{Name: "Smoke", Query: "MATCH (n) RETURN n LIMIT 1", Description: "v2"}
	if err := c.UpdateSavedQuery(context.Background(), 42, q); err != nil {
		t.Fatalf("UpdateSavedQuery() error: %v", err)
	}

	if receivedMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", receivedMethod)
	}
	if receivedPath != "/api/v2/saved-queries/42" {
		t.Errorf("path = %s, want /api/v2/saved-queries/42", receivedPath)
	}
	if !strings.Contains(string(receivedBody), `"description":"v2"`) {
		t.Errorf("body missing description: %s", receivedBody)
	}
}

func TestClient_UpdateSavedQuery_NoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	q := SavedQuery{Name: "X", Query: "MATCH (n) RETURN n"}
	if err := c.UpdateSavedQuery(context.Background(), 7, q); err != nil {
		t.Fatalf("expected 204 to be accepted, got %v", err)
	}
}

func TestClient_ListSavedQueries_ErrorBubblesUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errors":[{"message":"forbidden"}]}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	if _, err := c.ListSavedQueries(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"http://x.com", "http://x.com"},
		{"http://x.com/", "http://x.com"},
		{"http://x.com//", "http://x.com"},
		{"http://x.com/ui", "http://x.com"},
		{"http://x.com/ui/", "http://x.com"},
		{"http://x.com/UI", "http://x.com"},
		{"http://x.com:8001/ui", "http://x.com:8001"},
		{"https://bh.example.com/ui", "https://bh.example.com"},
		{"https://bh.example.com/bloodhound/ui", "https://bh.example.com/bloodhound"},
		// Genuine path that just happens to contain "ui" mid-segment is left alone.
		{"https://bh.example.com/build", "https://bh.example.com/build"},
	}
	for _, tc := range tests {
		got := NormalizeBaseURL(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewClient_StripsUiSuffix(t *testing.T) {
	c := NewClient("https://bh.example.com/ui", &fakeAuth{})
	if c.BaseURL != "https://bh.example.com" {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, "https://bh.example.com")
	}
}

func TestClient_RejectsHTMLResponse(t *testing.T) {
	// Simulate the SPA-fallback case: a 200 OK with HTML body that would
	// otherwise read as JSON-decode failure (or worse, silent success).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!DOCTYPE html><html><body>SPA</body></html>`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.MaxRetries = 0

	_, err := c.ListSavedQueries(context.Background())
	if err == nil {
		t.Fatal("expected error on HTML response, got nil")
	}
	if !strings.Contains(err.Error(), "text/html") {
		t.Errorf("error should mention text/html: %v", err)
	}
	if !strings.Contains(err.Error(), "/ui") {
		t.Errorf("error should mention the /ui hint: %v", err)
	}

	// Schema upload should also reject the SPA fallback now.
	if err := c.UploadSchema(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected schema upload to reject HTML response, got nil")
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
