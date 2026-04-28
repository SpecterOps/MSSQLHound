package uploader

import (
	"context"
	"encoding/json"
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

func TestUploader_UploadSavedQueries_CreateAndUpdate(t *testing.T) {
	var listCalls, postCalls, putCalls atomic.Int32
	var lastPutPath string
	var lastPostBody, lastPutBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			listCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": 11, "name": "Existing"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			postCalls.Add(1)
			lastPostBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v2/saved-queries/"):
			putCalls.Add(1)
			lastPutPath = r.URL.Path
			lastPutBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	u := &Uploader{
		Client: NewClient(srv.URL, &fakeAuth{}),
		Logger: discardLogger(),
	}

	queries := []SavedQuery{
		{Name: "New", Query: "MATCH (a) RETURN a", Description: "fresh"},
		{Name: "Existing", Query: "MATCH (b) RETURN b", Description: "rev2"},
	}

	summary := u.UploadSavedQueries(context.Background(), queries)

	if summary.Created != 1 {
		t.Errorf("Created = %d, want 1", summary.Created)
	}
	if summary.Updated != 1 {
		t.Errorf("Updated = %d, want 1", summary.Updated)
	}
	if summary.Failed != 0 {
		t.Errorf("Failed = %d, want 0", summary.Failed)
	}
	if listCalls.Load() != 1 {
		t.Errorf("list calls = %d, want 1", listCalls.Load())
	}
	if postCalls.Load() != 1 {
		t.Errorf("post calls = %d, want 1", postCalls.Load())
	}
	if putCalls.Load() != 1 {
		t.Errorf("put calls = %d, want 1", putCalls.Load())
	}
	if lastPutPath != "/api/v2/saved-queries/11" {
		t.Errorf("PUT path = %s, want /api/v2/saved-queries/11", lastPutPath)
	}
	if !strings.Contains(string(lastPostBody), `"name":"New"`) {
		t.Errorf("POST body missing new query name: %s", lastPostBody)
	}
	if !strings.Contains(string(lastPutBody), `"description":"rev2"`) {
		t.Errorf("PUT body missing updated description: %s", lastPutBody)
	}
}

func TestUploader_UploadSavedQueries_EmptyList(t *testing.T) {
	u := &Uploader{
		Client: NewClient("http://unused", &fakeAuth{}),
		Logger: discardLogger(),
	}
	summary := u.UploadSavedQueries(context.Background(), nil)
	if summary.Created != 0 || summary.Updated != 0 || summary.Failed != 0 {
		t.Errorf("expected zero summary, got %+v", summary)
	}
}

func TestUploader_UploadSavedQueries_PerQueryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"name":"FailMe"`) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":[{"message":"bad cypher"}]}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.MaxRetries = 0 // 4xx is not retried, but keep tests fast.
	u := &Uploader{Client: c, Logger: discardLogger()}

	queries := []SavedQuery{
		{Name: "Good", Query: "MATCH (a) RETURN a"},
		{Name: "FailMe", Query: "INVALID SYNTAX"},
		{Name: "AlsoGood", Query: "MATCH (b) RETURN b"},
	}

	summary := u.UploadSavedQueries(context.Background(), queries)
	if summary.Created != 2 {
		t.Errorf("Created = %d, want 2", summary.Created)
	}
	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1", summary.Failed)
	}
	if len(summary.Errors) != 1 {
		t.Errorf("len(Errors) = %d, want 1", len(summary.Errors))
	}
	if !strings.Contains(summary.Errors[0].Error(), "FailMe") {
		t.Errorf("error should mention FailMe: %v", summary.Errors[0])
	}
}

func TestUploader_UploadSavedQueries_SucceedsAfterSchema404(t *testing.T) {
	// Reproduces the deployed-BH-without-/api/v2/extensions case: schema PUT
	// returns 404, but saved-queries CRUD should still work end-to-end. The
	// uploader doesn't call schema itself — phase orchestration is in the
	// collector — but this verifies that a separately-failed phase doesn't
	// pollute the queries client state.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/extensions" && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errors":[{"message":"resource not found"}]}`)
		case r.URL.Path == "/api/v2/saved-queries" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"data":[]}`)
		case r.URL.Path == "/api/v2/saved-queries" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.MaxRetries = 0
	u := &Uploader{Client: c, Logger: discardLogger()}

	// Schema fails (the orchestrator would log+continue).
	if err := c.UploadSchema(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected schema upload to fail with 404")
	}

	// Queries phase still works.
	summary := u.UploadSavedQueries(context.Background(), []SavedQuery{
		{Name: "Q1", Query: "MATCH (n) RETURN n"},
	})
	if summary.Created != 1 || summary.Failed != 0 {
		t.Errorf("queries phase summary = %+v, want Created=1 Failed=0", summary)
	}
}

func TestUploader_UploadSavedQueries_ListFailureAborts(t *testing.T) {
	var postCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		postCalls.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, &fakeAuth{})
	c.MaxRetries = 0
	u := &Uploader{Client: c, Logger: discardLogger()}

	queries := []SavedQuery{
		{Name: "X", Query: "MATCH (n) RETURN n"},
		{Name: "Y", Query: "MATCH (n) RETURN n"},
	}
	summary := u.UploadSavedQueries(context.Background(), queries)
	if summary.Failed != 2 {
		t.Errorf("Failed = %d, want 2 (every query attributed to the list error)", summary.Failed)
	}
	if postCalls.Load() != 0 {
		t.Errorf("expected zero POST calls when list fails; got %d", postCalls.Load())
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
