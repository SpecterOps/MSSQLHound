package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// defaultMaxRetries is the number of retry attempts for transient errors.
	defaultMaxRetries = 3
	// defaultRetryDelay is the initial delay between retries.
	defaultRetryDelay = 2 * time.Second
	// defaultTimeout is the HTTP client timeout per request.
	defaultHTTPTimeout = 60 * time.Second

	// uploadStartPath is the BH CE API endpoint to initiate a file upload job.
	uploadStartPath = "/api/v2/file-upload/start"
	// uploadFilePath is the BH CE API endpoint to upload a file to a job.
	// The {job_id} placeholder must be replaced.
	uploadFilePath = "/api/v2/file-upload/%s"

	// extensionsPath is the BH CE API endpoint for custom schema/type definitions.
	extensionsPath = "/api/v2/extensions"

	// savedQueriesPath is the BH CE API endpoint for saved Cypher queries.
	savedQueriesPath = "/api/v2/saved-queries"
	// listSavedQueriesPageSize is the per-page limit used when paginating the
	// saved-queries listing. 1000 keeps the paginate-loop short while staying
	// well under any reasonable BH CE response budget.
	listSavedQueriesPageSize = 1000
)

// Client communicates with the BloodHound CE file upload API.
type Client struct {
	// BaseURL is the BloodHound CE instance URL (e.g. "https://bloodhound.corp.local").
	// Must not have a trailing slash.
	BaseURL string

	// Auth signs outgoing requests.
	Auth Authenticator

	// HTTPClient is the underlying HTTP client. If nil, a default client with
	// a 60-second timeout is used.
	HTTPClient *http.Client

	// MaxRetries is the number of retry attempts on transient errors (429, 5xx).
	// Defaults to 3.
	MaxRetries int

	// RetryDelay is the initial delay between retries. Doubled on each attempt.
	// Defaults to 2 seconds.
	RetryDelay time.Duration
}

// NewClient creates a Client for the given BloodHound CE instance.
// It uses the system (cgo) DNS resolver to avoid inheriting any overridden
// net.DefaultResolver (e.g. when --dc redirects DNS to a domain controller).
func NewClient(baseURL string, auth Authenticator) *Client {
	// PreferGo: false uses the system's C library resolver (getaddrinfo),
	// which correctly handles /etc/hosts, .localhost TLD, mDNS, and NSS —
	// unlike Go's pure resolver which only reads /etc/resolv.conf.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:  10 * time.Second,
			Resolver: &net.Resolver{PreferGo: false},
		}).DialContext,
	}
	return &Client{
		BaseURL: NormalizeBaseURL(baseURL),
		Auth:    auth,
		HTTPClient: &http.Client{
			Timeout:   defaultHTTPTimeout,
			Transport: transport,
		},
		MaxRetries: defaultMaxRetries,
		RetryDelay: defaultRetryDelay,
	}
}

// NormalizeBaseURL trims trailing slashes and a trailing "/ui" segment from
// baseURL. Users frequently paste the BloodHound CE URL straight from their
// browser address bar (e.g. "https://bh.example.com/ui"), but the API lives
// at "/api/v2/..." on the same origin — not under "/ui". Without this fix,
// the SPA's HTML fallback intercepts API calls and the JSON decode fails
// with "invalid character '<' looking for beginning of value", or worse,
// silently returns 200 OK on writes that never reached the API.
func NormalizeBaseURL(baseURL string) string {
	s := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(strings.ToLower(s), "/ui") {
		s = s[:len(s)-len("/ui")]
	}
	return strings.TrimRight(s, "/")
}

// startUploadResponse is the JSON response from POST /api/v2/file-upload/start.
type startUploadResponse struct {
	Data struct {
		ID int64 `json:"id"`
	} `json:"data"`
}

// StartUpload initiates a new file upload job on the BloodHound CE instance.
// Returns the job ID as a string or an error.
func (c *Client) StartUpload(ctx context.Context) (string, error) {
	body := []byte("{}")
	resp, err := c.doRequest(ctx, http.MethodPost, uploadStartPath, body, "application/json")
	if err != nil {
		return "", fmt.Errorf("failed to start upload job: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", c.readError(resp, "start upload")
	}

	var result startUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse start upload response: %w", err)
	}

	if result.Data.ID == 0 {
		return "", fmt.Errorf("BloodHound CE returned an empty job ID")
	}

	return fmt.Sprintf("%d", result.Data.ID), nil
}

// UploadFile uploads a single file to an existing upload job. The file is sent
// as raw content (application/json or application/zip) to
// POST /api/v2/file-upload/{job_id}.
func (c *Client) UploadFile(ctx context.Context, jobID, filePath string) error {
	body, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read output file %s: %w", filePath, err)
	}

	// Determine content type from file extension.
	contentType := "application/json"
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".zip" {
		contentType = "application/zip"
	}

	path := fmt.Sprintf(uploadFilePath, jobID)

	resp, err := c.doRequest(ctx, http.MethodPost, path, body, contentType)
	if err != nil {
		return fmt.Errorf("failed to upload file %s: %w", filepath.Base(filePath), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		return c.readError(resp, fmt.Sprintf("upload file %s", filepath.Base(filePath)))
	}

	return nil
}

// UploadSchema uploads custom schema/type definitions to BloodHound CE.
// PUT /api/v2/extensions
func (c *Client) UploadSchema(ctx context.Context, data []byte) error {
	resp, err := c.doRequest(ctx, http.MethodPut, extensionsPath, data, "application/json")
	if err != nil {
		return fmt.Errorf("failed to upload schema: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.readError(resp, "upload schema")
	}

	return nil
}

// EndUpload signals that all files for the given job have been uploaded.
// POST /api/v2/file-upload/{job_id}/end
func (c *Client) EndUpload(ctx context.Context, jobID string) error {
	path := fmt.Sprintf("/api/v2/file-upload/%s/end", jobID)
	resp, err := c.doRequest(ctx, http.MethodPost, path, []byte("{}"), "application/json")
	if err != nil {
		return fmt.Errorf("failed to end upload job %s: %w", jobID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.readError(resp, "end upload")
	}

	return nil
}

// doRequest performs an HTTP request with authentication and retry logic.
// It retries on 429 (Too Many Requests) and 5xx server errors with
// exponential backoff.
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte, contentType string) (*http.Response, error) {
	url := c.BaseURL + path
	maxRetries := c.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	delay := c.RetryDelay
	if delay <= 0 {
		delay = defaultRetryDelay
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				delay *= 2 // Exponential backoff.
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", contentType)

		if err := c.Auth.Authenticate(req, body); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Retry on transient errors.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
			continue
		}

		// Catch the SPA-fallback case: the server returned a successful HTML
		// response, which means the request never reached the API. Do not
		// retry — the URL is wrong, not transient.
		if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(strings.ToLower(ct), "text/html") {
			resp.Body.Close()
			return nil, fmt.Errorf("BloodHound API returned text/html (HTTP %d) for %s — check that --bloodhound-url points at the API root, not the /ui SPA path", resp.StatusCode, path)
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d retries (target: %s): %w", maxRetries+1, c.BaseURL, lastErr)
}

// readError extracts an error message from a non-success HTTP response.
func (c *Client) readError(resp *http.Response, operation string) error {
	body, _ := io.ReadAll(resp.Body)
	msg := truncate(string(body), 300)
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("%s failed (HTTP %d): %s", operation, resp.StatusCode, msg)
}

// savedQueryListResponse is the JSON shape returned by GET /api/v2/saved-queries.
// Only the fields we need are decoded; BH CE returns more.
type savedQueryListResponse struct {
	Data []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"data"`
}

// ListSavedQueries enumerates every saved query visible to the authenticated
// account, paginating through /api/v2/saved-queries until the server returns
// fewer rows than requested. The returned map is keyed by query Name (case-
// sensitive, as BH CE treats names) with the BH-assigned id as the value.
func (c *Client) ListSavedQueries(ctx context.Context) (map[string]int64, error) {
	out := make(map[string]int64)
	skip := 0
	for {
		path := fmt.Sprintf("%s?skip=%d&limit=%d", savedQueriesPath, skip, listSavedQueriesPageSize)
		resp, err := c.doRequest(ctx, http.MethodGet, path, nil, "application/json")
		if err != nil {
			return nil, fmt.Errorf("failed to list saved queries: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			err := c.readError(resp, "list saved queries")
			resp.Body.Close()
			return nil, err
		}

		var page savedQueryListResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to parse saved-query list response: %w", decodeErr)
		}

		for _, q := range page.Data {
			if q.Name != "" {
				out[q.Name] = q.ID
			}
		}

		if len(page.Data) < listSavedQueriesPageSize {
			return out, nil
		}
		skip += len(page.Data)
	}
}

// CreateSavedQuery POSTs a new saved query to /api/v2/saved-queries. Success
// is HTTP 201 (per the BH CE OpenAPI spec and the gophlare reference impl).
func (c *Client) CreateSavedQuery(ctx context.Context, q SavedQuery) error {
	body, err := json.Marshal(q)
	if err != nil {
		return fmt.Errorf("marshal saved query %q: %w", q.Name, err)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, savedQueriesPath, body, "application/json")
	if err != nil {
		return fmt.Errorf("create saved query %q: %w", q.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return c.readError(resp, fmt.Sprintf("create saved query %q", q.Name))
	}
	return nil
}

// UpdateSavedQuery PUTs to /api/v2/saved-queries/{id} to overwrite an existing
// query in-place, preserving its id, ownership, and any sharing settings.
// Success is HTTP 200 or 204.
func (c *Client) UpdateSavedQuery(ctx context.Context, id int64, q SavedQuery) error {
	body, err := json.Marshal(q)
	if err != nil {
		return fmt.Errorf("marshal saved query %q: %w", q.Name, err)
	}

	path := fmt.Sprintf("%s/%d", savedQueriesPath, id)
	resp, err := c.doRequest(ctx, http.MethodPut, path, body, "application/json")
	if err != nil {
		return fmt.Errorf("update saved query %q: %w", q.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.readError(resp, fmt.Sprintf("update saved query %q", q.Name))
	}
	return nil
}

// truncate returns s truncated to maxLen characters with "..." appended if needed.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
