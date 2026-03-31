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
// net.DefaultResolver (e.g. when --dc-ip redirects DNS to a domain controller).
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
		BaseURL: strings.TrimRight(baseURL, "/"),
		Auth:    auth,
		HTTPClient: &http.Client{
			Timeout:   defaultHTTPTimeout,
			Transport: transport,
		},
		MaxRetries: defaultMaxRetries,
		RetryDelay: defaultRetryDelay,
	}
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

// truncate returns s truncated to maxLen characters with "..." appended if needed.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
