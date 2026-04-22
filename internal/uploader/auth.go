// Package uploader implements the BloodHound CE file upload client for
// MSSQLHound. It supports two-phase uploads (start job → upload file),
// HMAC-SHA256 and JWT Bearer authentication, retry with exponential backoff,
// and progress reporting.
package uploader

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// Authenticator signs an outgoing HTTP request for the BloodHound CE API.
// The body parameter contains the raw request body bytes (needed for HMAC
// body hashing). Implementations must not modify the request body.
type Authenticator interface {
	Authenticate(req *http.Request, body []byte) error
}

// HMACAuth implements Authenticator using BloodHound's chained HMAC-SHA256
// request signing scheme. Each request is signed with a token ID and secret key
// using a three-step HMAC chain:
//
//  1. OperationKey = HMAC-SHA256(tokenKey, method + uri)
//  2. DateKey      = HMAC-SHA256(OperationKey, datetimeToHour)
//  3. Signature    = HMAC-SHA256(DateKey, requestBody)
//
// The final signature is base64-encoded and sent in the Signature header.
type HMACAuth struct {
	// TokenID is the public identifier of the API key pair (apiKeyId).
	TokenID string
	// TokenKey is the secret portion of the API key pair (decrypted apiKey).
	TokenKey string
	// NowFunc returns the current time. If nil, time.Now is used.
	// Exposed for deterministic testing.
	NowFunc func() time.Time
}

// Authenticate signs req using the BloodHound CE chained HMAC-SHA256 scheme.
// It sets the Authorization, RequestDate, and Signature headers.
func (h *HMACAuth) Authenticate(req *http.Request, body []byte) error {
	if h.TokenID == "" || h.TokenKey == "" {
		return fmt.Errorf("HMAC auth requires both tokenID and tokenKey; " +
			"check that bloodhound.apiKeyId and bloodhound.apiKey are set in your config")
	}

	now := time.Now
	if h.NowFunc != nil {
		now = h.NowFunc
	}
	t := now().UTC()
	requestDate := t.Format(time.RFC3339)

	// BH CE truncates the datetime to the hour for the date key.
	// Format: "2006-01-02T15" (RFC3339 up to and including the hour).
	datetimeToHour := t.Format("2006-01-02T15")

	// URI is the path + query string.
	uri := req.URL.RequestURI()

	// Step 1: OperationKey = HMAC-SHA256(tokenKey, method + uri)
	// Method and URI are concatenated with no delimiter.
	operationMAC := hmac.New(sha256.New, []byte(h.TokenKey))
	operationMAC.Write([]byte(req.Method + uri))
	operationKey := operationMAC.Sum(nil)

	// Step 2: DateKey = HMAC-SHA256(OperationKey, datetimeToHour)
	dateMAC := hmac.New(sha256.New, operationKey)
	dateMAC.Write([]byte(datetimeToHour))
	dateKey := dateMAC.Sum(nil)

	// Step 3: Signature = HMAC-SHA256(DateKey, requestBody)
	// If body is nil, sign an empty string.
	sigMAC := hmac.New(sha256.New, dateKey)
	if body != nil {
		sigMAC.Write(body)
	}
	signature := base64.StdEncoding.EncodeToString(sigMAC.Sum(nil))

	// Set BH CE API headers.
	req.Header.Set("Authorization", fmt.Sprintf("bhesignature %s", h.TokenID))
	req.Header.Set("RequestDate", requestDate)
	req.Header.Set("Signature", signature)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return nil
}

// BearerAuth implements Authenticator using a JWT Bearer token.
// This is the simpler of the two BloodHound CE authentication methods.
type BearerAuth struct {
	// Token is the JWT Bearer token.
	Token string
}

// Authenticate sets the Authorization header with a Bearer token.
func (b *BearerAuth) Authenticate(req *http.Request, _ []byte) error {
	if b.Token == "" {
		return fmt.Errorf("Bearer auth requires a non-empty token; " +
			"check that your BloodHound JWT token is configured")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", b.Token))
	return nil
}
