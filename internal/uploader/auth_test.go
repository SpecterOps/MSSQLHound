package uploader

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHMACAuth_Authenticate(t *testing.T) {
	fixedTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	auth := &HMACAuth{
		TokenID:  "test-key-id",
		TokenKey: "super-secret-key",
		NowFunc:  func() time.Time { return fixedTime },
	}

	body := []byte(`{"test": true}`)
	req, _ := http.NewRequest(http.MethodPost, "https://bh.example.com/api/v2/file-upload/start", nil)

	if err := auth.Authenticate(req, body); err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}

	// Verify Authorization header.
	authHeader := req.Header.Get("Authorization")
	if authHeader != "bhesignature test-key-id" {
		t.Errorf("Authorization = %q, want %q", authHeader, "bhesignature test-key-id")
	}

	// Verify RequestDate header.
	dateHeader := req.Header.Get("RequestDate")
	expectedDate := fixedTime.UTC().Format(time.RFC3339)
	if dateHeader != expectedDate {
		t.Errorf("RequestDate = %q, want %q", dateHeader, expectedDate)
	}

	// Verify Signature header is valid base64 and matches manual computation.
	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		t.Fatal("Signature header is empty")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		t.Fatalf("Signature header is not valid base64: %v", err)
	}
	if len(sigBytes) != sha256.Size {
		t.Errorf("Signature length = %d bytes, want %d", len(sigBytes), sha256.Size)
	}

	// Manually compute expected chained HMAC signature.
	// Step 1: OperationKey = HMAC-SHA256(tokenKey, method + uri)
	opMAC := hmac.New(sha256.New, []byte("super-secret-key"))
	opMAC.Write([]byte(http.MethodPost + "/api/v2/file-upload/start"))
	opKey := opMAC.Sum(nil)

	// Step 2: DateKey = HMAC-SHA256(OperationKey, datetimeToHour)
	datetimeToHour := fixedTime.UTC().Format("2006-01-02T15")
	dateMAC := hmac.New(sha256.New, opKey)
	dateMAC.Write([]byte(datetimeToHour))
	dateKey := dateMAC.Sum(nil)

	// Step 3: Signature = HMAC-SHA256(DateKey, body)
	sigMAC := hmac.New(sha256.New, dateKey)
	sigMAC.Write(body)
	expectedSig := base64.StdEncoding.EncodeToString(sigMAC.Sum(nil))

	if sigHeader != expectedSig {
		t.Errorf("Signature mismatch:\n  got:  %s\n  want: %s", sigHeader, expectedSig)
	}

	// Verify Content-Type default.
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestHMACAuth_PreservesExistingContentType(t *testing.T) {
	auth := &HMACAuth{
		TokenID:  "id",
		TokenKey: "key",
		NowFunc:  func() time.Time { return time.Now() },
	}

	req, _ := http.NewRequest(http.MethodPost, "https://bh.example.com/api/v2/file-upload/123", nil)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=abc")

	if err := auth.Authenticate(req, []byte{}); err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}

	if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(ct, "multipart/form-data") {
		t.Errorf("Content-Type was overwritten: %q", ct)
	}
}

func TestHMACAuth_EmptyCredentials(t *testing.T) {
	tests := []struct {
		name     string
		tokenID  string
		tokenKey string
	}{
		{"empty both", "", ""},
		{"empty tokenID", "", "key"},
		{"empty tokenKey", "id", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &HMACAuth{TokenID: tt.tokenID, TokenKey: tt.tokenKey}
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/test", nil)
			err := auth.Authenticate(req, nil)
			if err == nil {
				t.Error("expected error for empty credentials, got nil")
			}
		})
	}
}

func TestHMACAuth_DifferentBodies_DifferentSignatures(t *testing.T) {
	auth := &HMACAuth{
		TokenID:  "id",
		TokenKey: "key",
		NowFunc:  func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
	}

	req1, _ := http.NewRequest(http.MethodPost, "https://example.com/api/test", nil)
	req2, _ := http.NewRequest(http.MethodPost, "https://example.com/api/test", nil)

	auth.Authenticate(req1, []byte(`{"a":1}`))
	auth.Authenticate(req2, []byte(`{"b":2}`))

	if req1.Header.Get("Signature") == req2.Header.Get("Signature") {
		t.Error("different bodies produced the same signature")
	}
}

func TestBearerAuth_Authenticate(t *testing.T) {
	auth := &BearerAuth{Token: "eyJhbGciOiJIUzI1NiJ9.test"}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/api/test", nil)

	if err := auth.Authenticate(req, nil); err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer eyJhbGciOiJIUzI1NiJ9.test" {
		t.Errorf("Authorization = %q, want Bearer token", authHeader)
	}
}

func TestBearerAuth_EmptyToken(t *testing.T) {
	auth := &BearerAuth{Token: ""}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/test", nil)
	err := auth.Authenticate(req, nil)
	if err == nil {
		t.Error("expected error for empty token, got nil")
	}
}
