package mssql

import "strings"

// QueryResult represents a row of query results.
type QueryResult map[string]interface{}

// IsAuthError checks if the error is an authentication failure that would count
// toward AD account lockout, as opposed to transport/TLS errors that do not.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "login failed") ||
		strings.Contains(errStr, "untrusted domain") ||
		strings.Contains(errStr, "cannot be used with windows authentication") ||
		strings.Contains(errStr, "cannot be used with integrated authentication") ||
		strings.Contains(errStr, "no user credentials available")
}
