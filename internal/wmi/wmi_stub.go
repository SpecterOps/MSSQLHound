//go:build !windows

// Package wmi provides WMI-based enumeration of local group members.
// This is a stub for non-Windows platforms.
package wmi

import "log/slog"

// GroupMember represents a member of a local group
type GroupMember struct {
	Domain string
	Name   string
	SID    string
}

// GetLocalGroupMembers is not available on non-Windows platforms
func GetLocalGroupMembers(computerName, groupName string, logger *slog.Logger) ([]GroupMember, error) {
	return nil, nil
}

// GetLocalGroupMembersWithFallback is not available on non-Windows platforms
func GetLocalGroupMembersWithFallback(computerName, groupName string, logger *slog.Logger) []GroupMember {
	return nil
}
