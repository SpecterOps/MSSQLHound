//go:build !windows

// Package wmi provides WMI-based enumeration of local group members.
// This is a stub for non-Windows platforms.
package wmi

// GroupMember represents a member of a local group
type GroupMember struct {
	Domain string
	Name   string
	SID    string
}

// GetLocalGroupMembers is not available on non-Windows platforms
func GetLocalGroupMembers(computerName, groupName string, verbose bool) ([]GroupMember, error) {
	return nil, nil
}

// GetLocalGroupMembersWithFallback is not available on non-Windows platforms
func GetLocalGroupMembersWithFallback(computerName, groupName string, verbose bool) []GroupMember {
	return nil
}
