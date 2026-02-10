//go:build windows

// Package wmi provides WMI-based enumeration of local group members on Windows.
package wmi

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// GroupMember represents a member of a local group
type GroupMember struct {
	Domain string
	Name   string
	SID    string
}

// GetLocalGroupMembers enumerates members of a local group on a remote computer using WMI
func GetLocalGroupMembers(computerName, groupName string, verbose bool) ([]GroupMember, error) {
	var members []GroupMember

	// Always show which group we're enumerating
	fmt.Printf("Enumerating members of local group: %s\n", groupName)

	// Initialize COM
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		// Check if already initialized (error code 1 means S_FALSE - already initialized)
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 1 {
			return nil, fmt.Errorf("COM initialization failed: %w", err)
		}
	}
	defer ole.CoUninitialize()

	// Create WMI locator
	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, fmt.Errorf("failed to create WMI locator: %w", err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("failed to query WMI interface: %w", err)
	}
	defer wmi.Release()

	// Connect to remote WMI
	// Format: \\computername\root\cimv2
	wmiPath := fmt.Sprintf("\\\\%s\\root\\cimv2", computerName)
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", wmiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WMI on %s: %w", computerName, err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// Query for group members
	// WMI query: SELECT * FROM Win32_GroupUser WHERE GroupComponent="Win32_Group.Domain='COMPUTERNAME',Name='GROUPNAME'"
	query := fmt.Sprintf(`SELECT * FROM Win32_GroupUser WHERE GroupComponent="Win32_Group.Domain='%s',Name='%s'"`,
		computerName, groupName)

	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", query)
	if err != nil {
		return nil, fmt.Errorf("WMI query failed: %w", err)
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	// Get count
	countVar, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return nil, fmt.Errorf("failed to get result count: %w", err)
	}
	count := int(countVar.Val)

	if verbose {
		fmt.Printf("Found %d members in %s\n", count, groupName)
	}

	// Pattern to parse PartComponent
	// Example: \\\\COMPUTER\\root\\cimv2:Win32_UserAccount.Domain="DOMAIN",Name="USER"
	partPattern := regexp.MustCompile(`Domain="([^"]+)",Name="([^"]+)"`)

	// Iterate through results
	for i := 0; i < count; i++ {
		itemRaw, err := oleutil.CallMethod(result, "ItemIndex", i)
		if err != nil {
			continue
		}
		item := itemRaw.ToIDispatch()

		// Get PartComponent (the member)
		partComponentVar, err := oleutil.GetProperty(item, "PartComponent")
		if err != nil {
			item.Release()
			continue
		}
		partComponent := partComponentVar.ToString()

		// Parse the PartComponent to extract domain and name
		matches := partPattern.FindStringSubmatch(partComponent)
		if len(matches) >= 3 {
			memberDomain := matches[1]
			memberName := matches[2]

			// Skip local accounts and well-known local accounts
			upperDomain := strings.ToUpper(memberDomain)
			upperComputer := strings.ToUpper(computerName)

			if upperDomain != upperComputer &&
				upperDomain != "NT AUTHORITY" &&
				upperDomain != "NT SERVICE" {

				if verbose {
					fmt.Printf("Found domain member: %s\\%s\n", memberDomain, memberName)
				}

				members = append(members, GroupMember{
					Domain: memberDomain,
					Name:   memberName,
				})
			}
		}

		item.Release()
	}

	// Always show the result
	if len(members) > 0 {
		fmt.Printf("Found %d domain members in %s\n", len(members), groupName)
	} else {
		fmt.Printf("No domain members found in %s\n", groupName)
	}

	return members, nil
}

// GetLocalGroupMembersWithFallback tries WMI enumeration and returns an empty slice on failure
func GetLocalGroupMembersWithFallback(computerName, groupName string, verbose bool) []GroupMember {
	members, err := GetLocalGroupMembers(computerName, groupName, verbose)
	if err != nil {
		if verbose {
			fmt.Printf("WARNING: WMI enumeration failed for %s\\%s: %v\n", computerName, groupName, err)
		} else {
			fmt.Printf("WARNING: WMI enumeration failed for %s\\%s. This may require remote WMI access permissions.\n", computerName, groupName)
		}
		return nil
	}
	return members
}
