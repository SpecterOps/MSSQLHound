//go:build windows
// +build windows

package ad

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modNetapi32                = syscall.NewLazyDLL("netapi32.dll")
	modAdvapi32                = syscall.NewLazyDLL("advapi32.dll")
	procNetUserGetInfo         = modNetapi32.NewProc("NetUserGetInfo")
	procNetApiBufferFree       = modNetapi32.NewProc("NetApiBufferFree")
	procDsGetDcNameW           = modNetapi32.NewProc("DsGetDcNameW")
	procLookupAccountNameW     = modAdvapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSidW = modAdvapi32.NewProc("ConvertSidToStringSidW")
	procLocalFree              = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

// ResolveComputerSIDWindows resolves a computer's SID using Windows APIs
// This is more reliable than LDAP GSSAPI on Windows
func ResolveComputerSIDWindows(computerName, domain string) (string, error) {
	// Format the computer name with $ suffix for the account
	accountName := computerName
	if !strings.HasSuffix(accountName, "$") {
		accountName = accountName + "$"
	}

	// If it's an FQDN, strip the domain part
	if strings.Contains(accountName, ".") {
		parts := strings.SplitN(accountName, ".", 2)
		accountName = parts[0]
		if !strings.HasSuffix(accountName, "$") {
			accountName = accountName + "$"
		}
	}

	// Try with domain prefix
	if domain != "" {
		fullName := domain + "\\" + accountName
		sid, err := lookupAccountSID(fullName)
		if err == nil && sid != "" {
			return sid, nil
		}
	}

	// Try just the account name
	sid, err := lookupAccountSID(accountName)
	if err == nil && sid != "" {
		return sid, nil
	}

	return "", fmt.Errorf("could not resolve SID for computer %s: %v", computerName, err)
}

// lookupAccountSID uses LookupAccountNameW to get the SID for an account
func lookupAccountSID(accountName string) (string, error) {
	accountNamePtr, err := syscall.UTF16PtrFromString(accountName)
	if err != nil {
		return "", err
	}

	// First call to get buffer sizes
	var sidSize, domainSize uint32
	var sidUse uint32

	ret, _, _ := procLookupAccountNameW.Call(
		0, // lpSystemName - NULL for local
		uintptr(unsafe.Pointer(accountNamePtr)),
		0, // Sid - NULL to get size
		uintptr(unsafe.Pointer(&sidSize)),
		0, // ReferencedDomainName - NULL to get size
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)

	if sidSize == 0 {
		return "", fmt.Errorf("LookupAccountNameW failed to get buffer size")
	}

	// Allocate buffers
	sid := make([]byte, sidSize)
	domain := make([]uint16, domainSize)

	// Second call to get actual data
	ret, _, err = procLookupAccountNameW.Call(
		0,
		uintptr(unsafe.Pointer(accountNamePtr)),
		uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&sidSize)),
		uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)

	if ret == 0 {
		return "", fmt.Errorf("LookupAccountNameW failed: %v", err)
	}

	// Convert SID to string
	return convertSIDToString(sid)
}

// convertSIDToString converts a binary SID to string format
func convertSIDToString(sid []byte) (string, error) {
	var stringSidPtr *uint16

	ret, _, err := procConvertSidToStringSidW.Call(
		uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&stringSidPtr)),
	)

	if ret == 0 {
		return "", fmt.Errorf("ConvertSidToStringSidW failed: %v", err)
	}

	defer procLocalFree.Call(uintptr(unsafe.Pointer(stringSidPtr)))

	// Convert UTF16 to string
	sidString := syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(stringSidPtr))[:])
	return sidString, nil
}

// ResolveComputerSIDByDomainSID constructs the computer's SID by looking up its RID
// This tries to find the computer account and return its full SID
func ResolveComputerSIDByDomainSID(computerName, domainSID, domain string) (string, error) {
	// First try the direct Windows API method
	sid, err := ResolveComputerSIDWindows(computerName, domain)
	if err == nil && sid != "" && strings.HasPrefix(sid, domainSID) {
		return sid, nil
	}

	return "", fmt.Errorf("could not resolve computer SID using Windows APIs")
}

// ResolveAccountSIDWindows resolves any account name to a SID using Windows APIs
// This works for users, groups, and computers
func ResolveAccountSIDWindows(accountName string) (string, error) {
	return lookupAccountSID(accountName)
}
