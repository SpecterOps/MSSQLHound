//go:build !windows
// +build !windows

package ad

import "fmt"

// ResolveComputerSIDWindows resolves a computer's SID using Windows APIs
// On non-Windows platforms, this returns an error since Windows APIs aren't available
func ResolveComputerSIDWindows(computerName, domain string) (string, error) {
	return "", fmt.Errorf("Windows API SID resolution not available on this platform")
}

// ResolveComputerSIDByDomainSID constructs the computer's SID by looking up its RID
// On non-Windows platforms, this returns an error
func ResolveComputerSIDByDomainSID(computerName, domainSID, domain string) (string, error) {
	return "", fmt.Errorf("Windows API SID resolution not available on this platform")
}

// ResolveAccountSIDWindows resolves any account name to a SID using Windows APIs
// On non-Windows platforms, this returns an error since Windows APIs aren't available
func ResolveAccountSIDWindows(accountName string) (string, error) {
	return "", fmt.Errorf("Windows API SID resolution not available on this platform")
}
