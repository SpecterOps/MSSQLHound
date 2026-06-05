//go:build !windows

package collector

import "fmt"

func (c *Collector) enumerateComputersViaWindowsADSI() ([]domainComputer, error) {
	return nil, fmt.Errorf("Windows ADSI computer enumeration is only available on Windows")
}
