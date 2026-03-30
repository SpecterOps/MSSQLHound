package epamatrix

import "fmt"

// RegistrySettings holds the three SQL Server EPA-related registry values.
type RegistrySettings struct {
	ForceEncryption       int // 0 or 1
	ForceStrictEncryption int // 0 or 1
	ExtendedProtection    int // 0, 1, or 2
}

// SQLInstanceInfo holds auto-detected SQL Server instance details.
type SQLInstanceInfo struct {
	InstanceName string // e.g. "MSSQLSERVER" or "SQLEXPRESS"
	RegistryRoot string // e.g. "MSSQL16.MSSQLSERVER"
	ServiceName  string // e.g. "MSSQLSERVER" or "MSSQL$SQLEXPRESS"
	RegistryPath string // full path to SuperSocketNetLib key
}

// BuildDetectInstanceScript returns PowerShell that finds the SQL Server instance
// registry root and outputs "RegistryRoot|RegistryPath|ServiceName".
func BuildDetectInstanceScript(instanceName string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$instanceName = '%s'
$instances = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
$root = $instances.$instanceName
if (-not $root) {
    $available = ($instances.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } | ForEach-Object { $_.Name }) -join ', '
    throw "Instance '$instanceName' not found. Available: $available"
}
$regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$root\MSSQLServer\SuperSocketNetLib"
if (-not (Test-Path $regPath)) {
    throw "Registry path not found: $regPath"
}
$svcName = if ($instanceName -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { 'MSSQL$' + $instanceName }
Write-Output "$root|$regPath|$svcName"
`, instanceName)
}

// BuildReadSettingsScript returns PowerShell that reads the current EPA-related
// registry values and outputs "ForceEncryption|ForceStrictEncryption|ExtendedProtection".
func BuildReadSettingsScript(registryPath string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$path = '%s'
$fe = (Get-ItemProperty $path -Name ForceEncryption -ErrorAction SilentlyContinue).ForceEncryption
$fse = (Get-ItemProperty $path -Name ForceStrictEncryption -ErrorAction SilentlyContinue).ForceStrictEncryption
$ep = (Get-ItemProperty $path -Name ExtendedProtection -ErrorAction SilentlyContinue).ExtendedProtection
if ($null -eq $fe) { $fe = 0 }
if ($null -eq $fse) { $fse = 0 }
if ($null -eq $ep) { $ep = 0 }
Write-Output "$fe|$fse|$ep"
`, registryPath)
}

// BuildWriteSettingsScript returns PowerShell that sets the EPA-related registry values.
func BuildWriteSettingsScript(registryPath string, settings RegistrySettings) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$path = '%s'
Set-ItemProperty -Path $path -Name ForceEncryption -Value %d -Type DWord
Set-ItemProperty -Path $path -Name ForceStrictEncryption -Value %d -Type DWord
Set-ItemProperty -Path $path -Name ExtendedProtection -Value %d -Type DWord
Write-Output 'OK'
`, registryPath, settings.ForceEncryption, settings.ForceStrictEncryption, settings.ExtendedProtection)
}

// BuildRestartServiceScript returns PowerShell that restarts the SQL Server
// service and waits for it to reach Running status.
func BuildRestartServiceScript(serviceName string, waitSeconds int) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$svc = '%s'
Restart-Service -Name $svc -Force
$timeout = %d
$elapsed = 0
while ($elapsed -lt $timeout) {
    Start-Sleep -Seconds 2
    $elapsed += 2
    $s = Get-Service -Name $svc
    if ($s.Status -eq 'Running') {
        Write-Output 'OK'
        exit 0
    }
}
throw "Service $svc did not start within $timeout seconds"
`, serviceName, waitSeconds)
}
