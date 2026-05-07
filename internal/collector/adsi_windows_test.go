//go:build windows

package collector

import (
	"testing"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

func TestADSIComputerHostname(t *testing.T) {
	tests := []struct {
		name    string
		dnsName string
		bare    string
		domain  string
		want    string
	}{
		{name: "dns hostname wins", dnsName: "host.example.com", bare: "HOST", domain: "example.com", want: "host.example.com"},
		{name: "bare name appends domain", bare: "HOST", domain: "example.com", want: "HOST.example.com"},
		{name: "fqdn name is preserved", bare: "host.child.example.com", domain: "example.com", want: "host.child.example.com"},
		{name: "empty name is skipped", domain: "example.com", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := adsiComputerHostname(tt.dnsName, tt.bare, tt.domain); got != tt.want {
				t.Fatalf("hostname = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestADSIDomainToDN(t *testing.T) {
	if got, want := adsiDomainToDN("ad005.onehc.net"), "DC=ad005,DC=onehc,DC=net"; got != want {
		t.Fatalf("base DN = %q, want %q", got, want)
	}
	if got, want := adsiDomainToDN(" example.com "), "DC=example,DC=com"; got != want {
		t.Fatalf("trimmed base DN = %q, want %q", got, want)
	}
}

func TestDecodeBinarySID(t *testing.T) {
	sidBytes := []byte{
		1, 5,
		0, 0, 0, 0, 0, 5,
		21, 0, 0, 0,
		1, 0, 0, 0,
		2, 0, 0, 0,
		3, 0, 0, 0,
		244, 1, 0, 0,
	}
	if got, want := decodeBinarySID(sidBytes), "S-1-5-21-1-2-3-500"; got != want {
		t.Fatalf("SID = %q, want %q", got, want)
	}
	if got := decodeBinarySID([]byte{1, 5}); got != "" {
		t.Fatalf("short SID bytes decoded to %q", got)
	}
}

func TestSetADOCommandPageSizeProperty(t *testing.T) {
	if err := initializeCOMForADSI(); err != nil {
		t.Fatalf("initialize COM: %v", err)
	}
	defer ole.CoUninitialize()

	connectionUnknown, err := oleutil.CreateObject("ADODB.Connection")
	if err != nil {
		t.Fatalf("create ADODB connection: %v", err)
	}
	defer connectionUnknown.Release()

	connection, err := connectionUnknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		t.Fatalf("query ADODB connection interface: %v", err)
	}
	defer connection.Release()

	if result, err := oleutil.CallMethod(connection, "Open", "Provider=ADsDSOObject;"); err != nil {
		t.Fatalf("open ADSI provider: %v", err)
	} else if result != nil {
		defer result.Clear()
	}
	defer oleutil.CallMethod(connection, "Close")

	commandUnknown, err := oleutil.CreateObject("ADODB.Command")
	if err != nil {
		t.Fatalf("create ADODB command: %v", err)
	}
	defer commandUnknown.Release()

	command, err := commandUnknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		t.Fatalf("query ADODB command interface: %v", err)
	}
	defer command.Release()

	if result, err := oleutil.PutPropertyRef(command, "ActiveConnection", connection); err != nil {
		t.Fatalf("set active connection: %v", err)
	} else if result != nil {
		result.Clear()
	}

	if err := setADOCommandProperty(command, "Page Size", adsiPageSize); err != nil {
		t.Fatalf("set Page Size: %v", err)
	}
}
