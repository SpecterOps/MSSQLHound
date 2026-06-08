package ad

import (
	"errors"
	"reflect"
	"testing"
)

func TestIsLDAPSSPIChannelBindingError(t *testing.T) {
	err := errors.New(`LDAP Result Code 49 "Invalid Credentials": 80090346: LdapErr: DSID-0C0906B0, comment: AcceptSecurityContext error, data 80090346, v4f7c`)
	if !isLDAPAuthError(err) {
		t.Fatal("expected result 49 to be classified as an LDAP auth error")
	}
	if !isLDAPSSPIChannelBindingError(err) {
		t.Fatal("expected 80090346 to be classified as an SSPI channel binding error")
	}
}

func TestIsLDAPAuthErrorWithoutChannelBinding(t *testing.T) {
	err := errors.New(`LDAP Result Code 49 "Invalid Credentials": data 52e`)
	if !isLDAPAuthError(err) {
		t.Fatal("expected result 49 to be classified as an LDAP auth error")
	}
	if isLDAPSSPIChannelBindingError(err) {
		t.Fatal("did not expect generic invalid credentials to be classified as channel binding")
	}
}

func TestSimpleBindNamesDomainUserUsesConfiguredDNSDomainFirst(t *testing.T) {
	client := NewClient("mayyhem.com", "", false, `MAYYHEM\domainadmin`, "password", "")
	want := []string{
		"domainadmin@mayyhem.com",
		`MAYYHEM\domainadmin`,
		"domainadmin@MAYYHEM",
	}
	if got := client.simpleBindNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("simpleBindNames() = %#v, want %#v", got, want)
	}
}

func TestSimpleBindNamesUPNAndBareUser(t *testing.T) {
	upnClient := NewClient("mayyhem.com", "", false, "domainadmin@mayyhem.com", "password", "")
	if got, want := upnClient.simpleBindNames(), []string{"domainadmin@mayyhem.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UPN simpleBindNames() = %#v, want %#v", got, want)
	}

	bareClient := NewClient("mayyhem.com", "", false, "domainadmin", "password", "")
	if got, want := bareClient.simpleBindNames(), []string{"domainadmin@mayyhem.com", "domainadmin"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bare simpleBindNames() = %#v, want %#v", got, want)
	}
}
