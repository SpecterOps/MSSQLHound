// Package mssql - Custom NTLM authentication provider with EPA channel binding support.
// This bridges the go-mssqldb integratedauth interface with our custom ntlmAuth
// implementation that supports MsvAvChannelBindings and MsvAvTargetName AV_PAIRs.
//
// go-mssqldb's built-in NTLM implementation (integratedauth/ntlm) does NOT include
// EPA channel binding tokens, causing authentication failures when SQL Server has
// Extended Protection set to "Required". This provider solves that by injecting
// the correct CBT (computed from the TLS server certificate) into the NTLM Type3 message.
package mssql

import (
	"fmt"
	"strings"
	"sync"

	"github.com/microsoft/go-mssqldb/integratedauth"
	"github.com/microsoft/go-mssqldb/msdsn"
)

const epaAuthProviderName = "epa-ntlm"

// epaAuthProvider implements integratedauth.Provider with EPA channel binding support.
// It creates authenticators that use our custom ntlmAuth implementation which
// supports MsvAvChannelBindings and MsvAvTargetName AV_PAIRs in the NTLM Type3 message.
type epaAuthProvider struct {
	mu      sync.Mutex
	cbt     []byte // Channel binding token (16-byte MD5 of SEC_CHANNEL_BINDINGS)
	spn     string // Service Principal Name (MSSQLSvc/hostname:port)
	verbose bool
	debug   bool
}

// SetCBT stores the channel binding hash for the next authentication.
// This is typically called from a TLS VerifyPeerCertificate callback during
// the go-mssqldb TLS handshake, before GetIntegratedAuthenticator is invoked.
func (p *epaAuthProvider) SetCBT(cbt []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cbt = make([]byte, len(cbt))
	copy(p.cbt, cbt)
}

// SetSPN stores the service principal name for authentication.
func (p *epaAuthProvider) SetSPN(spn string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.spn = spn
}

// GetIntegratedAuthenticator creates a new NTLM authenticator with EPA support.
// This is called by go-mssqldb after the TLS handshake completes, so the CBT
// captured via VerifyPeerCertificate is already available.
func (p *epaAuthProvider) GetIntegratedAuthenticator(config msdsn.Config) (integratedauth.IntegratedAuthenticator, error) {
	if !strings.ContainsRune(config.User, '\\') {
		return nil, fmt.Errorf("epa-ntlm: invalid username format, expected DOMAIN\\user: %v", config.User)
	}
	parts := strings.SplitN(config.User, "\\", 2)
	domain, username := parts[0], parts[1]

	p.mu.Lock()
	cbt := make([]byte, len(p.cbt))
	copy(cbt, p.cbt)
	spn := p.spn
	p.mu.Unlock()

	if p.debug {
		fmt.Printf("    [EPA-auth] GetIntegratedAuthenticator: domain=%s, user=%s, spn=%s, cbt=%x (%d bytes)\n",
			domain, username, spn, cbt, len(cbt))
	}

	auth := newNTLMAuth(domain, username, config.Password, spn)
	auth.SetEPATestMode(EPATestNormal)
	if len(cbt) == 16 {
		auth.SetChannelBindingHash(cbt)
	} else if p.debug {
		fmt.Printf("    [EPA-auth] WARNING: CBT not set (len=%d, expected 16)!\n", len(cbt))
	}

	return &epaAuthenticator{auth: auth}, nil
}

// epaAuthenticator implements integratedauth.IntegratedAuthenticator using
// the custom ntlmAuth with EPA channel binding support.
type epaAuthenticator struct {
	auth *ntlmAuth
}

// InitialBytes returns the NTLM Type1 (Negotiate) message.
func (a *epaAuthenticator) InitialBytes() ([]byte, error) {
	return a.auth.CreateNegotiateMessage(), nil
}

// NextBytes processes the NTLM Type2 (Challenge) and returns the Type3 (Authenticate)
// message with EPA channel binding and service binding AV_PAIRs.
func (a *epaAuthenticator) NextBytes(challengeBytes []byte) ([]byte, error) {
	if err := a.auth.ProcessChallenge(challengeBytes); err != nil {
		return nil, fmt.Errorf("epa-ntlm: processing challenge: %w", err)
	}
	return a.auth.CreateAuthenticateMessage()
}

// Free releases any resources held by the authenticator.
func (a *epaAuthenticator) Free() {}
