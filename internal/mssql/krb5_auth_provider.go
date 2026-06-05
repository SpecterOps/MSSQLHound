// Package mssql - Custom Kerberos authentication provider for go-mssqldb.
//
// go-mssqldb's built-in krb5 provider (integratedauth/krb5) uses gokrb5's
// spnego.SPNEGOClient.InitSecContext() which hardcodes ContextFlagInteg and
// ContextFlagConf in the AP-REQ authenticator checksum. This can cause SQL
// Server to reject the token with "untrusted domain" errors when the connection
// is TLS-encrypted or EPA is enabled.
//
// This provider builds the SPNEGO token manually (same approach as the LDAP
// GSSAPI bind fix in gssapi_krb5.go) with empty GSS flags, giving us full
// control over the token generation.
package mssql

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/microsoft/go-mssqldb/integratedauth"
	"github.com/microsoft/go-mssqldb/msdsn"
)

const krb5CustomProviderName = "krb5-custom"

// krb5CustomProvider implements integratedauth.Provider using our own SPNEGO
// token generation with controllable GSS flags.
type krb5CustomProvider struct {
	krb5ConfigFile string
	krb5CCacheFile string
	krb5KeytabFile string
	krb5Realm      string
	verbose        bool
	logger         *slog.Logger
}

// GetIntegratedAuthenticator creates a custom Kerberos authenticator.
func (p *krb5CustomProvider) GetIntegratedAuthenticator(cfg msdsn.Config) (integratedauth.IntegratedAuthenticator, error) {
	// Parse username: handle user@realm and DOMAIN\user formats
	username := cfg.User
	realm := p.krb5Realm

	if realm == "" {
		if parts := strings.SplitN(username, "@", 2); len(parts) == 2 {
			username = parts[0]
			realm = parts[1]
		}
	}
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		if realm == "" {
			realm = parts[0]
		}
		username = parts[1]
	}

	// Load krb5 config
	krb5ConfigFile := p.krb5ConfigFile
	if krb5ConfigFile == "" {
		krb5ConfigFile = os.Getenv("KRB5_CONFIG")
	}
	if krb5ConfigFile == "" {
		krb5ConfigFile = "/etc/krb5.conf"
	}

	f, err := os.Open(krb5ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("krb5-custom: opening krb5 config %s: %w", krb5ConfigFile, err)
	}
	krb5Cfg, err := config.NewFromReader(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("krb5-custom: parsing krb5 config: %w", err)
	}
	krb5Cfg.LibDefaults.DNSLookupKDC = true
	krb5Cfg.LibDefaults.UDPPreferenceLimit = 1

	if realm == "" {
		realm = krb5Cfg.LibDefaults.DefaultRealm
	}
	realm = strings.ToUpper(realm)

	// Create Kerberos client based on available credentials
	var krb5Client *client.Client

	switch {
	case username != "" && cfg.Password != "":
		krb5Client = client.NewWithPassword(username, realm, cfg.Password, krb5Cfg, client.DisablePAFXFAST(true))

	case p.krb5KeytabFile != "":
		data, err := os.ReadFile(p.krb5KeytabFile)
		if err != nil {
			return nil, fmt.Errorf("krb5-custom: reading keytab: %w", err)
		}
		kt := &keytab.Keytab{}
		if err := kt.Unmarshal(data); err != nil {
			return nil, fmt.Errorf("krb5-custom: parsing keytab: %w", err)
		}
		krb5Client = client.NewWithKeytab(username, realm, kt, krb5Cfg, client.DisablePAFXFAST(true))

	default:
		// Try credential cache
		ccacheFile := p.krb5CCacheFile
		if ccacheFile == "" {
			ccacheFile = os.Getenv("KRB5CCNAME")
		}
		ccacheFile = strings.TrimPrefix(ccacheFile, "FILE:")
		if ccacheFile == "" {
			return nil, fmt.Errorf("krb5-custom: no credentials available (need password, keytab, or ccache)")
		}
		cache, err := credentials.LoadCCache(ccacheFile)
		if err != nil {
			return nil, fmt.Errorf("krb5-custom: loading ccache: %w", err)
		}
		krb5Client, err = client.NewFromCCache(cache, krb5Cfg, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("krb5-custom: creating client from ccache: %w", err)
		}
	}

	if err := krb5Client.Login(); err != nil {
		krb5Client.Destroy()
		return nil, fmt.Errorf("krb5-custom: Kerberos login: %w", err)
	}

	if p.verbose && p.logger != nil {
		p.logger.Log(context.Background(), logging.LevelVerbose, "Kerberos client created",
			"username", username,
			"realm", realm,
			"serverSPN", cfg.ServerSPN,
		)
	}

	return &krb5CustomAuthenticator{
		krb5Client: krb5Client,
		serverSPN:  cfg.ServerSPN,
		verbose:    p.verbose,
		logger:     p.logger,
	}, nil
}

// krb5CustomAuthenticator implements integratedauth.IntegratedAuthenticator
// with our own SPNEGO token generation.
type krb5CustomAuthenticator struct {
	krb5Client *client.Client
	serverSPN  string
	verbose    bool
	logger     *slog.Logger
}

// InitialBytes generates the SPNEGO token with empty GSS flags (no sign/seal).
func (a *krb5CustomAuthenticator) InitialBytes() ([]byte, error) {
	// Canonicalize the SPN by resolving CNAMEs
	targetSPN := canonicalizeSPN(a.serverSPN)

	tkt, key, err := a.krb5Client.GetServiceTicket(targetSPN)
	if err != nil {
		return nil, fmt.Errorf("krb5-custom: GetServiceTicket for %s: %w", targetSPN, err)
	}

	// Build AP-REQ matching Windows SSPI behavior:
	// - GSS flags: Mutual + Integrity + Confidentiality (Windows ISC_REQ_* flags)
	// - AP options: MutualRequired (Windows always requests mutual auth)
	// These flags are expected by SQL Server's AcceptSecurityContext.
	gssFlags := []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
	apOptions := []int{flags.APOptionMutualRequired}
	krb5Token, err := spnego.NewKRB5TokenAPREQ(a.krb5Client, tkt, key, gssFlags, apOptions)
	if err != nil {
		return nil, fmt.Errorf("krb5-custom: creating AP-REQ: %w", err)
	}

	mechTokenBytes, err := krb5Token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("krb5-custom: marshalling KRB5 token: %w", err)
	}

	negInit := spnego.NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mechTokenBytes,
	}

	spnegoToken := &spnego.SPNEGOToken{
		Init:         true,
		NegTokenInit: negInit,
	}

	tokenBytes, err := spnegoToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("krb5-custom: marshaling SPNEGO token: %w", err)
	}

	if a.verbose && a.logger != nil {
		a.logger.Log(context.Background(), logging.LevelVerbose, "Kerberos SPNEGO token",
			"spn", targetSPN,
			"token_b64", base64.StdEncoding.EncodeToString(tokenBytes),
		)
	}

	return tokenBytes, nil
}

// NextBytes processes the server's SPNEGO response (NegTokenResp).
// gokrb5's Verify() doesn't support AP-REP tokens, so we check the NegState
// directly instead of calling Verify(). When the server sends accept-complete
// (with an AP-REP for mutual auth), we accept without trying to verify the
// AP-REP cryptographically.
func (a *krb5CustomAuthenticator) NextBytes(serverToken []byte) ([]byte, error) {
	var resp spnego.SPNEGOToken
	if err := resp.Unmarshal(serverToken); err != nil {
		return nil, err
	}

	if resp.Resp {
		state := spnego.NegState(resp.NegTokenResp.NegState)
		if a.verbose && a.logger != nil {
			a.logger.Log(context.Background(), logging.LevelVerbose, "SPNEGO NegTokenResp received",
				"negState", int(state),
			)
		}
		switch state {
		case spnego.NegStateAcceptCompleted:
			return nil, nil
		case spnego.NegStateAcceptIncomplete:
			// The server sent accept-incomplete (mutual auth AP-REP). The TDS
			// protocol expects the client to send a packSSPIMessage in response.
			// Return a minimal valid empty SPNEGO NegTokenResp to acknowledge.
			ackResp := spnego.NegTokenResp{
				NegState: asn1.Enumerated(spnego.NegStateAcceptCompleted),
			}
			ackBytes, err := ackResp.Marshal()
			if err != nil {
				return nil, nil // fall back to empty
			}
			return ackBytes, nil
		case spnego.NegStateReject:
			return nil, fmt.Errorf("krb5-custom: server rejected SPNEGO negotiation")
		case spnego.NegStateRequestMIC:
			return nil, fmt.Errorf("krb5-custom: server requested MIC (unsupported)")
		}
	}

	return nil, nil
}

// Free releases Kerberos resources.
func (a *krb5CustomAuthenticator) Free() {
	if a.krb5Client != nil {
		a.krb5Client.Destroy()
		a.krb5Client = nil
	}
}

// canonicalizeSPN resolves CNAMEs in the SPN hostname, matching the behavior
// of go-mssqldb's built-in krb5 provider.
func canonicalizeSPN(service string) string {
	parts := strings.SplitAfterN(service, "/", 2)
	if len(parts) != 2 {
		return service
	}
	host, port, err := net.SplitHostPort(parts[1])
	if err != nil {
		return service
	}
	cname, err := net.LookupCNAME(strings.ToLower(host))
	if err != nil || cname == "" {
		return service
	}
	return parts[0] + net.JoinHostPort(strings.TrimSuffix(cname, "."), port)
}
