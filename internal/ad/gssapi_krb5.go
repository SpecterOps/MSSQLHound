// Package ad - Cross-platform Kerberos GSSAPI client using gokrb5.
// This is used when --kerberos is specified, providing Kerberos auth
// on all platforms (Linux, Mac, Windows) without requiring OS-level SSPI.
package ad

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/SpecterOps/MSSQLHound/internal/logging"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// gokrb5GSSAPIClient implements ldap.GSSAPIClient using gokrb5.
type gokrb5GSSAPIClient struct {
	krb5Client   *client.Client
	spnegoClient *spnego.SPNEGO
	// overTLS indicates the LDAP connection is already TLS-protected (LDAPS or
	// StartTLS). When true, InitSecContext omits the Integrity and Confidentiality
	// GSS flags from the AP-REQ authenticator checksum so that Active Directory
	// does not reject the bind with "Cannot bind using sign/seal on a connection
	// on which TLS or SSL is in effect".
	overTLS bool
	// Optional logger for dumping Kerberos service tickets.
	logger *slog.Logger
}

// newKerberosGSSAPIClient creates a GSSAPI client backed by gokrb5 for cross-platform Kerberos.
// If overTLS is true, the resulting client will not request signing/sealing in the
// GSSAPI context, which is required when binding over LDAPS or LDAP+StartTLS.
// If logger is non-nil, the base64-encoded SPNEGO token is logged at Info level.
func newKerberosGSSAPIClient(krb5ConfigFile, ccacheFile, keytabFile, realm, user, password string, overTLS bool, logger *slog.Logger) (ldap.GSSAPIClient, func() error, error) {
	cfg, err := loadKrb5Config(krb5ConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("loading krb5 config: %w", err)
	}

	krb5Client, err := createKrb5Client(cfg, ccacheFile, keytabFile, realm, user, password)
	if err != nil {
		return nil, nil, fmt.Errorf("creating Kerberos client: %w", err)
	}

	if err := krb5Client.Login(); err != nil {
		krb5Client.Destroy()
		return nil, nil, fmt.Errorf("Kerberos login: %w", err)
	}

	gssClient := &gokrb5GSSAPIClient{
		krb5Client: krb5Client,
		overTLS:    overTLS,
		logger:     logger,
	}
	// closeFn is a no-op: cleanup is handled by DeleteSecContext which is
	// called by go-ldap's GSSAPIBind via defer. Destroying here would nil
	// the client before the bind completes.
	closeFn := func() error { return nil }
	return gssClient, closeFn, nil
}

func loadKrb5Config(configFile string) (*config.Config, error) {
	if configFile == "" {
		configFile = os.Getenv("KRB5_CONFIG")
	}
	if configFile == "" {
		configFile = "/etc/krb5.conf"
	}
	f, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := config.NewFromReader(f)
	if err != nil {
		return nil, err
	}
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.UDPPreferenceLimit = 1
	return cfg, nil
}

func createKrb5Client(cfg *config.Config, ccacheFile, keytabFile, realm, user, password string) (*client.Client, error) {
	username := user
	if realm == "" {
		if parts := strings.SplitN(user, "@", 2); len(parts) == 2 {
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
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}
	realm = strings.ToUpper(realm)

	if username != "" && password != "" {
		return client.NewWithPassword(username, realm, password, cfg, client.DisablePAFXFAST(true)), nil
	}

	if keytabFile != "" {
		data, err := os.ReadFile(keytabFile)
		if err != nil {
			return nil, fmt.Errorf("reading keytab %s: %w", keytabFile, err)
		}
		kt := &keytab.Keytab{}
		if err := kt.Unmarshal(data); err != nil {
			return nil, fmt.Errorf("parsing keytab: %w", err)
		}
		if username == "" {
			return nil, fmt.Errorf("username required with keytab")
		}
		return client.NewWithKeytab(username, realm, kt, cfg, client.DisablePAFXFAST(true)), nil
	}

	if ccacheFile == "" {
		ccacheFile = os.Getenv("KRB5CCNAME")
	}
	// Strip FILE: prefix (standard Kerberos ccache path format)
	ccacheFile = strings.TrimPrefix(ccacheFile, "FILE:")
	if ccacheFile != "" {
		cache, err := credentials.LoadCCache(ccacheFile)
		if err != nil {
			return nil, fmt.Errorf("loading ccache %s: %w", ccacheFile, err)
		}
		return client.NewFromCCache(cache, cfg, client.DisablePAFXFAST(true))
	}

	return nil, fmt.Errorf("no Kerberos credentials available (need password, keytab, or ccache)")
}

// InitSecContext implements ldap.GSSAPIClient.
func (c *gokrb5GSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	if c.krb5Client == nil {
		return nil, false, fmt.Errorf("Kerberos client has been destroyed")
	}
	if token == nil {
		// First call: create the initial SPNEGO token.
		//
		// When the LDAP connection is already TLS-protected, we must NOT include
		// the Integrity (ContextFlagInteg) or Confidentiality (ContextFlagConf)
		// GSS flags. Active Directory rejects GSSAPI SASL binds that request
		// sign/seal over TLS with error "Cannot bind using sign/seal on a
		// connection on which TLS or SSL is in effect".
		//
		// Over plain LDAP we request Integ+Conf so that GSSAPI provides its own
		// signing/sealing to protect credentials on the wire.
		tkt, key, err := c.krb5Client.GetServiceTicket(target)
		if err != nil {
			return nil, false, fmt.Errorf("GetServiceTicket: %w", err)
		}

		var flags []int
		if c.overTLS {
			// TLS already provides integrity and confidentiality; omit all GSS
			// security flags so AD does not reject the bind with sign/seal errors.
			flags = []int{}
		} else {
			// Plain LDAP: request signing and sealing for credential protection.
			flags = []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
		}

		krb5Token, err := spnego.NewKRB5TokenAPREQ(c.krb5Client, tkt, key, flags, []int{})
		if err != nil {
			return nil, false, fmt.Errorf("creating KRB5 AP-REQ token: %w", err)
		}

		// Wrap in SPNEGO NegTokenInit
		mechTokenBytes, err := krb5Token.Marshal()
		if err != nil {
			return nil, false, fmt.Errorf("marshalling KRB5 token: %w", err)
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
			return nil, false, fmt.Errorf("marshaling SPNEGO token: %w", err)
		}

		if c.logger != nil {
			c.logger.Log(context.Background(), logging.LevelVerbose, "Kerberos SPNEGO token",
				"spn", target,
				"token_b64", base64.StdEncoding.EncodeToString(tokenBytes),
			)
		}

		// Over TLS without mutual auth, SPNEGO completes in one round trip:
		// the server validates the AP-REQ and returns success immediately.
		// Return needInit=false so go-ldap's loop can break when the server
		// responds with resultCode=0. (Returning true would cause an infinite
		// loop because go-ldap only breaks when !needInit && len(recvToken)==0.)
		//
		// Over plain LDAP, the server may send a NegTokenResp that requires
		// another InitSecContext round, so we keep needInit=true.
		needMore := !c.overTLS
		return tokenBytes, needMore, nil
	}

	// Second call (plain LDAP only): process the server's SPNEGO NegTokenResp.
	var resp spnego.SPNEGOToken
	if err := resp.Unmarshal(token); err != nil {
		return nil, false, fmt.Errorf("unmarshaling SPNEGO response: %w", err)
	}
	ok, status := resp.Verify()
	if !ok {
		if status.Code == gssapi.StatusContinueNeeded {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("SPNEGO verification failed: %v", status)
	}
	return nil, false, nil
}

// NegotiateSaslAuth implements ldap.GSSAPIClient per RFC 4752 section 3.1.
func (c *gokrb5GSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	if len(token) < 4 {
		return nil, fmt.Errorf("invalid SASL token from server (len=%d)", len(token))
	}

	// Select no security layer, zero buffer size
	response := make([]byte, 4+len(authzid))
	response[0] = 0x00 // No security layer
	binary.BigEndian.PutUint32(response[:4], 0)
	response[0] = 0x00 // Overwrite: no security layer
	copy(response[4:], []byte(authzid))

	return response, nil
}

// DeleteSecContext implements ldap.GSSAPIClient.
func (c *gokrb5GSSAPIClient) DeleteSecContext() error {
	if c.krb5Client != nil {
		c.krb5Client.Destroy()
		c.krb5Client = nil
	}
	return nil
}
