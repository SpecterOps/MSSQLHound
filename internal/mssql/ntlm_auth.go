// Package mssql - NTLMv2 authentication with controllable AV_PAIRs for EPA testing.
// Implements NTLM Type1/Type2/Type3 message generation with the ability to
// add, remove, or modify MsvAvChannelBindings and MsvAvTargetName AV_PAIRs.
package mssql

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NTLM AV_PAIR IDs (MS-NLMP 2.2.2.1).
// AV_PAIRs are typed attribute-value pairs embedded in the Type2 (Challenge)
// target info payload. The client parses these to extract the server's identity
// and timestamp, then rebuilds them in the Type3 (Authenticate) blob to convey
// EPA channel bindings (MsvAvChannelBindings) and service binding (MsvAvTargetName).
const (
	avIDMsvAvEOL             uint16 = 0x0000 // Terminator; marks the end of the AV_PAIR list
	avIDMsvAvNbComputerName  uint16 = 0x0001 // NetBIOS computer name of the server
	avIDMsvAvNbDomainName    uint16 = 0x0002 // NetBIOS domain name; used as input to NTLMv2 hash computation
	avIDMsvAvDNSComputerName uint16 = 0x0003 // FQDN of the server
	avIDMsvAvDNSDomainName   uint16 = 0x0004 // DNS domain name (e.g. "corp.example.com")
	avIDMsvAvDNSTreeName     uint16 = 0x0005 // DNS forest tree name
	avIDMsvAvFlags           uint16 = 0x0006 // Bitfield; bit 0x02 = MIC is present in the Type3 message
	avIDMsvAvTimestamp       uint16 = 0x0007 // 8-byte Windows FILETIME; used as the blob timestamp in Type3
	avIDMsvAvTargetName      uint16 = 0x0009 // SPN target name for service binding (EPA); e.g. "MSSQLSvc/host:1433"
	avIDMsvChannelBindings   uint16 = 0x000A // 16-byte MD5 of SEC_CHANNEL_BINDINGS for channel binding token (EPA)
)

// NTLM negotiate flags (MS-NLMP 2.2.2.5 NEGOTIATE).
// These flags are set in Type1 (Negotiate) and echoed/adjusted in Type2/Type3.
// They fall into three categories:
//   - Encoding: Unicode and OEM control string encoding (Unicode is required for NTLMv2).
//   - Authentication: NTLM, AlwaysSign, and ExtendedSessionSecurity select the NTLMv2
//     authentication scheme. ExtendedSessionSecurity is critical -- it enables NTLMv2
//     session security and is required for EPA channel binding to function.
//   - Capabilities: TargetInfo requests AV_PAIRs in the Type2 challenge (needed for
//     EPA), Version includes the OS version block, and 128/56/KeyExch control session
//     key strength and exchange.
const (
	ntlmFlagUnicode                 uint32 = 0x00000001 // NTLMSSP_NEGOTIATE_UNICODE: use UTF-16LE encoding
	ntlmFlagOEM                     uint32 = 0x00000002 // NTLMSSP_NEGOTIATE_OEM: support OEM character set
	ntlmFlagRequestTarget           uint32 = 0x00000004 // NTLMSSP_REQUEST_TARGET: request TargetName in Type2
	ntlmFlagSign                    uint32 = 0x00000010 // NTLMSSP_NEGOTIATE_SIGN: session signing capability
	ntlmFlagSeal                    uint32 = 0x00000020 // NTLMSSP_NEGOTIATE_SEAL: session sealing (encryption)
	ntlmFlagNTLM                    uint32 = 0x00000200 // NTLMSSP_NEGOTIATE_NTLM: NTLM authentication scheme
	ntlmFlagAlwaysSign              uint32 = 0x00008000 // NTLMSSP_NEGOTIATE_ALWAYS_SIGN: signing required on session
	ntlmFlagDomainSupplied          uint32 = 0x00001000 // NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	ntlmFlagWorkstationSupplied     uint32 = 0x00002000 // NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	ntlmFlagExtendedSessionSecurity uint32 = 0x00080000 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: NTLMv2 session security; required for EPA
	ntlmFlagTargetInfo              uint32 = 0x00800000 // NTLMSSP_NEGOTIATE_TARGET_INFO: server must include AV_PAIRs in Type2
	ntlmFlagVersion                 uint32 = 0x02000000 // NTLMSSP_NEGOTIATE_VERSION: include NTLM version block
	ntlmFlag128                     uint32 = 0x20000000 // NTLMSSP_NEGOTIATE_128: 128-bit session key
	ntlmFlagKeyExch                 uint32 = 0x40000000 // NTLMSSP_NEGOTIATE_KEY_EXCH: encrypted session key exchange
	ntlmFlag56                      uint32 = 0x80000000 // NTLMSSP_NEGOTIATE_56: 56-bit session key (legacy fallback)
)

// MsvAvFlags bit values
const (
	msvAvFlagMICPresent uint32 = 0x00000002
)

// NTLM message types
const (
	ntlmNegotiateType    uint32 = 1
	ntlmChallengeType    uint32 = 2
	ntlmAuthenticateType uint32 = 3
)

// EPATestMode controls what AV_PAIRs are included/excluded in the NTLM Type3 message.
type EPATestMode int

const (
	// EPATestNormal includes correct CBT and service binding
	EPATestNormal EPATestMode = iota
	// EPATestBogusCBT includes incorrect CBT hash
	EPATestBogusCBT
	// EPATestMissingCBT excludes MsvAvChannelBindings AV_PAIR entirely
	EPATestMissingCBT
	// EPATestBogusService includes incorrect service name ("cifs")
	EPATestBogusService
	// EPATestMissingService excludes MsvAvTargetName and strips target service
	EPATestMissingService
)

// ntlmAVPair represents a single AV_PAIR entry in NTLM target info.
type ntlmAVPair struct {
	ID    uint16
	Value []byte
}

// ntlmAuth handles NTLMv2 authentication with controllable EPA settings.
type ntlmAuth struct {
	domain     string
	username   string
	password   string
	ntHash     []byte // Pre-computed NT hash (16 bytes) for pass-the-hash; skips MD4(password) when set
	targetName string // SPN e.g. MSSQLSvc/hostname:port

	testMode           EPATestMode
	channelBindingHash []byte // 16-byte MD5 of SEC_CHANNEL_BINDINGS
	disableMIC         bool   // When true, omit MsvAvFlags and MIC from Type3 (diagnostic bypass)
	useRawTargetInfo   bool   // When true, use server's target info unmodified (no EPA, no MIC) - diagnostic baseline
	useClientTimestamp bool   // When true, use time.Now() instead of server's MsvAvTimestamp (diagnostic)

	// State preserved across message generation
	negotiateMsg    []byte
	challengeMsg    []byte // Raw Type2 bytes from server (needed for MIC computation)
	serverChallenge [8]byte
	targetInfoRaw   []byte
	negotiateFlags  uint32
	timestamp       []byte // 8-byte FILETIME from server
	serverDomain    string // NetBIOS domain name from Type2 MsvAvNbDomainName (for NTLMv2 hash)
}

func newNTLMAuth(domain, username, password, targetName string) *ntlmAuth {
	return &ntlmAuth{
		domain:     domain,
		username:   username,
		password:   password,
		targetName: targetName,
		testMode:   EPATestNormal,
	}
}

// SetEPATestMode configures how CBT and service binding are handled.
func (a *ntlmAuth) SetEPATestMode(mode EPATestMode) {
	a.testMode = mode
}

// SetChannelBindingHash sets the CBT hash computed from the TLS session.
func (a *ntlmAuth) SetChannelBindingHash(hash []byte) {
	a.channelBindingHash = hash
}

// SetDisableMIC disables MIC computation and MsvAvFlags in the Type3 message.
// This is a diagnostic tool to isolate whether incorrect MIC is causing auth failures.
func (a *ntlmAuth) SetDisableMIC(disable bool) {
	a.disableMIC = disable
}

// SetUseRawTargetInfo enables raw target info mode: uses the server's target info
// unmodified (no MsvAvFlags, no CBT, no SPN, no MIC). This matches go-mssqldb's
// baseline NTLM behavior and is used as a diagnostic to verify base NTLM auth works.
func (a *ntlmAuth) SetUseRawTargetInfo(raw bool) {
	a.useRawTargetInfo = raw
}

// SetUseClientTimestamp enables client-generated timestamp instead of server's
// MsvAvTimestamp. go-mssqldb uses time.Now() for the blob timestamp. This is a
// diagnostic to isolate timestamp-related auth failures.
func (a *ntlmAuth) SetUseClientTimestamp(use bool) {
	a.useClientTimestamp = use
}

// SetNTHash sets a pre-computed NT hash (16 bytes) for pass-the-hash authentication.
// When set, the password field is ignored and the MD4(UTF16LE(password)) step is skipped.
func (a *ntlmAuth) SetNTHash(hash []byte) {
	a.ntHash = hash
}

// GetAuthDomain returns the domain that will be used for NTLMv2 hash computation.
func (a *ntlmAuth) GetAuthDomain() string {
	return a.domain
}

// ComputeNTLMv2HashHex returns the hex-encoded NTLMv2 hash for diagnostic logging.
func (a *ntlmAuth) ComputeNTLMv2HashHex() string {
	hash := a.computeNTLMv2HashResolved()
	return fmt.Sprintf("%x", hash)
}

// computeNTLMv2HashResolved returns the NTLMv2 hash, using the pre-computed NT hash if set.
func (a *ntlmAuth) computeNTLMv2HashResolved() []byte {
	if len(a.ntHash) > 0 {
		return computeNTLMv2HashFromNT(a.ntHash, a.username, a.domain)
	}
	return computeNTLMv2Hash(a.password, a.username, a.domain)
}

// GetTargetInfoPairs returns the parsed AV_PAIRs from the server's Type2 target info
// for diagnostic logging.
func (a *ntlmAuth) GetTargetInfoPairs() []ntlmAVPair {
	if a.targetInfoRaw == nil {
		return nil
	}
	return parseAVPairs(a.targetInfoRaw)
}

// AVPairName returns a human-readable name for an AV_PAIR ID.
func AVPairName(id uint16) string {
	switch id {
	case avIDMsvAvEOL:
		return "MsvAvEOL"
	case avIDMsvAvNbComputerName:
		return "MsvAvNbComputerName"
	case avIDMsvAvNbDomainName:
		return "MsvAvNbDomainName"
	case avIDMsvAvDNSComputerName:
		return "MsvAvDNSComputerName"
	case avIDMsvAvDNSDomainName:
		return "MsvAvDNSDomainName"
	case avIDMsvAvDNSTreeName:
		return "MsvAvDNSTreeName"
	case avIDMsvAvFlags:
		return "MsvAvFlags"
	case avIDMsvAvTimestamp:
		return "MsvAvTimestamp"
	case avIDMsvAvTargetName:
		return "MsvAvTargetName"
	case avIDMsvChannelBindings:
		return "MsvAvChannelBindings"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", id)
	}
}

// CreateNegotiateMessage builds the NTLM Type1 (Negotiate) message per MS-NLMP
// Section 3.1.5.1.1. This is the first message in the NTLM 3-way handshake:
//   Type1 (client -> server) -> Type2 (server -> client) -> Type3 (client -> server)
//
// The Type1 message advertises the client's capabilities via negotiate flags and
// optionally includes domain/workstation payloads. We intentionally omit the
// domain payload: SQL Server rejects Type1 messages with a domain field before
// issuing a Type2 challenge, returning an "untrusted domain" error. The domain
// is instead supplied in the Type3 Authenticate message.
func (a *ntlmAuth) CreateNegotiateMessage() []byte {
	flags := ntlmFlagUnicode |
		ntlmFlagOEM |
		ntlmFlagRequestTarget |
		ntlmFlagNTLM |
		ntlmFlagAlwaysSign |
		ntlmFlagExtendedSessionSecurity |
		ntlmFlagTargetInfo |
		ntlmFlagVersion |
		ntlmFlag128 |
		ntlmFlag56

	// Minimal Type1: signature(8) + type(4) + flags(4) + domain fields(8) + workstation fields(8) + version(8)
	msg := make([]byte, 40)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], ntlmNegotiateType)
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	// Domain Name Fields (empty)
	// Workstation Fields (empty)
	// Version: 10.0.20348 (Windows Server 2022)
	msg[32] = 10                                     // Major
	msg[33] = 0                                      // Minor
	binary.LittleEndian.PutUint16(msg[34:36], 20348) // Build
	msg[39] = 0x0F                                   // NTLMSSP revision

	a.negotiateMsg = make([]byte, len(msg))
	copy(a.negotiateMsg, msg)
	return msg
}

// ProcessChallenge parses the NTLM Type2 (Challenge) message per MS-NLMP 2.2.1.2.
//
// Type2 byte layout:
//   Offset 0-7:   Signature ("NTLMSSP\x00")
//   Offset 8-11:  MessageType (uint32 = 2)
//   Offset 12-19: TargetNameFields (Len/MaxLen/Offset)
//   Offset 20-23: NegotiateFlags (uint32)
//   Offset 24-31: ServerChallenge (8 bytes -- the nonce for NTProofStr)
//   Offset 32-39: Reserved
//   Offset 40-47: TargetInfoFields (Len/MaxLen/Offset)
//   Offset 48+:   Version (optional), payload data
//
// Key extractions:
//   - ServerChallenge: 8-byte nonce used as HMAC input for NTProofStr in Type3.
//   - MsvAvNbDomainName: NetBIOS domain from the server's AV_PAIRs, stored in
//     serverDomain for NTLMv2 hash computation (though the user-provided domain
//     is used in practice -- see CreateAuthenticateMessage).
//   - MsvAvTimestamp: 8-byte FILETIME from the server's AV_PAIRs, used as the
//     blob timestamp in the Type3 NtChallengeResponse. Using the server's
//     timestamp (rather than a client-generated one) ensures the DC's replay
//     detection window is honored.
func (a *ntlmAuth) ProcessChallenge(challengeData []byte) error {
	if len(challengeData) < 32 {
		return fmt.Errorf("NTLM challenge too short: %d bytes", len(challengeData))
	}

	// Store raw challenge bytes for MIC computation (must use original bytes, not reconstructed)
	a.challengeMsg = make([]byte, len(challengeData))
	copy(a.challengeMsg, challengeData)

	sig := string(challengeData[0:8])
	if sig != "NTLMSSP\x00" {
		return fmt.Errorf("invalid NTLM signature")
	}

	msgType := binary.LittleEndian.Uint32(challengeData[8:12])
	if msgType != ntlmChallengeType {
		return fmt.Errorf("expected NTLM challenge (type 2), got type %d", msgType)
	}

	// Server challenge at offset 24 (8 bytes)
	copy(a.serverChallenge[:], challengeData[24:32])

	// Negotiate flags at offset 20
	a.negotiateFlags = binary.LittleEndian.Uint32(challengeData[20:24])

	// Target info fields at offsets 40-47 (if present)
	if len(challengeData) >= 48 {
		targetInfoLen := binary.LittleEndian.Uint16(challengeData[40:42])
		targetInfoOffset := binary.LittleEndian.Uint32(challengeData[44:48])

		if targetInfoLen > 0 && int(targetInfoOffset)+int(targetInfoLen) <= len(challengeData) {
			a.targetInfoRaw = make([]byte, targetInfoLen)
			copy(a.targetInfoRaw, challengeData[targetInfoOffset:targetInfoOffset+uint32(targetInfoLen)])

			// Extract timestamp and NetBIOS domain name from AV_PAIRs
			pairs := parseAVPairs(a.targetInfoRaw)
			for _, p := range pairs {
				if p.ID == avIDMsvAvTimestamp && len(p.Value) == 8 {
					a.timestamp = make([]byte, 8)
					copy(a.timestamp, p.Value)
				}
				if p.ID == avIDMsvAvNbDomainName && len(p.Value) > 0 {
					// Decode UTF-16LE domain name
					a.serverDomain = decodeUTF16LE(p.Value)
				}
			}
		}
	}

	return nil
}

// CreateAuthenticateMessage builds the NTLM Type3 (Authenticate) message per
// MS-NLMP Section 3.3.2. This is the final message in the handshake, containing
// the NTLMv2 proof-of-knowledge and (optionally) EPA bindings.
//
// NtChallengeResponse blob structure (MS-NLMP 3.3.2 NTLMv2_CLIENT_CHALLENGE):
//   ResponseType(1) + HiResponseType(1) + Reserved1(2) + Reserved2(4) +
//   TimeStamp(8) + ChallengeFromClient(8) + Reserved3(4) + AvPairs(variable) + Reserved4(4)
//   Total fixed overhead: 28 bytes + AV_PAIR payload + 4-byte trailing reserved.
//   NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge || blob) is prepended to form
//   the full NtChallengeResponse.
//
// Domain handling: authDomain uses the user-provided domain rather than
// serverDomain (MsvAvNbDomainName from Type2). Although MS-NLMP 3.3.2 suggests
// using MsvAvNbDomainName, real-world implementations (Windows SSPI, go-mssqldb,
// impacket) all use the user-supplied domain. The DC validates against the
// account's actual domain stored in AD.
//
// Type3 message layout uses an 88-byte header (matching go-mssqldb):
//   Offset 0-7:   Signature ("NTLMSSP\x00")
//   Offset 8-11:  MessageType (uint32 = 3)
//   Offset 12-19: LmChallengeResponse fields
//   Offset 20-27: NtChallengeResponse fields
//   Offset 28-35: DomainName fields
//   Offset 36-43: UserName fields
//   Offset 44-51: Workstation fields
//   Offset 52-59: EncryptedRandomSessionKey fields
//   Offset 60-63: NegotiateFlags
//   Offset 64-71: Version (zeroed)
//   Offset 72-87: MIC (16 bytes) -- HMAC-MD5(SessionBaseKey, Type1||Type2||Type3)
//   Offset 88+:   Payload data (LM, NT, domain, user, workstation)
func (a *ntlmAuth) CreateAuthenticateMessage() ([]byte, error) {
	if a.targetInfoRaw == nil {
		return nil, fmt.Errorf("no target info available from challenge")
	}

	// Generate client challenge (8 random bytes)
	var clientChallenge [8]byte
	if _, err := rand.Read(clientChallenge[:]); err != nil {
		return nil, fmt.Errorf("generating client challenge: %w", err)
	}

	// Determine which target info to use
	var targetInfoForBlob []byte
	if a.useRawTargetInfo {
		// Diagnostic mode: use server's raw target info unmodified (like go-mssqldb)
		targetInfoForBlob = a.targetInfoRaw
	} else {
		// Normal mode: build modified target info with EPA-controlled AV_PAIRs
		targetInfoForBlob = a.buildModifiedTargetInfo()
	}

	// Use server timestamp if available, otherwise generate one.
	// When useClientTimestamp is set, generate a Windows FILETIME from time.Now()
	// (this matches what some implementations like go-mssqldb do).
	var timestamp []byte
	if a.useClientTimestamp {
		timestamp = make([]byte, 8)
		// Windows FILETIME: 100-nanosecond intervals since January 1, 1601 (UTC).
		// The constant 116444736000000000 is the number of 100ns ticks between
		// the Windows epoch (1601-01-01) and the Unix epoch (1970-01-01):
		//   369 years * 365.2425 days/year * 86400 seconds/day * 10^7 ticks/second.
		// Go's UnixNano() returns nanoseconds since Unix epoch, so dividing by 100
		// converts to FILETIME ticks, then adding the offset shifts to the 1601 base.
		const windowsEpochDiff = 116444736000000000
		ft := uint64(time.Now().UnixNano()/100) + windowsEpochDiff
		binary.LittleEndian.PutUint64(timestamp, ft)
	} else if a.timestamp != nil {
		timestamp = a.timestamp
	} else {
		timestamp = make([]byte, 8)
	}

	// Compute NTLMv2 hash using the user-provided domain name.
	// Although MS-NLMP Section 3.3.2 says "UserDom SHOULD be set to MsvAvNbDomainName",
	// in practice Windows SSPI, go-mssqldb, and impacket all use the user-provided domain.
	// The DC validates against the account's actual domain (stored as uppercase in AD),
	// so the user-provided domain should match what the DC expects.
	// Tested both "MAYYHEM" (user) and "mayyhem" (server) - neither helped, confirming
	// the domain case is not the root cause of auth failures.
	authDomain := a.domain
	ntlmV2Hash := a.computeNTLMv2HashResolved()

	// Build the NtChallengeResponse blob (NTLMv2_CLIENT_CHALLENGE / temp)
	// Structure: ResponseType(1) + HiResponseType(1) + Reserved1(2) + Reserved2(4) +
	//            Timestamp(8) + ClientChallenge(8) + Reserved3(4) + TargetInfo + Reserved4(4)
	blobLen := 28 + len(targetInfoForBlob) + 4
	blob := make([]byte, blobLen)
	blob[0] = 0x01 // ResponseType
	blob[1] = 0x01 // HiResponseType
	copy(blob[8:16], timestamp)
	copy(blob[16:24], clientChallenge[:])
	copy(blob[28:], targetInfoForBlob)

	// Compute NTProofStr = HMAC_MD5(NTLMv2Hash, ServerChallenge + Blob)
	challengeAndBlob := make([]byte, 8+len(blob))
	copy(challengeAndBlob[:8], a.serverChallenge[:])
	copy(challengeAndBlob[8:], blob)
	ntProofStr := hmacMD5Sum(ntlmV2Hash, challengeAndBlob)

	// NtChallengeResponse = NTProofStr + Blob
	ntResponse := append(ntProofStr, blob...)

	// Session base key = HMAC_MD5(NTLMv2Hash, NTProofStr)
	sessionBaseKey := hmacMD5Sum(ntlmV2Hash, ntProofStr)

	// LmChallengeResponse: compute LMv2 (HMAC_MD5(NTLMv2Hash, serverChallenge + clientChallenge) + clientChallenge)
	// This matches go-mssqldb's behavior.
	challengeAndNonce := make([]byte, 16)
	copy(challengeAndNonce[:8], a.serverChallenge[:])
	copy(challengeAndNonce[8:], clientChallenge[:])
	lmHash := hmacMD5Sum(ntlmV2Hash, challengeAndNonce)
	lmResponse := append(lmHash, clientChallenge[:]...)

	// Use the server's negotiate flags from Type2 in Type3 (matching go-mssqldb behavior).
	// The server sends its supported flags in the challenge; the client echoes them back
	// to indicate agreement on the negotiated capabilities.
	flags := a.negotiateFlags

	// Build Type3 message (use same authDomain for consistency)
	domain16 := encodeUTF16LE(authDomain)
	user16 := encodeUTF16LE(a.username)
	workstation16 := encodeUTF16LE("") // empty workstation

	lmLen := len(lmResponse)
	ntLen := len(ntResponse)
	domainLen := len(domain16)
	userLen := len(user16)
	wsLen := len(workstation16)

	// Determine whether to include MIC.
	// MIC is included when we modify target info (EPA modes) and MIC is not explicitly disabled.
	// Raw target info mode acts like go-mssqldb: 88-byte header with zeroed MIC, no computation.
	includeMIC := !a.disableMIC && !a.useRawTargetInfo

	// Always use 88-byte header (matching go-mssqldb) to include the MIC field.
	// Even when MIC is not computed, the field is present but zeroed.
	headerSize := 88
	totalLen := headerSize + lmLen + ntLen + domainLen + userLen + wsLen

	msg := make([]byte, totalLen)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], ntlmAuthenticateType)

	offset := uint32(headerSize)

	// LmChallengeResponse fields
	binary.LittleEndian.PutUint16(msg[12:14], uint16(lmLen))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(lmLen))
	binary.LittleEndian.PutUint32(msg[16:20], offset)
	copy(msg[offset:], lmResponse)
	offset += uint32(lmLen)

	// NtChallengeResponse fields
	binary.LittleEndian.PutUint16(msg[20:22], uint16(ntLen))
	binary.LittleEndian.PutUint16(msg[22:24], uint16(ntLen))
	binary.LittleEndian.PutUint32(msg[24:28], offset)
	copy(msg[offset:], ntResponse)
	offset += uint32(ntLen)

	// Domain name fields
	binary.LittleEndian.PutUint16(msg[28:30], uint16(domainLen))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(domainLen))
	binary.LittleEndian.PutUint32(msg[32:36], offset)
	copy(msg[offset:], domain16)
	offset += uint32(domainLen)

	// User name fields
	binary.LittleEndian.PutUint16(msg[36:38], uint16(userLen))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(userLen))
	binary.LittleEndian.PutUint32(msg[40:44], offset)
	copy(msg[offset:], user16)
	offset += uint32(userLen)

	// Workstation fields
	binary.LittleEndian.PutUint16(msg[44:46], uint16(wsLen))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(wsLen))
	binary.LittleEndian.PutUint32(msg[48:52], offset)
	copy(msg[offset:], workstation16)
	offset += uint32(wsLen)

	// Encrypted random session key fields (empty)
	binary.LittleEndian.PutUint16(msg[52:54], 0)
	binary.LittleEndian.PutUint16(msg[54:56], 0)
	binary.LittleEndian.PutUint32(msg[56:60], offset)

	// Negotiate flags
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	// Version (zeroed, matching go-mssqldb)
	// bytes 64-71 are already zero from make()

	// MIC (16 bytes at offset 72-87):
	// Always present as a field (88-byte header), but only computed when EPA modifications
	// are active. When raw target info is used or MIC is disabled, the field stays zeroed.
	if includeMIC {
		mic := computeMIC(sessionBaseKey, a.negotiateMsg, a.challengeMsg, msg)
		copy(msg[72:88], mic)
	}

	return msg, nil
}

// buildModifiedTargetInfo constructs the target info for the NtChallengeResponse
// with AV_PAIRs added, removed, or modified per the EPATestMode.
//
// EPA (Extended Protection for Authentication, MS-TDS 3.2.5.2) relies on two
// AV_PAIRs in the Type3 target info: MsvAvChannelBindings (CBT) and
// MsvAvTargetName (SPN). By selectively including, omitting, or corrupting
// these pairs, we can probe each EPA enforcement level on the target server.
// The five test modes and their AV_PAIR manipulations:
//
//   EPATestNormal:         Correct CBT hash + correct SPN. Full EPA compliance.
//   EPATestBogusCBT:       Wrong (hardcoded) CBT hash + correct SPN. Tests whether
//                          the server validates the channel binding hash.
//   EPATestMissingCBT:     No MsvAvChannelBindings pair at all + correct SPN. Tests
//                          whether the server requires channel binding.
//   EPATestBogusService:   Correct CBT + wrong SPN (replaces "MSSQLSvc/" with "cifs/").
//                          Tests whether the server validates the service class.
//   EPATestMissingService: No MsvAvChannelBindings + no MsvAvTargetName. Tests
//                          whether the server requires any EPA bindings at all.
func (a *ntlmAuth) buildModifiedTargetInfo() []byte {
	pairs := parseAVPairs(a.targetInfoRaw)

	// Remove existing EOL, channel bindings, target name, and flags
	// (we'll re-add them with our modifications)
	var filtered []ntlmAVPair
	for _, p := range pairs {
		switch p.ID {
		case avIDMsvAvEOL:
			continue // will re-add at end
		case avIDMsvChannelBindings:
			continue // will add our own
		case avIDMsvAvTargetName:
			continue // will add our own
		case avIDMsvAvFlags:
			continue // will add our own with MIC flag
		default:
			filtered = append(filtered, p)
		}
	}

	// Add MsvAvFlags with MIC present bit (unless MIC is disabled for diagnostics)
	if !a.disableMIC {
		flagsValue := make([]byte, 4)
		binary.LittleEndian.PutUint32(flagsValue, msvAvFlagMICPresent)
		filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvFlags, Value: flagsValue})
	}

	// Add Channel Binding and Target Name based on test mode
	switch a.testMode {
	case EPATestNormal:
		// Include correct CBT hash
		if len(a.channelBindingHash) == 16 {
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvChannelBindings, Value: a.channelBindingHash})
		} else {
			// No TLS = no CBT (empty 16-byte hash)
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvChannelBindings, Value: make([]byte, 16)})
		}
		// Include correct SPN
		if a.targetName != "" {
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvTargetName, Value: encodeUTF16LE(a.targetName)})
		}

	case EPATestBogusCBT:
		// Include bogus 16-byte CBT hash
		bogusCBT := []byte{0xc0, 0x91, 0x30, 0xd2, 0xc4, 0xc3, 0xd4, 0xc7, 0x51, 0x5a, 0xb4, 0x52, 0xdf, 0x08, 0xaf, 0xfd}
		filtered = append(filtered, ntlmAVPair{ID: avIDMsvChannelBindings, Value: bogusCBT})
		// Include correct SPN
		if a.targetName != "" {
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvTargetName, Value: encodeUTF16LE(a.targetName)})
		}

	case EPATestMissingCBT:
		// Do NOT include MsvAvChannelBindings at all
		// Include correct SPN
		if a.targetName != "" {
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvTargetName, Value: encodeUTF16LE(a.targetName)})
		}

	case EPATestBogusService:
		// Include correct CBT (if available)
		if len(a.channelBindingHash) == 16 {
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvChannelBindings, Value: a.channelBindingHash})
		} else {
			filtered = append(filtered, ntlmAVPair{ID: avIDMsvChannelBindings, Value: make([]byte, 16)})
		}
		// Include bogus service name (cifs instead of MSSQLSvc)
		hostname := a.targetName
		if idx := strings.Index(hostname, "/"); idx >= 0 {
			hostname = hostname[idx+1:]
		}
		bogusTarget := "cifs/" + hostname
		filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvTargetName, Value: encodeUTF16LE(bogusTarget)})

	case EPATestMissingService:
		// Do NOT include MsvAvChannelBindings
		// Do NOT include MsvAvTargetName
		// (both stripped)
	}

	// Add EOL terminator
	filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvEOL, Value: nil})

	return serializeAVPairs(filtered)
}

// parseAVPairs parses raw target info bytes into a list of AV_PAIRs.
func parseAVPairs(data []byte) []ntlmAVPair {
	var pairs []ntlmAVPair
	offset := 0
	for offset+4 <= len(data) {
		id := binary.LittleEndian.Uint16(data[offset : offset+2])
		length := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if id == avIDMsvAvEOL {
			pairs = append(pairs, ntlmAVPair{ID: id})
			break
		}

		if offset+int(length) > len(data) {
			break
		}

		value := make([]byte, length)
		copy(value, data[offset:offset+int(length)])
		pairs = append(pairs, ntlmAVPair{ID: id, Value: value})
		offset += int(length)
	}
	return pairs
}

// serializeAVPairs serializes AV_PAIRs back to bytes.
func serializeAVPairs(pairs []ntlmAVPair) []byte {
	var buf []byte
	for _, p := range pairs {
		b := make([]byte, 4+len(p.Value))
		binary.LittleEndian.PutUint16(b[0:2], p.ID)
		binary.LittleEndian.PutUint16(b[2:4], uint16(len(p.Value)))
		copy(b[4:], p.Value)
		buf = append(buf, b...)
	}
	return buf
}

// computeNTLMv2Hash computes NTLMv2 hash: HMAC-MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(username) + domain))
func computeNTLMv2Hash(password, username, domain string) []byte {
	// NT hash = MD4(UTF16LE(password))
	h := md4.New()
	h.Write(encodeUTF16LE(password))
	ntHash := h.Sum(nil)

	return computeNTLMv2HashFromNT(ntHash, username, domain)
}

// computeNTLMv2HashFromNT computes NTLMv2 hash from a pre-computed NT hash (pass-the-hash).
// NTLMv2 hash = HMAC-MD5(ntHash, UTF16LE(UPPER(username) + domain))
func computeNTLMv2HashFromNT(ntHash []byte, username, domain string) []byte {
	identity := encodeUTF16LE(strings.ToUpper(username) + domain)
	return hmacMD5Sum(ntHash, identity)
}

// computeMIC computes the MIC over all three NTLM messages using HMAC-MD5.
func computeMIC(sessionBaseKey, negotiateMsg, challengeMsg, authenticateMsg []byte) []byte {
	data := make([]byte, 0, len(negotiateMsg)+len(challengeMsg)+len(authenticateMsg))
	data = append(data, negotiateMsg...)
	data = append(data, challengeMsg...)
	data = append(data, authenticateMsg...)
	return hmacMD5Sum(sessionBaseKey, data)
}

// computeCBTHash computes the MD5 hash of the SEC_CHANNEL_BINDINGS structure
// for the MsvAvChannelBindings AV_PAIR (MS-NLMP 2.2.2.1, RFC 5929).
//
// SEC_CHANNEL_BINDINGS layout (20-byte header + variable application data):
//   Offset 0-3:   dwInitiatorAddrType  (uint32 = 0, unused for TLS)
//   Offset 4-7:   cbInitiatorLength    (uint32 = 0, unused for TLS)
//   Offset 8-11:  dwAcceptorAddrType   (uint32 = 0, unused for TLS)
//   Offset 12-15: cbAcceptorLength     (uint32 = 0, unused for TLS)
//   Offset 16-19: cbApplicationDataLen (uint32 = length of application data)
//   Offset 20+:   Application data     (channel binding type prefix + binding value)
//
// The first four uint32 fields are always zero because TLS channel bindings
// do not use initiator/acceptor addresses. The application data is the
// concatenation of the binding type prefix string (e.g. "tls-unique:" or
// "tls-server-end-point:") and the binding value bytes.
//
// The final 16-byte MD5 hash of this structure becomes the value of the
// MsvAvChannelBindings AV_PAIR in the Type3 target info.
func computeCBTHash(prefix string, bindingValue []byte) []byte {
	appData := append([]byte(prefix), bindingValue...)
	appDataLen := len(appData)

	// 20-byte header (5 x uint32) + application data
	structure := make([]byte, 20+appDataLen)
	binary.LittleEndian.PutUint32(structure[16:20], uint32(appDataLen))
	copy(structure[20:], appData)

	hash := md5.Sum(structure)
	return hash[:]
}

// certHashForEndpoint returns the hash of a DER-encoded certificate per RFC 5929
// Section 4.1 (tls-server-end-point). The hash algorithm depends on the
// certificate's signature algorithm: SHA-256 for MD5/SHA-1 signed certs,
// otherwise the hash from the signature algorithm. In practice, most SQL Server
// certs use SHA-256.
func certHashForEndpoint(cert *x509.Certificate) []byte {
	// RFC 5929 Section 4.1: If the certificate's signatureAlgorithm uses
	// MD5 or SHA-1, use SHA-256. Otherwise use the signature's hash.
	// SHA-256 covers the vast majority of certs in practice.
	h := sha256.Sum256(cert.Raw)
	return h[:]
}

// getChannelBindingHashFromTLS computes the CBT hash from a TLS connection.
//
// RFC 5929 channel binding type selection:
//   - TLS 1.2 and below: uses "tls-unique", which is the TLS Finished message
//     from the handshake (available via ConnectionState.TLSUnique). This matches
//     impacket's behavior.
//   - TLS 1.3: uses "tls-server-end-point", which is the hash of the server's
//     leaf certificate. The "tls-unique" binding was removed in TLS 1.3
//     (RFC 8446 Appendix C.5) because the Finished message is encrypted and
//     not exported. Go's TLSUnique field is empty for TLS 1.3 connections,
//     so we fall through to the certificate-based binding.
//
// The certificate hash algorithm follows RFC 5929 Section 4.1: if the cert's
// signature algorithm uses MD5 or SHA-1, SHA-256 is used instead (see
// certHashForEndpoint). In practice, SHA-256 covers nearly all SQL Server certs.
func getChannelBindingHashFromTLS(tlsConn *tls.Conn) ([]byte, string, error) {
	state := tlsConn.ConnectionState()

	// Prefer tls-unique (works for TLS 1.2, matches impacket/Python)
	if len(state.TLSUnique) > 0 {
		return computeCBTHash("tls-unique:", state.TLSUnique), "tls-unique", nil
	}

	// Fallback to tls-server-end-point for TLS 1.3
	if len(state.PeerCertificates) == 0 {
		return nil, "", fmt.Errorf("no TLSUnique and no server certificate available")
	}
	certHash := certHashForEndpoint(state.PeerCertificates[0])
	return computeCBTHash("tls-server-end-point:", certHash), "tls-server-end-point", nil
}

// computeSPN builds the Service Principal Name for NTLM service binding.
func computeSPN(hostname string, port int) string {
	return fmt.Sprintf("MSSQLSvc/%s:%d", hostname, port)
}

// hmacMD5Sum computes HMAC-MD5.
func hmacMD5Sum(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// encodeUTF16LE encodes a string as UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(encoded))
	for i, r := range encoded {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return b
}

// decodeUTF16LE decodes UTF-16LE bytes to a string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
	}
	return string(utf16.Decode(u16))
}
