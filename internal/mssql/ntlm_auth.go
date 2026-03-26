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
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NTLM AV_PAIR IDs (MS-NLMP 2.2.2.1)
const (
	avIDMsvAvEOL             uint16 = 0x0000
	avIDMsvAvNbComputerName  uint16 = 0x0001
	avIDMsvAvNbDomainName    uint16 = 0x0002
	avIDMsvAvDNSComputerName uint16 = 0x0003
	avIDMsvAvDNSDomainName   uint16 = 0x0004
	avIDMsvAvDNSTreeName     uint16 = 0x0005
	avIDMsvAvFlags           uint16 = 0x0006
	avIDMsvAvTimestamp       uint16 = 0x0007
	avIDMsvAvTargetName      uint16 = 0x0009
	avIDMsvChannelBindings   uint16 = 0x000A
)

// NTLM negotiate flags
const (
	ntlmFlagUnicode                  uint32 = 0x00000001
	ntlmFlagOEM                      uint32 = 0x00000002
	ntlmFlagRequestTarget            uint32 = 0x00000004
	ntlmFlagSign                     uint32 = 0x00000010
	ntlmFlagSeal                     uint32 = 0x00000020
	ntlmFlagNTLM                     uint32 = 0x00000200
	ntlmFlagAlwaysSign               uint32 = 0x00008000
	ntlmFlagDomainSupplied           uint32 = 0x00001000
	ntlmFlagWorkstationSupplied      uint32 = 0x00002000
	ntlmFlagExtendedSessionSecurity  uint32 = 0x00080000
	ntlmFlagTargetInfo               uint32 = 0x00800000
	ntlmFlagVersion                  uint32 = 0x02000000
	ntlmFlag128                      uint32 = 0x20000000
	ntlmFlagKeyExch                  uint32 = 0x40000000
	ntlmFlag56                       uint32 = 0x80000000
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
	targetName string // SPN e.g. MSSQLSvc/hostname:port

	testMode           EPATestMode
	channelBindingHash []byte // 16-byte MD5 of SEC_CHANNEL_BINDINGS

	// State preserved across message generation
	negotiateMsg    []byte
	challengeMsg    []byte   // Raw Type2 bytes from server (needed for MIC computation)
	serverChallenge [8]byte
	targetInfoRaw   []byte
	negotiateFlags  uint32
	timestamp       []byte   // 8-byte FILETIME from server
	serverDomain    string   // NetBIOS domain name from Type2 MsvAvNbDomainName (for NTLMv2 hash)
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

// CreateNegotiateMessage builds NTLM Type1 (Negotiate) message.
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
	msg[32] = 10  // Major
	msg[33] = 0   // Minor
	binary.LittleEndian.PutUint16(msg[34:36], 20348) // Build
	msg[39] = 0x0F // NTLMSSP revision

	a.negotiateMsg = make([]byte, len(msg))
	copy(a.negotiateMsg, msg)
	return msg
}

// ProcessChallenge parses NTLM Type2 (Challenge) and extracts server challenge,
// flags, and target info AV_PAIRs.
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

// CreateAuthenticateMessage builds NTLM Type3 (Authenticate) message with
// controllable AV_PAIRs based on the test mode.
func (a *ntlmAuth) CreateAuthenticateMessage() ([]byte, error) {
	if a.targetInfoRaw == nil {
		return nil, fmt.Errorf("no target info available from challenge")
	}

	// Build modified target info with EPA-controlled AV_PAIRs
	modifiedTargetInfo := a.buildModifiedTargetInfo()

	// Generate client challenge (8 random bytes)
	var clientChallenge [8]byte
	if _, err := rand.Read(clientChallenge[:]); err != nil {
		return nil, fmt.Errorf("generating client challenge: %w", err)
	}

	// Use server timestamp if available, otherwise generate one
	timestamp := a.timestamp
	if timestamp == nil {
		timestamp = make([]byte, 8)
		// Use a reasonable default timestamp
	}

	// Compute NTLMv2 hash using the server's NetBIOS domain name (from Type2 MsvAvNbDomainName)
	// per MS-NLMP Section 3.3.2: "the client SHOULD use [MsvAvNbDomainName] for UserDom"
	authDomain := a.domain
	if a.serverDomain != "" {
		authDomain = a.serverDomain
	}
	ntlmV2Hash := computeNTLMv2Hash(a.password, a.username, authDomain)

	// Build the NtChallengeResponse blob
	// Structure: ResponseType(1) + HiResponseType(1) + Reserved1(2) + Reserved2(4) +
	//            Timestamp(8) + ClientChallenge(8) + Reserved3(4) + TargetInfo + Reserved4(4)
	blobLen := 28 + len(modifiedTargetInfo) + 4
	blob := make([]byte, blobLen)
	blob[0] = 0x01 // ResponseType
	blob[1] = 0x01 // HiResponseType
	// Reserved1 and Reserved2 are zero
	copy(blob[8:16], timestamp)
	copy(blob[16:24], clientChallenge[:])
	// Reserved3 is zero
	copy(blob[28:], modifiedTargetInfo)
	// Reserved4 (trailing 4 zero bytes)

	// Compute NTProofStr = HMAC_MD5(NTLMv2Hash, ServerChallenge + Blob)
	challengeAndBlob := make([]byte, 8+len(blob))
	copy(challengeAndBlob[:8], a.serverChallenge[:])
	copy(challengeAndBlob[8:], blob)
	ntProofStr := hmacMD5Sum(ntlmV2Hash, challengeAndBlob)

	// NtChallengeResponse = NTProofStr + Blob
	ntResponse := append(ntProofStr, blob...)

	// Session base key = HMAC_MD5(NTLMv2Hash, NTProofStr)
	sessionBaseKey := hmacMD5Sum(ntlmV2Hash, ntProofStr)

	// LmChallengeResponse for NTLMv2 with target info: 24 zero bytes
	lmResponse := make([]byte, 24)

	// Build the authenticate flags
	flags := ntlmFlagUnicode |
		ntlmFlagRequestTarget |
		ntlmFlagNTLM |
		ntlmFlagAlwaysSign |
		ntlmFlagExtendedSessionSecurity |
		ntlmFlagTargetInfo |
		ntlmFlagVersion |
		ntlmFlag128 |
		ntlmFlag56

	// Build Type3 message (use same authDomain for consistency)
	domain16 := encodeUTF16LE(authDomain)
	user16 := encodeUTF16LE(a.username)
	workstation16 := encodeUTF16LE("") // empty workstation

	lmLen := len(lmResponse)
	ntLen := len(ntResponse)
	domainLen := len(domain16)
	userLen := len(user16)
	wsLen := len(workstation16)

	// Header is 88 bytes (includes 16-byte MIC field)
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

	// Version: 10.0.20348
	msg[64] = 10
	msg[65] = 0
	binary.LittleEndian.PutUint16(msg[66:68], 20348)
	msg[71] = 0x0F // NTLMSSP revision

	// MIC (16 bytes at offset 72): compute over all three NTLM messages
	// Must use the raw Type2 bytes from the server (not reconstructed)
	// First zero it out (it's already zero), compute the MIC, then fill it in
	mic := computeMIC(sessionBaseKey, a.negotiateMsg, a.challengeMsg, msg)
	copy(msg[72:88], mic)

	return msg, nil
}

// buildModifiedTargetInfo constructs the target info for the NtChallengeResponse
// with AV_PAIRs added, removed, or modified per the EPATestMode.
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

	// Add MsvAvFlags with MIC present bit
	flagsValue := make([]byte, 4)
	binary.LittleEndian.PutUint32(flagsValue, msvAvFlagMICPresent)
	filtered = append(filtered, ntlmAVPair{ID: avIDMsvAvFlags, Value: flagsValue})

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

	// NTLMv2 hash = HMAC-MD5(ntHash, UTF16LE(UPPER(username) + domain))
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

// computeChannelBindingHash computes the MD5 hash of the SEC_CHANNEL_BINDINGS
// structure for the MsvAvChannelBindings AV_PAIR.
// The input is the DER-encoded TLS server certificate.
func computeChannelBindingHash(certDER []byte) []byte {
	// Compute certificate hash using SHA-256 (tls-server-end-point per RFC 5929)
	certHash := sha256.Sum256(certDER)

	// Build SEC_CHANNEL_BINDINGS structure:
	// Initiator addr type (4 bytes): 0
	// Initiator addr length (4 bytes): 0
	// Acceptor addr type (4 bytes): 0
	// Acceptor addr length (4 bytes): 0
	// Application data length (4 bytes): len("tls-server-end-point:" + certHash)
	// Application data: "tls-server-end-point:" + certHash

	prefix := []byte("tls-server-end-point:")
	appData := append(prefix, certHash[:]...)
	appDataLen := len(appData)

	// Total structure: 20 bytes header + 4 bytes app data length + app data
	// Actually the SEC_CHANNEL_BINDINGS struct is:
	// dwInitiatorAddrType (4) + cbInitiatorLength (4) +
	// dwAcceptorAddrType (4) + cbAcceptorLength (4) +
	// cbApplicationDataLength (4) = 20 bytes
	// Followed by the application data

	structure := make([]byte, 20+appDataLen)
	// All initiator/acceptor fields are zero
	binary.LittleEndian.PutUint32(structure[16:20], uint32(appDataLen))
	copy(structure[20:], appData)

	// MD5 hash of the entire structure
	hash := md5.Sum(structure)
	return hash[:]
}

// getChannelBindingHashFromTLS extracts the TLS server certificate and computes the CBT hash.
func getChannelBindingHashFromTLS(tlsConn *tls.Conn) ([]byte, error) {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate in TLS connection")
	}

	certDER := state.PeerCertificates[0].Raw
	return computeChannelBindingHash(certDER), nil
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
