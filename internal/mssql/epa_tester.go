// Package mssql - EPA test orchestrator.
// Performs raw TDS+TLS+NTLM login attempts with controllable Channel Binding
// and Service Binding AV_PAIRs to determine EPA enforcement level.
// This matches the approach used in the Python reference implementation
// (MssqlExtended.py / MssqlInformer.py).
package mssql

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

// EPATestConfig holds configuration for a single EPA test connection.
type EPATestConfig struct {
	Hostname     string
	Port         int
	InstanceName string
	Domain       string
	Username     string
	Password     string
	TestMode     EPATestMode
	Verbose      bool
}

// epaTestOutcome represents the result of a single EPA test connection attempt.
type epaTestOutcome struct {
	Success           bool
	ErrorMessage      string
	IsUntrustedDomain bool
	IsLoginFailed     bool
}

// TDS LOGIN7 option flags
const (
	login7OptionFlags2IntegratedSecurity byte = 0x80
	login7OptionFlags2ODBCOn            byte = 0x02
	login7OptionFlags2InitLangFatal     byte = 0x01
)

// TDS token types for parsing login response
const (
	tdsTokenLoginAck  byte = 0xAD
	tdsTokenError     byte = 0xAA
	tdsTokenEnvChange byte = 0xE3
	tdsTokenDone      byte = 0xFD
	tdsTokenDoneProc  byte = 0xFE
	tdsTokenInfo      byte = 0xAB
	tdsTokenSSPI      byte = 0xED
)

// Encryption flag values from PRELOGIN response
const (
	encryptOff    byte = 0x00
	encryptOn     byte = 0x01
	encryptNotSup byte = 0x02
	encryptReq    byte = 0x03
	// encryptStrict is a synthetic value used to indicate TDS 8.0 strict
	// encryption was detected (the server required TLS before any TDS messages).
	encryptStrict byte = 0x08
)

// runEPATest performs a single raw TDS+TLS+NTLM login with the specified EPA test mode.
// This replaces the old testConnectionWithEPA which incorrectly used encrypt=disable.
//
// The flow matches the Python MssqlExtended.login():
//  1. TCP connect
//  2. Send PRELOGIN, receive PRELOGIN response, extract encryption setting
//  3. Perform TLS handshake inside TDS PRELOGIN packets
//  4. Build LOGIN7 with NTLM Type1 in SSPI field, send over TLS
//  5. (For ENCRYPT_OFF: switch back to raw TCP after LOGIN7)
//  6. Receive NTLM Type2 challenge from server
//  7. Build Type3 with modified AV_PAIRs per testMode, send as TDS_SSPI
//  8. Receive final response: LOGINACK = success, ERROR = failure
func runEPATest(ctx context.Context, config *EPATestConfig) (*epaTestOutcome, byte, error) {
	logf := func(format string, args ...interface{}) {
		if config.Verbose {
			fmt.Printf("    [EPA-debug] "+format+"\n", args...)
		}
	}

	testModeNames := map[EPATestMode]string{
		EPATestNormal:         "Normal",
		EPATestBogusCBT:       "BogusCBT",
		EPATestMissingCBT:     "MissingCBT",
		EPATestBogusService:   "BogusService",
		EPATestMissingService: "MissingService",
	}

	// Resolve port
	port := config.Port
	if port == 0 {
		port = 1433
	}

	logf("Starting EPA test mode=%s against %s:%d", testModeNames[config.TestMode], config.Hostname, port)

	// TCP connect
	addr := fmt.Sprintf("%s:%d", config.Hostname, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	tds := newTDSConn(conn)

	// Step 1: PRELOGIN exchange
	preloginPayload := buildPreloginPacket()
	if err := tds.sendPacket(tdsPacketPrelogin, preloginPayload); err != nil {
		return nil, 0, fmt.Errorf("send PRELOGIN: %w", err)
	}

	_, preloginResp, err := tds.readFullPacket()
	if err != nil {
		return nil, 0, fmt.Errorf("read PRELOGIN response: %w", err)
	}

	encryptionFlag, err := parsePreloginEncryption(preloginResp)
	if err != nil {
		return nil, 0, fmt.Errorf("parse PRELOGIN: %w", err)
	}

	logf("Server encryption flag: 0x%02X", encryptionFlag)

	if encryptionFlag == encryptNotSup {
		return nil, encryptionFlag, fmt.Errorf("server does not support encryption, cannot test EPA")
	}

	// Step 2: TLS handshake over TDS
	tlsConn, sw, err := performTLSHandshake(tds, config.Hostname)
	if err != nil {
		return nil, encryptionFlag, fmt.Errorf("TLS handshake: %w", err)
	}
	logf("TLS handshake complete, cipher: 0x%04X", tlsConn.ConnectionState().CipherSuite)

	// Step 3: Compute channel binding hash from TLS certificate
	cbtHash, err := getChannelBindingHashFromTLS(tlsConn)
	if err != nil {
		return nil, encryptionFlag, fmt.Errorf("compute CBT: %w", err)
	}
	logf("CBT hash: %x", cbtHash)

	// Step 4: Setup NTLM authenticator
	spn := computeSPN(config.Hostname, port)
	auth := newNTLMAuth(config.Domain, config.Username, config.Password, spn)
	auth.SetEPATestMode(config.TestMode)
	auth.SetChannelBindingHash(cbtHash)
	logf("SPN: %s, Domain: %s, User: %s", spn, config.Domain, config.Username)

	// Generate NTLM Type1 (Negotiate)
	negotiateMsg := auth.CreateNegotiateMessage()
	logf("Type1 negotiate message: %d bytes", len(negotiateMsg))

	// Step 5: Build and send LOGIN7 with NTLM Type1 in SSPI field
	login7 := buildLogin7Packet(config.Hostname, "MSSQLHound-EPA", config.Hostname, negotiateMsg)
	logf("LOGIN7 packet: %d bytes", len(login7))

	// Send LOGIN7 through TLS (the TLS connection writes to the underlying TCP)
	// We need to wrap in TDS packet and send through the TLS layer
	login7TDS := buildTDSPacketRaw(tdsPacketLogin7, login7)
	if _, err := tlsConn.Write(login7TDS); err != nil {
		return nil, encryptionFlag, fmt.Errorf("send LOGIN7: %w", err)
	}
	logf("Sent LOGIN7 (%d bytes with TDS header)", len(login7TDS))

	// Step 6: For ENCRYPT_OFF, drop TLS after LOGIN7 (matching Python line 82-83)
	if encryptionFlag == encryptOff {
		sw.c = conn // Switch back to raw TCP
		logf("Dropped TLS (ENCRYPT_OFF)")
	}

	// Step 7: Read server response (contains NTLM Type2 challenge)
	// After TLS switch, we read from the appropriate transport
	var responseData []byte
	if encryptionFlag == encryptOff {
		// Read from raw TCP with TDS framing
		_, responseData, err = tds.readFullPacket()
	} else {
		// Read from TLS
		responseData, err = readTLSTDSPacket(tlsConn)
	}
	if err != nil {
		return nil, encryptionFlag, fmt.Errorf("read challenge response: %w", err)
	}
	logf("Received challenge response: %d bytes", len(responseData))

	// Extract NTLM Type2 from the SSPI token in the TDS response
	challengeData := extractSSPIToken(responseData)
	if challengeData == nil {
		// Check if we got an error instead (e.g., server rejected before NTLM)
		success, errMsg := parseLoginTokens(responseData)
		logf("No SSPI token found, login result: success=%v, error=%q", success, errMsg)
		return &epaTestOutcome{
			Success:           success,
			ErrorMessage:      errMsg,
			IsUntrustedDomain: strings.Contains(errMsg, "untrusted domain"),
			IsLoginFailed:     strings.Contains(errMsg, "Login failed"),
		}, encryptionFlag, nil
	}
	logf("Extracted NTLM Type2 challenge: %d bytes", len(challengeData))

	// Step 8: Process challenge and generate Type3
	if err := auth.ProcessChallenge(challengeData); err != nil {
		return nil, encryptionFlag, fmt.Errorf("process NTLM challenge: %w", err)
	}
	logf("Server NetBIOS domain from Type2: %q (user-provided: %q)", auth.serverDomain, config.Domain)

	authenticateMsg, err := auth.CreateAuthenticateMessage()
	if err != nil {
		return nil, encryptionFlag, fmt.Errorf("create NTLM authenticate: %w", err)
	}
	logf("Type3 authenticate message: %d bytes (mode=%s)", len(authenticateMsg), testModeNames[config.TestMode])

	// Step 9: Send Type3 as TDS_SSPI
	sspiTDS := buildTDSPacketRaw(tdsPacketSSPI, authenticateMsg)
	if encryptionFlag == encryptOff {
		// Send on raw TCP
		if _, err := conn.Write(sspiTDS); err != nil {
			return nil, encryptionFlag, fmt.Errorf("send SSPI auth: %w", err)
		}
	} else {
		// Send through TLS
		if _, err := tlsConn.Write(sspiTDS); err != nil {
			return nil, encryptionFlag, fmt.Errorf("send SSPI auth: %w", err)
		}
	}
	logf("Sent Type3 SSPI (%d bytes with TDS header)", len(sspiTDS))

	// Step 10: Read final response
	if encryptionFlag == encryptOff {
		_, responseData, err = tds.readFullPacket()
	} else {
		responseData, err = readTLSTDSPacket(tlsConn)
	}
	if err != nil {
		return nil, encryptionFlag, fmt.Errorf("read auth response: %w", err)
	}
	logf("Received auth response: %d bytes", len(responseData))

	// Parse for LOGINACK or ERROR
	success, errMsg := parseLoginTokens(responseData)
	logf("Login result: success=%v, error=%q", success, errMsg)
	return &epaTestOutcome{
		Success:           success,
		ErrorMessage:      errMsg,
		IsUntrustedDomain: strings.Contains(errMsg, "untrusted domain"),
		IsLoginFailed:     strings.Contains(errMsg, "Login failed"),
	}, encryptionFlag, nil
}

// buildTDSPacketRaw creates a TDS packet with header + payload (for writing through TLS).
func buildTDSPacketRaw(packetType byte, payload []byte) []byte {
	pktLen := tdsHeaderSize + len(payload)
	pkt := make([]byte, pktLen)
	pkt[0] = packetType
	pkt[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	// SPID, PacketID, Window all zero
	copy(pkt[tdsHeaderSize:], payload)
	return pkt
}

// buildLogin7Packet constructs a TDS LOGIN7 packet payload with SSPI (NTLM Type1).
func buildLogin7Packet(hostname, appName, serverName string, sspiPayload []byte) []byte {
	hostname16 := str2ucs2Login(hostname)
	appname16 := str2ucs2Login(appName)
	servername16 := str2ucs2Login(serverName)
	ctlintname16 := str2ucs2Login("MSSQLHound")

	hostnameRuneLen := utf16.Encode([]rune(hostname))
	appnameRuneLen := utf16.Encode([]rune(appName))
	servernameRuneLen := utf16.Encode([]rune(serverName))
	ctlintnameRuneLen := utf16.Encode([]rune("MSSQLHound"))

	// loginHeader is 94 bytes (matches go-mssqldb loginHeader struct)
	const headerSize = 94
	sspiLen := len(sspiPayload)

	// Calculate offsets
	offset := uint16(headerSize)

	hostnameOffset := offset
	offset += uint16(len(hostname16))

	// Username (empty for SSPI)
	usernameOffset := offset
	// Password (empty for SSPI)
	passwordOffset := offset

	appnameOffset := offset
	offset += uint16(len(appname16))

	servernameOffset := offset
	offset += uint16(len(servername16))

	// Extension (empty)
	extensionOffset := offset

	ctlintnameOffset := offset
	offset += uint16(len(ctlintname16))

	// Language (empty)
	languageOffset := offset
	// Database (empty)
	databaseOffset := offset

	sspiOffset := offset
	offset += uint16(sspiLen)

	// AtchDBFile (empty)
	atchdbOffset := offset
	// ChangePassword (empty)
	changepwOffset := offset

	totalLen := uint32(offset)

	// Build the packet
	pkt := make([]byte, totalLen)

	// Length
	binary.LittleEndian.PutUint32(pkt[0:4], totalLen)
	// TDS Version (7.4 = 0x74000004)
	binary.LittleEndian.PutUint32(pkt[4:8], 0x74000004)
	// Packet Size
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(tdsMaxPacketSize))
	// Client Program Version
	binary.LittleEndian.PutUint32(pkt[12:16], 0x07000000)
	// Client PID
	binary.LittleEndian.PutUint32(pkt[16:20], uint32(rand.Intn(65535)))
	// Connection ID
	binary.LittleEndian.PutUint32(pkt[20:24], 0)

	// Option Flags 1 (byte 24)
	pkt[24] = 0x00
	// Option Flags 2 (byte 25): Integrated Security ON + ODBC ON
	pkt[25] = login7OptionFlags2IntegratedSecurity | login7OptionFlags2ODBCOn | login7OptionFlags2InitLangFatal
	// Type Flags (byte 26)
	pkt[26] = 0x00
	// Option Flags 3 (byte 27)
	pkt[27] = 0x00

	// Client Time Zone (4 bytes at 28)
	// Client LCID (4 bytes at 32)

	// Field offsets and lengths
	binary.LittleEndian.PutUint16(pkt[36:38], hostnameOffset)
	binary.LittleEndian.PutUint16(pkt[38:40], uint16(len(hostnameRuneLen)))

	binary.LittleEndian.PutUint16(pkt[40:42], usernameOffset)
	binary.LittleEndian.PutUint16(pkt[42:44], 0) // empty username for SSPI

	binary.LittleEndian.PutUint16(pkt[44:46], passwordOffset)
	binary.LittleEndian.PutUint16(pkt[46:48], 0) // empty password for SSPI

	binary.LittleEndian.PutUint16(pkt[48:50], appnameOffset)
	binary.LittleEndian.PutUint16(pkt[50:52], uint16(len(appnameRuneLen)))

	binary.LittleEndian.PutUint16(pkt[52:54], servernameOffset)
	binary.LittleEndian.PutUint16(pkt[54:56], uint16(len(servernameRuneLen)))

	binary.LittleEndian.PutUint16(pkt[56:58], extensionOffset)
	binary.LittleEndian.PutUint16(pkt[58:60], 0) // no extension

	binary.LittleEndian.PutUint16(pkt[60:62], ctlintnameOffset)
	binary.LittleEndian.PutUint16(pkt[62:64], uint16(len(ctlintnameRuneLen)))

	binary.LittleEndian.PutUint16(pkt[64:66], languageOffset)
	binary.LittleEndian.PutUint16(pkt[66:68], 0)

	binary.LittleEndian.PutUint16(pkt[68:70], databaseOffset)
	binary.LittleEndian.PutUint16(pkt[70:72], 0)

	// ClientID (6 bytes at 72) - leave zero

	binary.LittleEndian.PutUint16(pkt[78:80], sspiOffset)
	binary.LittleEndian.PutUint16(pkt[80:82], uint16(sspiLen))

	binary.LittleEndian.PutUint16(pkt[82:84], atchdbOffset)
	binary.LittleEndian.PutUint16(pkt[84:86], 0)

	binary.LittleEndian.PutUint16(pkt[86:88], changepwOffset)
	binary.LittleEndian.PutUint16(pkt[88:90], 0)

	// SSPILongLength (4 bytes at 90)
	binary.LittleEndian.PutUint32(pkt[90:94], 0)

	// Payload
	copy(pkt[hostnameOffset:], hostname16)
	copy(pkt[appnameOffset:], appname16)
	copy(pkt[servernameOffset:], servername16)
	copy(pkt[ctlintnameOffset:], ctlintname16)
	copy(pkt[sspiOffset:], sspiPayload)

	return pkt
}

// str2ucs2Login converts a string to UTF-16LE bytes (for LOGIN7 fields).
func str2ucs2Login(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(encoded))
	for i, r := range encoded {
		b[2*i] = byte(r)
		b[2*i+1] = byte(r >> 8)
	}
	return b
}

// parsePreloginEncryption extracts the encryption flag from a PRELOGIN response payload.
func parsePreloginEncryption(payload []byte) (byte, error) {
	offset := 0
	for offset < len(payload) {
		if payload[offset] == 0xFF {
			break
		}
		if offset+5 > len(payload) {
			break
		}

		token := payload[offset]
		dataOffset := int(payload[offset+1])<<8 | int(payload[offset+2])
		dataLen := int(payload[offset+3])<<8 | int(payload[offset+4])

		if token == 0x01 && dataLen >= 1 && dataOffset < len(payload) {
			return payload[dataOffset], nil
		}

		offset += 5
	}
	return 0, fmt.Errorf("encryption option not found in PRELOGIN response")
}

// extractSSPIToken extracts the NTLM challenge from a TDS response containing SSPI token.
// The SSPI token is returned as TDS_SSPI (0xED) token in the tabular result stream.
func extractSSPIToken(data []byte) []byte {
	offset := 0
	for offset < len(data) {
		tokenType := data[offset]
		offset++

		switch tokenType {
		case tdsTokenSSPI:
			// SSPI token: 2-byte length (LE) + payload
			if offset+2 > len(data) {
				return nil
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2
			if offset+length > len(data) {
				return nil
			}
			return data[offset : offset+length]

		case tdsTokenError, tdsTokenInfo:
			// Variable-length token with 2-byte length
			if offset+2 > len(data) {
				return nil
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		case tdsTokenEnvChange:
			if offset+2 > len(data) {
				return nil
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		case tdsTokenDone, tdsTokenDoneProc:
			offset += 12 // fixed 12 bytes

		case tdsTokenLoginAck:
			if offset+2 > len(data) {
				return nil
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		default:
			// Unknown token - try to skip (assume 2-byte length prefix)
			if offset+2 > len(data) {
				return nil
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length
		}
	}
	return nil
}

// parseLoginTokens parses TDS response tokens to determine login success/failure.
func parseLoginTokens(data []byte) (bool, string) {
	success := false
	var errorMsg string

	offset := 0
	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		tokenType := data[offset]
		offset++

		switch tokenType {
		case tdsTokenLoginAck:
			success = true
			if offset+2 > len(data) {
				return success, errorMsg
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		case tdsTokenError:
			if offset+2 > len(data) {
				return success, errorMsg
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			if offset+2+length <= len(data) {
				errorMsg = parseErrorToken(data[offset+2 : offset+2+length])
			}
			offset += 2 + length

		case tdsTokenInfo:
			if offset+2 > len(data) {
				return success, errorMsg
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		case tdsTokenEnvChange:
			if offset+2 > len(data) {
				return success, errorMsg
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		case tdsTokenDone, tdsTokenDoneProc:
			if offset+12 <= len(data) {
				offset += 12
			} else {
				return success, errorMsg
			}

		case tdsTokenSSPI:
			if offset+2 > len(data) {
				return success, errorMsg
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length

		default:
			// Unknown token - try 2-byte length
			if offset+2 > len(data) {
				return success, errorMsg
			}
			length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2 + length
		}
	}

	return success, errorMsg
}

// parseErrorToken extracts the error message text from a TDS ERROR token payload.
// ERROR token format: Number(4) + State(1) + Class(1) + MsgTextLength(2) + MsgText(UTF16) + ...
func parseErrorToken(data []byte) string {
	if len(data) < 8 {
		return ""
	}
	// Skip Number(4) + State(1) + Class(1) = 6 bytes
	msgLen := int(binary.LittleEndian.Uint16(data[6:8]))
	if 8+msgLen*2 > len(data) {
		return ""
	}
	// Decode UTF-16LE message text
	msgBytes := data[8 : 8+msgLen*2]
	runes := make([]uint16, msgLen)
	for i := 0; i < msgLen; i++ {
		runes[i] = binary.LittleEndian.Uint16(msgBytes[i*2 : i*2+2])
	}
	return string(utf16.Decode(runes))
}

// runEPATestStrict performs an EPA test using the TDS 8.0 strict encryption flow.
// In TDS 8.0, TLS is established directly on the TCP socket before any TDS messages
// (like HTTPS), so PRELOGIN and all subsequent packets are sent through TLS.
// This is used when the server has "Enforce Strict Encryption" enabled and rejects
// cleartext PRELOGIN packets.
func runEPATestStrict(ctx context.Context, config *EPATestConfig) (*epaTestOutcome, error) {
	logf := func(format string, args ...interface{}) {
		if config.Verbose {
			fmt.Printf("    [EPA-debug] "+format+"\n", args...)
		}
	}

	testModeNames := map[EPATestMode]string{
		EPATestNormal:         "Normal",
		EPATestBogusCBT:       "BogusCBT",
		EPATestMissingCBT:     "MissingCBT",
		EPATestBogusService:   "BogusService",
		EPATestMissingService: "MissingService",
	}

	port := config.Port
	if port == 0 {
		port = 1433
	}

	logf("Starting EPA test mode=%s (TDS 8.0 strict) against %s:%d", testModeNames[config.TestMode], config.Hostname, port)

	// TCP connect
	addr := fmt.Sprintf("%s:%d", config.Hostname, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: TLS handshake directly on TCP (TDS 8.0 strict)
	// Unlike TDS 7.x where TLS records are wrapped in TDS PRELOGIN packets,
	// TDS 8.0 does a standard TLS handshake on the raw socket.
	tlsConn, err := performDirectTLSHandshake(conn, config.Hostname)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake (strict): %w", err)
	}
	logf("TLS handshake complete (strict mode), cipher: 0x%04X", tlsConn.ConnectionState().CipherSuite)

	// Step 2: Compute channel binding hash from TLS certificate
	cbtHash, err := getChannelBindingHashFromTLS(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("compute CBT: %w", err)
	}
	logf("CBT hash: %x", cbtHash)

	// Step 3: Send PRELOGIN through TLS (in strict mode, all TDS traffic is inside TLS)
	preloginPayload := buildPreloginPacket()
	preloginTDS := buildTDSPacketRaw(tdsPacketPrelogin, preloginPayload)
	if _, err := tlsConn.Write(preloginTDS); err != nil {
		return nil, fmt.Errorf("send PRELOGIN (strict): %w", err)
	}

	preloginResp, err := readTLSTDSPacket(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("read PRELOGIN response (strict): %w", err)
	}

	encryptionFlag, err := parsePreloginEncryption(preloginResp)
	if err != nil {
		logf("Could not parse encryption flag from strict PRELOGIN response: %v (continuing)", err)
	} else {
		logf("Server encryption flag (strict): 0x%02X", encryptionFlag)
	}

	// Step 4: Setup NTLM authenticator
	spn := computeSPN(config.Hostname, port)
	auth := newNTLMAuth(config.Domain, config.Username, config.Password, spn)
	auth.SetEPATestMode(config.TestMode)
	auth.SetChannelBindingHash(cbtHash)
	logf("SPN: %s, Domain: %s, User: %s", spn, config.Domain, config.Username)

	negotiateMsg := auth.CreateNegotiateMessage()
	logf("Type1 negotiate message: %d bytes", len(negotiateMsg))

	// Step 5: Build and send LOGIN7 with NTLM Type1 through TLS
	login7 := buildLogin7Packet(config.Hostname, "MSSQLHound-EPA", config.Hostname, negotiateMsg)
	login7TDS := buildTDSPacketRaw(tdsPacketLogin7, login7)
	if _, err := tlsConn.Write(login7TDS); err != nil {
		return nil, fmt.Errorf("send LOGIN7 (strict): %w", err)
	}
	logf("Sent LOGIN7 (%d bytes with TDS header) (strict)", len(login7TDS))

	// Step 6: Read server response (NTLM Type2 challenge) - always through TLS
	responseData, err := readTLSTDSPacket(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("read challenge response (strict): %w", err)
	}
	logf("Received challenge response: %d bytes", len(responseData))

	// Extract NTLM Type2 from SSPI token
	challengeData := extractSSPIToken(responseData)
	if challengeData == nil {
		success, errMsg := parseLoginTokens(responseData)
		logf("No SSPI token found, login result: success=%v, error=%q", success, errMsg)
		return &epaTestOutcome{
			Success:           success,
			ErrorMessage:      errMsg,
			IsUntrustedDomain: strings.Contains(errMsg, "untrusted domain"),
			IsLoginFailed:     strings.Contains(errMsg, "Login failed"),
		}, nil
	}
	logf("Extracted NTLM Type2 challenge: %d bytes", len(challengeData))

	// Step 7: Process challenge and generate Type3
	if err := auth.ProcessChallenge(challengeData); err != nil {
		return nil, fmt.Errorf("process NTLM challenge: %w", err)
	}
	logf("Server NetBIOS domain from Type2: %q (user-provided: %q)", auth.serverDomain, config.Domain)

	authenticateMsg, err := auth.CreateAuthenticateMessage()
	if err != nil {
		return nil, fmt.Errorf("create NTLM authenticate: %w", err)
	}
	logf("Type3 authenticate message: %d bytes (mode=%s)", len(authenticateMsg), testModeNames[config.TestMode])

	// Step 8: Send Type3 as TDS_SSPI through TLS
	sspiTDS := buildTDSPacketRaw(tdsPacketSSPI, authenticateMsg)
	if _, err := tlsConn.Write(sspiTDS); err != nil {
		return nil, fmt.Errorf("send SSPI auth (strict): %w", err)
	}
	logf("Sent Type3 SSPI (%d bytes with TDS header) (strict)", len(sspiTDS))

	// Step 9: Read final response through TLS
	responseData, err = readTLSTDSPacket(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("read auth response (strict): %w", err)
	}
	logf("Received auth response: %d bytes", len(responseData))

	// Parse for LOGINACK or ERROR
	success, errMsg := parseLoginTokens(responseData)
	logf("Login result: success=%v, error=%q", success, errMsg)
	return &epaTestOutcome{
		Success:           success,
		ErrorMessage:      errMsg,
		IsUntrustedDomain: strings.Contains(errMsg, "untrusted domain"),
		IsLoginFailed:     strings.Contains(errMsg, "Login failed"),
	}, nil
}

// readTLSTDSPacket reads a complete TDS packet through TLS.
// When encryption is ENCRYPT_REQ, TDS packets are wrapped in TLS records.
func readTLSTDSPacket(tlsConn net.Conn) ([]byte, error) {
	// Read TDS header through TLS
	hdr := make([]byte, tdsHeaderSize)
	n := 0
	for n < tdsHeaderSize {
		read, err := tlsConn.Read(hdr[n:])
		if err != nil {
			return nil, fmt.Errorf("read TDS header through TLS: %w", err)
		}
		n += read
	}

	pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if pktLen < tdsHeaderSize {
		return nil, fmt.Errorf("TDS packet length %d too small", pktLen)
	}

	payloadLen := pktLen - tdsHeaderSize
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		n = 0
		for n < payloadLen {
			read, err := tlsConn.Read(payload[n:])
			if err != nil {
				return nil, fmt.Errorf("read TDS payload through TLS: %w", err)
			}
			n += read
		}
	}

	// Check if this is EOM
	status := hdr[1]
	if status&0x01 != 0 {
		return payload, nil
	}

	// Read more packets until EOM
	for {
		moreHdr := make([]byte, tdsHeaderSize)
		n = 0
		for n < tdsHeaderSize {
			read, err := tlsConn.Read(moreHdr[n:])
			if err != nil {
				return nil, err
			}
			n += read
		}

		morePktLen := int(binary.BigEndian.Uint16(moreHdr[2:4]))
		morePayloadLen := morePktLen - tdsHeaderSize
		if morePayloadLen > 0 {
			morePay := make([]byte, morePayloadLen)
			n = 0
			for n < morePayloadLen {
				read, err := tlsConn.Read(morePay[n:])
				if err != nil {
					return nil, err
				}
				n += read
			}
			payload = append(payload, morePay...)
		}

		if moreHdr[1]&0x01 != 0 {
			break
		}
	}

	return payload, nil
}
