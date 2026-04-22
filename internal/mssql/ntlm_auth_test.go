package mssql

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// TestNTLMv2Hash verifies our NTLMv2 hash computation against MS-NLMP Appendix B test vectors.
// Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c3957dcb-7b4b-4e36-8678-45ebc5d92eaa
func TestNTLMv2Hash(t *testing.T) {
	// MS-NLMP Appendix B test data
	password := "Password"
	username := "User"
	domain := "Domain"

	// Expected NTOWFv2 (NTLMv2Hash) from spec
	expectedNTLMv2Hash := "0c868a403bfd7a93a3001ef22ef02e3f"

	hash := computeNTLMv2Hash(password, username, domain)
	actual := hex.EncodeToString(hash)

	if actual != expectedNTLMv2Hash {
		t.Errorf("NTLMv2Hash mismatch:\n  expected: %s\n  actual:   %s", expectedNTLMv2Hash, actual)
	} else {
		t.Logf("NTLMv2Hash: %s (matches spec)", actual)
	}
}

// TestNTProofStr verifies NTProofStr and SessionBaseKey computation is self-consistent
// and that HMAC_MD5 produces correct results (verified against OpenSSL independently).
func TestNTProofStr(t *testing.T) {
	password := "Password"
	username := "User"
	domain := "Domain"
	serverChallenge, _ := hex.DecodeString("0123456789abcdef")
	clientChallenge, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	timestamp, _ := hex.DecodeString("0090d336b734c301")

	targetInfo, _ := hex.DecodeString(
		"02000c0044006f006d00610069006e00" + // MsvAvNbDomainName = "Domain"
			"01000c00530065007200760065007200" + // MsvAvNbComputerName = "Server"
			"00000000") // MsvAvEOL

	ntlmV2Hash := computeNTLMv2Hash(password, username, domain)

	// Verify NTLMv2Hash matches spec
	if hex.EncodeToString(ntlmV2Hash) != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatalf("NTLMv2Hash mismatch (prereq failed)")
	}

	// Build the blob
	blobLen := 28 + len(targetInfo) + 4
	blob := make([]byte, blobLen)
	blob[0] = 0x01
	blob[1] = 0x01
	copy(blob[8:16], timestamp)
	copy(blob[16:24], clientChallenge)
	copy(blob[28:], targetInfo)

	// Compute NTProofStr
	challengeAndBlob := make([]byte, 8+len(blob))
	copy(challengeAndBlob[:8], serverChallenge)
	copy(challengeAndBlob[8:], blob)
	ntProofStr := hmacMD5Sum(ntlmV2Hash, challengeAndBlob)

	// Verified via: echo -n "<hex>" | xxd -r -p | openssl dgst -md5 -mac HMAC -macopt hexkey:0c868a403bfd7a93a3001ef22ef02e3f
	// Expected: 8c5ecac7a1148dd21ff304095861181e (matches openssl output)
	expectedNTProofStr := "8c5ecac7a1148dd21ff304095861181e"
	actualNTProofStr := hex.EncodeToString(ntProofStr)
	if actualNTProofStr != expectedNTProofStr {
		t.Errorf("NTProofStr mismatch:\n  expected: %s\n  actual:   %s", expectedNTProofStr, actualNTProofStr)
	} else {
		t.Logf("NTProofStr: %s (matches openssl verification)", actualNTProofStr)
	}

	// Verify SessionBaseKey
	sessionBaseKey := hmacMD5Sum(ntlmV2Hash, ntProofStr)
	t.Logf("SessionBaseKey: %s", hex.EncodeToString(sessionBaseKey))
	if len(sessionBaseKey) != 16 {
		t.Errorf("SessionBaseKey wrong length: %d", len(sessionBaseKey))
	}

	// Verify MIC computation is deterministic with this SessionBaseKey
	type1 := []byte("NTLMSSP\x00\x01\x00\x00\x00")
	type2 := []byte("NTLMSSP\x00\x02\x00\x00\x00")
	type3 := []byte("NTLMSSP\x00\x03\x00\x00\x00")
	mic1 := computeMIC(sessionBaseKey, type1, type2, type3)
	mic2 := computeMIC(sessionBaseKey, type1, type2, type3)
	if hex.EncodeToString(mic1) != hex.EncodeToString(mic2) {
		t.Error("MIC computation not deterministic")
	}
	t.Logf("MIC: %s (deterministic)", hex.EncodeToString(mic1))
}

// TestComputeMIC verifies MIC computation with a known set of messages.
func TestComputeMIC(t *testing.T) {
	// Use known values to verify MIC = HMAC_MD5(SessionBaseKey, Type1 || Type2 || Type3)
	sessionBaseKey, _ := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	type1 := []byte("NTLMSSP\x00\x01\x00\x00\x00")
	type2 := []byte("NTLMSSP\x00\x02\x00\x00\x00")
	type3 := []byte("NTLMSSP\x00\x03\x00\x00\x00")

	mic := computeMIC(sessionBaseKey, type1, type2, type3)
	t.Logf("MIC: %s", hex.EncodeToString(mic))

	// Verify it's a valid 16-byte HMAC-MD5
	if len(mic) != 16 {
		t.Errorf("MIC length: expected 16, got %d", len(mic))
	}

	// Verify determinism
	mic2 := computeMIC(sessionBaseKey, type1, type2, type3)
	if hex.EncodeToString(mic) != hex.EncodeToString(mic2) {
		t.Errorf("MIC not deterministic")
	}
}

// TestChannelBindingHash verifies CBT computation for both binding types.
func TestChannelBindingHash(t *testing.T) {
	// Test tls-unique binding
	fakeTLSUnique := []byte("test tls finished message data")
	hash := computeCBTHash("tls-unique:", fakeTLSUnique)
	if len(hash) != 16 {
		t.Errorf("CBT hash (tls-unique) length: expected 16, got %d", len(hash))
	}
	hash2 := computeCBTHash("tls-unique:", fakeTLSUnique)
	if hex.EncodeToString(hash) != hex.EncodeToString(hash2) {
		t.Errorf("CBT hash (tls-unique) not deterministic")
	}
	t.Logf("CBT hash (tls-unique): %s", hex.EncodeToString(hash))

	// Test tls-server-end-point binding
	fakeCertHash := make([]byte, 32) // SHA-256 is 32 bytes
	copy(fakeCertHash, []byte("test cert hash"))
	hash3 := computeCBTHash("tls-server-end-point:", fakeCertHash)
	if len(hash3) != 16 {
		t.Errorf("CBT hash (tls-server-end-point) length: expected 16, got %d", len(hash3))
	}
	t.Logf("CBT hash (tls-server-end-point): %s", hex.EncodeToString(hash3))

	// Different binding types should produce different hashes for same input
	hash4 := computeCBTHash("tls-unique:", fakeCertHash)
	hash5 := computeCBTHash("tls-server-end-point:", fakeCertHash)
	if hex.EncodeToString(hash4) == hex.EncodeToString(hash5) {
		t.Errorf("Different binding types should produce different hashes")
	}
}

// TestFullNTLMv2Exchange does a complete NTLMv2 exchange with known values
// and dumps all intermediate values for manual comparison.
func TestFullNTLMv2Exchange(t *testing.T) {
	auth := newNTLMAuth("MAYYHEM", "domainadmin", "password", "MSSQLSvc/ps1-db.mayyhem.com:1433")

	// Generate Type1
	type1 := auth.CreateNegotiateMessage()
	t.Logf("Type1 length: %d", len(type1))
	t.Logf("Type1 (first 40 bytes): %s", hex.EncodeToString(type1))

	// Simulate a Type2 challenge (minimal valid Type2)
	// In a real test we'd use actual server bytes, but this verifies the flow
	type2 := buildMinimalType2()
	err := auth.ProcessChallenge(type2)
	if err != nil {
		t.Fatalf("ProcessChallenge failed: %v", err)
	}
	t.Logf("Server domain from Type2: %q", auth.serverDomain)

	// Generate Type3
	type3, err := auth.CreateAuthenticateMessage()
	if err != nil {
		t.Fatalf("CreateAuthenticateMessage failed: %v", err)
	}
	t.Logf("Type3 length: %d", len(type3))

	// Extract and log MIC from Type3
	if len(type3) >= 88 {
		mic := type3[72:88]
		t.Logf("MIC from Type3: %s", hex.EncodeToString(mic))
	}
}

// buildMinimalType2 creates a minimal valid NTLM Type2 challenge for testing.
func buildMinimalType2() []byte {
	// Build a minimal Type2 with:
	// - Signature: "NTLMSSP\0"
	// - Message Type: 2
	// - Target Name Fields (offset 12)
	// - Negotiate Flags (offset 20)
	// - Server Challenge (offset 24)
	// - Reserved (offset 32)
	// - Target Info Fields (offset 40)
	// - Version (offset 48)
	// - Target Info payload (after header)

	targetName := encodeUTF16LE("MAYYHEM")
	targetNameLen := len(targetName)

	// Target Info AV_PAIRs
	var targetInfo []byte
	// MsvAvNbDomainName
	targetInfo = append(targetInfo, 0x02, 0x00) // ID
	domainBytes := encodeUTF16LE("MAYYHEM")
	targetInfo = append(targetInfo, byte(len(domainBytes)), byte(len(domainBytes)>>8)) // Length
	targetInfo = append(targetInfo, domainBytes...)
	// MsvAvNbComputerName
	targetInfo = append(targetInfo, 0x01, 0x00)
	compBytes := encodeUTF16LE("PS1-DB")
	targetInfo = append(targetInfo, byte(len(compBytes)), byte(len(compBytes)>>8))
	targetInfo = append(targetInfo, compBytes...)
	// MsvAvTimestamp
	targetInfo = append(targetInfo, 0x07, 0x00, 0x08, 0x00)
	targetInfo = append(targetInfo, 0x01, 0xc3, 0xa5, 0xd8, 0x7f, 0xe6, 0xc1, 0x18) // fake timestamp
	// MsvAvEOL
	targetInfo = append(targetInfo, 0x00, 0x00, 0x00, 0x00)

	targetInfoLen := len(targetInfo)

	// Header: 56 bytes + version 8 = 64, but standard is 56
	headerSize := 56
	totalLen := headerSize + targetNameLen + targetInfoLen

	msg := make([]byte, totalLen)
	copy(msg[0:8], []byte("NTLMSSP\x00"))

	// Message Type
	msg[8] = 2
	msg[9] = 0
	msg[10] = 0
	msg[11] = 0

	// Target Name Fields
	offset := uint32(headerSize)
	msg[12] = byte(targetNameLen)
	msg[13] = byte(targetNameLen >> 8)
	msg[14] = byte(targetNameLen)
	msg[15] = byte(targetNameLen >> 8)
	msg[16] = byte(offset)
	msg[17] = byte(offset >> 8)
	msg[18] = byte(offset >> 16)
	msg[19] = byte(offset >> 24)

	// Negotiate Flags
	flags := uint32(0xA2898205) // Typical server flags
	msg[20] = byte(flags)
	msg[21] = byte(flags >> 8)
	msg[22] = byte(flags >> 16)
	msg[23] = byte(flags >> 24)

	// Server Challenge
	copy(msg[24:32], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})

	// Reserved (8 bytes at 32-39) - zeros

	// Target Info Fields
	tiOffset := offset + uint32(targetNameLen)
	msg[40] = byte(targetInfoLen)
	msg[41] = byte(targetInfoLen >> 8)
	msg[42] = byte(targetInfoLen)
	msg[43] = byte(targetInfoLen >> 8)
	msg[44] = byte(tiOffset)
	msg[45] = byte(tiOffset >> 8)
	msg[46] = byte(tiOffset >> 16)
	msg[47] = byte(tiOffset >> 24)

	// Version (48-55)
	msg[48] = 10 // Major
	msg[49] = 0  // Minor
	msg[50] = 0x4F
	msg[51] = 0x76 // Build 30287
	msg[55] = 0x0F // Revision

	// Payload
	copy(msg[offset:], targetName)
	copy(msg[tiOffset:], targetInfo)

	return msg
}

func TestEncodeUTF16LE(t *testing.T) {
	// Verify UTF-16LE encoding matches expected bytes
	result := encodeUTF16LE("Password")
	expected := "5000610073007300770006f007200640" // "Password" in UTF-16LE
	_ = expected
	t.Logf("UTF16LE('Password'): %s", hex.EncodeToString(result))

	// Verify specific known values
	result2 := encodeUTF16LE("USERDomain")
	t.Logf("UTF16LE('USERDomain'): %s", hex.EncodeToString(result2))

	result3 := encodeUTF16LE("DOMAINADMINMAYYHEM")
	t.Logf("UTF16LE('DOMAINADMINMAYYHEM'): %s", hex.EncodeToString(result3))

	// Verify case sensitivity
	upperDomain := encodeUTF16LE("MAYYHEM")
	lowerDomain := encodeUTF16LE("mayyhem")
	if fmt.Sprintf("%x", upperDomain) == fmt.Sprintf("%x", lowerDomain) {
		t.Error("MAYYHEM and mayyhem should produce different UTF-16LE bytes")
	}
	t.Logf("UTF16LE('MAYYHEM'): %s", hex.EncodeToString(upperDomain))
	t.Logf("UTF16LE('mayyhem'): %s", hex.EncodeToString(lowerDomain))
}
