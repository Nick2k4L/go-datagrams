package datagrams

import (
	"bytes"
	"testing"
	"time"
)

// TestOfflineSignatureFromBytes_Ed25519 tests parsing an Ed25519 offline signature.
func TestOfflineSignatureFromBytes_Ed25519(t *testing.T) {
	// Build a minimal Ed25519 offline signature:
	// expires: 4 bytes (unix timestamp)
	// sigtype: 2 bytes (7 = Ed25519)
	// transient_public_key: 32 bytes (Ed25519 public key)
	// signature: 64 bytes (Ed25519 signature)
	// Total: 4 + 2 + 32 + 64 = 102 bytes

	expires := time.Now().Add(24 * time.Hour).Unix()

	data := make([]byte, 102)
	// expires (big-endian)
	data[0] = byte(expires >> 24)
	data[1] = byte(expires >> 16)
	data[2] = byte(expires >> 8)
	data[3] = byte(expires)
	// sigtype (7 = Ed25519)
	data[4] = 0x00
	data[5] = 0x07
	// transient public key (32 bytes of test data)
	for i := 0; i < 32; i++ {
		data[6+i] = byte(i)
	}
	// signature (64 bytes of test data)
	for i := 0; i < 64; i++ {
		data[38+i] = byte(i + 100)
	}

	offSig, consumed, err := OfflineSignatureFromBytes(data, 7) // Ed25519 destination
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != 102 {
		t.Errorf("expected 102 bytes consumed, got %d", consumed)
	}

	if offSig.TransientSigType != 7 {
		t.Errorf("expected sigtype 7, got %d", offSig.TransientSigType)
	}

	if len(offSig.TransientPublicKey) != 32 {
		t.Errorf("expected 32-byte public key, got %d", len(offSig.TransientPublicKey))
	}

	if len(offSig.Signature) != 64 {
		t.Errorf("expected 64-byte signature, got %d", len(offSig.Signature))
	}

	// Check public key content
	for i := 0; i < 32; i++ {
		if offSig.TransientPublicKey[i] != byte(i) {
			t.Errorf("public key byte %d: expected %d, got %d", i, i, offSig.TransientPublicKey[i])
		}
	}

	// Check signature content
	for i := 0; i < 64; i++ {
		if offSig.Signature[i] != byte(i+100) {
			t.Errorf("signature byte %d: expected %d, got %d", i, i+100, offSig.Signature[i])
		}
	}

	// Check expiration time (within 1 second tolerance)
	expectedExpires := time.Unix(expires, 0)
	if offSig.Expires.Sub(expectedExpires) > time.Second || expectedExpires.Sub(offSig.Expires) > time.Second {
		t.Errorf("expected expires %v, got %v", expectedExpires, offSig.Expires)
	}
}

// TestOfflineSignatureFromBytes_TooShort tests error handling for truncated data.
func TestOfflineSignatureFromBytes_TooShort(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"only_expires", []byte{0x00, 0x00, 0x00, 0x01}},
		{"only_header", []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x07}},
		{"truncated_pubkey", make([]byte, 30)}, // Need 6 + 32 + 64 = 102
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := OfflineSignatureFromBytes(tc.data, 7)
			if err == nil {
				t.Error("expected error for truncated data")
			}
		})
	}
}

// TestOfflineSignatureFromBytes_UnknownSigType tests error handling for unknown signature types.
func TestOfflineSignatureFromBytes_UnknownSigType(t *testing.T) {
	data := make([]byte, 102)
	// expires
	data[0] = 0x00
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x01
	// sigtype = 255 (unknown)
	data[4] = 0x00
	data[5] = 0xFF

	_, _, err := OfflineSignatureFromBytes(data, 7)
	if err == nil {
		t.Error("expected error for unknown signature type")
	}
}

// TestOfflineSignature_IsExpired tests expiration checking.
func TestOfflineSignature_IsExpired(t *testing.T) {
	// Test expired signature
	expiredSig := &OfflineSignature{
		Expires:            time.Now().Add(-1 * time.Hour),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}

	if !expiredSig.IsExpired() {
		t.Error("expected signature to be expired")
	}

	// Test valid signature
	validSig := &OfflineSignature{
		Expires:            time.Now().Add(1 * time.Hour),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}

	if validSig.IsExpired() {
		t.Error("expected signature to be valid")
	}
}

// TestOfflineSignature_Bytes tests encoding an offline signature.
func TestOfflineSignature_Bytes(t *testing.T) {
	expires := time.Unix(0x12345678, 0)
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 100)
	}

	offSig := &OfflineSignature{
		Expires:            expires,
		TransientSigType:   7,
		TransientPublicKey: pubKey,
		Signature:          sig,
	}

	data := offSig.Bytes()

	// Check expires (big-endian)
	if data[0] != 0x12 || data[1] != 0x34 || data[2] != 0x56 || data[3] != 0x78 {
		t.Errorf("wrong expires encoding: %x", data[0:4])
	}

	// Check sigtype
	if data[4] != 0x00 || data[5] != 0x07 {
		t.Errorf("wrong sigtype encoding: %x", data[4:6])
	}

	// Check public key
	if !bytes.Equal(data[6:38], pubKey) {
		t.Error("public key mismatch")
	}

	// Check signature
	if !bytes.Equal(data[38:], sig) {
		t.Error("signature mismatch")
	}
}

// TestOfflineSignature_Roundtrip tests encoding then decoding.
func TestOfflineSignature_Roundtrip(t *testing.T) {
	original := &OfflineSignature{
		Expires:            time.Unix(1234567890, 0),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}
	for i := range original.TransientPublicKey {
		original.TransientPublicKey[i] = byte(i)
	}
	for i := range original.Signature {
		original.Signature[i] = byte(i + 50)
	}

	data := original.Bytes()

	parsed, consumed, err := OfflineSignatureFromBytes(data, 7)
	if err != nil {
		t.Fatalf("roundtrip parse error: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("expected %d bytes consumed, got %d", len(data), consumed)
	}

	if !parsed.Expires.Equal(original.Expires) {
		t.Errorf("expires mismatch: %v vs %v", parsed.Expires, original.Expires)
	}

	if parsed.TransientSigType != original.TransientSigType {
		t.Errorf("sigtype mismatch: %d vs %d", parsed.TransientSigType, original.TransientSigType)
	}

	if !bytes.Equal(parsed.TransientPublicKey, original.TransientPublicKey) {
		t.Error("public key mismatch")
	}

	if !bytes.Equal(parsed.Signature, original.Signature) {
		t.Error("signature mismatch")
	}
}

// TestOfflineSignature_Len tests the Len() method.
func TestOfflineSignature_Len(t *testing.T) {
	// Ed25519: 4 + 2 + 32 + 64 = 102 bytes
	offSig := &OfflineSignature{
		Expires:            time.Now(),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}

	if offSig.Len() != 102 {
		t.Errorf("expected len 102, got %d", offSig.Len())
	}

	// Also verify against actual encoded length
	data := offSig.Bytes()
	if len(data) != offSig.Len() {
		t.Errorf("encoded len %d != Len() %d", len(data), offSig.Len())
	}
}

// TestPublicKeyLengthForSigType tests the public key length lookup.
func TestPublicKeyLengthForSigType(t *testing.T) {
	testCases := []struct {
		sigType     uint16
		expectedLen int
	}{
		{0, 128}, // DSA_SHA1
		{1, 64},  // ECDSA_SHA256_P256
		{2, 96},  // ECDSA_SHA384_P384
		{3, 132}, // ECDSA_SHA512_P521
		{7, 32},  // Ed25519
		{11, 32}, // RedDSA_SHA512_Ed25519
		{99, 0},  // Unknown
		{255, 0}, // Unknown
	}

	for _, tc := range testCases {
		t.Run(string(rune('A'+tc.sigType)), func(t *testing.T) {
			got := publicKeyLengthForSigType(tc.sigType)
			if got != tc.expectedLen {
				t.Errorf("sigType %d: expected %d, got %d", tc.sigType, tc.expectedLen, got)
			}
		})
	}
}

// TestSignatureLengthForSigType tests the signature length lookup.
func TestSignatureLengthForSigType(t *testing.T) {
	testCases := []struct {
		sigType     uint16
		expectedLen int
	}{
		{0, 40},  // DSA_SHA1
		{1, 64},  // ECDSA_SHA256_P256
		{2, 96},  // ECDSA_SHA384_P384
		{3, 132}, // ECDSA_SHA512_P521
		{7, 64},  // Ed25519
		{11, 64}, // RedDSA_SHA512_Ed25519
		{99, 0},  // Unknown
		{255, 0}, // Unknown
	}

	for _, tc := range testCases {
		t.Run(string(rune('A'+tc.sigType)), func(t *testing.T) {
			got := signatureLengthForSigType(tc.sigType)
			if got != tc.expectedLen {
				t.Errorf("sigType %d: expected %d, got %d", tc.sigType, tc.expectedLen, got)
			}
		})
	}
}

// TestOfflineSignatureFromBytes_DSA tests parsing a DSA-SHA1 offline signature.
func TestOfflineSignatureFromBytes_DSA(t *testing.T) {
	// DSA_SHA1: 4 + 2 + 128 + 40 = 174 bytes
	expires := time.Now().Add(24 * time.Hour).Unix()

	data := make([]byte, 174)
	// expires (big-endian)
	data[0] = byte(expires >> 24)
	data[1] = byte(expires >> 16)
	data[2] = byte(expires >> 8)
	data[3] = byte(expires)
	// sigtype (0 = DSA_SHA1)
	data[4] = 0x00
	data[5] = 0x00
	// transient public key (128 bytes)
	for i := 0; i < 128; i++ {
		data[6+i] = byte(i)
	}
	// signature (40 bytes)
	for i := 0; i < 40; i++ {
		data[134+i] = byte(i + 100)
	}

	offSig, consumed, err := OfflineSignatureFromBytes(data, 0) // DSA destination
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != 174 {
		t.Errorf("expected 174 bytes consumed, got %d", consumed)
	}

	if offSig.TransientSigType != 0 {
		t.Errorf("expected sigtype 0, got %d", offSig.TransientSigType)
	}

	if len(offSig.TransientPublicKey) != 128 {
		t.Errorf("expected 128-byte public key, got %d", len(offSig.TransientPublicKey))
	}

	if len(offSig.Signature) != 40 {
		t.Errorf("expected 40-byte signature, got %d", len(offSig.Signature))
	}
}
