package datagrams

import (
	"encoding/binary"
	"fmt"
	"time"
)

// OfflineSignature represents an I2P Offline Signature block used in Datagram2.
// This allows a transient key to sign messages on behalf of the destination,
// enabling offline destinations to pre-authorize signing.
//
// Format:
//
//	+----+----+----+----+----+----+----+----+
//	|      expires       |  sigtype  | ...
//	+----+----+----+----+----+----+----+----+
//	|   transient_public_key (variable)   |
//	+----+----+----+----+----+----+----+----+
//	|   signature of above (variable)     |
//	+----+----+----+----+----+----+----+----+
//
// expires: 4 bytes, seconds since epoch (unsigned big-endian)
// sigtype: 2 bytes, signature type of transient key
// transient_public_key: variable length based on sigtype
// signature: variable length, signed by destination's key
type OfflineSignature struct {
	// Expires is the expiration time of this offline signature authorization.
	// After this time, the transient key should no longer be accepted.
	Expires time.Time

	// TransientSigType is the signature type code for the transient key.
	// This determines the length of TransientPublicKey.
	TransientSigType uint16

	// TransientPublicKey is the public key authorized to sign messages.
	// Length depends on TransientSigType.
	TransientPublicKey []byte

	// Signature is the authorization signature from the destination's key.
	// This proves the destination authorized the transient key.
	// Length depends on the destination's signature type.
	Signature []byte
}

// OfflineSignatureFromBytes parses an Offline Signature block from binary data.
// Returns the OfflineSignature, number of bytes consumed, and any error.
//
// Parameters:
//   - data: raw bytes containing the offline signature block
//   - destSigType: signature type of the destination (determines auth signature length)
func OfflineSignatureFromBytes(data []byte, destSigType uint16) (*OfflineSignature, int, error) {
	if len(data) < 6 {
		return nil, 0, fmt.Errorf("offline signature: data too short for header (need 6 bytes, got %d)", len(data))
	}

	// Parse expires (4 bytes, big-endian, seconds since epoch)
	expiresSec := binary.BigEndian.Uint32(data[0:4])
	expires := time.Unix(int64(expiresSec), 0)

	// Parse transient sigtype (2 bytes, big-endian)
	transientSigType := binary.BigEndian.Uint16(data[4:6])

	// Get transient public key length from sigtype
	transientKeyLen := publicKeyLengthForSigType(transientSigType)
	if transientKeyLen == 0 {
		return nil, 0, fmt.Errorf("offline signature: unknown transient sigtype %d", transientSigType)
	}

	// Get authorization signature length from destination's sigtype
	authSigLen := signatureLengthForSigType(destSigType)
	if authSigLen == 0 {
		return nil, 0, fmt.Errorf("offline signature: unknown destination sigtype %d", destSigType)
	}

	totalLen := 6 + transientKeyLen + authSigLen
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("offline signature: data too short (need %d bytes, got %d)", totalLen, len(data))
	}

	offset := 6

	// Parse transient public key
	transientKey := make([]byte, transientKeyLen)
	copy(transientKey, data[offset:offset+transientKeyLen])
	offset += transientKeyLen

	// Parse authorization signature
	signature := make([]byte, authSigLen)
	copy(signature, data[offset:offset+authSigLen])
	offset += authSigLen

	return &OfflineSignature{
		Expires:            expires,
		TransientSigType:   transientSigType,
		TransientPublicKey: transientKey,
		Signature:          signature,
	}, totalLen, nil
}

// Bytes encodes the OfflineSignature to binary format.
func (o *OfflineSignature) Bytes() []byte {
	// Calculate total length
	totalLen := 6 + len(o.TransientPublicKey) + len(o.Signature)
	result := make([]byte, totalLen)

	// Encode expires (4 bytes, big-endian)
	binary.BigEndian.PutUint32(result[0:4], uint32(o.Expires.Unix()))

	// Encode transient sigtype (2 bytes, big-endian)
	binary.BigEndian.PutUint16(result[4:6], o.TransientSigType)

	// Copy transient public key
	offset := 6
	copy(result[offset:], o.TransientPublicKey)
	offset += len(o.TransientPublicKey)

	// Copy authorization signature
	copy(result[offset:], o.Signature)

	return result
}

// Len returns the encoded length of the OfflineSignature in bytes.
func (o *OfflineSignature) Len() int {
	return 6 + len(o.TransientPublicKey) + len(o.Signature)
}

// IsExpired returns true if the offline signature has expired.
func (o *OfflineSignature) IsExpired() bool {
	return time.Now().After(o.Expires)
}

// publicKeyLengthForSigType returns the public key length for a signature type.
// Returns 0 for unknown signature types.
//
// Signature types from I2P spec:
//   - 0: DSA_SHA1 (128 bytes)
//   - 7: Ed25519 (32 bytes)
//   - 11: RedDSA (32 bytes)
func publicKeyLengthForSigType(sigType uint16) int {
	switch sigType {
	case 0: // DSA_SHA1
		return 128
	case 1: // ECDSA_SHA256_P256
		return 64
	case 2: // ECDSA_SHA384_P384
		return 96
	case 3: // ECDSA_SHA512_P521
		return 132
	case 7: // Ed25519
		return 32
	case 11: // RedDSA_SHA512_Ed25519
		return 32
	default:
		return 0
	}
}

// signatureLengthForSigType returns the signature length for a signature type.
// Returns 0 for unknown signature types.
//
// Signature types from I2P spec:
//   - 0: DSA_SHA1 (40 bytes)
//   - 7: Ed25519 (64 bytes)
//   - 11: RedDSA (64 bytes)
func signatureLengthForSigType(sigType uint16) int {
	switch sigType {
	case 0: // DSA_SHA1
		return 40
	case 1: // ECDSA_SHA256_P256
		return 64
	case 2: // ECDSA_SHA384_P384
		return 96
	case 3: // ECDSA_SHA512_P521
		return 132
	case 7: // Ed25519
		return 64
	case 11: // RedDSA_SHA512_Ed25519
		return 64
	default:
		return 0
	}
}
