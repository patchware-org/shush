package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/curve25519"
)

// Common errors for better error handling
var (
	ErrInvalidPrivateKeyLength = errors.New("invalid Ed25519 private key length")
	ErrInvalidPublicKeyLength  = errors.New("invalid Ed25519 public key length")
	ErrLowOrderPoint           = errors.New("public key is a low-order point")
)

// ConvertPrivateKey converts an Ed25519 private key to X25519 private key
// This is based on RFC 7748 and follows the standard conversion algorithm
func ConvertPrivateKey(ed25519PrivKey ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	var x25519PrivKey [32]byte
	var hashBuffer [64]byte

	// Validate input length
	if len(ed25519PrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrInvalidPrivateKeyLength, len(ed25519PrivKey), ed25519.PrivateKeySize)
	}

	// Ed25519 private key is 64 bytes: 32-byte seed + 32-byte public key
	// We need the first 32 bytes (the seed)
	seed := ed25519PrivKey.Seed()

	// Hash the seed using SHA-512
	hash := sha512.Sum512(seed)
	copy(hashBuffer[:], hash[:])

	// Apply clamping as per RFC 7748, Section 5
	// - Clear the lowest 3 bits (make it a multiple of 8)
	// - Clear the highest bit
	// - Set the second-highest bit
	hashBuffer[0] &= 248  // Clear bottom 3 bits: 11111000
	hashBuffer[31] &= 127 // Clear top bit:       01111111
	hashBuffer[31] |= 64  // Set second-top bit:  01000000

	// Copy the clamped hash to the private key
	copy(x25519PrivKey[:], hashBuffer[:32])

	// Clear sensitive data from buffer using constant-time operation
	subtle.ConstantTimeCopy(1, hashBuffer[:], make([]byte, len(hashBuffer)))

	curve := ecdh.X25519()

	return curve.NewPrivateKey(x25519PrivKey[:])
}

// ConvertPublicKey converts an Ed25519 public key to X25519 public key
// This uses the birational map between Edwards25519 and Montgomery curves
func ConvertPublicKey(ed25519PubKey ed25519.PublicKey) (*ecdh.PublicKey, error) {
	var x25519PubKey [32]byte
	var publicBuffer [32]byte

	// Validate input length
	if len(ed25519PubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d",
			ErrInvalidPublicKeyLength, len(ed25519PubKey), ed25519.PublicKeySize)
	}

	// Check for low-order points that could cause security issues
	if err := validatePublicKey(ed25519PubKey); err != nil {
		return nil, err
	}

	// Copy input to buffer to avoid modifying original
	copy(publicBuffer[:], ed25519PubKey)

	// Convert using the birational map from Edwards to Montgomery curve
	// Formula: u = (1 + y) / (1 - y) mod p
	// where y is the y-coordinate of the Ed25519 point

	// The Ed25519 public key is already the y-coordinate (with sign bit)
	// We need to extract the y-coordinate and convert it
	y := publicBuffer[:]

	// Remove the sign bit (highest bit of the last byte)
	y[31] &= 0x7F

	// Perform the conversion using the established algorithm
	// This is a complex field arithmetic operation
	if !edwardsToMontgomery(y, x25519PubKey[:]) {
		return nil, fmt.Errorf("conversion failed: invalid point")
	}

	// Clear buffer using constant-time operation
	subtle.ConstantTimeCopy(1, publicBuffer[:], make([]byte, len(publicBuffer)))

	curve := ecdh.X25519()

	return curve.NewPublicKey(x25519PubKey[:])
}

// ConvertKeyPair converts a complete Ed25519 keypair to X25519
func ConvertKeyPair(ed25519PrivKey ed25519.PrivateKey, ed25519PubKey ed25519.PublicKey) (ecdh.PrivateKey, ecdh.PublicKey, error) {
	// Convert private key
	x25519PrivKey, err := ConvertPrivateKey(ed25519PrivKey)
	if err != nil {
		return ecdh.PrivateKey{}, ecdh.PublicKey{}, fmt.Errorf("private key conversion failed: %w", err)
	}

	// Convert public key
	x25519PubKey, err := ConvertPublicKey(ed25519PubKey)
	if err != nil {
		return ecdh.PrivateKey{}, ecdh.PublicKey{}, fmt.Errorf("public key conversion failed: %w", err)
	}

	// Verify the conversion by checking if the derived public key matches
	derivedPubKey, err := curve25519.X25519(x25519PrivKey.Bytes(), curve25519.Basepoint)
	if err != nil {
		return ecdh.PrivateKey{}, ecdh.PublicKey{}, fmt.Errorf("derived public key verification failed: %w", err)
	} else if subtle.ConstantTimeCompare(derivedPubKey, x25519PubKey.Bytes()) != 1 {
		return ecdh.PrivateKey{}, ecdh.PublicKey{}, fmt.Errorf("converted public key does not match derived public key")
	}

	return *x25519PrivKey, *x25519PubKey, nil
}

// validatePublicKey performs security checks on the Ed25519 public key
func validatePublicKey(pubKey ed25519.PublicKey) error {
	// Check for known low-order points (8-torsion points)
	// These are the actual 8-torsion points that form the small subgroup of order 8
	// Based on RFC 8032 and cryptographic literature
	lowOrderPoints := [][32]byte{
		// Identity point (point at infinity in Edwards coordinates)
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// Point of order 2: (0, -1)
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		// Point of order 4: (sqrt(-1), 0) - first root
		{38, 232, 68, 72, 1, 153, 207, 134, 70, 55, 120, 182, 30, 175, 104, 204, 4, 19, 30, 87, 100, 9, 232, 82, 88, 176, 198, 225, 69, 30, 77, 47},
		// Point of order 4: (-sqrt(-1), 0) - second root
		{217, 23, 187, 183, 254, 102, 48, 121, 185, 200, 135, 73, 225, 80, 151, 51, 251, 236, 225, 168, 155, 246, 23, 173, 167, 79, 57, 30, 186, 225, 178, 80},
		// Additional 8-torsion points (order 8)
		{198, 166, 154, 28, 86, 34, 144, 79, 162, 9, 138, 16, 150, 68, 93, 185, 112, 119, 213, 34, 25, 83, 101, 109, 5, 104, 15, 22, 68, 155, 201, 110},
		{57, 89, 101, 227, 169, 221, 111, 176, 93, 246, 117, 239, 105, 187, 162, 70, 143, 136, 42, 221, 230, 172, 154, 146, 250, 151, 240, 233, 187, 100, 54, 17},
		{145, 44, 159, 56, 125, 251, 164, 81, 7, 18, 184, 242, 186, 85, 129, 119, 140, 75, 195, 19, 44, 188, 20, 79, 75, 132, 253, 19, 186, 245, 43, 45},
		{110, 211, 96, 199, 130, 4, 91, 174, 248, 237, 71, 13, 69, 170, 126, 136, 115, 180, 60, 236, 211, 67, 235, 176, 180, 123, 2, 236, 69, 10, 212, 82},
	}

	for _, lowOrder := range lowOrderPoints {
		if subtle.ConstantTimeCompare(pubKey, lowOrder[:]) == 1 {
			return ErrLowOrderPoint
		}
	}

	return nil
}

// edwardsToMontgomery implements the map u = (1+y)/(1−y) mod p
// where p = 2^255−19, y is little-endian 32-byte Edwards25519 y-coordinate,
// and u is written out little-endian into b. Returns false if (1−y) is zero.
func edwardsToMontgomery(y []byte, b []byte) bool {
	// Convert little-endian y to big.Int
	var rev [32]byte

	copy(rev[:], y)
	rev[31] &= 0x7F // clear sign bit

	// reverse bytes
	for i := 0; i < 16; i++ {
		rev[i], rev[31-i] = rev[31-i], rev[i]
	}

	yInt := new(big.Int).SetBytes(rev[:])

	// p = 2^255 − 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	one := big.NewInt(1)

	if yInt.Cmp(p) >= 0 {
		return false
	}

	// numerator = (1 + y) mod p
	num := new(big.Int).Add(one, yInt)
	num.Mod(num, p)

	// denominator = (1 − y) mod p
	den := new(big.Int).Sub(one, yInt)
	den.Mod(den, p)
	if den.Sign() == 0 {
		return false
	}

	// invDen = den^(-1) mod p
	invDen := new(big.Int).ModInverse(den, p)
	if invDen == nil {
		return false
	}

	// u = num * invDen mod p
	u := new(big.Int).Mul(num, invDen)
	u.Mod(u, p)

	// encode u little-endian into b (zero-pad to 32 bytes)
	uBytes := u.Bytes() // big-endian
	for i := range b {
		b[i] = 0
	}
	for i, _ := range uBytes {
		if i >= 32 {
			break
		}
		b[i] = uBytes[len(uBytes)-1-i]
	}

	return true
}
