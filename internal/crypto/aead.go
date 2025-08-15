package crypto

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Encrypt encrypts plaintext using the provided AEAD cipher and associated data.
func Encrypt(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	out := append(nonce, ciphertext...)
	return out, nil
}

// Decrypt expects nonce‐prefixed ciphertext and returns plaintext or an error.
func Decrypt(aead cipher.AEAD, in, aad []byte) ([]byte, error) {
	ns := aead.NonceSize()
	minLen := ns + aead.Overhead()
	if len(in) < minLen {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(in), minLen)
	}

	// split out nonce + ciphertext
	nonce, ciphertext := in[:ns], in[ns:]

	// decrypt in-place into ct’s slice to avoid an extra allocation
	// if that matters you can also let the caller pass a dst buffer
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("aead.Open failed: %w", err)
	}

	return plaintext, nil
}

// DeriveAEAD derives an AEAD cipher from a shared secret using HKDF.
func DeriveAEAD(key, salt, info []byte) (cipher.AEAD, error) {
	// HKDF-SHA256 to produce a 32-byte AEAD key
	hk := hkdf.New(sha256.New, key, salt, info)
	aeadKey := make([]byte, chacha20poly1305.KeySize) // 32 bytes
	if _, err := io.ReadFull(hk, aeadKey); err != nil {
		return nil, err
	}

	// Prefer XChaCha20-Poly1305 (NewX) so you can safely use random nonces:
	return chacha20poly1305.NewX(aeadKey)
}

// DeriveAEADFromEd25519 derives an AEAD cipher from Ed25519 keys.
// It converts Ed25519 keys to X25519, computes a shared secret, and derives an AEAD key using HKDF.
func DeriveAEADFromEd25519(priv ed25519.PrivateKey, pub ed25519.PublicKey, salt, info []byte) (cipher.AEAD, error) {
	xPriv, err := ConvertPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	xPub, err := ConvertPublicKey(pub)
	if err != nil {
		return nil, err
	}

	shared, err := xPriv.ECDH(xPub)
	if err != nil {
		return nil, err
	}

	return DeriveAEAD(shared, salt, info)
}
