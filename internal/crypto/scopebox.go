package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
)

var ErrInvalidSignature = errors.New("invalid wrapper signature")
var ErrPayloadTooShort = errors.New("payload too short")
var ErrInvalidKeyLength = errors.New("invalid key length")

// EncryptSecret encrypts a secret using the given scope key and owner private key.
func EncryptSecret(secret, scopeKey []byte, ownerEdPriv ed25519.PrivateKey, secretID, scopeID string) ([]byte, error) {
	info := deriveSecretInfoHash(1, secretID, scopeID)

	aead, err := DeriveAEAD(scopeKey, nil, info)
	if err != nil {
		return nil, err
	}

	payload, err := Encrypt(aead, secret, info)
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(ownerEdPriv, payload)
	out := append(signature, payload...)

	return out, nil
}

// WrapScopeKey wraps the scope key to be transferred from the scope owner to a recipient.
func WrapScopeKey(scopeKey []byte, ownerEdPriv ed25519.PrivateKey, recipientEdPub ed25519.PublicKey, scopeID string, ownerID string, recipientID string) ([]byte, error) {
	info := deriveScopeInfoHash(1, scopeID, ownerID, recipientID)

	aead, err := DeriveAEADFromEd25519(ownerEdPriv, recipientEdPub, nil, info)
	if err != nil {
		return nil, err
	}

	payload, err := Encrypt(aead, scopeKey, info)
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(ownerEdPriv, payload)
	out := append(signature, payload...)

	return out, nil
}

// UnwrapScopeKey unwraps the scope key using the recipient's private key and verifies the owner's signature.
func UnwrapScopeKey(in []byte, recipientEdPriv ed25519.PrivateKey, ownerEdPub ed25519.PublicKey, scopeID string, ownerID string, recipientID string) ([]byte, error) {
	payload, err := verifySignature(in, ownerEdPub)
	if err != nil {
		return nil, err
	}

	info := deriveScopeInfoHash(1, scopeID, ownerID, recipientID)

	aead, err := DeriveAEADFromEd25519(recipientEdPriv, ownerEdPub, nil, info)
	if err != nil {
		return nil, err
	}

	scopeKey, err := Decrypt(aead, payload, info)
	if err != nil {
		return nil, err
	}

	return scopeKey, nil
}

// DecryptSecret decrypts the data envelope using the given DEK and verifies the AAD matches expectations.
func DecryptSecret(in, scopeKey []byte, ownerEdPub ed25519.PublicKey, secretID, scopeID string) ([]byte, error) {
	payload, err := verifySignature(in, ownerEdPub)
	if err != nil {
		return nil, err
	}

	info := deriveSecretInfoHash(1, secretID, scopeID)

	aead, err := DeriveAEAD(scopeKey, nil, info)
	if err != nil {
		return nil, err
	}

	secret, err := Decrypt(aead, payload, info)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// verifySignature verifies the Ed25519 signature on the data
func verifySignature(in []byte, ownerEdPub ed25519.PublicKey) ([]byte, error) {
	if len(in) < ed25519.SignatureSize {
		return nil, ErrPayloadTooShort
	}
	if len(ownerEdPub) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeyLength
	}
	sig := in[:ed25519.SignatureSize]
	payload := in[ed25519.SignatureSize:]
	if !ed25519.Verify(ownerEdPub, payload, sig) {
		return nil, ErrInvalidSignature
	}
	return payload, nil
}

// deriveSecretInfoHash derives a hash for the secret information
func deriveSecretInfoHash(version int, secretID, scopeID string) []byte {
	h := sha256.New()
	h.Write([]byte{byte(version)})
	h.Write([]byte{0})
	h.Write([]byte(secretID))
	h.Write([]byte{0})
	h.Write([]byte(scopeID))
	return h.Sum(nil)
}

// deriveScopeInfoHash derives a hash for the scope information
func deriveScopeInfoHash(version int, scopeID, ownerID, recipientID string) []byte {
	h := sha256.New()

	h.Write([]byte{byte(version)})
	h.Write([]byte{0})
	h.Write([]byte(scopeID))
	h.Write([]byte{0})
	h.Write([]byte(ownerID))
	h.Write([]byte{0})
	h.Write([]byte(recipientID))

	return h.Sum(nil)
}
