package cryptoutils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
)

// returns a simple SHA-256 hash of the given plaintext
func Sha256Hash(plaintext []byte) []byte {
	hasher := sha256.New()
	return hasher.Sum(plaintext)
}

// generates an AES key from a password, by hashing it with a salt repeatedly
func HashKey(password []byte, salt []byte, rounds int) []byte {
	key := password
	for range rounds {
		hasher := sha256.New()
		hasher.Write(key)
		hasher.Write(salt)
		key = hasher.Sum(nil)
	}
	return key
}

// hashes a given password with a salt, and compares it against the password checksum. All arguments taken as strings
func VerifyPassword(password string, checksum string, salt string) bool {
	// parse the salt and checksum
	checksum_bytes, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil {
		return false
	}
	salt_bytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}
	// compare the checksum with the hash of the given password
	pass_bytes := []byte(password)
	hash_bytes := HashKey(pass_bytes, salt_bytes, 32)
	return bytes.Equal(hash_bytes, checksum_bytes)
}
