package cryptoutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

const RSA_KEY_SIZE = 4096

// imports an RSA public key from a byte string of the pem-encoded key
func ImportRsaPub(pemStr []byte) (rsa.PublicKey, error) {
	pubBlock, _ := pem.Decode(pemStr)
	if pubBlock == nil {
		return rsa.PublicKey{}, errors.New("invalid RSA public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return rsa.PublicKey{}, errors.New("the provided public key is not RSA")
	}
	return *rsaPubKey, nil
}

// imports an RSA public key from a file path
func ImportRsaPubFile(keyPath string) (rsa.PublicKey, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	return ImportRsaPub(keyBytes)
}

// encrypts a given plaintext with the provided public key
func RsaEncrypt(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}
