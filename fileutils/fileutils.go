package fileutils

import (
	"crypto/rsa"
	"encoding/binary"
	"os"

	"github.com/DrewRoss5/keygate-server/cryptoutils"
)

func EncryptFile(path string, plaintext []byte, pub_key *rsa.PublicKey) error {
	// generate the aes key, and encrypt the file's content
	aes_key := cryptoutils.GenAesKey()
	ciphertext, err := cryptoutils.AesEncrypt(plaintext, aes_key)
	if err != nil {
		return err
	}
	// encrypt the AES key for storage
	cipher_key, err := cryptoutils.RsaEncrypt(pub_key, aes_key)
	if err != nil {
		return err
	}
	// store the file and encrypted key
	ciphertext_size := len(ciphertext)
	size_buf := make([]byte, 8)
	binary.BigEndian.PutUint64(size_buf, uint64(ciphertext_size))
	content := append(size_buf, ciphertext...)
	content = append(content, cipher_key...)
	err = os.WriteFile(path, content, 0644)
	if err != nil {
		return err
	}
	return nil
}
