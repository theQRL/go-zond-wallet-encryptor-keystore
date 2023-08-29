package keystorev1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
)

func passwordToDecryptionKey(password string, salt []byte) ([]byte, error) {
	h := sha3.NewShake256()
	if _, err := h.Write([]byte(password)); err != nil {
		return []byte{}, fmt.Errorf("shake256 hash write failed %v", err)
	}

	if _, err := h.Write(salt); err != nil {
		return []byte{}, fmt.Errorf("shake256 hash write failed %v", err)
	}

	var decryptionKey [32]uint8
	_, err := h.Read(decryptionKey[:])
	return decryptionKey[:], err
}

func (e *Encryptor) Decrypt(data map[string]interface{}, passphrase string) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("keystore cannot be parsed | reason %v", err)
	}
	ks := &keystoreV4{}
	err = json.Unmarshal(b, &ks)
	if err != nil {
		return nil, fmt.Errorf("keystore cannot be parsed | reason %v", err)
	}

	if ks.Checksum == nil {
		return nil, errors.New("checksum cannot be nil")
	}
	if ks.Cipher == nil {
		return nil, errors.New("cipher cannot be nil")
	}

	var decryptionKey []byte
	kdfParams := ks.KDF.Params
	salt, err := hex.DecodeString(kdfParams.Salt)
	if err != nil {
		return nil, fmt.Errorf("KDF salt is invalid | reason %v", err)
	}
	switch ks.KDF.Function {
	case "custom":
		decryptionKey, err = passwordToDecryptionKey(passphrase, salt)
	default:
		return nil, fmt.Errorf("invalid KDF %s", ks.KDF.Function)
	}
	if err != nil {
		return nil, errors.New("invalid KDF param")
	}

	if len(decryptionKey) < 32 {
		return nil, fmt.Errorf("decryption key size is less than 32 bytes | current size %d", len(decryptionKey))
	}
	cipherMsg, err := hex.DecodeString(ks.Cipher.Message)
	if err != nil {
		return nil, errors.New("invalid cipher message")
	}
	h := sha256.New()
	if _, err := h.Write(decryptionKey[16:32]); err != nil {
		return nil, err
	}
	if _, err := h.Write(cipherMsg); err != nil {
		return nil, err
	}
	expectedChecksum := h.Sum(nil)
	foundChecksum, err := hex.DecodeString(ks.Checksum.Message)
	if err != nil {
		return nil, fmt.Errorf("invalid checksum message | reason %v", err.Error())
	}
	if !bytes.Equal(expectedChecksum, foundChecksum) {
		return nil, fmt.Errorf("checksum mismatch | expected %s | found %s",
			hex.EncodeToString(expectedChecksum), hex.EncodeToString(foundChecksum))
	}

	res := make([]byte, len(cipherMsg))
	switch ks.Cipher.Function {
	case "aes-128-ctr":
		aesCipher, err := aes.NewCipher(decryptionKey[:16])
		if err != nil {
			return nil, err
		}
		iv, err := hex.DecodeString(ks.Cipher.Params.IV)
		if err != nil {
			return nil, fmt.Errorf("invalid aes IV | reason %v", err.Error())
		}
		stream := cipher.NewCTR(aesCipher, iv)
		stream.XORKeyStream(res, cipherMsg)
	default:
		return nil, fmt.Errorf("unsupported cipher %s", ks.Cipher.Function)
	}

	return res, nil
}
