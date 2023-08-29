package keystorev1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Encrypt encrypts data.
func (e *Encryptor) Encrypt(secret []byte, passphrase string) (map[string]interface{}, error) {
	if secret == nil {
		return nil, errors.New("no secret")
	}

	// Random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	var decryptionKey []byte
	var err error
	switch e.cipher {
	case "custom":
		decryptionKey, err = passwordToDecryptionKey(passphrase, salt)
	default:
		return nil, fmt.Errorf("invalid cipher %s", e.cipher)
	}
	if err != nil {
		return nil, err
	}

	cipherMsg := make([]byte, len(secret))
	aesCipher, err := aes.NewCipher(decryptionKey[:16])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesCipher, iv)
	stream.XORKeyStream(cipherMsg, secret)

	h := sha256.New()
	if _, err := h.Write(decryptionKey[16:32]); err != nil {
		return nil, err
	}
	if _, err := h.Write(cipherMsg); err != nil {
		return nil, err
	}
	checksumMsg := h.Sum(nil)

	var kdf *_kdf
	switch e.cipher {
	case "custom":
		kdf = &_kdf{
			Function: "custom",
			Params: &paramsKDF{
				Salt: hex.EncodeToString(salt),
			},
			Message: "",
		}
	}

	output := &keystoreV4{
		KDF: kdf,
		Checksum: &_checksum{
			Function: "sha256",
			Params:   make(map[string]interface{}),
			Message:  hex.EncodeToString(checksumMsg),
		},
		Cipher: &_cipher{
			Function: "aes-128-ctr",
			Params: &paramsCipher{
				IV: hex.EncodeToString(iv),
			},
			Message: hex.EncodeToString(cipherMsg),
		},
	}

	bytes, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}
	res := make(map[string]interface{})
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
