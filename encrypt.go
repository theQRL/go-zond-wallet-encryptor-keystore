package keystorev1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/theQRL/go-qrllib/common"
)

// Encrypt encrypts data.
func (e *Encryptor) Encrypt(seed [common.SeedSize]byte, passphrase string) (map[string]interface{}, error) {
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

	block, err := aes.NewCipher(decryptionKey[:16])
	if err != nil {
		return nil, err
	}

	//cipherMsg := make([]byte, len(seed))
	aesIV := make([]byte, 16)
	if _, err := rand.Read(aesIV); err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(seed))
	copy(cipherText[:aes.BlockSize], aesIV)
	stream := cipher.NewCTR(block, aesIV)
	stream.XORKeyStream(cipherText[aes.BlockSize:], seed[:])

	h := sha256.New()
	if _, err := h.Write(decryptionKey[16:32]); err != nil {
		return nil, err
	}
	if _, err := h.Write(cipherText); err != nil {
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
				IV: hex.EncodeToString(aesIV),
			},
			Message: hex.EncodeToString(cipherText),
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
