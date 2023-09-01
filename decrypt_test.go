package keystorev1_test

import (
	"encoding/json"
	"github.com/theQRL/go-qrllib/common"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev1 "github.com/theQRL/go-zond-wallet-encryptor-keystore"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		passphrase string
		output     [common.SeedSize]byte
		err        string
	}{
		{
			name:       "NoCipher",
			input:      `{"kdf":{"function":"custom","message":"","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}},"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}}}`,
			passphrase: "password--1",
			err:        "cipher cannot be nil",
		},
		{
			name:       "InvalidSalt",
			input:      `{"kdf":{"function":"custom","message":"","params":{"salt":"z518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}},"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"aes-128-ctr","message":"22d56edac922e2a47e0d6b7a51d94ebf2b56c7eca4c7ca625f8a98353480d15b","params":{}}}`,
			passphrase: "password--1",
			err:        "KDF salt is invalid | reason encoding/hex: invalid byte: U+007A 'z'",
		},
		{
			name:       "InvalidKDF",
			input:      `{"kdf":{"function":"shasha","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"},"message":""},"checksum":{"function":"sha256","params":{},"message":"22d56edac922e2a47e0d6b7a51d94ebf2b56c7eca4c7ca625f8a98353480d15b"},"cipher":{"function":"aes-128-ctr","params":{"iv":"149fd62ed291aa9631359be4916fc042"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: "password--1",
			err:        `invalid KDF shasha`,
		},
		{
			name:       "InvalidCipherMessage",
			input:      `{"kdf":{"function":"custom","message":"","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}},"checksum":{"function":"SHA256","message":"cb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"aes-128-ctr","message":"h18afad793ec8dc3263169c07add77515d9f301464a05508d7ecb42ced24ed3a","params":{}}}`,
			passphrase: "password--1",
			err:        "invalid cipher message",
		},
		{
			name:       "InvalidChecksumMessage",
			input:      `{"kdf":{"function":"custom","message":"","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}},"checksum":{"function":"SHA256","message":"hb27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"aes-128-ctr","message":"22d56edac922e2a47e0d6b7a51d94ebf2b56c7eca4c7ca625f8a98353480d15b","params":{}}}`,
			passphrase: "password--1",
			err:        "invalid checksum message | reason encoding/hex: invalid byte: U+0068 'h'",
		},
		{
			name:       "ChecksumMismatch",
			input:      `{"kdf":{"function":"custom","message":"","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}},"checksum":{"function":"SHA256","message":"db27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e","params":{}},"cipher":{"function":"aes-128-ctr","message":"22d56edac922e2a47e0d6b7a51d94ebf2b56c7eca4c7ca625f8a98353480d15b","params":{}}}`,
			passphrase: "password--1",
			err:        "checksum mismatch | expected 8a4a5eac8c5e5c0dd95beb25477a158762308657cc0d94a68a90c71e05f88383 | found db27fe860c96f269f7838525ba8dce0886e0b7753caccc14162195bcdacbf49e",
		},
		{
			name:       "InvalidAES-IV",
			input:      `{"kdf":{"function":"custom","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"},"message":""},"checksum":{"function":"sha256","params":{},"message":"a71e5d1e9943b5abcf3ed55123d2b76e72ae1c360ac980e8fc800415a71b3f84"},"cipher":{"function":"aes-128-ctr","params":{"iv":"z49fd62ed291aa9631359be4916fc042"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: "password--1",
			err:        "invalid aes IV | reason encoding/hex: invalid byte: U+007A 'z'",
		},
		{
			name:       "InvalidCipher",
			input:      `{"kdf":{"function":"custom","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"},"message":""},"checksum":{"function":"sha256","params":{},"message":"a71e5d1e9943b5abcf3ed55123d2b76e72ae1c360ac980e8fc800415a71b3f84"},"cipher":{"function":"aes-aes","params":{"iv":"149fd62ed291aa9631359be4916fc042"},"message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"}}`,
			passphrase: "password--1",
			err:        `unsupported cipher aes-aes`,
		},
		{
			name:       "Valid",
			input:      `{"kdf":{"function":"custom","message":"","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}},"checksum":{"function":"SHA256","message":"8a4a5eac8c5e5c0dd95beb25477a158762308657cc0d94a68a90c71e05f88383","params":{}},"cipher":{"function":"aes-128-ctr","message":"22d56edac922e2a47e0d6b7a51d94ebf2b56c7eca4c7ca625f8a98353480d15b","params":{"iv":"149fd62ed291aa9631359be4916fc042"}}}`,
			passphrase: "password--1",
			output:     [common.SeedSize]byte{0x4, 0xe4, 0x1e, 0x23, 0xc5, 0x47, 0x2d, 0x11, 0xa2, 0xc0, 0x18, 0x50, 0xaf, 0xb8, 0xc9, 0xbd, 0xd8, 0x3b, 0x7f, 0xb0, 0x11, 0x9c, 0xc5, 0xb7, 0xe7, 0x5b, 0x4e, 0xd3, 0xef, 0x13, 0xad, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev1.New()
			input := make(map[string]interface{})
			err := json.Unmarshal([]byte(test.input), &input)
			require.Nil(t, err)
			output, err := encryptor.Decrypt(input, test.passphrase)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.output, output)
			}
		})
	}
}

func TestDecryptIncorrectInput(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		err   string
	}{
		{
			name: "Nil",
			err:  "data cannot be nil",
		},
		{
			name:  "Empty",
			input: map[string]interface{}{},
			err:   "checksum cannot be nil",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev1.New()
			_, err := encryptor.Decrypt(test.input, "irrelevant")
			require.EqualError(t, err, test.err)
		})
	}
}
