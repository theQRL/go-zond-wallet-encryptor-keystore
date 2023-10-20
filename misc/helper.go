package misc

import (
	"encoding/hex"
)

func DecodeHex(hexString string) ([]byte, error) {
	if hexString[:2] == "0x" {
		hexString = hexString[2:]
	}
	return hex.DecodeString(hexString)
}
