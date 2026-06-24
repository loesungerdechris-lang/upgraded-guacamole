package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const DigestPrefix = "sha256:"

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return DigestPrefix + hex.EncodeToString(sum[:])
}

func ValidateSHA256Digest(value string) error {
	if !strings.HasPrefix(value, DigestPrefix) {
		return errors.New("digest must start with sha256:")
	}
	hexPart := strings.TrimPrefix(value, DigestPrefix)
	if len(hexPart) != 64 {
		return errors.New("sha256 digest must contain 64 hex characters")
	}
	_, err := hex.DecodeString(hexPart)
	return err
}
