package crypt

import (
	"fmt"
)

// Encrypt some data using the given password and the latest encryption
// function.
func Encrypt(password string, data []byte) ([]byte, error) {
	return CryptVersions.Latest().Encrypt(password, data)
}

// Decrypt some data using the given password and its associated encryption
// function.
func Decrypt(password string, data []byte) ([]byte, error) {
	// Try to get a version number from the given data.
	versionNumber, err := parseBlobVersionBytes(data)
	if err != nil {
		return nil, err
	}

	// Delegate decryption based on the indicated version.
	cryptRecord, ok := CryptVersions.Find(versionNumber)
	if !ok {
		return nil, fmt.Errorf("Unable to read files of version %d", versionNumber)
	}

	// Decrypt the data using the given version's decryption function.
	return cryptRecord.Decrypt(password, data)
}
