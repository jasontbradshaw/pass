package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
)

// Some data we can play with.
var Data []byte = []byte("insert super important data here")

// Make sure we get msgpack data back from encryption.
// NOTE: This is a requirement of our top-level format.
func TestEncryptYieldsMsgpack(t *testing.T) {
	for _, version := range CryptVersions.All() {
		ciphertext, err := version.Encrypt(Data, "password")
		assert.NoError(t, err)

		var (
			msgpack map[string]interface{}
			mh      codec.MsgpackHandle
		)
		dec := codec.NewDecoderBytes(ciphertext, &mh)
		err = dec.Decode(&msgpack)
		assert.NoError(t, err)
	}
}

// The top-level encrypt function should always be using the latest version.
func TestEncryptUsesLatestVersion(t *testing.T) {
	password := "password"

	// Encrypt with our top-level function.
	ciphertext, err := Encrypt(Data, password)
	assert.NoError(t, err)

	// The version should match the latest version.
	versionNumber, err := getBlobVersion(ciphertext)
	assert.NoError(t, err)

	// Get the latest version and make sure that's what we got.
	latest := CryptVersions.Latest()
	assert.Equal(t, latest.Version, versionNumber)

	// For good measure, decryption with the latest version's decrypt function
	// should work too.
	plaintext, err := latest.Decrypt(ciphertext, password)
	assert.NoError(t, err)
	assert.Equal(t, Data, plaintext)
}

// Each encrypted blob must be readable as a map that contains a "Version" key.
// NOTE: This is necessary so the top-level functions can delegate to a specific
// algorithm when decrypting.
func TestEncryptYieldsMsgpackWithVersionKey(t *testing.T) {
	for _, version := range CryptVersions.All() {
		ciphertext, err := version.Encrypt(Data, "password")
		assert.NoError(t, err)

		var (
			msgpack map[string]interface{}
			mh      codec.MsgpackHandle
		)
		dec := codec.NewDecoderBytes(ciphertext, &mh)
		err = dec.Decode(&msgpack)
		assert.NoError(t, err)

		_, ok := msgpack["Version"]
		assert.True(t, ok)
	}
}

// Each version should be able to encrypt and decrypt its own data.
// NOTE: This is necessary for pretty obvious reasons.
func TestEncryptAndDecryptAllVersions(t *testing.T) {
	password := "password"
	for _, version := range CryptVersions.All() {
		encrypted, err := version.Encrypt(Data, password)
		assert.NoError(t, err)

		decrypted, err := version.Decrypt(encrypted, password)
		assert.NoError(t, err)

		assert.Equal(t, Data, decrypted)
	}
}

// Each version should yield different data for two different encrypt calls on
// the same data.
// NOTE: This preserves the "anonymity" of the data, since an attacker can't
// tell reliably whether the data has been changed or just re-encrypted. This
// also ensures that whatever encryption is being done is using a random salt,
// which is basically necessary for this kind of application.
func TestEncryptTwiceYieldsDifferentOutput(t *testing.T) {
	password := "password"
	for _, version := range CryptVersions.All() {
		encrypted1, err := version.Encrypt(Data, password)
		assert.NoError(t, err)

		encrypted2, err := version.Encrypt(Data, password)
		assert.NoError(t, err)

		assert.NotEqual(t, encrypted1, encrypted2)
	}
}

// Make sure that encrypting the data is doing some sort of compression. We
// supply it with a large amount of repetitious data, which any self-respecting
// compression algorithm should reduce the size of with ease. The size of the
// data should me much longer than the minimum encrypted length, in order to
// ensure that the compression and encryption overhead is balanced out.
// NOTE: This is necessary since compressing before encrypting can prevent
// known-plaintext attacks, since compression is squeezing any low-entropy areas
// out of the plaintext, "randomizing" it and making it more difficult to detect
// what lies within.
func TestEncryptCompressesPlaintext(t *testing.T) {
	// Lots of zeros should always compress very well!
	size := 10000
	repetitiousData := make([]byte, size)

	for _, version := range CryptVersions.All() {
		encrypted, err := version.Encrypt(repetitiousData, "password")
		assert.NoError(t, err)

		// In this case, the encrypted data should be smaller.
		assert.True(t, len(encrypted) < size)
	}
}

// No public version should have a `nil` function value
func TestAllVersionsHaveNonNilFunctions(t *testing.T) {
	for _, version := range CryptVersions.All() {
		assert.NotNil(t, version.Encrypt)
		assert.NotNil(t, version.Decrypt)
	}
}
