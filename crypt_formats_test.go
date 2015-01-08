package pass

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
)

// some data we can play with
var Data []byte = []byte("insert super important data here")

// make sure we get msgpack data back from encryption
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

// the top-level encrypt function should always be using the latest version
func TestEncryptUsesLatestVersion(t *testing.T) {
	// TODO: build it
}

// each encrypted blob must be readable as a map that contains a "Version" key
// NOTE: this is necessary so the top-level functions can delegate to a specific
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

// each version should be able to encrypt and decrypt its own data
// NOTE: this is necessary for pretty obvious reasons
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

// each version should yield different data for two different encrypt calls on
// the same data.
// NOTE: this preserves the "anonymity" of the data, since an attacker can't
// tell reliably whether the data has been changed or just re-encrypted. this
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

// make sure that encrypting the data is doing some sort of compression. we
// supply it with a large amount of repetitious data, which any self-respecting
// compression algorithm should reduce the size of with ease. the size of the
// data should me much longer than the minimum encrypted length, in order to
// ensure that the compression and encryption overhead is balanced out.
// NOTE: this is necessary since compressing before encrypting can prevent
// known-plaintext attacks, since compression is squeezing any low-entropy areas
// out of the plaintext, "randomizing" it and making it more difficult to detect
// what lies within.
func TestEncryptCompressesPlaintext(t *testing.T) {
	// lots of zeros should always compress very well size := 10000
	size := 10000
	repetitiousData := make([]byte, size)

	for _, version := range CryptVersions.All() {
		encrypted, err := version.Encrypt(repetitiousData, "password")
		assert.NoError(t, err)

		// in this case, the encrypted data should be smaller
		assert.True(t, len(encrypted) < size)
	}
}

// no public version should have a nil function value
func TestAllVersionsHaveNonNilFunctions(t *testing.T) {
	for _, version := range CryptVersions.All() {
		assert.NotNil(t, version.Encrypt)
		assert.NotNil(t, version.Decrypt)
	}
}
