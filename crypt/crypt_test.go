package crypt

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Make sure we get the original data back after we encrypt and decrypt it with
// the top-level public functions.
func TestEncryptAndDecrypt(t *testing.T) {
	// We make most of these parallel so they can run concurrently and take less
	// real time.
	t.Parallel()

	password := "password"
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(password, plaintext)
		assert.NoError(t, err)

		decrypted, err := Decrypt(password, encrypted)
		assert.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
	}
}

// Attempting to decrypt an empty blob should fail.
func TestDecryptEmptyDataFails(t *testing.T) {
	t.Parallel()

	_, err := Decrypt("password", make([]byte, 0))
	assert.Error(t, err)
}

// Attempting to decrypt an empty blob with an empty password should fail.
func TestDecryptEmptyDataEmptyPasswordFails(t *testing.T) {
	t.Parallel()

	_, err := Decrypt("", make([]byte, 0))
	assert.Error(t, err)
}

// Attempting to decrypt a blob with an empty password (when the original
// password wasn't empty) should fail.
func TestDecryptEmptyPasswordFails(t *testing.T) {
	t.Parallel()

	password := "password"
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(password, plaintext)
		assert.NoError(t, err)

		_, err = Decrypt("", encrypted)
		assert.Error(t, err)
	}
}

// Attempting to decrypt a blob with the wrong password should fail.
func TestDecryptWrongPasswordFails(t *testing.T) {
	t.Parallel()

	password := "password"
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(password, plaintext)
		assert.NoError(t, err)

		_, err = Decrypt("incorrect", encrypted)
		assert.Error(t, err)
	}
}

// Attempting to decrypt a blob that has had any one byte modified should fail.
// TODO: This test takes a _very_ long time to complete. Instead of running each
// encryption/decryption sequentially, we should be running them all in parallel
// to make things progress as quickly as possible. This also applies to all the
// other tests in this file, which should really be running all the tests on the
// data they're given in parallel as well, even if not so much as this one is.
func TestDecryptModifiedBlobFails(t *testing.T) {
	t.Parallel()

	password := "password"

	for _, plaintext := range AllData {
		encrypted, err := Encrypt(password, plaintext)
		assert.NoError(t, err)

		if (testing.Short()) {
			// Change a single byte to save time and do a sanity check, otherwise this
			// test can take many minutes.
			encrypted[rand.Intn(len(encrypted))]++

			_, err = Decrypt(password, encrypted)
			assert.Error(t, err)
		} else {
			// Change every single byte in turn and attempt to decrypt it. Any byte
			// being changed should result in a failed decryption!
			for i, originalByte := range encrypted {
				encrypted[i]++

				_, err = Decrypt(password, encrypted)
				assert.Error(t, err)

				// Restore the original byte value so we're only modifying one byte at a
				// time from the original.
				encrypted[i] = originalByte
			}
		}
	}
}

// Decrypting a blob protected with an empty password should work.
func TestDecryptEmptyPassword(t *testing.T) {
	t.Parallel()

	password := ""
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(password, plaintext)
		assert.NoError(t, err)

		decrypted, err := Decrypt(password, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}
