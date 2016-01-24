package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/ugorji/go/codec"
)

// Expose our record so it can be added to the version database.
var cryptVersionRecord0 cryptVersionRecord = cryptVersionRecord{
	cryptVersionNumber0, encrypt0, decrypt0,
}

const cryptVersionNumber0 cryptVersionNumber = 0

func encrypt0(password string, plaintext []byte) ([]byte, error) {
	var (
		// Data we'll include in the encrypted/authenticated output blob.
		salt  salt128
		nonce aes128GCMNonce
		N     scryptN = 1 << 16
		r     scryptR = 16
		p     scryptP = 2
	)

	// Generate securely-random salt bytes.
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	// Generate a securely-random nonce. This should never be identical for two
	// different encryptions using the same key. 96 bits of randomness is more
	// than enough to ensure that we don't get duplicate nonces since at the end
	// of the day we have a human initiating all encryption. The human heart beats
	// around 3 billion times in a single lifetime; even if you encrypted the same
	// blob with the same key and a random nonce that many times, we'd only have a
	// 1 in 5.7e-11 chance of seeing a duplicate nonce (see
	// https://en.wikipedia.org/wiki/Universally_unique_identifier#Random_UUID_probability_of_duplicates
	// and
	// http://www.wolframalpha.com/input/?i=1-e%5E%28-n%5E2%2F%282%C3%972%5Ex%29%29+where+n+%3D+3000000000%2C+x+%3D+96
	// for the source of the calculation and its explanation.
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	// Compress the plaintext to obfuscate its contents and reduce its size.
	// Compression maximizes its entropy prior to encryption, ensuring that we're
	// encrypting the most random-looking thing possible and hardening against
	// known-plaintext attacks (see http://superuser.com/a/257802).
	compressedPlaintext, err := compressLZ4(plaintext)
	if err != nil {
		return nil, err
	}

	// Hash the password into an AES-128 key.
	var encryptionKey aes128Key
	err = hashFillScrypt(N, r, p, salt, []byte(password), encryptionKey[:])
	if err != nil {
		return nil, err
	}

	// Build the AES cipher we'll use with GCM. The GCM will error during
	// instantiation if we don't use AES-128.
	block, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, err
	}

	// Create our associated data header, starting with the globally required
	// pieces.
	header, err := buildHeaderBlob(cryptVersionNumber0)
	if err != nil {
		return nil, err
	}

	// Encode our custom associated data values and append them in turn. Order
	// matters here since when we decrypt them we'll need to do so in a particular
	// order.
	encodedSalt, err := encodeMsgpack(&salt)
	if err != nil {
		return nil, err
	}
	header = append(header, encodedSalt...)

	encodedNonce, err := encodeMsgpack(&nonce)
	if err != nil {
		return nil, err
	}
	header = append(header, encodedNonce...)

	encodedN, err := encodeMsgpack(&N)
	if err != nil {
		return nil, err
	}
	header = append(header, encodedN...)

	encodedR, err := encodeMsgpack(&r)
	if err != nil {
		return nil, err
	}
	header = append(header, encodedR...)

	encodedP, err := encodeMsgpack(&p)
	if err != nil {
		return nil, err
	}
	header = append(header, encodedP...)

	// Create the AEAD we'll be using to encrypt the plaintext.
	aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}

	// Calculate how long we expect the ciphertext to be.
	ciphertextExpectedLength := len(compressedPlaintext) + aead.Overhead()

	// Manually generate a msgpack header for the ciphertext. We don't have the
	// actual ciphertext just yet, but we _do_ know how long it's going to be,
	// which is all we need to generate the header. We always use the
	// maximum-length bin format type for conveninence, and we ensure that the
	// resulting ciphertext will be shorter than this to prevent ugly things from
	// happening if it was too large. See
	// https://github.com/msgpack/msgpack/blob/master/spec.md#formats-map for
	// detailed information about the format.

	// Ensure the ciphertext isn't too long to be encoded in msgpack.
	if ciphertextExpectedLength > ciphertextMaxLength {
		return nil, fmt.Errorf("Ciphertext is too large to be correctly encoded.")
	}

	// We first write the type marker for a maximum-size binary data string, then
	// we encode the length of our ciphertext as a big-endian `uint32` and append
	// it to the header. Once we encrypt/authenticate the plaintext, we'll be able
	// to append it wholesale to this existing authenticated header, and later
	// decode it all from the same stream. This lets us have a single stream of
	// msgpack data that's entirely authenticated while at the same time
	// containing the authenticated ciphertext itself!
	header = append(header, 0xc6)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(ciphertextExpectedLength))
	header = append(header, buf.Bytes()...)

	// The ciphertext data will include a GCM tag along with the encrypted data,
	// so its output will therefore be larger than its input. Ensure the final
	// data was as long as we expected it to be, otherwise we have some serious
	// problems.
	ciphertext := aead.Seal(nil, nonce[:], compressedPlaintext, header)
	if len(ciphertext) != ciphertextExpectedLength {
		return nil, fmt.Errorf(
			"Encryption/authentication output data wasn't of the expected length (expected: %d bytes, got: %d bytes)",
			ciphertextExpectedLength,
			len(ciphertext),
		)
	}

	// Append the authenticated ciphertext to our authenticated header and return
	// the final result.
	return append(header, ciphertext...), nil
}

func decrypt0(password string, blob []byte) ([]byte, error) {
	// Build a decoder for the blob data.
	var mh codec.MsgpackHandle
	dec := codec.NewDecoderBytes(blob, &mh)

	// Ensure we got the correct blob version.
	version, err := parseBlobVersion(dec)
	if err != nil {
		return nil, err
	}
	if version != cryptVersionNumber0 {
		return nil, fmt.Errorf(
			"Invalid version (expected: %d, got: %d)",
			cryptVersionNumber0,
			version,
		)
	}

	// Decode all the parts we'll need to verify the blob version. If we can't
	// decode all of them, we must fail since we need all the data we're
	// expecting. Note that order matters, and must match the order these were
	// encoded in!
	var (
		salt       salt128
		nonce      aes128GCMNonce
		N          scryptN
		r          scryptR
		p          scryptP
		ciphertext []byte
	)

	err = dec.Decode(&salt)
	if err != nil {
		return nil, err
	}

	err = dec.Decode(&nonce)
	if err != nil {
		return nil, err
	}

	err = dec.Decode(&N)
	if err != nil {
		return nil, err
	}

	err = dec.Decode(&r)
	if err != nil {
		return nil, err
	}

	err = dec.Decode(&p)
	if err != nil {
		return nil, err
	}

	err = dec.Decode(&ciphertext)
	if err != nil {
		return nil, err
	}

	// Once we've decoded the ciphertext, we can subtract its length from the
	// original blob and retrieve the header bytes, which together form the
	// associated data we need to decrypt the ciphertext.
	associatedData := blob[0 : len(blob)-len(ciphertext)]

	// Hash the password into an AES-128 key.
	var encryptionKey aes128Key
	err = hashFillScrypt(N, r, p, salt, []byte(password), encryptionKey[:])
	if err != nil {
		return nil, err
	}

	// Build the AES cipher we'll use with GCM. The GCM will error during
	// instantiation if we don't use AES-128.
	block, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, err
	}

	// Create the AEAD we'll be using to decrypt the plaintext.
	aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}

	// Decrypt our ciphertext to receive the compressed plaintext.
	compressedPlaintext, err := aead.Open(nil, nonce[:], ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	// Decompress the compressed plaintext.
	plaintext, err := decompressLZ4(compressedPlaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
