package pass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/ugorji/go/codec"
)

// the struct used to compute the signature for all the data
type cryptSignature0 struct {
	N scryptN
	R scryptR
	P scryptP
	Salt salt32
	IV aesIV
	Ciphertext []byte
}

// the struct used to store the metadata for the ciphertext payload
type cryptMeta0 struct {
	N scryptN
	R scryptR
	P scryptP
	Salt salt32
	IV aesIV
	Signature sha512Signature
}

func encrypt0(plaintext []byte, password string) (meta, payload, error) {
	var (
		// these get populated later
		salt salt32
		iv aesIV
		encryptionKey aes256Key
		hmacKey sha512Key
		signature sha512Signature

		N scryptN = 1 << 16
		r scryptR = 16
		p scryptP = 2
	)

	// generate securely-random salt and initialization vectors
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, nil, err
	}

	// compress the plaintext to obfuscate its contents and reduce its size.
	// compression maximizes the entropy prior to encryption, ensuring that we're
	// encrypting the most random-looking thing possible (see:
	// http://superuser.com/a/257802).
	compressedPlaintext, err := compressGzip(plaintext)
	if err != nil {
		return nil, nil, err
	}

	// hash the password into enough bytes to get an AES-256 key and HMAC key
	hashBytes, err := hashPasswordScrypt(password, salt, N, r, p,
		len(encryptionKey) + len(hmacKey))
	if err != nil {
		return nil, nil, err
	}

	// copy the parts into their respective arrays, ensuring we copied the correct
	// number of bytes for each.
	en := copy(encryptionKey[:], hashBytes[:len(encryptionKey)])
	if en != len(encryptionKey) {
		return nil, nil, fmt.Errorf(
			"Incorrect number of encryption key bytes copied (got: %d, expected: %d)",
			en, len(encryptionKey),
		)
	}

	hn := copy(hmacKey[:], hashBytes[len(encryptionKey):])
	if hn != len(hmacKey) {
		return nil, nil, fmt.Errorf(
			"Incorrect number of HMAC key bytes copied (got: %d, expected: %d)",
			hn, len(hmacKey),
		)
	}

	// encrypt the compressed plaintext
	block, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, nil, err
	}

	// uses CFB mode to encrypt the data, so we don't have to pad the input (see:
	// http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Padding).
	var ciphertext []byte
	stream := cipher.NewCFBEncrypter(block, iv[:])
	stream.XORKeyStream(ciphertext, compressedPlaintext)

	// create the struct we'll use to compute the signature
	sig := cryptSignature0 {
		N, r, p,
		salt,
		iv,
		ciphertext,
	}

	// serialize the signature struct, then sign the serialized bytes
	var (
		sigBytes []byte
		mh codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&sigBytes, &mh)
	err = enc.Encode(sig)
	if err != nil {
		return nil, nil, err
	}

	signature, err = signSHA512(sigBytes, hmacKey)
	if err != nil {
		return nil, nil, err
	}

	// build the metadata struct with the signature we just computed
	var metaBytes []byte
	meta := cryptMeta0 {
		N, r, p,
		salt,
		iv,
		signature,
	}

	// serialize the metadata struct
	enc = codec.NewEncoderBytes(&metaBytes, &mh)
	err = enc.Encode(meta)
	if err != nil {
		return nil, nil, err
	}

	// return the signed metadata and encrypted payload
	return metaBytes, ciphertext, nil
}

func decrypt0(metaBytes meta, ciphertext []byte, password string) ([]byte, error) {
	// decode the given metadata
	var (
		meta = cryptMeta0{}
		mh codec.MsgpackHandle
	)
	dec := codec.NewDecoderBytes(metaBytes, &mh)
	err := dec.Decode(&meta)
	if err != nil {
		return nil, err
	}

	// hash the password into an AES-256 key and HMAC key
	var (
		encryptionKey aes256Key
		hmacKey sha512Key
	)
	hashBytes, err := hashPasswordScrypt(password, meta.Salt, meta.N, meta.R,
		meta.P, len(encryptionKey) + len(hmacKey))
	if err != nil {
		return nil, err
	}

	// copy the parts into their respective arrays, ensuring we copied the correct
	// number of bytes for each.
	en := copy(encryptionKey[:], hashBytes[:len(encryptionKey)])
	if en != len(encryptionKey) {
		return nil, fmt.Errorf(
			"Incorrect number of encryption key bytes copied (got: %d, expected: %d)",
			en, len(encryptionKey),
		)
	}

	hn := copy(hmacKey[:], hashBytes[len(encryptionKey):])
	if hn != len(hmacKey) {
		return nil, fmt.Errorf(
			"Incorrect number of HMAC key bytes copied (got: %d, expected: %d)",
			hn, len(hmacKey),
		)
	}

	// sign the received data and make sure the signature verifies
	sig := cryptSignature0 {
		meta.N, meta.R, meta.P,
		meta.Salt,
		meta.IV,
		ciphertext,
	}

	// serialize the signature struct, then ensure the signature verifies it
	var sigBytes []byte
	enc := codec.NewEncoderBytes(&sigBytes, &mh)
	err = enc.Encode(sig)
	if err != nil {
		return nil, err
	}

	err = verifySHA512(sigBytes, meta.Signature, hmacKey)
	if err != nil {
		return nil, err
	}

	// decrypt the ciphertext
	block, err := aes.NewCipher(encryptionKey[:])
	if err != nil {
		return nil, err
	}

	compressedPlaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, meta.IV[:])
	stream.XORKeyStream(compressedPlaintext, ciphertext)

	// decompress and return the plaintext
	plaintext, err := decompressGzip(compressedPlaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
