package pass

import (
	"crypto/rand"
	"crypto/sha512"

	"github.com/ugorji/go/codec"
)

// expose our record so it can be added to the version database
var cryptVersionRecord0 cryptVersionRecord = cryptVersionRecord{
	0, encrypt0, decrypt0,
}

// the struct used to store the metadata for the ciphertext payload
type cryptData0 struct {
	Version    cryptVersionNumber
	ScryptN    scryptN
	ScryptR    scryptR
	ScryptP    scryptP
	Salt       salt128
	IV         aesIV
	Ciphertext []byte
}

func encrypt0(plaintext []byte, password string) ([]byte, error) {
	var (
		// these get populated later
		salt          salt128
		iv            aesIV
		encryptionKey aes256Key
		hmacKey       sha512Key
		signature     sha512Signature

		N scryptN = 1 << 16
		r scryptR = 16
		p scryptP = 2
	)

	// generate securely-random salt and initialization vector bytes
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, err
	}

	// compress the plaintext to obfuscate its contents and reduce its size.
	// compression maximizes the entropy prior to encryption, ensuring that we're
	// encrypting the most random-looking thing possible and hardening against
	// known-plaintext attacks (see: http://superuser.com/a/257802).
	compressedPlaintext, err := compressGzip(plaintext)
	if err != nil {
		return nil, err
	}

	// hash the password into an AES-256 key and HMAC key
	err = hashFillScrypt([]byte(password), salt, N, r, p, encryptionKey[:], hmacKey[:])
	if err != nil {
		return nil, err
	}

	// encrypt the compressed plaintext
	ciphertext, err := encryptAES256CFB(compressedPlaintext, iv, encryptionKey)

	// the struct used to serialize the data to msgpack
	meta := cryptData0{
		0,
		N, r, p,
		salt,
		iv,
		ciphertext,
	}

	// serialize the struct to bytes
	metaBytes, err := encodeMsgpack(&meta)
	if err != nil {
		return nil, err
	}

	// append a msgpack bin 8 object header to the stream, sans any body data.
	// this will identify the signature and its body bytes once we append the
	// signature itself. we hash this along with the other data so we can get a
	// HMAC hash of the complete content (sans the signature), but still adhere to
	// the msgpack spec and be able to decode it normally later. see:
	// https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family
	// for spec details.
	metaWithSigHeaderBytes := append(metaBytes, 0xc4, uint8(len(signature)))

	// sign everything, including the newly-added header
	signature, err = signSHA512(metaWithSigHeaderBytes, hmacKey)
	if err != nil {
		return nil, err
	}

	// append the calculated signature to the newly-signed bytes
	metaWithSigBytes := append(metaWithSigHeaderBytes, signature[:]...)

	return metaWithSigBytes, nil
}

func decrypt0(signedMeta []byte, password string) ([]byte, error) {
	// decode the metadata object
	var (
		meta cryptData0
		mh   codec.MsgpackHandle
	)
	dec := codec.NewDecoderBytes(signedMeta, &mh)
	err := dec.Decode(&meta)
	if err != nil {
		return nil, err
	}

	// decode the signature, the next object in the input bytes
	var signature sha512Signature
	err = dec.Decode(&signature)
	if err != nil {
		return nil, err
	}

	// hash the password into an AES-256 key and HMAC key
	var (
		encryptionKey aes256Key
		hmacKey       sha512Key
	)
	err = hashFillScrypt([]byte(password), meta.Salt,
		meta.ScryptN, meta.ScryptR, meta.ScryptP, encryptionKey[:], hmacKey[:])
	if err != nil {
		return nil, err
	}

	// verify the signed data, the meta plus the signature header bytes
	sigStartIndex := len(signedMeta) - sha512.Size
	err = verifySHA512(signedMeta[:sigStartIndex], hmacKey, signature)
	if err != nil {
		return nil, err
	}

	// decrypt, decompress, and return the plaintext
	compressedPlaintext, err := decryptAES256CFB(meta.Ciphertext, meta.IV, encryptionKey)
	plaintext, err := decompressGzip(compressedPlaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
