package pass

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
	"reflect"

	"code.google.com/p/go.crypto/scrypt"
	"github.com/ugorji/go/codec"
)

// alias types to prevent mixing up the otherwise-unlabeled simple types used
// all over the place.
type aes256Key [32]byte        // 256 bits == use AES-256
type aesIV [aes.BlockSize]byte // a block's worth of random data
type salt128 [16]byte          // a 128-bit random salt value
type scryptN int32
type scryptP int32
type scryptR int32
type sha512Key [sha512.BlockSize]byte
type sha512Signature [sha512.Size]byte

// encode something using msgpack and return the encoded bytes.
// NOTE: you should probably pass in the thing to be encoded as a pointer!
func encodeMsgpack(thingPointer interface{}) ([]byte, error) {
	var (
		out []byte
		mh  codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&out, &mh)
	err := enc.Encode(thingPointer)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// compress some data using the GZip algorithm and return it
func compressGzip(data []byte) ([]byte, error) {
	compressed := new(bytes.Buffer)
	writer, err := gzip.NewWriterLevel(compressed, flate.BestCompression)
	if err != nil {
		return nil, err
	}

	// compress our data
	writer.Write(data)
	writer.Close()

	return compressed.Bytes(), nil
}

// decompress some data compressed by the GZip algorithm
func decompressGzip(data []byte) ([]byte, error) {
	b := bytes.NewBuffer(data)
	reader, err := gzip.NewReader(b)
	if err != nil {
		return nil, err
	}

	// decompress our data
	result, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	reader.Close()

	return result, nil
}

// get the signature of the given data as a byte array using SHA-512
//
// NOTE: we want the key to be no shorter than the hash algorithm's block size,
// otherwise it will be zero-padded. longer keys are hashed to obtain a key of
// the same size as the block size, so there'really no benefit in using a key
// size that's not equal to the block size of the hash algorithm. we just
// enforce the exact key size to keep things simple.
//
// see:
// * http://stackoverflow.com/a/12207647
// * http://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Definition_.28from_RFC_2104.29
func signSHA512(data []byte, key sha512Key) (sha512Signature, error) {
	mac := hmac.New(sha512.New, key[:])
	mac.Write(data)

	// copy the unsized-array from the sum into a sized array
	var sig sha512Signature
	n := copy(sig[:], mac.Sum(nil))

	// ensure that we got a sum with the exact number of bytes we wanted
	if n != sha512.Size {
		return sha512Signature{}, fmt.Errorf(
			"Signature didn't contain the correct number of bytes (got: %d, expected: %d)",
			n, sha512.Size,
		)
	}

	return sig, nil
}

// return an error if the given signature doesn't verify the given data
func verifySHA512(data []byte, key sha512Key, suppliedSignature sha512Signature) error {
	// sign the data ourselves
	computedSignature, err := signSHA512(data, key)
	if err != nil {
		return err
	}

	// signal an error if the computed signature doesn't match the given one.
	// notice that we securely compare the signatures to avoid timing attacks!
	if !hmac.Equal(suppliedSignature[:], computedSignature[:]) {
		return fmt.Errorf(
			"Signatures do not match:\n  supplied: %v\n  computed: %v",
			suppliedSignature, computedSignature,
		)
	}

	// return no error since the data authenticated correctly
	return nil
}

// given some bytes, a salt, and some scrypt params, return a byte slice with
// the requested number of bytes.
func hashScrypt(data []byte, salt salt128, N scryptN, r scryptR, p scryptP, size int) ([]byte, error) {
	// NOTE: scrypt memory usage is approximately 128 * `N` * `r` bytes. since `p`
	// has little effect on memory usage, it can be used to tune the running time
	// of the algorithm.

	// ensure that all the encryption parameters meet minimum requirements
	if N <= 1 {
		return nil, fmt.Errorf("N must be larger than one")
	} else if r <= 0 {
		return nil, fmt.Errorf("r must be larger than zero")
	} else if p <= 0 {
		return nil, fmt.Errorf("p must be larger than zero")
	}

	// generate the needed bytes. since scrypt is checking the sizes of the
	// parameter values for us, we don't need to do it ourselves (see:
	// http://code.google.com/p/go/source/browse/scrypt/scrypt.go?repo=crypto).
	return scrypt.Key(data, salt[:], int(N), int(r), int(p), size)
}

// given some bytes, a salt, and some scrypt params, populate the given byte
// slices with the bytes generated by scrypt-hashing the input data using the
// given parameters. the slices are populated first-to-last, consuming the
// generated bytes first-to-last as they're populated.
func hashFillScrypt(data []byte, salt salt128, N scryptN, r scryptR, p scryptP, outputs ...[]byte) error {
	// calculate the number of bytes we need to generate overall
	size := 0
	for _, b := range outputs {
		size += len(b)
	}

	// generate the exact number of bytes we need
	hashed, err := hashScrypt(data, salt, N, r, p, size)
	if err != nil {
		return err
	}

	// fill each output byte slice in turn with the generated bytes, in the order
	// the bytes and slices were given to us.
	offset := 0
	for i, b := range outputs {
		count := len(b)

		n := copy(b, hashed[offset:offset+count])
		if n != count {
			return fmt.Errorf(
				"Failed to copy enough bytes to fill output byte slice at index %d", i)
		}

		offset += count
	}

	return nil
}

// encrypts the given byte array using AES-256 in CFB mode and returns the
// resulting bytes.
func encryptAES256CFB(plaintext []byte, iv aesIV, key aes256Key) ([]byte, error) {
	// encrypt the compressed plaintext
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// uses CFB mode to encrypt the data, so we don't have to pad the input (see:
	// http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Padding).
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv[:])
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

// decrypts the given byte array using AES-256 in CFB mode and returns the
// resulting bytes.
func decryptAES256CFB(ciphertext []byte, iv aesIV, key aes256Key) ([]byte, error) {
	// decrypt the ciphertext
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv[:])
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// gets the reputed version of a blob, or an error if that wasn't possible
func getBlobVersion(blob []byte) (cryptVersionNumber, error) {
	// parse the data as a simple map so we can extract the version
	var (
		meta map[string]interface{}
		mh   codec.MsgpackHandle
	)

	dec := codec.NewDecoderBytes(blob, &mh)
	err := dec.Decode(&meta)
	if err != nil {
		return -1, err
	}

	// ensure that the blob included a version
	versionNumberRaw, ok := meta["Version"]
	if !ok {
		return -1, fmt.Errorf("Blob includes no \"Version\" field")
	}

	// convert the version to the expected type. since we decoded into an
	// interface type, the library decodes integers to int64. we convert to that
	// in one step, then downconvert that into the specific type we need next.
	versionNumberLarge, ok := versionNumberRaw.(int64)
	if !ok {
		versionNumberRawType := reflect.TypeOf(versionNumberRaw)
		return -1, fmt.Errorf(
			"\"Version\" value could not be read as int64 (got: %v, of type: %s)",
			versionNumberRaw,
			versionNumberRawType,
		)
	}

	// downconvert into our specific type. we shouldn't lose any information
	// (assuming a well-formed blob) since we didn't put any more information than
	// this into it in the first place!
	return cryptVersionNumber(versionNumberLarge), nil
}

// encrypt some data using the given password and the latest encryption function
func Encrypt(data []byte, password string) ([]byte, error) {
	return CryptVersions.Latest().Encrypt(data, password)
}

// decrypt some data using the given password
func Decrypt(data []byte, password string) ([]byte, error) {
	// try to get a version number from the given data
	versionNumber, err := getBlobVersion(data)
	if err != nil {
		return nil, err
	}

	// delegate decryption based on the indicated version
	cryptRecord, ok := CryptVersions.Find(versionNumber)
	if !ok {
		return nil, fmt.Errorf("Unable to read file of version %d", versionNumber)
	}

	// decrypt the data using the given version's decryption function
	return cryptRecord.Decrypt(data, password)
}
