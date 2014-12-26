package pass

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io/ioutil"

	"code.google.com/p/go.crypto/scrypt"
)

// the top-level format of the encrypted blob:
//
//   ----
//   magic number (4 bytes, always 0xEA8F73F5)
//   version number as a uint32 (4 bytes)
//   ----
//   metadata size as a uint32 (4 bytes)
//   medadata (of the given size above)
//   ----
//   payload (the remaining bytes)
//   ---
//
// the version number specifies how the program interprets the metadata, and the
// metadata determines how the program interprets the payload. this gives
// maximum flexibility in the face of future changes and backwards
// compatability.

// the size of our magic number, in bytes
const MagicNumberSize = 4

// the magic number that marks all of our encrypted blobs as belonging to us
const MagicNumber uint32 = 0xEA8F73F5

// the current version of the encrypted blob format, and the one all new blobs
// will be created with.
const Version uint32 = 0

// the size of our version number, in bytes
const VersionSize = 4

// how large the size of the metadata header size block is, in bytes
const MetaDataSizeSize = 4

// the size of the signature added to signed data
const SignatureSize = sha512.Size

// the size of the random salt in bytes we use during password hashing
const SaltSize = 32

// the size of key to use for encryption. using 32 bytes (256 bits) selects
// AES-256 encryption (see: http://golang.org/pkg/crypto/aes/#NewCipher).
const EncryptionKeySize = 32

// we want our HMAC keys to be the same size as the blocksize (see:
// http://stackoverflow.com/a/12207647 and
// http://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Definition_.28from_RFC_2104.29).
const HMACKeySize = sha512.BlockSize

// the parameters to use when hashing the master password. we shoot for a memory
// requirement of 128Mb (128 * N * r bytes).
const HashN uint32 = 1 << 16 // 2^16
const HashR uint32 = 16
const HashP uint32 = 2

// how large each hash parameter is, in bytes
const HashParamSize = 4

// the minimum size of encrypted content. it must include a version, the
// password salt, the hashing parameters, an initialization vector, and a
// signature - at a minimum!
const minEncryptedLength = (VersionSize + SaltSize + (3 * HashParamSize) +
	aes.BlockSize + SignatureSize)

// compress some data using the GZip algorithm and return it
func compress(data []byte) ([]byte, error) {
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
func decompress(data []byte) ([]byte, error) {
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

// get the signature of the given data as a byte array using SHA-512. the
// resulting byte array will have a length of SignatureSize.
func sign(data, key []byte) ([]byte, error) {
	// we want the key to be no shorter than the hash algorithm's block size,
	// otherwise it will be zero-padded. longer keys are hashed to obtain a key of
	// the same size as the block size, so there's really no benefit in using a
	// key size that's not equal to the block size of the hash algorithm. it
	// doesn't hurt, however, so we let that case alone.
	if len(key) < sha512.BlockSize {
		err := fmt.Errorf("Key size is too small (should be %d bytes)",
			sha512.BlockSize)
		return nil, err
	}

	mac := hmac.New(sha512.New, key)
	mac.Write(data)

	// compute and return the signature
	return mac.Sum(nil), nil
}

// return whether the given signature verifies the given data
func verify(data, suppliedSignature, key []byte) error {
	// make sure the signature is the correct size
	if len(suppliedSignature) != sha512.Size {
		err := fmt.Errorf("Signature must be %d bytes long (got %d)",
			sha512.Size, len(suppliedSignature))
		return err
	}

	// sign the data ourself
	computedSignature, err := sign(data, key)
	if err != nil {
		return err
	}

	// signal an error if the computed signature doesn't match the given one.
	// notice that we securely compare the signatures to avoid timing attacks!
	if !hmac.Equal(suppliedSignature, computedSignature) {
		err := fmt.Errorf(
			"Signatures do not match:\n  supplied: %v\n  computed: %v",
			suppliedSignature, computedSignature)
		return err
	}

	// return no error since the data authenticated correctly
	return nil
}

// encode the given number as an array of bytes, then return the array and
// whether there was an error.
func uint32ToBytes(number uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, number); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// read a number from an array of bytes and return the number, or an error if
// something went wrong.
func bytesToUint32(numberBytes []byte) (uint32, error) {
	// make sure we got enough bytes to parse a version out of them
	uint32Bytes := 4
	if len(numberBytes) < uint32Bytes {
		return 0, fmt.Errorf(
			"Not enough bytes to contain a number (minimum: %d)", uint32Bytes)
	}

	// read the number from the bytes and return it
	buf := bytes.NewBuffer(numberBytes)
	var number uint32
	if err := binary.Read(buf, binary.BigEndian, &number); err != nil {
		return 0, err
	}

	return number, nil
}

// given a password string and a salt, return two byte arrays. the first should
// be used for encryption, the second for HMAC.
func hashPassword(password string, salt []byte, N, r, p uint32) ([]byte, []byte, error) {
	// ensure that all the encryption paramters meet minimum requirements
	if N <= 1 {
		return nil, nil, fmt.Errorf("N must be larger than one")
	} else if r <= 0 {
		return nil, nil, fmt.Errorf("r must be larger than zero")
	} else if p <= 0 {
		return nil, nil, fmt.Errorf("p must be larger than zero")
	}

	// NOTE: scrypt memory usage is approximately 128 * `N` * `r` bytes. since `p`
	// has little effect on memory usage, it can be used to tune the running time
	// of the algorithm.

	// generate enough bytes for both the encryption and HMAC keys. additionally,
	// since scrypt is checking the sizes of the paramter values for us, we don't
	// need to do it ourselves (see:
	// http://code.google.com/p/go/source/browse/scrypt/scrypt.go?repo=crypto).
	hash, err := scrypt.Key([]byte(password), salt, int(N), int(r), int(p),
		EncryptionKeySize+HMACKeySize)
	if err != nil {
		return nil, nil, err
	}

	// return the keys according to our convention (encryption, then hmac)
	encryptionKey := hash[:EncryptionKeySize]
	hmacKey := hash[EncryptionKeySize:]
	return encryptionKey, hmacKey, nil
}

// given a blob, confirms it's of the required format, then returns its
// constituent parts: the version, the metadata, and the payload. returns an
// error if something goes wrong.
func loadBlob(blobBytes []byte) (uint32, []byte, []byte, error) {
	// if the blob is too short to be valid, give up
	const minSize = MagicNumberSize + VersionSize + MetaDataSizeSize
	if (len(blobBytes) < minSize) {
		return 0, nil, nil, fmt.Errorf(
			"Blob is too short to be valid (minimum size: %d bytes)", minSize);
	}

	// load as much information as we can at this point
	blob := NewBlob(
		"magic_number", MagicNumberSize,
		"version", VersionSize,
		"meta_size", MetaDataSizeSize,
		blobBytes,
	)

	// validate the magic number to perform a sanity check on our data
	magicNumber, err := bytesToUint32(blob.Get("magic_number"))
	if err != nil {
		return 0, nil, nil, err
	}
	if (magicNumber != MagicNumber) {
		return 0, nil, nil, fmt.Errorf(
			"Unrecognized file format: magic number did not match")
	}

	// parse the version number
	version, err := bytesToUint32(blob.Get("version"))
	if err != nil {
		return 0, nil, nil, err
	}

	// parse the metadata size
	metaSize, err := bytesToUint32(blob.Get("meta_size"))
	if err != nil {
		return 0, nil, nil, err
	}

	// the bytes from the start of the metadata body onwards
	restBytes := blobBytes[minSize:]

	// if the remaining data isn't large enough to cover the given size, return an
	// error.
	if (metaSize > uint32(len(restBytes))) {
		return 0, nil, nil, fmt.Errorf(
			"Got invalid metadata size: %d bytes (remaining data only %d bytes)",
			metaSize,
			len(restBytes),
		)
	}

	// retrieve the metadata and the payload
	metaBytes := restBytes[:metaSize]
	payloadBytes := restBytes[metaSize:]

	return version, metaBytes, payloadBytes, nil
}

// encrypt some data using the given password and default scrypt params, then
// return the result.
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	// use the default params to encrypt this text
	return EncryptWithHashParams(plaintext, password, HashN, HashR, HashP)
}

// encrypt some data using the given password and scrypt params, then return the
// result.
func EncryptWithHashParams(plaintext []byte, password string, N, r, p uint32) ([]byte, error) {
	// NOTE: no plaintext padding is needed since we're using CFB mode (see:
	// http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Padding).

	// first, compress the plaintext to obfuscate its contents and reduce its size
	compressedPlaintext, err := compress(plaintext)
	if err != nil {
		return nil, err
	}

	// make a blob that conforms to our defined structure
	blob := NewBlob(
		"version", VersionSize,
		"N", HashParamSize,
		"r", HashParamSize,
		"p", HashParamSize,
		"salt", SaltSize,
		"iv", aes.BlockSize,
		"data", len(compressedPlaintext),
		"signature", SignatureSize,
	)

	// get the slices we'll be working with
	version := blob.Get("version")
	salt := blob.Get("salt")
	blobN := blob.Get("N")
	blobR := blob.Get("r")
	blobP := blob.Get("p")
	iv := blob.Get("iv")
	ciphertext := blob.Get("data")
	signature := blob.Get("signature")

	// serialize and store the current version
	versionBytes, err := uint32ToBytes(Version)
	if err != nil {
		return nil, err
	}
	copy(version, versionBytes)

	// randomize the salt and the initialization vector
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// serialize and store the hash paramters
	nBytes, err := uint32ToBytes(N)
	if err != nil {
		return nil, err
	}
	copy(blobN, nBytes)

	rBytes, err := uint32ToBytes(r)
	if err != nil {
		return nil, err
	}
	copy(blobR, rBytes)

	pBytes, err := uint32ToBytes(p)
	if err != nil {
		return nil, err
	}
	copy(blobP, pBytes)

	// hash the password into the necessary keys using the salt
	encryptionKey, hmacKey, err := hashPassword(password, salt, N, r, p)
	if err != nil {
		return nil, err
	}

	// encrypt the compressed plaintext
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	// use CFB mode to encrypt the data, so we don't have to pad
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, compressedPlaintext)

	// sign our data (everything _but_ the signature space)
	content := blob.To("data")
	signatureData, err := sign(content, hmacKey)
	if err != nil {
		return nil, err
	}

	// store the signature
	copy(signature, signatureData)

	return blob.Bytes(), nil
}

// decrypt some data using the given password
func Decrypt(data []byte, password string) ([]byte, error) {
	// make sure our data is of at least the minimum length
	if len(data) < minEncryptedLength {
		err := fmt.Errorf("Data is too short to be valid (min length: %d)",
			minEncryptedLength)
		return nil, err
	}

	// make a blob that conforms to our defined structure
	blob := NewBlob(
		"version", VersionSize,
		"N", HashParamSize,
		"r", HashParamSize,
		"p", HashParamSize,
		"salt", SaltSize,
		"iv", aes.BlockSize,

		// the ciphertext is everything in the blob _except_ the other fields
		"data", len(data)-(VersionSize+
			SaltSize+
			(3*HashParamSize)+
			aes.BlockSize+
			SignatureSize),

		"signature", SignatureSize,

		// initalize the blob with the encrypted data
		data,
	)

	// make sure we can decrypt this version
	version, err := bytesToUint32(blob.Get("version"))
	if err != nil {
		return nil, err
	}

	// we'll never be able to handle newer versions!
	if version > Version {
		return nil, fmt.Errorf("Latest supported version is %d (got: %d)",
			Version, version)
	}

	// decrypt using a version of the algorithm that matches the given blob
	if version < Version {
		// TODO: add support for older versions once they exist
		panic("No older versions shoud exist at this time!")
	}

	// read the the parts we need from the unverified data
	salt := blob.Get("salt")
	iv := blob.Get("iv")
	ciphertext := blob.Get("data")
	signature := blob.Get("signature")

	// read the hash paramters we need to hash the password
	N, err := bytesToUint32(blob.Get("N"))
	if err != nil {
		return nil, err
	}
	r, err := bytesToUint32(blob.Get("r"))
	if err != nil {
		return nil, err
	}
	p, err := bytesToUint32(blob.Get("p"))
	if err != nil {
		return nil, err
	}

	// hash the password with the supplied salt and paramters to get the keys
	encryptionKey, hmacKey, err := hashPassword(password, salt, N, r, p)
	if err != nil {
		return nil, err
	}

	// verify the integrity of the blob (including the version)
	err = verify(blob.To("data"), signature, hmacKey)
	if err != nil {
		return nil, err
	}

	// decrypt the ciphertext
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	// decrypt directly into the original slice to save creating a new array
	compressedPlaintext := ciphertext[:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(compressedPlaintext, ciphertext)

	// decompress the compressed plaintext
	plaintext, err := decompress(compressedPlaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
