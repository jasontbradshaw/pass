package pass

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io/ioutil"

  "code.google.com/p/go.crypto/scrypt"
  "github.com/ugorji/go/codec"
)

// the current version of the encrypted blob format, and the one all new blobs
// will be created with.
const CurrentVersion version = 0

// the magic number that marks all of our encrypted blobs as belonging to us
const MagicNumber magicNumber = 0x7A8FE3F5

// alias types to prevent mixing up the otherwise-unlabeled simple types used
// all over the place.
type version int32
type magicNumber int32
type meta []byte
type payload []byte

type aes256Key [32]byte
type aesIV [aes.BlockSize]byte
type salt32 [32]byte
type scryptN int32
type scryptP int32
type scryptR int32
type sha512Key [sha512.BlockSize]byte
type sha512Signature [sha512.Size]byte

// the top-level container format for our blobs. the version number specifies
// how the program interprets the metadata, and the metadata determines how the
// program interprets the payload. this gives maximum flexibility in the face of
// future changes, as well as simpler backwards-compatability.
//
// NOTE: all information exposed here, including metadata, must be considered
// _public_ information! the `payload` should be encrypted independently, as no
// encryption _of any kind_ takes place at this level!
type container struct {
	MagicNumber magicNumber
	Version version
	Meta meta
	Payload payload
}

// compress some data using the GZip algorithm and return it
func compressGzip(data []byte) ([]byte, error) {
	compressed := new(bytes.Buffer)
	writer, err := gzip.NewWriterLevel(compressed, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	defer writer.Close()

	// compress our data
	writer.Write(data)

	return compressed.Bytes(), nil
}

// decompress some data compressed by the GZip algorithm
func decompressGzip(data []byte) ([]byte, error) {
	b := bytes.NewBuffer(data)
	reader, err := gzip.NewReader(b)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// decompress our data
	result, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

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

// return an erro if the given signature doesn't verify the given data
func verifySHA512(data []byte, suppliedSignature sha512Signature, key sha512Key) error {
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

// given a password string and a salt, return a byte array of the specified size
func hashPasswordScrypt(password string, salt salt32, N scryptN, r scryptR, p scryptP, size int) ([]byte, error) {
	// ensure that all the encryption paramters meet minimum requirements
	if N <= 1 {
		return nil, fmt.Errorf("N must be larger than one")
	} else if r <= 0 {
		return nil, fmt.Errorf("r must be larger than zero")
	} else if p <= 0 {
		return nil, fmt.Errorf("p must be larger than zero")
	}

	// NOTE: scrypt memory usage is approximately 128 * `N` * `r` bytes. since `p`
	// has little effect on memory usage, it can be used to tune the running time
	// of the algorithm.

	// generate and return the requested bytes. since scrypt is checking the sizes
	// of the paramter values for us, we don't need to do it ourselves (see:
	// http://code.google.com/p/go/source/browse/scrypt/scrypt.go?repo=crypto).
	return scrypt.Key([]byte(password), salt[:], int(N), int(r), int(p), size)
}

// create container blob bytes for the given version, metadata, and payload
func makeContainer(v version, metaBytes meta, payloadBytes payload) ([]byte, error) {
	c := container {
		MagicNumber,
		v,
		metaBytes,
		payloadBytes,
	}

	// encode our container struct as a msgpack map
	var (
		out []byte
		mh codec.MsgpackHandle
	)

	enc := codec.NewEncoderBytes(&out, &mh)
	err := enc.Encode(c)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// given a container blob, returns the struct it represents
func parseContainer(blobBytes []byte) (container, error) {
	// decode our container data
	var (
		c = container{}
		mh codec.MsgpackHandle
	)

	dec := codec.NewDecoderBytes(blobBytes, &mh)
	err := dec.Decode(&c)
	if err != nil {
		return container{}, err
	}

	return c, nil
}

// encrypt some data using the given password
func Encrypt(data []byte, password string) ([]byte, error) {
	// NOTE: always use the latest encryption version's functions here!
	metaBytes, ciphertextBytes, err := encrypt0(data, password)
	if err != nil {
		return nil, err
	}

	return makeContainer(CurrentVersion, metaBytes, ciphertextBytes)
}

// decrypt some data using the given password
func Decrypt(data []byte, password string) ([]byte, error) {
	// load the container blob first
	container, err := parseContainer(data)
	if err != nil {
		return nil, err
	}

	// decrypt based on the indicated version
	switch container.Version {
	default:
		// disallow all unrecognized versions
		return nil, fmt.Errorf("Unable to read file of version %d", container.Version)

	// add new versions as we need them!
	case 0:
		return decrypt0(container.Meta, container.Payload, password)
	}

	panic("This should be impossible!")
}
