package database

import (
  "bytes"
  "compress/flate"
  "compress/gzip"
  "crypto/aes"
  "crypto/cipher"
  "crypto/hmac"
  "crypto/rand"
  "crypto/sha512"
  "fmt"
  "io/ioutil"
  "math"

  "code.google.com/p/go.crypto/scrypt"
  sj "github.com/bitly/go-simplejson"
)

// IMPLEMENTATION NOTES:
// - BUILD LOTS OF TESTS, especially around database loading/saving/durability
// - encrypt PII separately from the main database
// - decrypt once to get all non-PII with encrypted PII, then decrypt each
//   individual PII (passwords, custom fields, etc.) as needed. this should
//   prevent more than one PII from existing in memory at a time.
// - use simpler internal encryption so decryption of in-memory stuff is fast
// - use a "tags" format instead of folders (array of strings).
// - user fields are at same level as internal fields
// - internal fields can't be deleted (for simplicity's sake, allow this?)
// - allow easy integration with autotype-like tools via user scripts (plugins)
// - use a sub-command style command line API
// - allow the user to do _everything_ through the command line
// - include an HTTPS-only interface that uses the same mechanism as command
//   line API. this will decrease the maintenance burden by making the HTTP
//   interface a consumer of said API, and increase dogfooding of the same.
// - include a password generator that's independent of entry creation
// - allow several password customization options (see
//   http://passwordsgenerator.net), arbitrary lengths, and the ability to
//   generate several passwords at once.
// - include history for all modifications

// the size of the signature appended to signed data
const SignatureSize = sha512.Size

// the size of the random salt in bytes we use during password hashing
const SaltSize = 32

// the size of key to use for encryption. using 32 bytes (256 bits) selects
// AES-256 encryption (see: http://golang.org/pkg/crypto/aes/#NewCipher).
const KeySize = 32

// we want our HMAC keys to be at least as large as the blocksize (see:
// http://stackoverflow.com/a/12207647), so we double that to get ours.
const HMACKeySize = sha512.BlockSize * 2

// the work factor to use when hashing the master password. this number is used
// as the exponent of a power of 2, which is used for the N parameter to the
// scrypt algorithm. we shoot for a hash time of around 1/4 second on decent
// hardware, to keep the amount of time spent hashing from being inconvenient
// for users.
const HashWorkFactor = 12

// the minimum size of encrypted content, since it must include a password salt,
// an initialization vector, and a SHA-256 checksum at a minimum.
const minEncryptedLength = SaltSize + aes.BlockSize + SignatureSize

// compress some data using the GZip algorithm and return it
func compress(data []byte) ([]byte, error) {
  compressed := new(bytes.Buffer)
  writer, err := gzip.NewWriterLevel(compressed, flate.BestCompression)
  if err != nil { return nil, err }

  // compress our data
  writer.Write(data)
  writer.Close()

  return compressed.Bytes(), nil
}

// decompress some data compressed by the GZip algorithm
func decompress(data []byte) ([]byte, error) {
  b := bytes.NewBuffer(data)
  reader, err := gzip.NewReader(b)
  if err != nil { return nil, err }

  // decompress our data
  result, err := ioutil.ReadAll(reader)
  if err != nil { return nil, err }
  reader.Close()

  return result, nil
}

// get the signature of the given data as a byte array using SHA-512. the
// resulting byte array will have a length of SignatureSize.
func getSignature(data, key []byte) ([]byte, error) {
  if len(key) < HMACKeySize {
    err := fmt.Errorf("Key size is too small (must be at least %d bytes)",
        HMACKeySize)
    return nil, err
  }

  mac := hmac.New(sha512.New, key)
  mac.Write(data)

  // compute and return the signature
  return mac.Sum(nil), nil
}

// sign some data with HMAC-SHA512 and a key, then return the original data with
// the signature appended.
func sign(data, key []byte) ([]byte, error) {
  // copy the original data into a new array
  signedData := make([]byte, len(data))
  copy(signedData, data)

  // return the data with the signature appended
  signature, err := getSignature(data, key)
  if err != nil { return nil, err }

  return append(signedData, signature...), nil
}

// verify that the signature at the end of the given data is valid, then return
// the verified data with the signature stripped off. if the data doesn't
// authenticate, returns an error.
func verify(signedData, key []byte) ([]byte, error) {
  // make sure the data is long enough
  if len(signedData) < SignatureSize {
    err := fmt.Errorf(
        "Data is too short to have a valid signature (minimum length: %d",
        SignatureSize)
    return nil, err
  }

  // stript the signature from the end of the data
  suppliedSignature := signedData[len(signedData) - SignatureSize:]
  data := signedData[:len(signedData) - SignatureSize]

  // sign the data once more
  signature, err := getSignature(data, key)
  if err != nil { return nil, err }

  // signal an error if the computed signature doesn't match the given one.
  // notice that we securely compare the signatures to avoid timing attacks!
  if !hmac.Equal(suppliedSignature, signature) {
    err := fmt.Errorf("Signatures do not match (supplied: %v; computed: %v)",
        suppliedSignature, signature)
    return nil, err
  }

  // return the data slice without the signature attached
  return data, nil
}

// given a password string and a salt, return two byte arrays. the first should
// be used for encryption, the second for HMAC.
func hashPassword(password string, salt []byte, workFactor int) ([]byte, []byte, error) {
  minWorkFactor := 1
  maxWorkFactor := 31
  if workFactor < minWorkFactor || workFactor > maxWorkFactor {
    err := fmt.Errorf("Work factor must be between %d and %d (got: %d)",
        minWorkFactor, maxWorkFactor, workFactor)
    return nil, nil, err
  }

  // turn the work factor into an iteration count, which must be a power of two
  N := int(math.Pow(2, float64(workFactor)))
  r := 32
  p := 4

  // generate enough bytes for both the encryption and HMAC keys. additionally,
  // since scrypt is checking the sizes of the paramter values for us, we don't
  // need to do it ourselves (see:
  // http://code.google.com/p/go/source/browse/scrypt/scrypt.go?repo=crypto).
  hash, err := scrypt.Key([]byte(password), salt, N, r, p, KeySize + HMACKeySize)
  if err != nil { return nil, nil, err }

  // return the keys according to our convention (encryption, then hmac)
  encryptionKey := hash[:KeySize]
  hmacKey := hash[KeySize:]
  return encryptionKey, hmacKey, nil
}

// encrypt some data using the given password and return the result
func encrypt(plaintext []byte, password string) ([]byte, error) {
  // NOTE: no plaintext padding is needed since we're using CFB mode (see:
  // http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Padding).

  // create the parts of the result byte array we need. overall output is the
  // salt, followed by the IV, followed by the ciphertext, followed by the
  // signature of the ciphertext.
  output := make([]byte,
      SaltSize + aes.BlockSize + len(plaintext) + SignatureSize)

  // slice out the pieces we'll be working with
  salt := output[:SaltSize]
  iv := output[SaltSize:SaltSize + aes.BlockSize]

  // same size as the plaintext, a nice property of CFB mode
  ciphertext := output[SaltSize + aes.BlockSize:
      SaltSize + aes.BlockSize + len(plaintext)]

  // randomize the salt and the IV
  if _, err := rand.Read(salt); err != nil { return nil, err }
  if _, err := rand.Read(iv); err != nil { return nil, err }

  // hash the password into an AES-256 (32-byte) key using the generated salt
  encryptionKey, hmacKey, err := hashPassword(password, salt, HashWorkFactor)
  if err != nil { return nil, err }

  // encrypt the plaintext
  block, err := aes.NewCipher(encryptionKey)
  if err != nil { return nil, err }

  // use CFB mode to encrypt the data, so we don't have to pad
  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext, plaintext)

  // get slices of the entire content and the signature
  content := output[:SaltSize + aes.BlockSize + len(plaintext)]
  signature := output[len(output) - SignatureSize:]

  // sign the content
  signatureData, err := sign(content, hmacKey)
  if err != nil { return nil, err }

  // store the signature at the end of the content
  copy(signature, signatureData)

  return output, nil
}

// decrypt some data using the given password
func decrypt(data []byte, password string) ([]byte, error) {
  // make sure our data is of at least the minimum length
  if len(data) < minEncryptedLength {
    err := fmt.Errorf("Data is too short to be valid (min length: %d)",
        minEncryptedLength)
    return nil, err
  }

  // read the salt, IV, and ciphertext from the unverified data
  salt := data[:SaltSize]
  iv := data[SaltSize:SaltSize + aes.BlockSize]
  ciphertext := data[SaltSize + aes.BlockSize:len(data) - SignatureSize]

  // hash the password with the supplied salt to get the keys
  encryptionKey, hmacKey, err := hashPassword(password, salt, HashWorkFactor)
  if err != nil { return nil, err }

  // verify the integrity of the data
  if _, err = verify(data, hmacKey); err != nil { return nil, err }

  // decrypt the ciphertext
  block, err := aes.NewCipher(encryptionKey)
  if err != nil { return nil, err }

  // decrypt directly into the ciphertext to save creating another array
  plaintext := ciphertext[:]
  stream := cipher.NewCFBDecrypter(block, iv)
  stream.XORKeyStream(plaintext, ciphertext)

  return plaintext, nil
}

// load raw JSON from some database file bytes and a password
func load(data []byte, password string) (*sj.Json, error) {
  compressed, err := decrypt(data, password)
  if err != nil { return nil, err }

  plaintext, err := decompress(compressed)
  if err != nil { return nil, err }

  return sj.NewJson(plaintext)
}

// given JSON, encrypt it to our database format using a password
func dump(data *sj.Json, password string) ([]byte, error) {
  json, err := data.Encode()
  if err != nil { return nil, err }

  compressed, err := compress(json)
  if err != nil { return nil, err }

  return encrypt(compressed, password)
}
