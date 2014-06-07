package database

import (
  "bytes"
  "compress/flate"
  "compress/gzip"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
  "fmt"
  "io/ioutil"
  sj "github.com/bitly/go-simplejson"
  "code.google.com/p/go.crypto/scrypt"
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

// the size of the salt data that's pre-pended to the encrypted data
const SaltSize = 32

// the size of the signature appended to signed data
const SignatureSize = sha256.Size

// the number of iterations to use when hashing the master password
const HashIterations = 32768

// this is the smallest length of compressed content we can generate, the result
// of using our compression function on an empty input array. for reference, the
// minimum compressed bytes are:
//   [31 139 8 0 0 9 110 136 2 255 1 0 0 255 255 0 0 0 0 0 0 0 0]
const minCompressedLength = 23

// the database in which password data is stored, including methods for
// loading, reading, modifying, and storing it.
type Database struct {
  // where the database is currently stored on disk
  Location string

  // the internal data storage format, as JSON
  data *sj.Json
}

// compress some data using the GZip algorithm
func compress(data []byte) ([]byte, error) {
  var result bytes.Buffer
  writer, err := gzip.NewWriterLevel(&result, flate.BestCompression)

  if err != nil { return nil, err }

  // compress our data
  writer.Write(data)
  writer.Close()

  return result.Bytes(), nil
}

// decompress some data compressed by the GZip algorithm
func decompress(data []byte) ([]byte, error) {
  // make sure we get non-empty data
  if len(data) < minCompressedLength {
    err := fmt.Errorf("Data is too short to be valid (min length: %d)",
        minCompressedLength)
    return nil, err
  }

  b := bytes.NewBuffer(data)
  reader, err := gzip.NewReader(b)

  if err != nil { return nil, err }

  // compress our data and close the reader
  result, err := ioutil.ReadAll(reader)
  if err != nil { return nil, err }
  reader.Close()

  return result, nil
}

// get the signature of the given data as a byte array
func getSignature(data []byte) []byte {
  // hash the data
  signature32 := sha256.Sum256(data)
  return []byte(signature32[:])
}

// sign some data with SHA-256 and return the original data with the signature
// appended.
func sign(data []byte) []byte {
  // hash the data
  signature := getSignature(data)

  // copy the data and signature into a new array
  signedData := make([]byte, len(data) + sha256.Size)
  copy(signedData, data)
  copy(signedData[len(signedData) - sha256.Size:], signature)

  return signedData
}

// verify that the SHA-256 signature at the end of the given data is valid, then
// return the verified data with the signature stripped off. if the data doesn't
// pass the checksum, returns an error.
func verify(signedData []byte) ([]byte, error) {
  // make sure the data is long enough
  minLength := sha256.Size
  if len(signedData) < minLength {
    err := fmt.Errorf(
        "Data is too short to have a valid signature (minimum length: %d",
        minLength)
    return nil, err
  }

  // get the signature from the end of the data
  suppliedSignature := signedData[len(signedData) - sha256.Size:]
  data := signedData[:len(signedData) - sha256.Size]

  // sign the data once more
  signature := getSignature(data)

  // securely compare the signatures to determine validity. it's important that
  // we don't bail on the comparison early in order to avoid timing attacks!
  valid := true
  for i := 0; i < len(signature); i++ {
    valid = valid && (signature[i] == suppliedSignature[i])
  }

  // signal an error if the computed signature doesn't match the given one
  if !valid {
    err := fmt.Errorf("Signatures do not match (supplied: %v; computed: %v)",
        suppliedSignature, signature)
    return nil, err
  }

  // return the data without the signature
  return data, nil
}

// given a password string and a salt, return the hashed variant
func hashPassword(password string, salt []byte, iterations int) []byte {
  // create a 32-byte key for use with AES-256
  keySize := 32

  // get the result and return it
  hash, _ := scrypt.Key([]byte(password), salt, iterations, 16, 2, keySize)
  return hash
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
  key := hashPassword(password, salt, HashIterations)

  // encrypt the plaintext
  block, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext, plaintext)

  // get slices of the entire content and the signature
  content := output[:SaltSize + aes.BlockSize + len(plaintext)]
  signature := output[len(output) - SignatureSize:]

  // sign the content and store the signature at the end
  copy(signature, sign(content))

  return output, nil
}

// decrypt some data using the given password
func decrypt(data []byte, password string) ([]byte, error) {
  // make sure our data is of at least the minimum length
  minEncryptedLength := SaltSize + aes.BlockSize + SignatureSize
  if len(data) < minEncryptedLength {
    err := fmt.Errorf("Data is too short to be valid (min length: %d)",
        minEncryptedLength)
    return nil, err
  }

  // verify the integrity of the data and get the data itself back
  data, err := verify(data)
  if err != nil { return nil, err }

  // read the salt, IV, ciphertext, and signature from the verified data
  salt := data[:SaltSize]
  iv := data[SaltSize:SaltSize + aes.BlockSize]
  ciphertext := data[SaltSize + aes.BlockSize:]

  // hash the password with the just-read salt to get the key
  key := hashPassword(password, salt, HashIterations)

  // decrypt the ciphertext
  block, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  // decrypt directly into the ciphertext
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
