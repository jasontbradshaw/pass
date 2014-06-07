package database

import (
  "bytes"
  "compress/flate"
  "compress/gzip"
  "crypto/aes"
  "crypto/cipher"
  "crypto/sha256"
  "crypto/rand"
  "errors"
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
  if len(data) == 0 { return nil, errors.New("Invalid data") }

  b := bytes.NewBuffer(data)
  reader, err := gzip.NewReader(b)

  if err != nil { return nil, err }

  // compress our data and close the reader
  result, err := ioutil.ReadAll(reader)
  if err != nil { return nil, err }
  reader.Close()

  return result, nil
}

// given some data, pad it to the given block size. if the data is already a
// multiple of the given blocksize, adds another block of padding. the padding
// is added to the end of the original data. the padding consists of bytes that
// are given a value equal to the number of bytes added as padding.
func pad(data []byte, blockSize int) ([]byte, error) {
  // make sure we get a block size that fits into a single byte
  if blockSize <= 0 || blockSize > 255 {
    return nil, errors.New("Block size must fit into a single byte (0 to 255)")
  }

  // calculate the number of bytes that need to be added to bring the length
  // to an integer multiple of the block size. see:
  // http://tools.ietf.org/html/rfc5652#section-6.3
  padLength := blockSize - (len(data) % blockSize)

  // fill the first part of the padded data with the original data
  paddedData := make([]byte, len(data) + padLength)
  copy(paddedData, data)

  // fill the padding with bytes of value equal to the amount of padding added
  for i := len(data); i < len(paddedData); i++ {
    paddedData[i] = byte(padLength)
  }

  return paddedData, nil
}

// given some padded data, return the data sans the included padding
func unpad(data []byte) []byte {
  // if we got no data, return what we got
  if len(data) == 0 { return data }

  // get the number of padding bytes (always stored in the final byte)
  padLength := data[len(data) - 1]

  // return the data without the included padding
  return data[:-padLength]
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
  if len(signedData) < sha256.Size {
    return nil, errors.New("Data is too short to have a valid signature")
  }

  // get the signature from the end of the data
  suppliedSignature := signedData[len(signedData) - sha256.Size:]
  data := signedData[:len(signedData) - sha256.Size]

  // sign the data once more
  signature := getSignature(data)

  // securely compare the signatures to determine validity. it's important that
  // we don't bail on the comparison early to avoid timing attacks!
  valid := true
  for i := 0; i < len(signature); i++ {
    valid = valid && (signature[i] == suppliedSignature[i])
  }

  // signal an error if the computed signature doesn't match the given one
  if !valid {
    return nil, errors.New("Computed and supplied signatures do not match")
  }

  // return the data without the signature
  return data, nil
}

// encrypt some data using the given password
func encrypt(plaintext []byte, password string) ([]byte, error) {
  // pad the plaintext to a multiple of the AES block size (see:
  // http://security.stackexchange.com/a/31657,
  // http://tools.ietf.org/html/rfc5652#section-6.3).
  paddedPlaintext, err := pad(plaintext, aes.BlockSize)
  if err != nil { return nil, err }

  // create the parts of the result byte array we need. overall output is the
  // salt, followed by the IV, followed by the ciphertext, followed by the
  // signature of the ciphertext.
  salt := make([]byte, SaltSize)
  iv := make([]byte, aes.BlockSize)
  ciphertext := make([]byte, len(paddedPlaintext))

  // randomize the salt and the IV
  if _, err := rand.Read(salt); err != nil { return nil, err }
  if _, err := rand.Read(iv); err != nil { return nil, err }

  // hash the password into an AES-256 (32-byte) key using the generated salt
  key := hashPassword(password, salt, HashIterations)

  // encrypt the plaintext
  block, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext, paddedPlaintext)

  // concatenate all the parts together into a single array
  output := salt
  output = append(output, iv...)
  output = append(output, ciphertext...)

  // sign the entire output and append the signature
  signature := sign(output)
  output = append(output, signature...)

  return output, nil
}

// decrypt some data using the given password
func decrypt(data []byte, password string) ([]byte, error) {
  // make sure our data is of at least the minimum length
  if len(data) < SaltSize + aes.BlockSize + SignatureSize {
    return nil, errors.New("Data too short to be valid")
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

  paddedPlaintext := make([]byte, len(ciphertext))
  stream := cipher.NewCFBDecrypter(block, iv)
  stream.XORKeyStream(paddedPlaintext, ciphertext)

  // unpad the plaintext
  plaintext := unpad(paddedPlaintext)

  return plaintext, nil
}

// given a password string and a salt, return the hashed variant
func hashPassword(password string, salt []byte, iterations int) []byte {
  // create a 32-byte key for use with AES-256
  keySize := 32

  // get the result and return it
  hash, _ := scrypt.Key([]byte(password), salt, iterations, 16, 2, keySize)
  return hash
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
