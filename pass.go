package main

import (
  "bytes"
  "compress/flate"
  "compress/gzip"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "errors"
  "fmt"
  "io/ioutil"
  sj "github.com/bitly/go-simplejson"
  "code.google.com/p/go.crypto/scrypt"
)

// IMPLEMENTATION NOTES:
// - HAVE LOTS OF TESTS!!! especially around database loading/saving/stability
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

// the number of iterations to use when hashing the master password
const HashIterations = 32768

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
// is added to the end of the original data. the padding consists of secure
// random bytes, with the final byte indicating the amount of padding that was
// added, the count byte included.
func pad(data []byte, blockSize uint8) ([]byte, error) {
  // determine how much padding we need to add. if the data's length is already
  // a multiple of the block size, a full block of padding will be added.
  padMod := uint8(len(data)) % blockSize
  padLength := padMod
  if padLength == 0 { padLength = blockSize }

  // fill the first part of the padded data with the original data
  paddedData := make([]byte, len(data) + int(padLength))
  copy(paddedData, data)

  // fill the padding with random bytes
  padding := paddedData[len(data):]
  if _, err := rand.Read(padding); err != nil { return nil, err }

  // set the last byte to the amount of padding that was just added
  padding[padLength - 1] = padLength

  return paddedData, nil
}

// given some padded data, return the data sans the included padding
func unpad(data []byte) []byte {
  // if we got no data, return what we got
  if len(data) == 0 { return data }

  // get the number of padding bytes (always stored in the final byte)
  padLength := uint8(data[len(data) - 1])

  // return the data without the included padding
  return data[:-padLength]
}

// encrypt some data using the given password
func encrypt(plaintext []byte, password string) ([]byte, error) {
  // pad the plaintext to a multiple of the AES block size (see:
  // http://security.stackexchange.com/a/31657,
  // http://tools.ietf.org/html/rfc5652#section-6.3).
  paddedPlaintext, err := pad(plaintext, aes.BlockSize)
  if err != nil { return nil, err }

  // overall output is the salt, followed by the IV, followed by the ciphertext
  output := make([]byte, SaltSize + aes.BlockSize + len(paddedPlaintext))

  // get the parts of the result byte array we need as slices
  salt := output[:SaltSize]
  iv := output[SaltSize:SaltSize + aes.BlockSize]
  ciphertext := output[SaltSize + aes.BlockSize:]

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

  return output, nil
}

// decrypt some data using the given password
func decrypt(data []byte, password string) ([]byte, error) {
  // make sure our data is of the minimum length, at least
  if (len(data) < SaltSize + aes.BlockSize) {
    return nil, errors.New("data too short")
  }

  // read the salt, IV, and ciphertext from our blob
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
  if (err != nil) { return nil, err }

  plaintext, err := decompress(compressed)
  if (err != nil) { return nil, err }

  return sj.NewJson(plaintext)
}

// given JSON, encrypt it to our database format using a password
func dump(data *sj.Json, password string) ([]byte, error) {
  json, err := data.Encode()
  if (err != nil) { return nil, err }

  compressed, err := compress(json)
  if (err != nil) { return nil, err }

  return encrypt(compressed, password)
}

func main() {
  // some test database data
  data := sj.New()
  data.Set("hello", "world")
  data.Set("foo", 1)
  data.Set("bar", 2.25)
  data.Set("baz", true)
  data.Set("pants", sj.New());
  data.Get("pants").Set("something_else", false)
  data.Get("pants").Set("bad", nil)

  password := "password123"
  plaintext := []byte("hello, world!")
  fmt.Printf("plaintext:\t%s\n", plaintext)

  ciphertext, _ := encrypt(plaintext, password)
  fmt.Printf("ciphertext:\t%#v\n", ciphertext)

  deciphertext, _ := decrypt(ciphertext, password)
  fmt.Printf("deciphertext:\t%#v\n", deciphertext)
  fmt.Printf("new plaintext:\t%s\n", deciphertext)
}
