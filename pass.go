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

// NOTES:
//  - need to encrypt PII separately from the main database
//  - decrypt once to get all non-PII with encrypted PII, then decrypt each
//    individual PII (passwords, custom fields, etc.) as needed. this should
//    prevent more than one PII from existing in memory at a time.

// the size of the salt data that's pre-pended to the encrypted data
const SaltSize = 32

// gzip some data
func compress(data []byte) ([]byte, error) {
  var result bytes.Buffer
  writer, err := gzip.NewWriterLevel(&result, flate.BestCompression)

  if err != nil { return nil, err }

  // compress our data
  writer.Write(data)
  writer.Close()

  return result.Bytes(), nil
}

// gunzip some data
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

// encrypt some data using the given password
func encrypt(plaintext []byte, password string) ([]byte, error) {
  // overall output is the salt, followed by the IV, followed by the ciphertext
  output := make([]byte, SaltSize + aes.BlockSize + len(plaintext))

  // get the parts of the result byte array we need as slices
  salt := output[:SaltSize]
  iv := output[SaltSize:SaltSize + aes.BlockSize]
  ciphertext := output[SaltSize + aes.BlockSize:]

  // randomize the salt and the IV
  if _, err := rand.Read(salt); err != nil { return nil, err }
  if _, err := rand.Read(iv); err != nil { return nil, err }

  // hash the password into an AES-256 (32-byte) key using the generated salt
  key := hashPassword(password, salt)

  // encrypt the plaintext
  block, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext, plaintext)

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
  key := hashPassword(password, salt)

  // decrypt the ciphertext
  block, err := aes.NewCipher(key)
  if err != nil { return nil, err }

  plaintext := make([]byte, len(ciphertext))
  stream := cipher.NewCFBDecrypter(block, iv)
  stream.XORKeyStream(plaintext, ciphertext)

  // return the decrypted ciphertext
  return plaintext, nil
}

// given a password string, return the hashed variant
func hashPassword(password string, salt []byte) []byte {
  // create a 32-byte key for use with AES-256
  keySize := 32

  // get the result and return it
  hash, _ := scrypt.Key([]byte(password), salt, 32768, 16, 2, keySize)
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
