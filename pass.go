package main

import (
  "bytes"
  "compress/gzip"
  "compress/flate"
  "io/ioutil"
  "crypto/aes"
  "crypto/rand"
  "crypto/cipher"
  "encoding/json"
  "fmt"
  "code.google.com/p/go.crypto/scrypt"
)

// the size of the salt data that's pre-pended to the encrypted data
const SaltSize = 32

func dumpJSON(data *map[string]interface{}) []byte {
  result, err := json.Marshal(data)
  if err != nil { panic(err) }
  return result
}

func loadJSON(data []byte) map[string]interface{} {
  result := make(map[string]interface{})
  err := json.Unmarshal(data, &result)
  if err != nil { panic(err) }
  return result
}

// gzip some data
func compress(data []byte) []byte {
  var result bytes.Buffer
  writer, err := gzip.NewWriterLevel(&result, flate.BestCompression)

  if err != nil { panic(err) }

  // compress our data
  writer.Write(data)
  writer.Close()

  return result.Bytes()
}

// gunzip some data
func decompress(data []byte) []byte {
  b := bytes.NewBuffer(data)
  reader, err := gzip.NewReader(b)

  if err != nil { panic(err) }

  // compress our data and close the reader
  result, err := ioutil.ReadAll(reader)
  if err != nil { panic(err) }
  reader.Close()

  return result
}

// encrypt some data using the given password
func encrypt(plaintext []byte, password string) []byte {
  // overall output is the salt, followed by the IV, followed by the ciphertext
  output := make([]byte, SaltSize + aes.BlockSize + len(plaintext))

  // get the parts of the result byte array we need as slices
  salt := output[:SaltSize]
  iv := output[SaltSize:SaltSize + aes.BlockSize]
  ciphertext := output[SaltSize + aes.BlockSize:]

  // randomize the salt and the IV
  if _, err := rand.Read(salt); err != nil { panic(err) }
  if _, err := rand.Read(iv); err != nil { panic(err) }

  // hash the password into an AES-256 (32-byte) key using the generated salt
  key := hashPassword(password, salt)

  // encrypt the plaintext
  block, err := aes.NewCipher(key)
  if err != nil { panic(err) }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext, plaintext)

  return output
}

// decrypt some data using the given password
func decrypt(data []byte, password string) []byte {
  // make sure our data is of the minimum length, at least
  if (len(data) < SaltSize + aes.BlockSize) {
    panic("data too short")
  }

  // read the salt, IV, and ciphertext from our blob
  salt := data[:SaltSize]
  iv := data[SaltSize:SaltSize + aes.BlockSize]
  ciphertext := data[SaltSize + aes.BlockSize:]

  // hash the password with the just-read salt to get the key
  key := hashPassword(password, salt)

  // decrypt the ciphertext
  block, err := aes.NewCipher(key)
  if err != nil { panic(err) }

  plaintext := make([]byte, len(ciphertext))
  stream := cipher.NewCFBDecrypter(block, iv)
  stream.XORKeyStream(plaintext, ciphertext)

  // return the decrypted ciphertext
  return plaintext
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
func load(data []byte, password string) map[string]interface{} {
  return loadJSON(decompress(decrypt(data, password)))
}

// given JSON, encrypt it to our database format using a password
func dump(data *map[string]interface{}, password string) []byte {
  return encrypt(compress(dumpJSON(data)), password)
}

func main() {
  // some test database data
  data := make(map[string]interface{})
  data["hello"] = "world"
  data["foo"] = 1
  data["bar"] = 2.25
  data["baz"] = true
  data["pants"] = map[string]interface{} {
    "something_else": false,
    "bad": nil,
  }

  password := "password123"
  plaintext := []byte("hello, world!")
  fmt.Printf("plaintext:\t%s\n", plaintext)

  ciphertext := encrypt(plaintext, password)
  fmt.Printf("ciphertext:\t%#v\n", ciphertext)

  deciphertext := decrypt(ciphertext, password)
  fmt.Printf("deciphertext:\t%#v\n", deciphertext)
  fmt.Printf("new plaintext:\t%s\n", deciphertext)
}
