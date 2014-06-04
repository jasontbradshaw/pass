package main

import (
  "bytes"
  "compress/gzip"
  "compress/flate"
  "io"
  // "crypto/aes"
  "crypto/rand"
  "encoding/json"
  "fmt"
  "code.google.com/p/go.crypto/scrypt"
)

func marshal(data *map[string]interface{}) []byte {
  result, err := json.Marshal(data)

  if err != nil {
    panic(fmt.Sprintf("Failed to marshall JSON data: %v", err))
  }

  return result
}

func unmarshal(data []byte) map[string]interface{} {
  result := make(map[string]interface{})
  err := json.Unmarshal(data, &result)

  if err != nil {
    panic(fmt.Sprintf("Failed to unmarshall JSON data: %v", err))
  }

  return result
}

// gzip some data
func compress(data []byte) []byte {
  var result bytes.Buffer
  w, err := gzip.NewWriterLevel(&result, flate.BestCompression)

  if err != nil {
    panic(fmt.Sprintf("Failed to compress data: %v", err))
  }

  // compress our data
  w.Write(data)
  w.Close()

  return result.Bytes()
}

// gunzip some data
func decompress(data []byte) []byte {
  b := bytes.NewBuffer(data)
  r, err := gzip.NewReader(b)

  if err != nil {
    panic(fmt.Sprintf("Failed to decompress data: %v", err))
  }

  // compress our data
  var result []byte
  _, err = io.ReadFull(r, result)

  if err != nil {
    panic(fmt.Sprintf("Failed to copy decompressed data: %v", err))
  }

  return result
}

// encrypt a data blob using our scheme
func encrypt(blob []byte, password string) []byte {
  return compress(blob)
}

// decrypt a data blob using our scheme
func decrypt(blob []byte, password string) []byte {
  return decompress(blob)
}

// given a password string, return the hashed variant
func hashPassword(password string) []byte {
  saltSize := 32

  // FIXME: handle salting better
  // get a random salt
  salt := make([]byte, saltSize)
  rand.Read(salt)

  // get the result and return it
  hash, _ := scrypt.Key([]byte(password), salt, 32768, 16, 2, 32)
  return hash
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

  fmt.Printf("original: %#v\n\n", data)

  encryptedData := encrypt(marshal(&data), "password")

  fmt.Printf("encrypted: %#v\n\n", encryptedData)

  decryptedData := decrypt(encryptedData, "password")

  fmt.Printf("decrypted: %#v\n\n", decryptedData)

  decryptedJSON := unmarshal(decryptedData)

  fmt.Printf("new: %#v\n\n", decryptedJSON)

  fmt.Printf("hashedPassword: %#v\n\n", hashPassword("password"))
}
