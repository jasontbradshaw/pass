package pass

import (
  "crypto/rand"
  "math/big"
  "testing"

  "github.com/stretchr/testify/assert"
)

// test signing and verifying lots of random data with random keys
func TestFuzzSignAndVerify(t *testing.T) {
  skipIfShort(t)

  for i := 0; i < 100000; i++ {
    // create a randomly-sized data array
    size, err := rand.Int(rand.Reader, big.NewInt(512))
    assert.NoError(t, err)

    // fill the array and key with random data
    data := make([]byte, size.Int64())
    _, err = rand.Read(data)
    assert.NoError(t, err)

    key := make([]byte, HMACKeySize)
    _, err = rand.Read(key)
    assert.NoError(t, err)

    // sign, verify, and compare to the original
    signature, err := sign(data, key)
    assert.NoError(t, err)

    err = verify(data, signature, key)
    assert.NoError(t, err)
  }
}

// fuzz test compression with lots of random data
func TestFuzzCompressAndDecompress(t *testing.T) {
  skipIfShort(t)

  for i := 0; i < 100000; i++ {
    // create a randomly-sized array, possibly larger than a byte in length
    size, err := rand.Int(rand.Reader, big.NewInt(512))
    assert.NoError(t, err)

    // fill the array with random data
    data := make([]byte, size.Int64())
    _, err = rand.Read(data)
    assert.NoError(t, err)

    // compress, decompress, and compare to the original
    compressed, err := compress(data)
    assert.NoError(t, err)

    decompressed, err := decompress(compressed)
    assert.NoError(t, err)

    assert.Equal(t, decompressed, data)
  }
}

// fuzz test encrypting and decrypting with lots of random data
func TestFuzzEncryptWithHashParamsAndDecrypt(t *testing.T) {
  skipIfShort(t)

  for i := 0; i < 100000; i++ {
    // create a randomly-sized array, possibly larger than a byte in length
    size, err := rand.Int(rand.Reader, big.NewInt(512))
    assert.NoError(t, err)

    // fill the array with random data
    data := make([]byte, size.Int64())
    _, err = rand.Read(data)
    assert.NoError(t, err)

    // encrypy, decrypt, and compare to the original
    encrypted, err := EncryptWithHashParams(data, "password", 8, 2, 1)
    assert.NoError(t, err)

    decrypted, err := Decrypt(encrypted, "password")
    assert.NoError(t, err)

    assert.Equal(t, decrypted, data)
  }
}
