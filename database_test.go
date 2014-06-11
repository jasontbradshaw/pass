package database

import (
  "crypto/rand"
  "math/big"
  "testing"

  "github.com/stretchr/testify/assert"
)

// used for testing empty data
var EmptyData []byte = []byte("")
var SingleData []byte = []byte("a")
var DoubleData []byte = []byte("ab")
var ShortData []byte = []byte("abcdefghijklmnopqrstuvwxyz")
var LongData []byte = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var UnicodeData []byte = []byte("a®Ďƃɕʶ ̂ΆԃЌԵﬗאر݃ݓޤ‎߅ࡄখஷഖคබໄ၇ꩦႦᄓᎄⷄꬓᏄᑖᣆᚅᛕᜅᜤᝄᝣ‴№⁷✚z")

var AllData [][]byte = [][]byte{
  EmptyData,
  SingleData,
  DoubleData,
  ShortData,
  LongData,
  UnicodeData,
}

// a global result for deoptimization and a bunch of random bytes
var deoptimizer []byte
var randomBytes = make([]byte, 512)
var _, _ = rand.Read(randomBytes)

// we do a lot of signing tests and need a key of a specific length for them
var hmacKeyData []byte = randomBytes[:HMACKeySize]

// skip the given test if running in short mode
func skipIfShort(t *testing.T) {
  if (testing.Short()) { t.Skip("Skipping test in short mode") }
}

// should be able to decompress the compressed empty array
func TestDecompressMinCompressed(t *testing.T) {
  minCompressed, err := compress([]byte{})
  assert.NoError(t, err)

  decompressed, err := decompress(minCompressed)
  assert.NoError(t, err)

  assert.Equal(t, decompressed, EmptyData);
}

func TestDecompressTooShort(t *testing.T) {
  minCompressed, err := compress([]byte{})
  assert.NoError(t, err)

  minCompressedLength := len(minCompressed)

  // check all possible sizes below the minimum compressed length to ensure that
  // they error.
  for size := len(minCompressed) - 1; size >= 0; size-- {
    _, err := decompress(make([]byte, minCompressedLength))
    assert.Error(t, err)
  }
}

// decompressing invalid data should fail
func TestDecompressInvalid(t *testing.T) {
  // null data is certainly invalid
  data := make([]byte, 50)

  _, err := decompress(data)
  assert.Error(t, err)
}

// compression and decompression are inverse operations, and therefor passing
// input through the compressor and then the decompressor should yield the input
// data once again.
func TestCompressAndDecompress(t *testing.T) {
  for _, data := range AllData {
    compressed, err := compress(data)
    assert.NoError(t, err)

    decompressed, err := decompress(compressed)
    assert.NoError(t, err)

    assert.Equal(t, decompressed, data)
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

// make sure that trying to sign with a key that's too short produces errors
func TestGetSignatureShortKey(t *testing.T) {
  for keySize := 0; keySize < HMACKeySize - 1; keySize++ {
    key := make([]byte, keySize)
    _, err := getSignature(LongData, key)
    assert.Error(t, err)
  }
}

// trying to sign with a key that's long enough should produce no errors
func TestGetSignatureMinLengthKey(t *testing.T) {
  key := make([]byte, HMACKeySize)
  _, err := getSignature(LongData, key)
  assert.NoError(t, err)
}

// make sure that trying to sign with a key that's longer than the minimum
// produces no errors.
func TestGetSignatureLongKey(t *testing.T) {
  for keySize := HMACKeySize; keySize < HMACKeySize * 2; keySize++ {
    key := make([]byte, keySize)
    _, err := getSignature(LongData, key)
    assert.NoError(t, err)
  }
}

// make sure that signing a block of bytes always produces a signature of the
// correct length.
func TestGetSignatureSize(t *testing.T) {
  for _, data := range AllData {
    signature, err := getSignature(data, hmacKeyData)
    assert.NoError(t, err)

    assert.Equal(t, len(signature), SignatureSize)
  }
}

// make sure that signing a block of bytes always produces a signature that's
// not just full of null bytes. a null signature is technically possible, but
// it's vastly, vastly more likeky to be an error than a hash collision!
func TestGetSignatureNonNull(t *testing.T) {
  nullSignature := make([]byte, SignatureSize)
  for _, data := range AllData {
    signature, err := getSignature(data, hmacKeyData)
    assert.NoError(t, err)

    assert.NotEqual(t, signature, nullSignature)
  }
}

// make sure that signing identical (but distinct) blocks of bytes always
// produces the same signature.
func TestGetSignatureIdentical(t *testing.T) {
  for _, data := range AllData {
    copiedData := make([]byte, len(data))
    copy(copiedData, data)

    signature1, err := getSignature(data, hmacKeyData)
    assert.NoError(t, err)

    signature2, err := getSignature(copiedData, hmacKeyData)
    assert.NoError(t, err)

    assert.Equal(t, signature1, signature2)
  }
}

// make sure that signing identical (but distinct) blocks of bytes always
// produces the same output.
func TestSignIdentical(t *testing.T) {
  for _, data := range AllData {
    copiedData := make([]byte, len(data))
    copy(copiedData, data)

    signed1, err := sign(data, hmacKeyData)
    assert.NoError(t, err)

    signed2, err := sign(copiedData, hmacKeyData)
    assert.NoError(t, err)

    assert.Equal(t, signed1, signed2)
  }
}

// make sure that signing data has a length equal to the length of the original
// data plus the size of a signature.
func TestSignLength(t *testing.T) {
  for _, data := range AllData {
    signed, err := sign(data, hmacKeyData)
    assert.NoError(t, err)
    assert.Equal(t, len(signed), len(data) + SignatureSize)
  }
}

// make sure that signed data always starts with the original data
func TestSignStartsWithOriginalData(t *testing.T) {
  for _, data := range AllData {
    signed, err := sign(data, hmacKeyData)
    assert.NoError(t, err)
    assert.Equal(t, data, signed[:len(data)])
  }
}

// data with a null signature shouldn't verify
func TestVerifyNullSignature(t *testing.T) {
  for _, data := range AllData {
    // create a signature with all null bytes
    invalidSigned := make([]byte, len(data) + SignatureSize)
    copy(invalidSigned, data)

    _, err := verify(invalidSigned, hmacKeyData)
    assert.Error(t, err)
  }
}

// data with a random signature shouldn't verify
func TestVerifyInvalidSignature(t *testing.T) {
  for _, data := range AllData {
    // create a signature of random bytes
    invalidSigned := make([]byte, len(data) + SignatureSize)
    copy(invalidSigned, data)
    copy(invalidSigned[len(data):], randomBytes[:SignatureSize])

    _, err := verify(invalidSigned, hmacKeyData)
    assert.Error(t, err)
  }
}

// data shorter than the signature length shouldn't verify
func TestVerifyShort(t *testing.T) {
  for i := 0; i < SignatureSize; i++ {
    invalidSigned := make([]byte, i)

    _, err := verify(invalidSigned, hmacKeyData)
    assert.Error(t, err)
  }
}

// signing and verifying data should work, and the result data should equal the
// input data.
func TestSignAndVerify(t *testing.T) {
  for _, data := range AllData {
    signed, err := sign(data, hmacKeyData)
    assert.NoError(t, err)

    verified, err := verify(signed, hmacKeyData)
    assert.NoError(t, err)

    assert.Equal(t, data, verified)
  }
}

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
    signed, err := sign(data, key)
    assert.NoError(t, err)

    verified, err := verify(signed, key)
    assert.NoError(t, err)

    assert.Equal(t, data, verified)
  }
}

// data should take the same amount of time to determine validity, no matter how
// soon the signatures differ (i.e. should be robust against timing attacks).
func TestVerifyConstantTime(t *testing.T) {
  skipIfShort(t)
  // TODO: statistically verify verification time
}

// hashed passwords should always output hashes of the determined key sizes
func TestHashPasswordSize(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    encryptionKey, hmacKey, err := hashPassword(string(data), salt, 5)
    assert.NoError(t, err)

    assert.Equal(t, KeySize, len(encryptionKey))
    assert.Equal(t, HMACKeySize, len(hmacKey))
  }
}

// test that the iterations parameter can't be negative
func TestHashPasswordNegativeWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, _, err := hashPassword("test", salt, -1)
  assert.Error(t, err)
}

// test that the iterations parameter can't be zero
func TestHashPasswordZeroWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, _, err := hashPassword("test", salt, 0)
  assert.Error(t, err)
}

// test that the iterations parameter can be 1
func TestHashPasswordOneWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, _, err := hashPassword("test", salt, 1)
  assert.NoError(t, err)
}

// test that the iterations parameter can't be larger than 31
func TestHashPasswordTooLargeWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, _, err := hashPassword("test", salt, 32)
  assert.Error(t, err)
}

// make sure encryption output is large enough to include all the needed data at
// a minimum.
func TestEncryptOutputLength(t *testing.T) {
  skipIfShort(t)

  for _, plaintext := range AllData {
    encrypted, err := encrypt(plaintext, "password")
    assert.NoError(t, err)

    assert.Equal(t, len(encrypted), minEncryptedLength + len(plaintext))
  }
}

// BENCHMARKS
//
// NOTE: these tests all store a result globally to prevent the compiler from
// optimizing the benchmark function call away since its result isn't being
// used.

// benchmark password hashing using the defaults used internally
var hashPasswordBenchmarkPassword = string(randomBytes[32:64])
var hashPasswordBenchmarkSalt = randomBytes[:SaltSize]
func BenchmarkHashPasswordWithDefaults(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, deoptimizer, _ = hashPassword(
        hashPasswordBenchmarkPassword,
        hashPasswordBenchmarkSalt,
        HashWorkFactor)
  }
}

func BenchmarkCompress(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = compress(randomBytes)
  }
}

var decompressBenchmarkData, _ = compress(randomBytes)
func BenchmarkDecompress(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = decompress(decompressBenchmarkData)
  }
}

func BenchmarkSign(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = sign(randomBytes, hmacKeyData)
  }
}

var verifyBenchmarkData, _ = sign(randomBytes, hmacKeyData)
func BenchmarkVerify(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = verify(verifyBenchmarkData, hmacKeyData)
  }
}
