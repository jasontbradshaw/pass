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

// make sure that signing identical blocks of bytes always produces a signature
// of the reported length.
func TestGetSignatureSize(t *testing.T) {
  for _, data := range AllData {
    signature := getSignature(data)
    assert.Equal(t, len(signature), SignatureSize)
  }
}

// make sure that signing identical (but distinct) blocks of bytes always
// produces the same signature.
func TestGetSignatureIdentical(t *testing.T) {
  for _, data := range AllData {
    copiedData := make([]byte, len(data))
    copy(copiedData, data)

    signature1 := getSignature(data)
    signature2 := getSignature(copiedData)

    assert.Equal(t, signature1, signature2)
  }
}

// make sure that signing identical (but distinct) blocks of bytes always
// produces the same output.
func TestSignIdentical(t *testing.T) {
  for _, data := range AllData {
    copiedData := make([]byte, len(data))
    copy(copiedData, data)

    signed1 := sign(data)
    signed2 := sign(copiedData)

    assert.Equal(t, signed1, signed2)
  }
}

// make sure that signing data has a length equal to the length of the original
// data plus the size of a signature.
func TestSignLength(t *testing.T) {
  for _, data := range AllData {
    signed := sign(data)
    assert.Equal(t, len(signed), len(data) + SignatureSize)
  }
}

// make sure that signed data always starts with the original data
func TestSignStartsWithOriginalData(t *testing.T) {
  for _, data := range AllData {
    signed := sign(data)
    assert.Equal(t, data, signed[:len(data)])
  }
}

// data with an invalid signature shouldn't verify
func TestVerifyInvalid(t *testing.T) {
  for _, data := range AllData {
    // create a signature with all null bytes
    invalidSigned := make([]byte, len(data) + SignatureSize)
    copy(invalidSigned, data)

    _, err := verify(invalidSigned)
    assert.Error(t, err)
  }
}

// data shorter than the signature length shouldn't verify
func TestVerifyShort(t *testing.T) {
  for i := SignatureSize; i >= 0; i-- {
    invalidSigned := make([]byte, i)

    _, err := verify(invalidSigned)
    assert.Error(t, err)
  }
}

// signing and verifying data should work, and the result data should equal the
// input data.
func TestSignAndVerify(t *testing.T) {
  for _, data := range AllData {
    signed := sign(data)
    verified, err := verify(signed)

    assert.NoError(t, err)
    assert.Equal(t, data, verified)
  }
}

// test signing and verifying lots of random data
func TestFuzzSignAndVerify(t *testing.T) {
  skipIfShort(t)

  for i := 0; i < 100000; i++ {
    // create a randomly-sized array
    size, err := rand.Int(rand.Reader, big.NewInt(512))
    assert.NoError(t, err)

    // fill the array with random data
    data := make([]byte, size.Int64())
    _, err = rand.Read(data)
    assert.NoError(t, err)

    // sign, verify, and compare to the original
    signed := sign(data)
    verified, err := verify(signed)

    assert.NoError(t, err)
    assert.Equal(t, data, verified)
  }
}

// data should take the same amount of time to determine validity, no matter how
// soon the signatures differ (i.e. should be robust against timing attacks).
func TestVerifyConstantTime(t *testing.T) {
  skipIfShort(t)
  // TODO: statistically verify verify times
}

// hashed passwords should always output at the determined key size
func TestHashPasswordSize(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    hashed, err := hashPassword(string(data), salt, 5)
    assert.NoError(t, err)

    assert.Equal(t, KeySize, len(hashed))
  }
}

// test that the iterations parameter must be larger than 1
func TestHashPasswordNegativeWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, err := hashPassword("test", salt, -1)
  assert.Error(t, err)
}

// test that the iterations parameter must be larger than 1
func TestHashPasswordZeroWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, err := hashPassword("test", salt, 0)
  assert.Error(t, err)
}

// test that the iterations parameter can be 1
func TestHashPasswordOneWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, err := hashPassword("test", salt, 1)
  assert.NoError(t, err)
}

// test that the iterations parameter must be larger than 1
func TestHashPasswordTooLargeWorkFactor(t *testing.T) {
  salt := make([]byte, SaltSize)
  _, err := hashPassword("test", salt, 32)
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

// encrypted output should be verifiable
func TestEncryptVerify(t *testing.T) {
  skipIfShort(t)

  for _, plaintext := range AllData {
    encrypted, err := encrypt(plaintext, "password")
    assert.NoError(t, err)

    data, err := verify(encrypted)
    assert.NoError(t, err)

    assert.Equal(t, data, encrypted[:len(data)])
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
    deoptimizer, _ = hashPassword(
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
    deoptimizer = sign(randomBytes)
  }
}

var verifyBenchmarkData = sign(randomBytes)
func BenchmarkVerify(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = verify(verifyBenchmarkData)
  }
}
