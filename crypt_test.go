package pass

import (
  "crypto/rand"
  "testing"
  "time"

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
var deoptimizer interface{}
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

// make sure that trying to sign with a key that's too short produces errors
func TestGetSignatureShortKey(t *testing.T) {
  for keySize := 0; keySize < HMACKeySize - 1; keySize++ {
    key := make([]byte, keySize)
    _, err := sign(LongData, key)
    assert.Error(t, err)
  }
}

// trying to sign with a key that's long enough should produce no errors
func TestGetSignatureMinLengthKey(t *testing.T) {
  key := make([]byte, HMACKeySize)
  _, err := sign(LongData, key)
  assert.NoError(t, err)
}

// make sure that trying to sign with a key that's longer than the minimum
// produces no errors.
func TestGetSignatureLongKey(t *testing.T) {
  for keySize := HMACKeySize; keySize < HMACKeySize * 2; keySize++ {
    key := make([]byte, keySize)
    _, err := sign(LongData, key)
    assert.NoError(t, err)
  }
}

// make sure that signing a block of bytes always produces a signature of the
// correct length.
func TestGetSignatureSize(t *testing.T) {
  for _, data := range AllData {
    signature, err := sign(data, hmacKeyData)
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
    signature, err := sign(data, hmacKeyData)
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

    signature1, err := sign(data, hmacKeyData)
    assert.NoError(t, err)

    signature2, err := sign(copiedData, hmacKeyData)
    assert.NoError(t, err)

    assert.Equal(t, signature1, signature2)
  }
}

// a null signature (with extremely high probability) shouldn't verify
func TestVerifyNullSignature(t *testing.T) {
  for _, data := range AllData {
    // create a signature with all null bytes
    invalidSignature := make([]byte, SignatureSize)

    err := verify(data, invalidSignature, hmacKeyData)
    assert.Error(t, err)
  }
}

// data with a random signature shouldn't verify
func TestVerifyInvalidSignature(t *testing.T) {
  for _, data := range AllData {
    // create a signature of random bytes
    invalidSignature := make([]byte, SignatureSize)
    _, err := rand.Read(invalidSignature)
    assert.NoError(t, err)

    err = verify(data, invalidSignature, hmacKeyData)
    assert.Error(t, err)
  }
}

// a signature shorter than the default signature length shouldn't verify
func TestVerifyShort(t *testing.T) {
  for i := 0; i < SignatureSize; i++ {
    shortSignature := make([]byte, i)

    err := verify(ShortData, shortSignature, hmacKeyData)
    assert.Error(t, err)
  }
}

// signing and verifying data should work
func TestSignAndVerify(t *testing.T) {
  for _, data := range AllData {
    signature, err := sign(data, hmacKeyData)
    assert.NoError(t, err)

    err = verify(data, signature, hmacKeyData)
    assert.NoError(t, err)
  }
}

// hashed passwords should always output hashes of the determined key sizes
func TestHashPasswordSize(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    encryptionKey, hmacKey, err := hashPassword(string(data), salt, 16, 2, 1)
    assert.NoError(t, err)

    assert.Equal(t, EncryptionKeySize, len(encryptionKey))
    assert.Equal(t, HMACKeySize, len(hmacKey))
  }
}

// shouldn't accept an N value that's not a power of two
func TestHashPasswordNonPowerOfTwoN(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    _, _, err := hashPassword(string(data), salt, 15, 2, 1)
    assert.Error(t, err)
  }
}

// shouldn't accept an N value that's zero
func TestHashPasswordZeroN(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    _, _, err := hashPassword(string(data), salt, 0, 2, 1)
    assert.Error(t, err)
  }
}

// shouldn't accept an N value that's one
func TestHashPasswordOneN(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    _, _, err := hashPassword(string(data), salt, 1, 2, 1)
    assert.Error(t, err)
  }
}

// shouldn't accept an `r` value that's zero
func TestHashPasswordZeroR(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    _, _, err := hashPassword(string(data), salt, 16, 0, 1)
    assert.Error(t, err)
  }
}

// shouldn't accept an `p` value that's zero
func TestHashPasswordZeroP(t *testing.T) {
  salt := make([]byte, SaltSize)
  for _, data := range AllData {
    _, _, err := hashPassword(string(data), salt, 16, 2, 0)
    assert.Error(t, err)
  }
}

// getting version bytes should work
func TestUint32ToBytesZero(t *testing.T) {
  bytes, err := uint32ToBytes(0)
  assert.NoError(t, err)
  assert.Equal(t, bytes, make([]byte, VersionSize))
}

// getting version bytes should return the result in big-endian mode
func TestUint32ToBytesBigEndian(t *testing.T) {
  bytes, err := uint32ToBytes(1)
  assert.NoError(t, err)
  assert.Equal(t, bytes, []byte{0, 0, 0, 1})
}

// parsing a too-short byte array should fail
func TestBytesToUint32(t *testing.T) {
  for i := 0; i < 4; i++ {
    _, err := bytesToUint32(make([]byte, i))
    assert.Error(t, err)
  }
}

// parsing version bytes should work
func TestBytesToUint32Zero(t *testing.T) {
  version, err := bytesToUint32([]byte{0, 0, 0, 0})
  assert.NoError(t, err)
  assert.Equal(t, version, 0)
}

// parsing version bytes should interperet the result in big-endian mode
func TestBytesToUint32BigEndian(t *testing.T) {
  version, err := bytesToUint32([]byte{0, 0, 0, 1})
  assert.NoError(t, err)
  assert.Equal(t, version, 1)
}

// converting a uint32 to bytes and back should always produce the same result
func TestUint32ToBytesAndBytesToUint32(t *testing.T) {
  var i uint32;
  for i = 0; i < 1024; i++ {
    iBytes, err := uint32ToBytes(i)
    assert.NoError(t, err)

    newI, err := bytesToUint32(iBytes)
    assert.NoError(t, err)

    assert.Equal(t, i, newI)
  }
}

// make sure encryption output is large enough to include all the needed data at
// a minimum.
func TestEncryptWithHashParamsHasMinimumOutputLength(t *testing.T) {
  for _, plaintext := range AllData {
    encrypted, err := EncryptWithHashParams(plaintext, "password", 8, 2, 1)
    assert.NoError(t, err)

    // we can never have less data than this, but since we compress the given
    // plaintext, we may have less data than the length of the original
    // plaintext!
    assert.True(t, len(encrypted) >= minEncryptedLength)
  }
}

// make sure that encrypting the data is doing some sort of compression. we
// supply it with a large amount of repetitious data, which any self-respecting
// compression algorithm should reduce the size of with ease. the size of the
// data should me much longer than the minimum encrypted length, in order to
// ensure that the compression and encryption overhead is balanced out.
func TestEncryptWithHashParamsIsCompressing(t *testing.T) {
  // lots of zeros should compress very well!
  repetitiousData := make([]byte, minEncryptedLength * 10)

  encrypted, err := EncryptWithHashParams(repetitiousData, "password", 8, 2, 1)
  assert.NoError(t, err)

  // in this case, the encrypted data should be smaller
  assert.True(t, len(encrypted) < minEncryptedLength + len(repetitiousData))
}

// encrypting with an empty password should be allowed
func TestEncryptWithHashParamsEmptyPassword(t *testing.T) {
  for _, plaintext := range AllData {
    _, err := EncryptWithHashParams(plaintext, "", 8, 2, 1)
    assert.NoError(t, err)
  }
}

// encrypting the same data two different times should always produce a
// different blob, since the initialization vector and salt should be random.
func TestEncryptWithHashParamsSameDataIsDifferent(t *testing.T) {
  password := "password"
  for _, plaintext := range AllData {
    encrypted1, err := EncryptWithHashParams(plaintext, password, 8, 2, 1)
    assert.NoError(t, err)

    encrypted2, err := EncryptWithHashParams(plaintext, password, 8, 2, 1)
    assert.NoError(t, err)

    assert.NotEqual(t, encrypted1, encrypted2)
  }
}

// make sure we get the original data back after we encrypt and decrypt it
func TestEncryptWithHashParamsAndDecrypt(t *testing.T) {
  password := "password"
  for _, plaintext := range AllData {
    encrypted, err := EncryptWithHashParams(plaintext, password, 2, 7, 3)
    assert.NoError(t, err)

    decrypted, err := Decrypt(encrypted, password)
    assert.NoError(t, err)

    assert.Equal(t, plaintext, decrypted)
  }
}

// encrypting with a non-power-of-two N param should fail
func TestEncryptWithHashParamsNonPowerOfTwoN(t *testing.T) {
  password := "password"
  for _, plaintext := range AllData {
    _, err := EncryptWithHashParams(plaintext, password, 100, 2, 1)
    assert.Error(t, err)
  }
}

// attempting to decrypt an empty blob should fail
func TestDecryptEmptyDataFails(t *testing.T) {
  _, err := Decrypt(make([]byte, 0), "password")
  assert.Error(t, err)
}

// attempting to decrypt an empty blob with an empty password should fail
func TestDecryptEmptyDataEmptyPasswordFails(t *testing.T) {
  _, err := Decrypt(make([]byte, 0), "")
  assert.Error(t, err)
}

// attempting to decrypt a blob with an empty password (when the original
// password wasn't empty) should fail.
func TestDecryptEmptyPasswordFails(t *testing.T) {
  password := "password"
  for _, plaintext := range AllData {
    encrypted, err := EncryptWithHashParams(plaintext, password, 2, 2, 1)
    assert.NoError(t, err)

    _, err = Decrypt(encrypted, "")
    assert.Error(t, err)
  }
}

// attempting to decrypt a blob with the wrong password should fail
func TestDecryptWrongPasswordFails(t *testing.T) {
  password := "password"
  for _, plaintext := range AllData {
    encrypted, err := EncryptWithHashParams(plaintext, password, 2, 2, 1)
    assert.NoError(t, err)

    _, err = Decrypt(encrypted, "incorrect")
    assert.Error(t, err)
  }
}

// attempting to decrypt a blob that has had bytes modified should fail
func TestDecryptModifiedBlobFails(t *testing.T) {
  password := "password"
  for _, plaintext := range AllData {
    encrypted, err := EncryptWithHashParams(plaintext, password, 2, 2, 1)
    assert.NoError(t, err)

    // change a single byte to throw off the checksum
    encrypted[0]++

    _, err = Decrypt(encrypted, password)
    assert.Error(t, err)
  }
}

// decrypting a blob protected with an empty password should work
func TestDecryptEmptyPassword(t *testing.T) {
  password := ""
  for _, plaintext := range AllData {
    encrypted, err := EncryptWithHashParams(plaintext, password, 2, 2, 1)
    assert.NoError(t, err)

    decrypted, err := Decrypt(encrypted, password)
    assert.NoError(t, err)
    assert.Equal(t, plaintext, decrypted)
  }
}

// make sure that we're using a good amount of memory when hashing. this helps
// mitigate attacks by making a brute-force take lots of memory, not just CPU
// time.
func TestDefaultHashParametersUseEnoughMemory(t *testing.T) {
  enoughMemoryBytes := 1024 * 1024 * 128
  assert.Equal(t, int(128 * HashN * HashR), enoughMemoryBytes)

  // force periodic re-evaluation of these assumptions
  msg := "Ensure that the assumptions made about scrypt paramters still hold!"
  reevaluateDate := time.Date(2015, time.January, 1, 23, 0, 0, 0, time.UTC)
  assert.True(t, time.Now().Before(reevaluateDate), msg)
}

// BENCHMARKS
//
// NOTE: these tests all store a result globally to prevent the compiler from
// optimizing the benchmark function call away since its result isn't being
// used.

// benchmark password hashing using the defaults used internally
func BenchmarkHashPassword(b *testing.B) {
  hashPasswordBenchmarkPassword := string(randomBytes[32:64])
  hashPasswordBenchmarkSalt := randomBytes[:SaltSize]

  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    deoptimizer, _, _ = hashPassword(
        hashPasswordBenchmarkPassword,
        hashPasswordBenchmarkSalt,
        HashN, HashR, HashP)
  }
}

func BenchmarkCompress(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = compress(randomBytes)
  }
}

func BenchmarkDecompress(b *testing.B) {
  decompressBenchmarkData, _ := compress(randomBytes)

  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = decompress(decompressBenchmarkData)
  }
}

func BenchmarkSign(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = sign(randomBytes, hmacKeyData)
  }
}

func BenchmarkVerify(b *testing.B) {
  benchmarkDataSignature, _ := sign(randomBytes, hmacKeyData)

  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    deoptimizer = verify(randomBytes, benchmarkDataSignature, hmacKeyData)
  }
}

func BenchmarkEncrypt(b *testing.B) {
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = Encrypt(randomBytes, "password")
  }
}

func BenchmarkDecrypt(b *testing.B) {
  encryptedData, _ := Encrypt(randomBytes, "password")

  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    deoptimizer, _ = Decrypt(encryptedData, "password")
  }
}
