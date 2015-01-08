package pass

import (
	"crypto/rand"
	"regexp"
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
var deoptimizer interface{}
var randomBytes = make([]byte, 512)
var _, _ = rand.Read(randomBytes)

// fill some arbitrary bits with random data
var key aes256Key = aes256Key{}
var _ int = copy(key[:], randomBytes)

var iv aesIV = aesIV{}
var _ int = copy(iv[:], randomBytes)

var hmacKey sha512Key = sha512Key{}
var _ int = copy(hmacKey[:], randomBytes)

var salt salt128 = salt128{}
var _ int = copy(salt[:], randomBytes)

// skip the given test if running in short mode
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}
}

// should be able to decompress the compressed empty array
func TestDecompressGzipMinCompressed(t *testing.T) {
	compressed, err := compressGzip(EmptyData)
	assert.NoError(t, err)

	decompressed, err := decompressGzip(compressed)
	assert.NoError(t, err)

	assert.Equal(t, decompressed, EmptyData)
}

func TestDecompressGzipTooShort(t *testing.T) {
	minCompressed, err := compressGzip([]byte{})
	assert.NoError(t, err)

	minCompressedLength := len(minCompressed)

	// check all possible sizes below the minimum compressed length to ensure that
	// they error.
	for size := len(minCompressed) - 1; size >= 0; size-- {
		_, err := decompressGzip(make([]byte, minCompressedLength))
		assert.Error(t, err)
	}
}

// decompressing invalid data should fail
func TestDecompressGzipInvalid(t *testing.T) {
	// null data is certainly invalid
	data := make([]byte, 50)

	_, err := decompressGzip(data)
	assert.Error(t, err)
}

// compression and decompression are inverse operations, and therefor passing
// input through the compressor and then the decompressor should yield the input
// data once again.
func TestCompressGzipAndDecompressGzip(t *testing.T) {
	for _, data := range AllData {
		compressed, err := compressGzip(data)
		assert.NoError(t, err)

		decompressed, err := decompressGzip(compressed)
		assert.NoError(t, err)

		assert.Equal(t, decompressed, data)
	}
}

// make sure that signing identical (but distinct) blocks of bytes always
// produces the same signature.
func TestSignSHA512Identical(t *testing.T) {
	for _, data := range AllData {
		copiedData := make([]byte, len(data))
		copy(copiedData, data)

		signature1, err := signSHA512(data, hmacKey)
		assert.NoError(t, err)

		signature2, err := signSHA512(copiedData, hmacKey)
		assert.NoError(t, err)

		assert.Equal(t, signature1, signature2)
	}
}

// data with an invalid signature shouldn't verify
func TestVerifySHA512InvalidSignature(t *testing.T) {
	for _, data := range AllData {
		// create a signature of random bytes
		invalidSignature := sha512Signature{}
		_, err := rand.Read(invalidSignature[:])
		assert.NoError(t, err)

		err = verifySHA512(data, hmacKey, invalidSignature)
		assert.Error(t, err)
	}
}

// signing and verifying data should work
func TestSignSHA512AndVerifySHA512(t *testing.T) {
	for _, data := range AllData {
		signature, err := signSHA512(data, hmacKey)
		assert.NoError(t, err)

		err = verifySHA512(data, hmacKey, signature)
		assert.NoError(t, err)
	}
}

// make sure we got the requested number of bytes out of the hash function
func TestHashScryptCorrectSize(t *testing.T) {
	for _, data := range AllData {
		size := 30

		data, err := hashScrypt(data, salt, 16, 2, 1, size)
		assert.Len(t, data, size)
		assert.NoError(t, err)
	}
}

// this should dutifully provide us an empty byte array
func TestHashScryptZeroSize(t *testing.T) {
	for _, data := range AllData {
		data, err := hashScrypt(data, salt, 16, 2, 1, 0)
		assert.Len(t, data, 0)
		assert.NoError(t, err)
	}
}

func TestHashScryptOneSize(t *testing.T) {
	for _, data := range AllData {
		data, err := hashScrypt(data, salt, 16, 2, 1, 1)
		assert.Len(t, data, 1)
		assert.NoError(t, err)
	}
}

func TestHashScryptTwoSize(t *testing.T) {
	for _, data := range AllData {
		data, err := hashScrypt(data, salt, 16, 2, 1, 2)
		assert.Len(t, data, 2)
		assert.NoError(t, err)
	}
}

// make sure we're not just getting null bytes
func TestHashScryptNonNull(t *testing.T) {
	for _, data := range AllData {
		size := 30

		data, err := hashScrypt(data, salt, 16, 2, 1, size)
		assert.NotEqual(t, make([]byte, size), data)
		assert.NoError(t, err)
	}
}

// shouldn't accept an N value that's not a power of two
func TestHashScryptNonPowerOfTwoN(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 15, 2, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bN\b`), err.Error())
	}
}

// shouldn't accept an N value that's zero
func TestHashScryptZeroN(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 0, 2, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bN\b`), err.Error())
	}
}

// shouldn't accept an N value that's one
func TestHashScryptOneN(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 1, 2, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bN\b`), err.Error())
	}
}

// shouldn't accept an `r` value that's zero
func TestHashScryptZeroR(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 16, 0, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\br\b`), err.Error())
	}
}

// shouldn't accept a `p` value that's zero
func TestHashScryptZeroP(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 16, 2, 0, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bp\b`), err.Error())
	}
}

// the given byte slices should be populated in the order they're specified,
// with the bytes filling them in the same order the bytes have been generated.
// we don't need to re-test everything else since this function should be
// delegating to the "plain" `hash` function.
func TestHashFillScryptPopulateInOrder(t *testing.T) {
	for _, data := range AllData {
		var (
			size = 30
			N    = scryptN(16)
			r    = scryptR(2)
			p    = scryptP(1)
		)

		// get the original bytes
		hashed, err := hashScrypt(data, salt, N, r, p, size)
		assert.NoError(t, err)

		// make some slices from a single array, for easy comparison later
		parts := make([]byte, size)
		part1 := parts[:12]
		part2 := parts[12:]

		// fill the slices with the hashed bytes
		hashFillScrypt(data, salt, N, r, p, part1, part2)

		// ensure they were filled in the correct order with the same bytes
		// generated by the "plain" function.
		assert.Equal(t, hashed, parts)
	}
}

// the output of encryption should be ot the same length as the input
func TestEncryptAES256CFBSameLengthAsInput(t *testing.T) {
	for _, data := range AllData {
		encrypted, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)
		assert.Len(t, encrypted, len(data))
	}
}

// the output of encryption should be different from the input (unless empty)
func TestEncryptAES256CFBDifferentFromInput(t *testing.T) {
	for _, data := range AllData {
		encrypted, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		if len(data) != 0 {
			assert.NotEqual(t, encrypted, data)
		}
	}
}

// the output of encryption should be the same if the inputs are identical
func TestEncryptAES256CFBConstantWithSameParameters(t *testing.T) {
	for _, data := range AllData {
		encrypted1, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		encrypted2, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		assert.Equal(t, encrypted1, encrypted2)
	}
}

// the output of decryption should be ot the same length as the input
func TestDecryptAES256CFBSameLengthAsInput(t *testing.T) {
	for _, data := range AllData {
		decrypted, err := decryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		assert.Len(t, decrypted, len(data))
	}
}

// the output of encryption should be the same if the inputs are identical
func TestDecryptAES256CFBConstantWithSameParameters(t *testing.T) {
	for _, data := range AllData {
		decrypted1, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		decrypted2, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		assert.Equal(t, decrypted1, decrypted2)
	}
}

// the output of decryption should be different from the input (unless empty)
func TestDecryptAES256CFBDifferentFromInput(t *testing.T) {
	for _, data := range AllData {
		decrypted, err := decryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		if len(data) != 0 {
			assert.NotEqual(t, decrypted, data)
		}
	}
}

// the output of decryption should be the same as the original plaintext
func TestEncryptAES256CFBAndDecryptAES256CFB(t *testing.T) {
	for _, data := range AllData {
		encrypted, err := encryptAES256CFB(data, iv, key)
		assert.NoError(t, err)

		decrypted, err := decryptAES256CFB(encrypted, iv, key)
		assert.NoError(t, err)

		assert.Equal(t, data, decrypted)
	}
}

// make sure that encrypting the data is doing some sort of compression. we
// supply it with a large amount of repetitious data, which any self-respecting
// compression algorithm should reduce the size of with ease. the size of the
// data should me much longer than the minimum encrypted length, in order to
// ensure that the compression and encryption overhead is balanced out.
func TestEncryptIsCompressing(t *testing.T) {
	// lots of zeros should compress very well!
	size := 10000
	repetitiousData := make([]byte, size)

	encrypted, err := Encrypt(repetitiousData, "password")
	assert.NoError(t, err)

	// in this case, the encrypted data should be smaller
	assert.True(t, len(encrypted) < size)
}

// encrypting with an empty password should be allowed
func TestEncryptWithHashParamsEmptyPassword(t *testing.T) {
	for _, plaintext := range AllData {
		_, err := Encrypt(plaintext, "")
		assert.NoError(t, err)
	}
}

// encrypting the same data two different times should always produce a
// different blob, since the initialization vector and salt should be random.
func TestEncryptSameDataIsDifferent(t *testing.T) {
	password := "password"
	for _, plaintext := range AllData {
		encrypted1, err := Encrypt(plaintext, password)
		assert.NoError(t, err)

		encrypted2, err := Encrypt(plaintext, password)
		assert.NoError(t, err)

		assert.NotEqual(t, encrypted1, encrypted2)
	}
}

// make sure we get the original data back after we encrypt and decrypt it
func TestEncryptAndDecrypt(t *testing.T) {
	password := "password"
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(plaintext, password)
		assert.NoError(t, err)

		decrypted, err := Decrypt(encrypted, password)
		assert.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
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
		encrypted, err := Encrypt(plaintext, password)
		assert.NoError(t, err)

		_, err = Decrypt(encrypted, "")
		assert.Error(t, err)
	}
}

// attempting to decrypt a blob with the wrong password should fail
func TestDecryptWrongPasswordFails(t *testing.T) {
	password := "password"
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(plaintext, password)
		assert.NoError(t, err)

		_, err = Decrypt(encrypted, "incorrect")
		assert.Error(t, err)
	}
}

// attempting to decrypt a blob that has had bytes modified should fail
func TestDecryptModifiedBlobFails(t *testing.T) {
	password := "password"
	for _, plaintext := range AllData {
		encrypted, err := Encrypt(plaintext, password)
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
		encrypted, err := Encrypt(plaintext, password)
		assert.NoError(t, err)

		decrypted, err := Decrypt(encrypted, password)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

// BENCHMARKS
//
// NOTE: these tests all store a result globally to prevent the compiler from
// optimizing the benchmark function call away since its result isn't being
// used.

// benchmark password hashing using the defaults used internally
func BenchmarkHashPassword(b *testing.B) {
	hashPasswordBenchmarkPassword := randomBytes[32:64]
	var hashPasswordBenchmarkSalt salt128
	copy(hashPasswordBenchmarkSalt[:], randomBytes[:32])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = hashScrypt(
			hashPasswordBenchmarkPassword,
			hashPasswordBenchmarkSalt,
			1<<16,
			16,
			2,
			128,
		)
	}
}

func BenchmarkCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = compressGzip(randomBytes)
	}
}

func BenchmarkDecompress(b *testing.B) {
	decompressBenchmarkData, _ := compressGzip(randomBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = decompressGzip(decompressBenchmarkData)
	}
}

func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = signSHA512(randomBytes, hmacKey)
	}
}

func BenchmarkVerify(b *testing.B) {
	benchmarkDataSignature, _ := signSHA512(randomBytes, hmacKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deoptimizer = verifySHA512(randomBytes, hmacKey, benchmarkDataSignature)
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
