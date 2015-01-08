package pass

import (
	"crypto/rand"
	"testing"
)

// a global result for deoptimization and a bunch of random bytes
var deoptimizer interface{}
var randomBytes = make([]byte, 512)
var _, _ = rand.Read(randomBytes)

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
