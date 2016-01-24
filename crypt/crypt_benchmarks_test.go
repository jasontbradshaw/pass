package crypt

import (
	"crypto/rand"
	"testing"
)

// A global result for deoptimization and a bunch of random bytes.
var deoptimizer interface{}
var randomBytes = make([]byte, 512)
var _, _ = rand.Read(randomBytes)

// BENCHMARKS
//
// NOTE: These tests all store a result globally to prevent the compiler from
// optimizing the benchmark function call away since its result isn't being
// used.

// Benchmark password hashing using the defaults used internally.
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

func BenchmarkCompressGZip(b *testing.B) {
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = compressGZip(randomBytes)
	}
}

func BenchmarkDecompressGZip(b *testing.B) {
	decompressBenchmarkData, _ := compressGZip(randomBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = decompressGZip(decompressBenchmarkData)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = Encrypt("password", randomBytes)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	encryptedData, _ := Encrypt("password", randomBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = Decrypt("password", encryptedData)
	}
}
