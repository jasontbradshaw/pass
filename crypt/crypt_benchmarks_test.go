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

func BenchmarkCompressLZ4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = compressLZ4(randomBytes)
	}
}

func BenchmarkDecompressLZ4(b *testing.B) {
	decompressBenchmarkData, _ := compressLZ4(randomBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deoptimizer, _ = decompressLZ4(decompressBenchmarkData)
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
