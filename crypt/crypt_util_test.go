package crypt

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Just a smoke test to make sure msgpack encoding works, since this is almost
// entirely delegated to a library.
func TestEncodeMsgpackWorks(t *testing.T) {
	enc, err := encodeMsgpack(map[string]int{
		"foo": 1,
	})
	assert.NoError(t, err)

	// `fixmap` of one item, `fixstr` of three characters, `fixnum` of 1.
	assert.Equal(t, enc, []byte{0x81, 0xa3, 0x66, 0x6f, 0x6f, 1})
}

// Should be able to decompress the compressed empty array.
func TestDecompressLZ4MinCompressed(t *testing.T) {
	compressed, err := compressLZ4(EmptyData)
	assert.NoError(t, err)
	assert.NotEmpty(t, compressed)

	decompressed, err := decompressLZ4(compressed)
	assert.NoError(t, err)

	assert.Equal(t, EmptyData, decompressed)
}

func TestDecompressLZ4TooShort(t *testing.T) {
	minCompressed, err := compressLZ4([]byte{})
	assert.NoError(t, err)
	assert.NotEmpty(t, minCompressed)

	// Check all possible sizes below the minimum compressed length to ensure that
	// they error.
	for size := len(minCompressed) - 1; size >= 0; size-- {
		_, err := decompressLZ4(make([]byte, size))
		assert.Error(t, err)
	}
}

// Decompressing invalid data should fail.
func TestDecompressLZ4Invalid(t *testing.T) {
	// Null data is certainly invalid.
	data := make([]byte, 50)

	_, err := decompressLZ4(data)
	assert.Error(t, err)
}

// Compression and decompression are inverse operations, and therefore passing
// input through the compressor and then the decompressor should yield the input
// data once again.
func TestCompressLZ4AndDecompressLZ4(t *testing.T) {
	for _, data := range AllData {
		compressed, err := compressLZ4(data)
		assert.NoError(t, err)

		decompressed, err := decompressLZ4(compressed)
		assert.NoError(t, err)

		assert.Equal(t, data, decompressed)
	}
}

// Make sure we got the requested number of bytes out of the hash function.
func TestHashScryptCorrectSize(t *testing.T) {
	// We make most of these parallel so they can run concurrently and take less
	// real time.
	t.Parallel()

	for _, data := range AllData {
		size := 30

		data, err := hashScrypt(data, salt, 16, 2, 1, size)
		assert.Len(t, data, size)
		assert.NoError(t, err)
	}
}

// This should dutifully provide us an empty byte array.
func TestHashScryptZeroSize(t *testing.T) {
	t.Parallel()

	for _, data := range AllData {
		data, err := hashScrypt(data, salt, 16, 2, 1, 0)
		assert.Len(t, data, 0)
		assert.NoError(t, err)
	}
}

func TestHashScryptOneSize(t *testing.T) {
	t.Parallel()

	for _, data := range AllData {
		data, err := hashScrypt(data, salt, 16, 2, 1, 1)
		assert.Len(t, data, 1)
		assert.NoError(t, err)
	}
}

func TestHashScryptTwoSize(t *testing.T) {
	t.Parallel()

	for _, data := range AllData {
		data, err := hashScrypt(data, salt, 16, 2, 1, 2)
		assert.Len(t, data, 2)
		assert.NoError(t, err)
	}
}

// Make sure we're not just getting null bytes.
func TestHashScryptNonNull(t *testing.T) {
	t.Parallel()

	for _, data := range AllData {
		size := 30

		data, err := hashScrypt(data, salt, 16, 2, 1, size)
		assert.NotEqual(t, make([]byte, size), data)
		assert.NoError(t, err)
	}
}

// Shouldn't accept an `N` value that's not a power of two.
func TestHashScryptNonPowerOfTwoN(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 15, 2, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bN\b`), err.Error())
	}
}

// Shouldn't accept an `N` value that's zero.
func TestHashScryptZeroN(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 0, 2, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bN\b`), err.Error())
	}
}

// Shouldn't accept an `N` value that's one.
func TestHashScryptOneN(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 1, 2, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bN\b`), err.Error())
	}
}

// Shouldn't accept an `r` value that's zero.
func TestHashScryptZeroR(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 16, 0, 1, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\br\b`), err.Error())
	}
}

// Shouldn't accept a `p` value that's zero.
func TestHashScryptZeroP(t *testing.T) {
	for _, data := range AllData {
		_, err := hashScrypt(data, salt, 16, 2, 0, 1)
		assert.Error(t, err)
		assert.Regexp(t, regexp.MustCompile(`\bp\b`), err.Error())
	}
}

// The given byte slices should be populated in the order they're specified,
// with the bytes filling them in the same order the bytes have been generated.
// We don't need to re-test everything else since this function should be
// delegating to the "plain" `hash` function.
func TestHashFillScryptPopulateInOrder(t *testing.T) {
	t.Parallel()

	for _, data := range AllData {
		var (
			size = 30
			N    = scryptN(16)
			r    = scryptR(2)
			p    = scryptP(1)
		)

		// Get the original bytes.
		hashed, err := hashScrypt(data, salt, N, r, p, size)
		assert.NoError(t, err)

		// Make some slices from a single array, for easy comparison later.
		parts := make([]byte, size)
		part1 := parts[:12]
		part2 := parts[12:]

		// Fill the slices with the hashed bytes.
		hashFillScrypt(N, r, p, salt, data, part1, part2)

		// Ensure they were filled in the correct order with the same bytes
		// generated by the "plain" function.
		assert.Equal(t, hashed, parts)
	}
}

// The header blob should output data consisting of 4 magic bytes followed by a
// single unsigned int containing the provided version number.
func TestBuildHeaderBlobOutputsCorrectBytes(t *testing.T) {
	expected := []byte{
		0xa4, // A fixstr containing our four magic bytes.
		0x4a, 0x1a, 0xb5, 0x52,
		0x00, // Literal zero for the version number we're passing in here.
	}

	header, err := buildHeaderBlob(0)
	assert.NoError(t, err)
	assert.Equal(t, expected, header)

	// Test a larger version number to ensure it serializes correctly.
	expected = []byte{
		0xa4, // A fixstr containing our four magic bytes.
		0x4a, 0x1a, 0xb5, 0x52,
		0xcd, // A larger version number
		0x01, 0x01,
	}

	header, err = buildHeaderBlob(257)
	assert.NoError(t, err)
	assert.Equal(t, expected, header)
}
