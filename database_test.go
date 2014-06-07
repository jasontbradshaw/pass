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
