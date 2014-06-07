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

// shouldn't be able to decompress empty data
func TestDecompressEmpty(t *testing.T) {
  _, err := decompress(EmptyData)
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

// should never be allowed to pad to a negative block size
func TestPadBlocksizeNegative(t *testing.T) {
  for _, data := range AllData {
    _, err := pad(data, -1)
    assert.Error(t, err)
  }
}

// should never be allowed to pad to a 0 block size
func TestPadBlocksizeZero(t *testing.T) {
  for _, data := range AllData {
    _, err := pad(data, 0)
    assert.Error(t, err)
  }
}

// padding data that is smaller than a single block should work fine
func TestPadBlockSizeSmallerThanDataLength(t *testing.T) {
  for _, data := range AllData {
    // make sure the block size exceeds the data length
    blockSize := len(data) + 1

    padded, err := pad(data, len(data) + 1)
    assert.NoError(t, err)

    assert.Equal(t, len(padded), blockSize)
  }
}

// should be allowed to pad to a block size of up to a full byte
func TestPadBlocksize255(t *testing.T) {
  for _, data := range AllData {
    _, err := pad(data, 255)
    assert.NoError(t, err)
  }
}

// should never be allowed to pad to a block size larger than a single byte
func TestPadBlocksize256(t *testing.T) {
  for _, data := range AllData {
    _, err := pad(data, 256)
    assert.Error(t, err)
  }
}

// when the size of the input data is an integer multiple of the block size, an
// entire block of padding should be added.
func TestPadDataLengthIntegerMultipleOfBlockSize(t *testing.T) {
  data := []byte("abcdefghi")
  const blockSize = 3

  // make sure our input and blocksize fit our requirements
  assert.True(t, len(data) > blockSize)
  assert.Equal(t, len(data) % blockSize, 0)

  padded, err := pad(data, blockSize)
  assert.NoError(t, err)

  // ensure that we added a full block of padding
  assert.Equal(t, len(padded), len(data) + blockSize)
  assert.Equal(t, padded[len(padded) - 1], blockSize)
}

// test every possible block size against all data
func TestPad(t *testing.T) {
  for _, data := range AllData {
    for blockSize := 1; blockSize < 255; blockSize++ {
      padded, err := pad(data, blockSize)

      assert.NoError(t, err)

      // make sure the padded data is an integer multiple of the block size
      assert.Equal(t, len(padded) % blockSize, 0)

      // make sure all padding bytes are equal to the final byte
      finalByte := padded[len(padded) - 1]
      for _, b := range padded[len(padded) - int(finalByte):] {
        assert.Equal(t, b, finalByte)
      }

      // make sure all the original bytes are included in the padded output
      assert.Equal(t, data, padded[:len(data)])
    }
  }
}

// fuzz test padding with lots of random data
func TestFuzzPadAndUnpad(t *testing.T) {
  skipIfShort(t)

  for i := 0; i < 10000; i++ {
    // create a randomly-sized array, possibly larger than a byte in length
    size, err := rand.Int(rand.Reader, big.NewInt(512))
    assert.NoError(t, err)

    // create a random block size, from the min (0) up the the max (255)
    blockSizeLarge, err := rand.Int(rand.Reader, big.NewInt(254))
    assert.NoError(t, err)
    blockSize := int(blockSizeLarge.Int64()) + 1

    // fill the array with random data
    data := make([]byte, size.Int64())
    _, err = rand.Read(data)
    assert.NoError(t, err)

    // pad, unpad, and compare to the original
    padded, err := pad(data, blockSize)
    assert.NoError(t, err)

    // make sure all padding bytes are equal to the final byte
    finalByte := padded[len(padded) - 1]
    for _, b := range padded[len(padded) - int(finalByte):] {
      assert.Equal(t, b, finalByte)
    }

    // make sure all the original bytes are included in the padded output
    assert.Equal(t, data, padded[:len(data)])

    unpadded := unpad(padded)

    assert.Equal(t, unpadded, data)
  }
}
