package pass

import (
  "testing"

  "github.com/stretchr/testify/assert"
)

// we can't create an empty blob
func TestNewBlobEmpty(t *testing.T) {
  assert.Panics(t, func() {
    NewBlob()
  })
}

// we can't create a blob if we don't give it enough parameters
func TestNewBlobShort(t *testing.T) {
  assert.Panics(t, func() {
    NewBlob("foo")
  })

  assert.Panics(t, func() {
    NewBlob(1)
  })

  assert.Panics(t, func() {
    NewBlob(make([]byte, 0))
  })
}

// can't create blobs with negative sizes
func TestNewBlobNegativeSize(t *testing.T) {
  var blob Blob
  assert.Panics(t, func() {
    blob = NewBlob("foo", -1)
  })
}

// can't create blobs with byte arrays that don't match the blob's size
func TestNewBlobWrongInitSize(t *testing.T) {
  assert.Panics(t, func() {
    NewBlob(
      "foo", 1,
      make([]byte, 0),
    )
  })
}

// can create a blob with a single empty field
func TestNewBlobEmptyField(t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob("foo", 0)
  })
}

// can create and init a blob with a single empty field
func TestNewBlobEmptyFieldInit(t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob("foo", 0, make([]byte, 0))
  })
}

// can create a blob with many empty fields
func TestNewBlobEmptyFields(t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob(
      "foo", 0,
      "bar", 0,
      "baz", 0,
    )
  })
}

// can create and init a blob with many empty fields
func TestNewBlobEmptyFieldsInit (t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob(
      "foo", 0,
      "bar", 0,
      "baz", 0,
      make([]byte, 0),
    )
  })
}

// can create a blob with a single normal field
func TestNewBlobSingleField (t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob(
      "foo", 5,
    )
  })
}

// can create and init a blob with a single normal field
func TestNewBlobSingleFieldInit (t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob(
      "foo", 5,
      make([]byte, 5),
    )
  })
}

// can create a blob with many fields
func TestNewBlobManyFields(t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob(
      "foo", 1,
      "bar", 2,
      "baz", 3,
    )
  })
}

// can create and init a blob with many fields
func TestNewBlobManyFieldsInit(t *testing.T) {
  assert.NotPanics(t, func() {
    NewBlob(
      "foo", 1,
      "bar", 2,
      "baz", 3,
      make([]byte, 6),
    )
  })
}

// can't create a blob with duplicate fields
func TestNewBlobDuplicateField(t *testing.T) {
  assert.Panics(t, func() {
    NewBlob(
      "foo", 1,
      "bar", 2,
      "foo", 3,
    )
  })
}

// can't access a non-existent field
func TestBlobGetNoSuchField(t *testing.T) {
  b := NewBlob("foo", 0)
  assert.Panics(t, func() {
    b.Get("bar")
  })
}

// can access an existing field
func TestBlobGet(t *testing.T) {
  b := NewBlob("foo", 0)
  assert.NotPanics(t, func() {
    b.Get("foo")
  })
}

// can modify an existing field
func TestBlobGetModify(t *testing.T) {
  b := NewBlob("foo", 3)
  assert.Equal(t, b.Get("foo"), make([]byte, 3))

  slice := b.Get("foo")
  copy(slice, []byte{1, 2, 3})

  assert.Equal(t, b.Get("foo"), []byte{1, 2, 3})

  slice[0] = 5
  assert.Equal(t, b.Get("foo")[0], byte(5))
}

// length of a blob with an empty field should be zero
func TestBlobEmptyFieldLen(t *testing.T) {
  b := NewBlob("foo", 0)
  assert.Equal(t, b.Len(), 0)
}

// length of a blob with many empty fields should be zero
func TestBlobEmptyFieldsLen(t *testing.T) {
  b := NewBlob(
    "foo", 0,
    "bar", 0,
    "baz", 0,
  )
  assert.Equal(t, b.Len(), 0)
}

// length of a blob with empty and non-empty fields should be correct
func TestBlobMixedEmptyFieldsLen(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 0,
    "baz", 2,
  )
  assert.Equal(t, b.Len(), 3)
}

// length of a blob with many fields should be correct
func TestBlobManyFieldsLen(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
  )
  assert.Equal(t, b.Len(), 6)
}

// length of a blob's field from a single-field blob should be the same as the
// initial field size.
func TestBlobSingleFieldGetLen(t *testing.T) {
  b := NewBlob("foo", 3)
  assert.Equal(t, len(b.Get("foo")), 3)
}

// the length of a blob's fields should match their initial sizes
func TestBlobManyFieldsGetLen(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
  )
  assert.Equal(t, len(b.Get("foo")), 1)
  assert.Equal(t, len(b.Get("bar")), 2)
  assert.Equal(t, len(b.Get("baz")), 3)
}

// the length of an empty field should be zero
func TestBlobGetEmptyFieldLen(t *testing.T) {
  b := NewBlob(
    "foo", 0,
  )
  assert.Equal(t, len(b.Get("foo")), 0)
}

// the length of a normal field should be its specified length
func TestBlobGetNormalFieldLen(t *testing.T) {
  b := NewBlob(
    "foo", 3,
  )
  assert.Equal(t, len(b.Get("foo")), 3)
}

// the length of an empty field mixed in with some normal fields should be zero,
// and the normal fields should be their specified lengths.
func TestBlobGetMixedFieldsLen(t *testing.T) {
  b := NewBlob(
    "foo", 0,
    "bar", 1,
    "baz", 2,
  )
  assert.Equal(t, len(b.Get("foo")), 0)
  assert.Equal(t, len(b.Get("bar")), 1)
  assert.Equal(t, len(b.Get("baz")), 2)

  b = NewBlob(
    "bar", 1,
    "foo", 0,
    "baz", 2,
  )
  assert.Equal(t, len(b.Get("bar")), 1)
  assert.Equal(t, len(b.Get("foo")), 0)
  assert.Equal(t, len(b.Get("baz")), 2)

  b = NewBlob(
    "bar", 1,
    "baz", 2,
    "foo", 0,
  )
  assert.Equal(t, len(b.Get("bar")), 1)
  assert.Equal(t, len(b.Get("baz")), 2)
  assert.Equal(t, len(b.Get("foo")), 0)
}

// a blob's bytes should start off empty
func TestBlobUnchangedEmptyBytes(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
  )
  assert.Equal(t, b.Bytes(), make([]byte, b.Len()))
}

// a blob's bytes should be initialized to the given bytes
func TestBlobInitBytesSameValues(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Exactly(t, b.Bytes(), initBytes)
}

// a blob shouldn't use the given init bytes directly (it should copy them)
func TestBlobInitBytesCopied(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )

  // make sure the blob's bytes are initially the same
  assert.Equal(t, b.Bytes(), initBytes)

  // change the original byte array
  initBytes[0] = 5

  // make sure the blob's bytes are different in only the way we changed them
  assert.NotEqual(t, b.Bytes(), initBytes)
  assert.Equal(t, b.Bytes()[1:], initBytes[1:])
  assert.NotEqual(t, b.Bytes()[0], initBytes[0])
}

// the length of a blob's bytes should match the length of the blob
func TestBlobBytesLen(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
  )

  assert.Equal(t, b.Len(), len(b.Bytes()))
}

// modifying a blob's bytes should work
func TestBlobBytesModify(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
  )

  bytes := b.Bytes()

  bytes[2] = 7

  assert.Equal(t, b.Get("bar")[1], byte(7))
}

// the length of an empty blob's bytes should match the length of the blob
func TestBlobEmptyBytesLen(t *testing.T) {
  b := NewBlob(
    "foo", 0,
  )

  assert.Equal(t, b.Len(), len(b.Bytes()))
}

// the length of the bytes of a blob with mixed fields should match the length
// of the blob.
func TestBlobMixedFieldsBytesLen(t *testing.T) {
  b := NewBlob(
    "foo", 0,
    "bar", 1,
    "baz", 2,
  )
  assert.Equal(t, b.Len(), len(b.Bytes()))

  b = NewBlob(
    "bar", 1,
    "foo", 0,
    "baz", 2,
  )
  assert.Equal(t, b.Len(), len(b.Bytes()))

  b = NewBlob(
    "bar", 1,
    "baz", 2,
    "foo", 0,
  )
  assert.Equal(t, b.Len(), len(b.Bytes()))
}

// slicing a blob with the From method should work
func TestBlobFrom(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Equal(t, b.From("bar"), initBytes[1:])
}

// slicing a blob from the first field should return the entire blob
func TestBlobFromAll(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Equal(t, b.From("foo"), b.Bytes())
}

// slicing from the last field of a blob should equal the last field
func TestBlobFromLast(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Equal(t, b.From("baz"), b.Get("baz"))
}

// modifying the sliced slice should modify the underlying field
func TestBlobFromModify(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )

  slice := b.From("bar")
  slice[0] = 7
  assert.Equal(t, b.Get("bar")[0], byte(7))
}

// slicing a blob with the To method should work
func TestBlobTo(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Equal(t, b.To("baz"), initBytes[:3])
}

// slicing to the first field of a blob should be empty
func TestBlobToFirst(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Equal(t, b.To("foo"), []byte{})
}

// modifying the sliced slice should modify the underlying field
func TestBlobToModify(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )

  slice := b.To("baz")
  slice[0] = 7
  assert.Equal(t, b.Get("foo")[0], byte(7))
}

// slicing a blob with the Slice method should work
func TestBlobSlice(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    "pants", 4,
    initBytes,
  )
  assert.Equal(t, b.Slice("bar", "pants"), initBytes[1:6])
}

// slicing to the same field should return empty
func TestBlobSliceEmpty(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    initBytes,
  )
  assert.Equal(t, b.Slice("bar", "bar"), []byte{})
}

// modifying the sliced slice should modify the underlying field
func TestBlobSliceModify(t *testing.T) {
  initBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    "pants", 4,
    initBytes,
  )

  slice := b.Slice("baz", "pants")
  slice[0] = 7
  assert.Equal(t, b.Get("baz")[0], byte(7))
}

// make sure we can get the data out of a blob that we put in
func TestBlobCreateAndInit(t *testing.T) {
  b := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
  )

  // set some random data in the bytes
  b.Get("foo")[0] = 1

  b.Get("bar")[0] = 2
  b.Get("bar")[1] = 2

  b.Get("baz")[0] = 3
  b.Get("baz")[1] = 3
  b.Get("baz")[2] = 3

  // get the bytes for this blob
  bBytes := b.Bytes()

  // re-create the blob from the original's bytes
  newB := NewBlob(
    "foo", 1,
    "bar", 2,
    "baz", 3,
    bBytes,
  )

  // make sure all the fields match exactly
  assert.Equal(t, b.Get("foo"), newB.Get("foo"))
  assert.Equal(t, b.Get("bar"), newB.Get("bar"))
  assert.Equal(t, b.Get("baz"), newB.Get("baz"))
}
