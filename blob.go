package pass

import (
  "fmt"
)

type Blob struct {
  // a map of boundary names to their indices, tuples of (inclusive, exclusive)
  boundaries map[string][2]int
  data []byte
}

// given a bunch of (name, size)... parameter tuples, constructs a blob from
// them. the internal field boundaries are calculated from the given names and
// sizes. if the final parameter is a byte array, it's used to initalize the
// blob.
func NewBlob(params ...interface{}) Blob {
  // require at _least_ one field
  if len(params) < 2 { panic("At least one field is required") }

  // used as the final boundaries map, but used initially to check for duplicate
  // field names.
  boundaries := make(map[string][2]int)
  fieldNamePlaceholder := [2]int{-1, -1}

  // verify the parameters separately to ensure that they alternate (string,
  // int) and are valid. this is slower than doing it as we go, but much easier
  // to read.
  lastWasString := false
  for i, param := range params {
    switch t := param.(type) {
    default:
      // only accept the given types
      panic(fmt.Sprintf("Unexpected paramter type %T", t))
    case string:
      // make sure the field names are non-null and unique
      if lastWasString {
        panic("Parameter list must have the pattern (string, int)...")
      } else if len(t) == 0 {
        panic("Field names must not be empty")
      } else if _, ok := boundaries[t]; ok {
        panic(fmt.Sprintf("Duplicate field name: %s", t))
      }

      // store the marker value in this field name
      boundaries[t] = fieldNamePlaceholder

      lastWasString = true
    case int:
      // make sure field sizes are at least 0
      if !lastWasString {
        panic("Parameter list must have the pattern (string, int)...")
      } else if t < 0 {
        panic(fmt.Sprintf("Field sizes must be >= 0 (got: %d)", t))
      }
      lastWasString = false
    case []byte:
      // make sure that the initialization bytes, if any, only come at the very
      // end of all the other paramters.
      if i != len(params) - 1 {
        panic("Any initialization byte array must come at the end, if at all")
      }
    }
  }

  // build the internal boundaries map from the given paramters
  fieldName := ""
  boundaryStart := 0
  var initBytes []byte = nil
  for _, param := range params {
    switch t := param.(type) {
    case string:
      // store the name until we get a boundary size
      fieldName = t
    case int:
      // store a new boundary pair
      end := boundaryStart + t
      boundaries[fieldName] = [2]int{boundaryStart, end}

      // move the boundary marker to the new start position if the field was of
      // non-zero length. otherwise, we should start at the same place as last
      // time since the field didn't consume any space.
      if t > 0 { boundaryStart = end }
    case []byte:
      // store the initialization bytes
      initBytes = t
    }
  }

  // use the given initialization bytes if available, otherwise an empty slice
  size := boundaryStart
  bytes := make([]byte, size)
  if initBytes != nil {
    if len(initBytes) != len(bytes) {
      panic(fmt.Sprintf(
        "Initialization bytes must have the same length as the combined fields (expected %d, got %d)",
        len(bytes), len(initBytes)))
    } else {
      // use the initialization bytes instead of an empty byte array
      copy(bytes, initBytes)
    }
  }

  return Blob {
    boundaries,
    bytes,
  }
}

// returns the slice of bytes corresponding to the given field name. if no such
// field name exists, panics. the slice is a view into the internal data,
// and as such can (and should!) be modified in order to change the underlying
// field's byte value.
func (blob *Blob) Get(fieldName string) []byte {
  // get the field name we want. we panic since we're treating field names as
  // accessors, and trying to access a non-existent field name is a big no-no
  // that is unrecoverable, just as trying to call a non-existent function would
  // be.
  fieldBoundary, ok := blob.boundaries[fieldName]
  if !ok { panic(fmt.Sprintf("Invalid field name: %s", fieldName)) }

  return blob.data[fieldBoundary[0]:fieldBoundary[1]]
}

// get the entire content of this blob as a slice of bytes
func (blob *Blob) Bytes() []byte {
  return blob.data[:]
}

// returns a slice of bytes from the start of the given field to the end of the
// internal data.
func (blob *Blob) From(startFieldName string) []byte {
  boundary, ok := blob.boundaries[startFieldName]
  if !ok { panic(fmt.Sprintf("Invalid field name: %s", startFieldName)) }

  return blob.data[boundary[0]:]
}

// returns a slice of bytes from the start of the data to the beginning of the
// given field.
func (blob *Blob) To(endFieldName string) []byte {
  endBoundary, ok := blob.boundaries[endFieldName]
  if !ok { panic(fmt.Sprintf("Invalid field name: %s", endFieldName)) }

  return blob.data[:endBoundary[0]]
}

// returns a slice of bytes from the start of the first field to the start of
// the second.
func (blob *Blob) Slice(startFieldName, endFieldName string) []byte {
  startBoundary, ok := blob.boundaries[startFieldName]
  if !ok { panic(fmt.Sprintf("Invalid field name: %s", startFieldName)) }

  endBoundary, ok := blob.boundaries[endFieldName]
  if !ok { panic(fmt.Sprintf("Invalid field name: %s", endFieldName)) }

  return blob.data[startBoundary[0]:endBoundary[0]]
}

// returns the number of bytes in this blob. blob.Len() == len(blob.Bytes())
func (blob *Blob) Len() int {
  return len(blob.data)
}
