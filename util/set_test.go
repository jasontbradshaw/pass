package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
)

func TestNewSortedStringSetEmpty(t *testing.T) {
	// creating a new empty set via function should work
	s := NewSortedStringSet()
	assert.Equal(t, []string{}, s.Values())
	assert.Equal(t, 0, s.Len())
}

func TestNewSortedStringSetSingle(t *testing.T) {
	// creating a new empty set via function should work
	s := NewSortedStringSet("foo")
	assert.Equal(t, []string{"foo"}, s.Values())
	assert.Equal(t, 1, s.Len())
}

func TestSortedStringSetValuesLexicographicallySorted(t *testing.T) {
	// values should be sorted lexicographically if added on create
	s1 := NewSortedStringSet("c", "a", "b", "aa")
	assert.Equal(t, []string{"a", "aa", "b", "c"}, s1.Values())
	assert.Equal(t, 4, s1.Len())

	// values should be sorted lexicographically if added post-create
	s2 := NewSortedStringSet()
	s2.Add("c", "a", "b", "aa")
	assert.Equal(t, []string{"a", "aa", "b", "c"}, s2.Values())
	assert.Equal(t, 4, s2.Len())
}

func TestNewSortedStringSetMultiple(t *testing.T) {
	// creating a new empty set via function should work
	s := NewSortedStringSet("foo", "bar", "baz")
	assert.Equal(t, []string{"bar", "baz", "foo"}, s.Values())
	assert.Equal(t, 3, s.Len())
}

func TestSortedStringSetAddNothing(t *testing.T) {
	s := NewSortedStringSet()

	s.Add()

	assert.Equal(t, []string{}, s.Values())
	assert.Equal(t, 0, s.Len())
}

func TestSortedStringSetAddSingle(t *testing.T) {
	s := NewSortedStringSet()

	// adding a value should be reflected in the output
	s.Add("foo")

	assert.Equal(t, []string{"foo"}, s.Values())
	assert.Equal(t, 1, s.Len())
}

func TestSortedStringSetAddMultiple(t *testing.T) {
	s := NewSortedStringSet()

	// adding several values should be reflected in the output
	s.Add("foo", "bar")

	assert.Equal(t, []string{"bar", "foo"}, s.Values())
	assert.Equal(t, 2, s.Len())
}

func TestSortedStringSetAddDuplicate(t *testing.T) {
	s := NewSortedStringSet()

	// adding a value twice should be reflected only once in the output
	s.Add("foo")
	s.Add("foo")

	assert.Equal(t, []string{"foo"}, s.Values())
	assert.Equal(t, 1, s.Len())
}

func TestSortedStringSetAddDuplicateMultiple(t *testing.T) {
	s := NewSortedStringSet()

	// adding a value twice should be reflected only once in the output
	s.Add("foo", "foo")

	assert.Equal(t, []string{"foo"}, s.Values())
	assert.Equal(t, 1, s.Len())
}

// the set should always be a slice at the bottom of it all. this ensures that
// when encoded to/decoded from msgpack by the codec library, it will be a
// simple datatype that's portable to all its supported encoders (JSON, etc.).
func TestSortedStringSetIsAStringSlice(t *testing.T) {
	s := NewSortedStringSet("a", "b", "c")
	assert.Equal(t, []string{"a", "b", "c"}, *s)
}

func TestSortedStringSetEncodesToMsgpackAsAStringArray(t *testing.T) {
	s := NewSortedStringSet("foo", "bar", "baz")

	var (
		encoded []byte
		mh      codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&encoded, &mh)
	err := enc.Encode(s)
	assert.NoError(t, err)

	// ensure we got an array of three elements
	assert.Equal(t, 0x93, encoded[0])

	// ensure all elements are strings of three elements
	assert.Equal(t, 0xA3, encoded[1])
	assert.Equal(t, 0xA3, encoded[5])
	assert.Equal(t, 0xA3, encoded[9])

	// make sure we got only what we asked for
	assert.Len(t, encoded, 13)
}

func TestSortedStringSetDecodesFromMsgpackToAStringArray(t *testing.T) {
	s := NewSortedStringSet("foo", "bar", "baz")

	var (
		encoded []byte
		mh      codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&encoded, &mh)
	err := enc.Encode(s)
	assert.NoError(t, err)

	// decode to a string array
	var sd []string
	dec := codec.NewDecoderBytes(encoded, &mh)
	err = dec.Decode(&sd)
	assert.NoError(t, err)

	// make sure we received the expected array
	assert.Equal(t, []string{"bar", "baz", "foo"}, sd)
}

func TestSortedStringSetDecodesFromMsgpackToASortedStringSet(t *testing.T) {
	s := NewSortedStringSet("foo", "bar", "baz")

	var (
		encoded []byte
		mh      codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&encoded, &mh)
	err := enc.Encode(s)
	assert.NoError(t, err)

	// decode to a string array
	var sd SortedStringSet
	dec := codec.NewDecoderBytes(encoded, &mh)
	err = dec.Decode(&sd)
	assert.NoError(t, err)

	// make sure we received the expected array as our type
	assert.Equal(t, []string{"bar", "baz", "foo"}, sd)
	assert.IsType(t, SortedStringSet{}, sd)
}
