package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
)

func TestDefaultTimeIsZero(t *testing.T) {
	i := Time{}
	assert.True(t, i.IsZero())
}

func TestCodecEncodeSelfZeroTimeEncodesAsNil(t *testing.T) {
	var (
		encoded []byte
		mh  codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&encoded, &mh)

	i := Time{}
	i.CodecEncodeSelf(enc)

	// the zero time should encode as nil
	assert.Equal(t, []byte{0xc0}, encoded)
}

func TestCodecEncodeSelfNormalTimeEncodesAsISO8601String(t *testing.T) {
	var (
		encoded []byte
		mh  codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&encoded, &mh)

	i := Time{time.Date(1944, 06, 06, 12, 13, 14, 0, time.UTC)}
	i.CodecEncodeSelf(enc)

	// a fixstr of length 20, with its single-byte header
	assert.Equal(t, 0xb4, encoded[0])
	assert.Len(t, encoded, 21)

	// should equal the time we specified
	assert.Equal(t, "1944-06-06T12:13:14Z", string(encoded[1:]))
}

func TestCodecDecodeSelfNilDecodesToZeroTime(t *testing.T) {
	// build a nil byte array to decode
	var mh  codec.MsgpackHandle
	dec := codec.NewDecoderBytes([]byte{0xc0}, &mh)

	// start with a different time to make certain the struct is decoding in-place
	i := Time{time.Date(1944, 06, 06, 12, 13, 14, 0, time.UTC)}
	assert.False(t, i.IsZero())
	i.CodecDecodeSelf(dec)

	// the zero time should encode as nil
	assert.True(t, i.IsZero())
}

func TestCodecDecodeSelfStringDecodesToNormalTime(t *testing.T) {
	// encode a normal time
	var (
		encoded []byte
		mh  codec.MsgpackHandle
	)
	enc := codec.NewEncoderBytes(&encoded, &mh)

	i := Time{time.Date(1944, 06, 06, 12, 13, 14, 0, time.UTC)}
	i.CodecEncodeSelf(enc)

	dec := codec.NewDecoderBytes(encoded, &mh)

	j := Time{}
	j.CodecDecodeSelf(dec)

	// the new time should equal the old one
	assert.Equal(t, i.Format(time.RFC3339), j.Format(time.RFC3339))
}
