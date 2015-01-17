package util

import (
  "time"

  "github.com/ugorji/go/codec"
)

const iso8601 = "2006-01-02T03:04:05Z"

type Time struct {
  time.Time
}

// extend the time.Time struct to encode to an ISO-8601 string
func (t *Time) CodecEncodeSelf(enc *codec.Encoder) {
  // ensure the time is UTC, then format it to the zone-less ISO-8601 format and
  // encode it as the resulting string. if it's the zero time, encode it as nil.
  if !t.IsZero() {
    utcISO8601 := t.UTC().Format(iso8601)
    enc.Encode(utcISO8601)
  } else {
    // encode it as nil so it will show up as `null` in JSON
    enc.Encode(nil)
  }
}

// extend the time.Time struct to decode from an ISO-8601 string
func (t *Time) CodecDecodeSelf(dec *codec.Decoder) {
  var utcISO8601 interface{}
  dec.Decode(&utcISO8601)

  switch utcISO8601 := utcISO8601.(type) {
  case []uint8: // we get the most basic type instead of a proper string
    // parse the time as UTC (the default since no zone info will be present)
    parsedTime, err := time.Parse(iso8601, string(utcISO8601))

    // decode to the zero time if there was an error
    if err != nil {
      parsedTime = time.Time{}
    }

    // change our time to one matching the resulting time.Time instance
    *t = Time{parsedTime}
  case nil:
    // parse the time as the empty time if it was nil
    *t = Time{}
  default:
    // if it's some other type, just parse to the empty time
    *t = Time{}
  }
}
