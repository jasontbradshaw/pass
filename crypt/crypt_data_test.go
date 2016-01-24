package crypt

import (
	"crypto/rand"
)

// NOTE: This file contains common test data used for the various tests we run.
// The tests themselves exist in other files.

// Used for testing empty data.
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

// A bunch of random bytes for whatever.
var _, _ = rand.Read(randomBytes)

// Fill some arbitrary bits with random data.
var key aes128Key = aes128Key{}
var _ int = copy(key[:], randomBytes)

var salt salt128 = salt128{}
var _ int = copy(salt[:], randomBytes)
