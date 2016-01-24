package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCryptVersionsShouldPanicWithoutArguments(t *testing.T) {
	assert.Panics(t, func() {
		newCryptVersions()
	}, "Should panic if given no arguments")
}

func TestNewCryptVersionsShouldPanicWhenGivenDuplicateVersionNumbers(t *testing.T) {
	assert.Panics(t, func() {
		_ = newCryptVersions(
			cryptVersionRecord{0, nil, nil},
			cryptVersionRecord{0, nil, nil},
		)
	}, "Should panic if given duplicate version numbers")
}

func TestNewCryptVersionsShouldWorkWithASingleValue(t *testing.T) {
	_ = newCryptVersions(
		cryptVersionRecord{0, nil, nil},
	)
}

func TestNewCryptVersionsShouldWorkWithTwoDifferentValues(t *testing.T) {
	_ = newCryptVersions(
		cryptVersionRecord{0, nil, nil},
		cryptVersionRecord{1, nil, nil},
	)
}

func TestModifyingARecordShouldNotAffectTheDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	assert.Equal(t, r.Version, db.All()[0].Version)

	r.Version = 1
	assert.Equal(t, cryptVersionNumber(1), r.Version)

	assert.Equal(t, cryptVersionNumber(0), db.All()[0].Version)
}

func TestVersionsListShouldBeSameLengthAsGivenRecords(t *testing.T) {
	db := newCryptVersions(
		cryptVersionRecord{0, nil, nil},
		cryptVersionRecord{2, nil, nil},
		cryptVersionRecord{1, nil, nil},
	)

	assert.Len(t, db.All(), 3)
}

func TestModifyingTheVersionsListShouldNotModifyTheDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	versions := db.All()

	versions[0] = cryptVersionRecord{1, nil, nil}
	assert.Equal(t, cryptVersionNumber(0), db.All()[0].Version)
}

func TestModifyingAVersionsListRecordShouldNotModifyTheDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	versions := db.All()

	versions[0].Version = 1
	assert.Equal(t, cryptVersionNumber(0), db.All()[0].Version)
}

func TestLatestOneVersion(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	latest := db.Latest()

	assert.Equal(t, r, latest)
}

func TestLatestTwoVersions(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(r, s)

	latest := db.Latest()

	assert.Equal(t, s, latest)
}

func TestModifyingLatestVersionShouldNotModifyDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	latest := db.Latest()
	latest.Version = 1

	assert.Equal(t, cryptVersionNumber(0), db.All()[0].Version)
}

func TestVersionsShouldNotBeReordered(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(s, r)

	latest := db.Latest()

	assert.Equal(t, r, latest)
}

func TestFindVersionShouldFindAnExistingVersion(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(s, r)

	version, ok := db.Find(0)

	assert.True(t, ok)
	assert.Equal(t, r, version)
}

func TestFindVersionShouldReturnNotOkIfNoVersionIsFound(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(s, r)

	_, ok := db.Find(3)
	assert.False(t, ok)
}

func TestModifyingFoundVersionShouldNotModifyDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(r, s)

	version, _ := db.Find(0)
	version.Version = 2

	assert.Equal(t, cryptVersionNumber(0), db.All()[0].Version)
}

func TestCryptVersionsShouldContainVersionRecords(t *testing.T) {
	assert.NotNil(t, CryptVersions)
	assert.True(t, len(CryptVersions.All()) > 0)
}

func TestCryptVersionsShouldHaveNonNilFunctionValues(t *testing.T) {
	for _, version := range CryptVersions.All() {
		assert.NotNil(t, version.Encrypt)
		assert.NotNil(t, version.Decrypt)
	}
}
