package pass

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

	assert.Equal(t, r.Version, db.Versions()[0].Version)

	r.Version = 1
	assert.Equal(t, 1, r.Version)

	assert.Equal(t, 0, db.Versions()[0].Version)
}

func TestVersionsListShouldBeSameLengthAsGivenRecords(t *testing.T) {
	db := newCryptVersions(
		cryptVersionRecord{0, nil, nil},
		cryptVersionRecord{2, nil, nil},
		cryptVersionRecord{1, nil, nil},
	)

	assert.Len(t, db.Versions(), 3)
}

func TestModifyingTheVersionsListShouldNotModifyTheDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	versions := db.Versions()

	versions[0] = cryptVersionRecord{1, nil, nil}
	assert.Equal(t, 0, db.Versions()[0].Version)
}

func TestModifyingAVersionsListRecordShouldNotModifyTheDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	versions := db.Versions()

	versions[0].Version = 1
	assert.Equal(t, 0, db.Versions()[0].Version)
}

func TestLatestVersionOneVersion(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	latest := db.LatestVersion()

	assert.Equal(t, r, latest)
}

func TestLatestVersionTwoVersions(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(r, s)

	latest := db.LatestVersion()

	assert.Equal(t, s, latest)
}

func TestModifyingLatestVersionShouldNotModifyDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	db := newCryptVersions(r)

	latest := db.LatestVersion()
	latest.Version = 1

	assert.Equal(t, 0, db.Versions()[0].Version)
}

func TestVersionsShouldNotBeReordered(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(s, r)

	latest := db.LatestVersion()

	assert.Equal(t, r, latest)
}

func TestFindVersionShouldFindAnExistingVersion(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(s, r)

	version, ok := db.FindVersion(0)

	assert.True(t, ok)
	assert.Equal(t, r, version)
}

func TestFindVersionShouldReturnNotOkIfNoVersionIsFound(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(s, r)

	_, ok := db.FindVersion(3)
	assert.False(t, ok)
}

func TestModifyingFoundVersionShouldNotModifyDatabase(t *testing.T) {
	r := cryptVersionRecord{0, nil, nil}
	s := cryptVersionRecord{1, nil, nil}
	db := newCryptVersions(r, s)

	version, _ := db.FindVersion(0)
	version.Version = 2

	assert.Equal(t, 0, db.Versions()[0].Version)
}

func TestCryptVersionsShouldContainVersionRecords(t *testing.T) {
	assert.NotNil(t, CryptVersions)
	assert.True(t, len(CryptVersions.Versions()) > 0)
}
