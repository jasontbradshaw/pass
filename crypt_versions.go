package pass

import (
	"fmt"
)

type cryptVersionNumber int32

// a simple box to hold the number and functions associated with a particular
// set of crypt functions.
type cryptVersionRecord struct {
	Version cryptVersionNumber
	Encrypt func([]byte, string) ([]byte, error)
	Decrypt func([]byte, string) ([]byte, error)
}

// a container that holds all the available version container in an immutable
// manner, to prevent any modification of the canonical source list.
type cryptVersions struct {
	// an ordered list of crypt versions, from oldest to newest. the last item in
	// the slice is guaranteed to be the latest version!
	versions []cryptVersionRecord

	// a map of version number to version pointer, to speed lookup
	versionsById map[cryptVersionNumber]*cryptVersionRecord
}

// given a bunch of versions, builds the internal version list and populates the
// lookup map.
func newCryptVersions(records ...cryptVersionRecord) cryptVersions {
	if len(records) == 0 {
		panic("Must be called with at least one version record")
	}

	versions := make([]cryptVersionRecord, len(records))
	versionsById := make(map[cryptVersionNumber]*cryptVersionRecord)

	// populate the preallocated slice and the lookup map. the slice holds the raw
	// objects, while the map holds only pointers to them.
	for i, v := range records {
		// ensure we never have duplicate version numbers
		if _, ok := versionsById[v.Version]; ok {
			panic(
				fmt.Sprintf("Can't duplicate version numbers (duplicated: %d", v.Version))
		}

		versions[i] = v
		versionsById[v.Version] = &v
	}

	return cryptVersions{
		versions,
		versionsById,
	}
}

// returns a copy of all the internal version records
func (c *cryptVersions) All() []cryptVersionRecord {
	records := make([]cryptVersionRecord, len(c.versions))
	copy(records, c.versions)
	return records
}

// get a copy of the latest available crypt version's record
func (c *cryptVersions) Latest() cryptVersionRecord {
	return c.versions[len(c.versions)-1]
}

// get a copy of the given version's record, returning "not ok" if a record with
// the given version number couldn't be found.
func (c *cryptVersions) Find(requestedVersion cryptVersionNumber) (cryptVersionRecord, bool) {
	record, ok := c.versionsById[requestedVersion]
	if !ok {
		return cryptVersionRecord{}, false
	}

	return *record, true
}

// expose the canonical list of available versions, as defined by their
// respective files.
// NOTE: we maintain this _here and only here_ to prevent modifying the version
// database, which we want to be immutable for all intents and purposes.
var CryptVersions cryptVersions = newCryptVersions(
	cryptVersionRecord0,
)
