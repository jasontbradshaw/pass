package database

import (
	"bytes"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/jasontbradshaw/pass/util"
)

type record struct {
	// a unique id for this entry
	id uuid.UUID `codec:"Id"`

	// timestamps for each value, exposed as ISO-8601 strings through the API
	createdAt util.Time `codec:"CreatedAt"`
	deletedAt util.Time `codec:"DeletedAt"`
	updatedAt util.Time `codec:"UpdatedAt"`

	// a pointer to a wholesale copy of the previous version of the entry, made
	// every time a modification is saved. this will allow for any desired
	// undo/revert/restore operations to take place, and will be
	// forward-compatible as long as child entries are migrated to newer database
	// versions along with their parents.
	previousVersion *record `codec:"PreviousVersions"`

	// standard data
	Title    string
	URL      string
	Username string
	Password []byte

	// a lexicographically-sorted set of arbitrary string tags
	Tags util.SortedStringSet

	// a map of arbitrary string key/value pairs the user can create and manage
	Data map[string]string
}

// return a copy of the record's id value
func (r *record) Id() uuid.UUID {
	ic := uuid.UUID{}
	copy(ic, r.id)
	return ic
}

func (r *record) CreatedAt() time.Time {
	// a simple hack to convert the time back into a normal time struct. also
	// ensures that we present all our internal times as UTC, not that they can
	// ever be set to anything that's _not_ UTC...
	return r.createdAt.UTC()
}

func (r *record) UpdatedAt() time.Time {
	return r.updatedAt.UTC()
}

func (r *record) DeletedAt() time.Time {
	return r.deletedAt.UTC()
}

// returns the time the record was permanently deleted at, and whether the
// record has been permanently deleted at all.
func (r *record) PermanentlyDeletedAt() (time.Time, bool) {
	// the record has been permanently deleted if it's "updated at" time is after
	// it's "deleted at" time. this only happens if the record has been
	// permanently deleted by the database!
	if r.IsDeleted() && r.updatedAt.After(r.DeletedAt()) {
		return r.UpdatedAt(), true
	}

	// return an empty time, and indicate that the record hasn't yet been
	// permanently deleted.
	return time.Time{}, false
}

// returns a searchable string of the given record's data. this returns
// something a regular expression can be run over to determine whether a
// full-text query should match the given record. the string parts should be
// ordered in order of decreasing overall relevance, in order to provide the
// best results.
func (r *record) Tokenize() string {
	var b bytes.Buffer

	b.WriteString(r.Title)
	b.WriteString(" ")

	b.WriteString(r.Username)
	b.WriteString(" ")

	// write all the tags
	for _, tag := range r.Tags {
		b.WriteString(tag)
		b.WriteString(" ")
	}

	// write all the data values, followed by their keys
	for key, value := range r.Data {
		b.WriteString(value)
		b.WriteString(" ")
		b.WriteString(key)
		b.WriteString(" ")
	}

	b.WriteString(r.URL)
	b.WriteString(" ")

	return b.String()
}

// copies all the user-modifiable fields of the current record to the given
// record.
func (r *record) copyPublicFieldsTo(dst *record) {
	copy(dst.Tags, r.Tags)
	copy(dst.Password, r.Password)

	// copy the map
	dst.Data = make(map[string]string)
	for k, v := range r.Data {
		dst.Data[k] = v
	}
}

// copies all the private fields of the current record to the given record.
// `PreviousVersion` will retain its pointer value.
func (r *record) copyPrivateFieldsTo(dst *record) {
	copy(dst.id[:], r.id[:])
	dst.createdAt = r.createdAt
	dst.deletedAt = r.deletedAt
	dst.updatedAt = r.updatedAt
	dst.previousVersion = r.previousVersion
}

// duplicates this record and returns a pointer to the duplicate.
// `PreviousVersion` will retain its pointer value.
func (r *record) Duplicate() (rd *record) {
	r.copyPublicFieldsTo(rd)
	r.copyPrivateFieldsTo(rd)
	return rd
}

// returns whether the record has been marked as "deleted" by having a non-zero
// "deleted at" value.
func (r *record) IsDeleted() bool {
	return r.deletedAt.IsZero()
}

// a record has been permanently deleted if the last update done to it was after
// the "deleted at" time. this indicates that the record no longer exists in the
// database.
func (r *record) IsPermanentlyDeleted() bool {
	_, ok := r.PermanentlyDeletedAt()
	return ok
}

// set the record's id to a new value
func (r *record) setId(id *uuid.UUID) {
	r.id = uuid.Parse(id.String())
}

// gets the string value of the id to use as a key to the database's records map
func (r *record) idKeyString() string {
	return uuidToKeyString(&r.id)
}

// randomizes the record's id value to a new UUID.
// NOTE: don't do this to records that are already in the database, otherwise
// they won't be correctly matched to their record map key!
func (r *record) regenerateId() {
	r.id = uuid.NewRandom()
}

func (r *record) setCreatedAt(t time.Time) {
	// ensure we're always storing the time internally as UTC
	r.createdAt = util.Time{t.UTC()}
}

func (r *record) setUpdatedAt(t time.Time) {
	r.updatedAt = util.Time{t.UTC()}
}

func (r *record) setDeletedAt(t time.Time) {
	r.deletedAt = util.Time{t.UTC()}
}

func (r *record) setPreviousVersion(p *record) {
	r.previousVersion = p
}

// duplicates the existing record, then sets the original record as the previous
// version of the newly-duplicated record. returns the newly duplicated record.
func (r *record) version() *record {
	rv := r.Duplicate()
	rv.setPreviousVersion(r)
	return rv
}
