package database

import (
	"fmt"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"
)

// IMPLEMENTATION NOTES:
// - use a "tags" format instead of folders (array of strings).
// - allow easy integration with autotype-like tools via user scripts (plugins)
// - use a sub-command style command line API
// - allow the user to do _everything_ through the command line
// - include an HTTPS-only interface that uses the same mechanism as command
//   line API. this will decrease the maintenance burden by making the HTTP
//   interface a consumer of said API, and increase dogfooding of the same.
// - investigate buying certs for the HTTPS connection
// - include a password generator that's independent of entry creation
// - allow several password customization options (see
//   http://passwordsgenerator.net), arbitrary lengths, and the ability to
//   generate several passwords at once.
// - include history for all modifications

type databaseVersion int32

type Database struct {
	// the format of this database, to ensure that we can migrate existing files
	// to newer versions as they're released.
	Version databaseVersion

	Settings struct {
		// how long to keep the copied data in the clipboard before overwriting it,
		// in milliseconds.
		// NOTE: make sure to compare the data in the clipboard to the
		// originally-copied data, so we don't blindly overwrite the user's new
		// copied data!
		clipboardClearDelayMilliseconds int32 `codec:"ClipboardClearDelayMilliseconds"`

		// how long to wait after the most recent interaction before saving and
		// closing the database, in milliseconds
		databaseLockDelayMilliseconds int32 `codec:"DatabaseLockDelayMilliseconds"`

		// the maximum number of previous versions to keep. negative means "no
		// limit"
		// NOTE: the user should have to confirm before lowering this, since a
		// history trim should take place every time it's changed, and lowering it
		// is effectively the same as deleting old history.
		previousVersionsToKeep int32 `codec:"PreviousVersionsToKeep"`

		// the maximum number of days to keep deleted entries for before removing
		// them from the database entirely. if set to negative, means "no limit".
		maximumDeletedEntryAgeDays int32 `codec:"MaximumDeletedEntryAgeDays"`
	}

	// kept private to prevent direct tampering with the records list. we have to
	// use the UUID string as the key since we can't use the UUID directly.
	records map[string]*record `codec:"Records"`

	// the normalized path of the currently opened database file, empty if none is
	// currently open.
	path string

	// used for serializing all access to the database. this isn't the most
	// performant thing in the world, but it _is_ the safest in terms of
	// preventing data corruption and the like. it's also dead simple and should
	// cover the 90% use case of a single user accessing the database.
	mutex sync.Mutex
}

// turns a UUID into a key string for our records map
func uuidToKeyString(id *uuid.UUID) string {
	return id.String()
}

// runs the given function while the database is locked. automatically releases
// the lock after the function has exited and this function has returned.
func (db *Database) withLock(fn func()) {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	fn()
}

// adds the given record to the database and modifies the given record to have
// the same values as the record that was just created.
func (db *Database) Create(r *record) {
	db.withLock(func() {
		// use the user's record as a base for what we'll add to the database
		rn := r.Duplicate()

		// give the record an id that we know doesn't already exist in the database.
		// unlikely to collide? certainly. does it hurt? no.
		rn.regenerateId()
		for db.records[rn.idKeyString()] != nil {
			rn.regenerateId()
		}

		// set the timestamps to the current time
		now := time.Now()
		rn.setCreatedAt(now)
		rn.setUpdatedAt(now)

		// add the new record to the database
		db.records[rn.idKeyString()] = rn

		// update the user's record with the private values we just set
		rn.copyPrivateFieldsTo(r)
	})
}

// updates the database's copy of the given record to match what is passed in.
// the given record will be updated to match the changes made in the database.
// the given record must already exist in the database.
func (db *Database) Update(ru *record) (err error) {
	db.withLock(func() {
		// load the existing record from the database
		r := db.records[ru.idKeyString()]

		// bail if we couldn't find the requested record or the record has already
		// been deleted.
		if r == nil || r.IsDeleted() {
			err = fmt.Errorf("Record %s doesn't exist in the database", ru.id)
			return
		}

		// version and update the record
		rv := r.version()
		ru.copyPublicFieldsTo(rv)
		rv.setUpdatedAt(time.Now())

		// save the new record back to the database and update the original record
		rv.copyPrivateFieldsTo(ru)
		db.records[r.idKeyString()] = rv
	})

	return err
}

// attempts to locate the given record in the database, returning a pointer to a
// copy of the record if found, otherwise nil.
func (db *Database) FindById(id *uuid.UUID) (r *record) {
	db.withLock(func() {
		// if the record exists and hasn't been deleted, return it. otherwise,
		// return nil.
		re := db.records[uuidToKeyString(id)]
		if re != nil && !re.IsDeleted() {
			r = re.Duplicate()
		}
	})

	return r
}

// same as `FindById`, but will return deleted records
func (db *Database) FindByIdWithDeleted(id *uuid.UUID) (r *record) {
	db.withLock(func() {
		// if the record exists, return it. otherwise, return nil.
		re := db.records[uuidToKeyString(id)]
		if re != nil {
			r = re.Duplicate()
		}
	})

	return r
}

// deletes the given record from the database and modifies the passed-in record
// to match. if the record has no "deleted at" value yet, sets that value to the
// current time (i.e. marks the record as deleted). if the record already has a
// "deleted at" value in the database, deletes the record permanently and
// doesn't sets the "updated at" time of the input record to the current time,
// indicating that it has now been totally destroyed.
func (db *Database) Delete(r *record) (err error) {
	db.withLock(func() {
		// if the record is not already in the database, return nil
		rd := db.records[r.idKeyString()]
		if rd == nil {
			err = fmt.Errorf("Record %s doesn't exist in the database", r.id)
			return
		}

		rv := rd.version()
		now := time.Now()

		if rv.IsDeleted() {
			// delete the record permanently if it's already been marked as deleted
			delete(db.records, rd.idKeyString())
		} else {
			// update "deleted at" to mark it as deleted
			rv.setDeletedAt(now)
		}

		// set the "updated at" time. if the record has now been removed from the
		// database, this will be _after_ the "deleted at" time, which marks the
		// record as having been permanently deleted.
		rv.setUpdatedAt(now)

		// update the user's record with our new data
		rv.copyPrivateFieldsTo(r)
	})

	return err
}

// removes the "deleted" status from the given record, as long as the record
// hasn't been permanently deleted. if the record doesn't exist or has been
// permanently deleted, returns an error.
func (db *Database) Restore(r *record) (err error) {
	// don't restore permanently-deleted records, since we don't want to re-use
	// their id values and cause confusion amongst clients who may have stored
	// them.
	if r.IsPermanentlyDeleted() {
		return fmt.Errorf("Cannot restore permanently-deleted record %s", r.id)
	}

	db.withLock(func() {
		rv := r.version()
		rv.setUpdatedAt(time.Now())

		// remove the record's "deleted at" time (i.e. replace it with a zero-value
		// time struct), making other functions recognize it as valid once again.
		rv.setDeletedAt(time.Time{})

		rv.copyPublicFieldsTo(r)
		db.records[rv.idKeyString()] = rv
	})

	return err
}
