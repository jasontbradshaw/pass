package database

import (
	"net/url"
	"time"
)

// IMPLEMENTATION NOTES:
// - encrypt PII separately from the main database
// - decrypt once to get all non-PII with encrypted PII, then decrypt each
//   individual PII (passwords, custom fields, etc.) as needed. this should
//   prevent more than one PII from existing in memory at a time.
// - use simpler internal encryption so decryption of in-memory stuff is fast
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
type RecordId [16]byte

// all the configurable settings allowed in our database
type DatabaseSettings struct {
	// how long to keep the copied data in the clipboard before overwriting it, in
	// milliseconds.
	// NOTE: make sure to compare the data in the clipboard to the
	// originally-copied data, so we don't blindly overwrite the user's new copied
	// data!
	ClipboardClearDelayMS int32

	// how long to wait before saving and closing the database, in milliseconds
	DatabaseLockDelayMS int32

	// the maximum number of previous versions to keep. negative means "no limit"
	// NOTE: the user should have to confirm before lowering this, since a history
	// trim should take place every time it's changed, and lowering it is
	// effectively the same as deleting old history.
	PreviousVerionsToKeep int32
}

type Database struct {
	// incremented every time the format changes so that migrations may be done
	Version databaseVersion

	Settings DatabaseSettings

	// a map of record id to record
	Records map[RecordId]*Record
}

type Record struct {
	// a unique id for this entry
	Id RecordId

	// timestamps for each value
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	// standard data
	Title    string
	URL      url.URL
	Username string
	Password []byte

	// an array of GMail-like string tags, in sorted order, de-duplicated
	Tags []string

	// a map of arbitrary string key/value pairs the user can create and manage
	Data map[string]string

	// a pointer to a wholesale copy of the previous version of the entry, made
	// every time a modification is saved. this will allow for any desired
	// undo/revert/restore operations to take place, and will be
	// forward-compatible as long as child entries are migrated to newer database
	// versions along with their parents.
	PreviousVersion *Record
}

// OPERATIONS:
// - Create
// - FindBy*
// - Update
// - Delete
// - TrimHistory(count)
// - TrimDeleted(age)
