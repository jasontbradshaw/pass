package database

import (
	"net/url"
	"time"
)

// IMPLEMENTATION NOTES:
// - Encrypt PII separately from the main database.
// - Decrypt once to get all non-PII with encrypted PII, then decrypt each
//   individual PII (passwords, custom fields, etc.) as needed. This should
//   prevent more than one PII from existing in memory at a time.
// - Use simpler internal encryption so decryption of in-memory stuff is fast.
// - Use a "tags" format instead of folders (array of strings).
// - Allow easy integration with autotype-like tools via user scripts (plugins)
// - Use a sub-command style command line API.
// - Allow the user to do _everything_ through the command line
// - Include an HTTPS-only interface that uses the same mechanism as command
//   line API. This will decrease the maintenance burden by making the HTTP
//   interface a consumer of said API, and increase dogfooding of the same.
// - Investigate buying certs for the HTTPS connection.
// - Include a password generator that's independent of entry creation.
// - Allow several password customization options (see
//   http://passwordsgenerator.net), arbitrary lengths, and the ability to
//   generate several passwords at once.
// - Include history for all modifications.

type databaseVersion int32
type RecordId [16]byte

// All the configurable settings allowed in our database.
type DatabaseSettings struct {
	// How long to keep the copied data in the clipboard before overwriting it, in
	// milliseconds.
	// NOTE: Make sure to compare the data in the clipboard to the
	// originally-copied data, so we don't blindly overwrite the user's new copied
	// data!
	ClipboardClearDelayMS int32

	// How long to wait before saving and closing the database, in milliseconds.
	DatabaseLockDelayMS int32

	// The maximum number of previous versions to keep. Negative means "no limit".
	// NOTE: The user should have to confirm before lowering this, since a history
	// trim should take place every time it's changed, and lowering it is
	// effectively the same as deleting old history.
	// NOTE: Alternatively, leave old history entries intact and only trim them
	// once the entry is accessed.
	PreviousVerionsToKeep int32
}

type Database struct {
	// Incremented every time the format changes so that migrations may be done.
	Version databaseVersion

	Settings DatabaseSettings

	// A map of record id to record.
	Records map[RecordId]*Record
}

type Record struct {
	// A unique id for this entry.
	Id RecordId

	// Timestamps for each value.
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time

	// Standard data.
	Title    string
	URL      url.URL
	Username string
	Password []byte

	// An array of GMail-like string tags, in sorted order, de-duplicated.
	Tags []string

	// A map of arbitrary string key/value pairs the user can create and manage.
	Data map[string]string

	// A pointer to a wholesale copy of the previous version of the entry, made
	// every time a modification is saved. This will allow for any desired
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
