package database

// IMPLEMENTATION NOTES:
// - Encrypt PII separately from the main database.
// - Decrypt once to get all non-PII with encrypted PII, then decrypt each
//   individual PII (passwords, custom fields, etc.) as needed. This should
//   prevent more than one PII from existing in memory at a time.
// - Use simpler internal encryption so decryption of in-memory stuff is fast.
// - Use a "tags" format instead of folders (array of strings).
// - Allow easy integration with autotype-like tools via user scripts (plugins)
// - Use a sub-command style command line API.
// - Allow several password customization options (see
//   http://passwordsgenerator.net), arbitrary lengths, and the ability to
//   generate several passwords at once.
// - Include history for all modifications.

type databaseVersion int32

type Database struct {
	// Incremented every time the format changes so that migrations may be done.
	Version databaseVersion

	// A map of record id to record.
	Records map[UniqueId]*Record
}

// OPERATIONS:
// - Create
// - Where
// - Update
// - Delete
