package pass

import ()

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

// the database looks like this:
/*
{
  // the current version of the database format, as an integer. this is
  // incremented every time the format changes, so that migrations may be done.
  "version": 0,

  "settings": {
    "clipboard_clear_delay_ms": 10000,
    "database_lock_delay_ms": 30000
  },

  // these are encrypted with a password generated from the master password,
  // that's _different_ from the one that unlocks the database at large. this
  // lets us store it in memory when the user enters their password for the
  // first time, then decrypt things only as-needed to prevent them from getting
  // written to the swap area if memory swaps. the encryption/decryption of
  // these blobs should be pretty much instantaneous. each entry is keyed by its
  // UUID, which will allow us to easily access the data for a specific entry
  // without having to do a linear search to find a specific one.
  "entries": {
    "uuid0": "encrypted:base64blob",
    "uuid1": "encrypted:base64blob",
    "uuid2": "encrypted:base64blob",
    "uuid3": "encrypted:base64blob",
    "uuid4": "encrypted:base64blob"
  }
}
*/

// decrypted entries look like this:
/*
{
  // a UUID for this entry
  "id": "00000000-0000-0000-0000-000000000000",

  // ISO-8601 timestamps for each value
  "created_at": "2014-12-20T14:42:30Z",
  "updated_at": "2014-12-20T14:42:30Z",
  "deleted_at": nil,

  // standard data
  "title": "Hacker News",
  "url": "https://news.ycombinator.com",
  "username": "pg",
  "password": "sjf3489yrhlOFasdfklj44445",

  // the ISO-8601 timestamp after which this entry is considered "expired"
  "expires_at": "2014-12-20T14:42:30Z",

  // an array of GMail-like string tags, in sorted order, de-duplicated
  "tags": []

  // a map of arbitrary string key/value pairs the user can create and manage
  "data": {},

  // a wholesale copy of the previous version of the entry, made every time a
  // modification is saved.
  "previous_version": {}
}
*/

// OPERATIONS:
// - create
// - query
// - update
// - delete
// - trim_history(count)
// - trim_deleted(age)
