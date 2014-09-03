package pass

import (
)

// IMPLEMENTATION NOTES:
// - encrypt PII separately from the main database
// - decrypt once to get all non-PII with encrypted PII, then decrypt each
//   individual PII (passwords, custom fields, etc.) as needed. this should
//   prevent more than one PII from existing in memory at a time.
// - use simpler internal encryption so decryption of in-memory stuff is fast
// - use a "tags" format instead of folders (array of strings).
// - user fields are at same level as internal fields
// - internal fields can't be deleted (for simplicity's sake, allow this?)
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
  "settings": {
    "clipboard_clear_delay": 10000,
    "database_lock_delay": 30000
  },

  // these are encrypted with a password generated from the master password,
  // that's _different_ from the one that unlocks the database at large. this
  // lets us store it in memory when the user enters their password for the
  // first time, then decrypt things only as-needed to prevent them from getting
  // written to the swap area if memory swaps. the encryption/decryption of
  // these blobs should be pretty much instantaneous. each entry is keyed by a
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

  // unix timestamps for each value
  "create_date": 1234567890,
  "update_date": 1234567890,
  "delete_date": 1234567890,

  // standard data
  "title": "Hacker News",
  "url": "https://news.ycombinator.com",
  "username": "pg",
  "password": "sjf3489yrhlOFasdfklj44445",

  // the unix timestamp after which this entry is considered "expired"
  "expiry_date": 1234567890,

  // an arbitrary map of string key/value pairs the user can create and manage
  "data": {

  },

  // a wholesale copy of the previous version of the entry, made every time a
  // modification is saved.
  "previous_version": { }
}
*/

// OPERATIONS:
// - create
// - query
// - update
// - delete
// - trim_history(count)
// - trim_deleted(age)
