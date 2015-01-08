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
  "Version": 0,

  "Settings": {
    "ClipboardClearDelayMS": 10000,
    "DatabaseLockDelayMS": 30000,
  },

  "Entries": {
    "uuid0": {...},
    "uuid1": {...},
    "uuid2": {...},
    "uuid3": {...},
    "uuid4": {...},
  }
}
*/

// decrypted entries look like this:
/*
{
  // a UUID for this entry
  "Id": "00000000-0000-0000-0000-000000000000",

  // ISO-8601 timestamps for each value
  "CreatedAt": "2014-12-20T14:42:30Z",
  "UpdatedAt": "2014-12-20T14:42:30Z",
  "DeletedAt": nil,

  // standard data
  "Title": "Hacker News",
  "URL": "https://news.ycombinator.com",
  "Username": "pg",
  "Password": "sjf3489yrhlOFasdfklj44445",

  // an array of GMail-like string tags, in sorted order, de-duplicated
  "Tags": []

  // a map of arbitrary string key/value pairs the user can create and manage
  "Data": {},

  // a wholesale copy of the previous version of the entry, made every time a
  // modification is saved.
  "PreviousVersion": {}
}
*/

// OPERATIONS:
// - create
// - query
// - update
// - delete
// - trim_history(count)
// - trim_deleted(age)
