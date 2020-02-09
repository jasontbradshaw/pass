package database

import (
  "time"
)

type Record struct {
	Id        UniqueId
	CreatedAt time.Time

	// The dates this item existed during. If it's the first version of the
	// record, `ValidFrom` will be identical to `CreatedAt`. If it's the current
	// version of the record, `ValidTo` will be `nil`.
	ValidFrom time.Time
	ValidTo   time.Time

	// The title of this record.
	Title string

	// An array of GMail-like string tags, in sorted order, de-duplicated.
	Tags []string

  // The fields used by this record.
	Data []*Field
}
