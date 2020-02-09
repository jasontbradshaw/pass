package database

// A single field within a record. Certain fields are special and cannot be
// modified.
type Field struct {
	// The human-readable title of this field.
	Title string

	// Whether this field is for use by the system, meaning primarily that it
	// can't be removed or modified by the user in any way.
	IsSystemField bool

	// The data this field contains, or the empty string if it contains no data.
	Data string

	// A slice of validation functions to use on this field. Each function should
	// take a pointer to a single field, then return whether the field is
	// considered "valid" or not.
	Validators []func(*Field) bool
}
