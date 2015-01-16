package util

import (
	"sort"
)

// a set of strings with simple add and remove methods. we use a []string
// underneath in order to simplify encoding/decoding with the codec package!
type SortedStringSet []string

func NewSortedStringSet(items ...string) *SortedStringSet {
	s := make([]string, 0, len(items))

	// turn s into a string set
	set := SortedStringSet(s)

	set.Add(items...)
	return &set
}

// returns the values in the set sorted lexicographically
func (s *SortedStringSet) Values() []string {
	values := make([]string, s.Len())
	copy(values, *s)
	return values
}

// returns the number of items in the set
func (s *SortedStringSet) Len() int {
	return len(*s)
}

// add the given strings to the set. if the string already exists in the set,
// that string is ignored.
func (s *SortedStringSet) Add(items ...string) {
	for _, item := range items {
		// add the string at the given index if we don't already have it
		i := sort.SearchStrings(*s, item)
		if i < len(*s) && (*s)[i] == item {
			// value already exists in the set and should be skipped
		} else {
			// i is now the index at which the value should be inserted
			if len(*s) == 0 {
				*s = append(*s, item)
			} else {
				// insert the string into the slice if the slice isn't empty
				*s = append(*s, "")
				copy((*s)[i+1:], (*s)[i:])
				(*s)[i] = item
			}
		}
	}
}

// remove the given strings from the set. if the string doesn't exist in the
// set, does nothing.
func (s *SortedStringSet) Remove(items ...string) {
	for _, itemToRemove := range items {
		// if we have the string we're trying to remove, remove it from the slice
		i := sort.SearchStrings((*s), itemToRemove)
		if i < len(*s) && (*s)[i] == itemToRemove {
			// reconstruct the slice without the given string (i.e. remove it)
			*s = append((*s)[:i], (*s)[i+1:]...)
		}
	}

	// NOTE: we don't have to re-sort since removing strings doesn't alter the
	// original sorted order.
}
