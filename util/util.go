package util

import (
	"bytes"
	"crypto/rand"
	"regexp"
	"strings"
)

var reMidStringCaps *regexp.Regexp = regexp.MustCompile(`([A-Z]+)[A-Z][a-z]`)

var digitStrings map[string]bool = map[string]bool{
	"0": true, "1": true, "2": true, "3": true, "4": true,
	"5": true, "6": true, "7": true, "8": true, "9": true,
}

type UUID [16]byte

// takes a camel-case or upper-camel-case string and converts it to snake_case.
// converts intelligently around case transitions, so something like `camelCASE`
// becomes `camel_case` and not `camel_c_a_s_e`. if the input string is not in
// valid camel-case, the result is not guaranteed to be well-formed.
func CamelCaseToSnakeCase(s string) string {
	if len(s) == 0 {
		return ""
	}

	// pre-process the string to replace any min-string runs of all-caps with
	// their title-cased equivalents. this lets us turn things like "FOOBar" and
	// "bazFOOBar" into "foo_bar" and "baz_foo_bar" using the loop below.
	san := s
	groups := reMidStringCaps.FindAllStringSubmatch(san, -1)
	for _, group := range groups {
		match := group[1]
		san = strings.Replace(san, match, strings.Title(strings.ToLower(match)), 1)
	}

	parts := strings.Split(san, "")
	divider := "_"

	var buf bytes.Buffer
	lastWasUpper := strings.ToUpper(parts[0]) == parts[0]
	lastWasDigit := digitStrings[parts[0]]
	for _, c := range parts {
		isUpper := strings.ToUpper(c) == c
		isDigit := digitStrings[c]

		// if we've changed case, insert a divider
		if (isUpper && !lastWasUpper) ||
			(isDigit && !lastWasDigit) ||
			(isDigit != lastWasDigit) {
			buf.WriteString(divider)
		}

		buf.WriteString(c)

		lastWasUpper = isUpper
		lastWasDigit = isDigit
	}

	return strings.ToLower(buf.String())
}

// generates and returns a new version 4 UUID as a byte array. panics if the
// UUID fails to generate.
func UUID4() UUID {
	uuid := [16]byte{}

	// fill our slice with random bytes
	n, err := rand.Read(uuid[:])
	if err != nil {
		panic(err)
	}
	if n != len(uuid) {
		panic("Not enough random bytes were generated to fill a UUID!")
	}

	// update the bytes to match the UUIDv4 spec (see:
	// http://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_.28random.29).
	uuid[6] = (uuid[6] & 0x0F) | 0x40
	uuid[8] = (uuid[8] & 0x3F) | 0x80

	return uuid
}
