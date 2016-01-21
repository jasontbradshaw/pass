package util

import (
	"bytes"
	"regexp"
	"strings"
)

var reMidStringCaps *regexp.Regexp = regexp.MustCompile(`([A-Z]+)[A-Z][a-z]`)

var digitStrings map[string]bool = map[string]bool{
	"0": true, "1": true, "2": true, "3": true, "4": true,
	"5": true, "6": true, "7": true, "8": true, "9": true,
}

// Takes a camel-case or upper-camel-case string and converts it to snake_case.
// Converts intelligently around case transitions, so something like `camelCASE`
// becomes `camel_case` and not `camel_c_a_s_e`. If the input string is not in
// valid camel-case, the result is not guaranteed to be well-formed.
func CamelCaseToSnakeCase(s string) string {
	if len(s) == 0 {
		return ""
	}

	// Pre-process the string to replace any mid-string runs of all-caps with
	// their title-cased equivalents. This lets us turn things like "FOOBar" and
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

		// If we've changed case, insert a divider.
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
