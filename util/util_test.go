package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCamelCaseToSnakeCase(t *testing.T) {
	assert.Equal(t, "", CamelCaseToSnakeCase(""))

	assert.Equal(t, "fo", CamelCaseToSnakeCase("fo"))
	assert.Equal(t, "fo", CamelCaseToSnakeCase("FO"))
	assert.Equal(t, "fo", CamelCaseToSnakeCase("Fo"))
	assert.Equal(t, "f_o", CamelCaseToSnakeCase("fO"))

	assert.Equal(t, "1_f", CamelCaseToSnakeCase("1F"))
	assert.Equal(t, "1_f", CamelCaseToSnakeCase("1f"))

	assert.Equal(t, "foo", CamelCaseToSnakeCase("foo"))
	assert.Equal(t, "foo", CamelCaseToSnakeCase("FOO"))
	assert.Equal(t, "foo", CamelCaseToSnakeCase("Foo"))
	assert.Equal(t, "foo_x", CamelCaseToSnakeCase("fooX"))
	assert.Equal(t, "foo_x", CamelCaseToSnakeCase("FooX"))

	assert.Equal(t, "foo_bar", CamelCaseToSnakeCase("fooBar"))
	assert.Equal(t, "foo_bar", CamelCaseToSnakeCase("fooBAR"))
	assert.Equal(t, "foo_bar", CamelCaseToSnakeCase("FooBar"))
	assert.Equal(t, "foo_bar", CamelCaseToSnakeCase("FooBAR"))
	assert.Equal(t, "foo_bar", CamelCaseToSnakeCase("FOOBar"))

	assert.Equal(t, "123", CamelCaseToSnakeCase("123"))
	assert.Equal(t, "foo_123", CamelCaseToSnakeCase("foo123"))
	assert.Equal(t, "foo_123", CamelCaseToSnakeCase("foo123"))
	assert.Equal(t, "123_foo", CamelCaseToSnakeCase("123Foo"))
	assert.Equal(t, "123_foo", CamelCaseToSnakeCase("123FOO"))

	assert.Equal(t, "foo_bar_baz", CamelCaseToSnakeCase("fooBARBaz"))
	assert.Equal(t, "foo_bar_baz", CamelCaseToSnakeCase("FooBARBaz"))
	assert.Equal(t, "foo_bar_baz", CamelCaseToSnakeCase("fooBarBAZ"))

	assert.Equal(t, "foo_bar_123_baz", CamelCaseToSnakeCase("fooBAR123Baz"))
	assert.Equal(t, "foo_bar_123_baz", CamelCaseToSnakeCase("fooBar123BAZ"))
	assert.Equal(t, "foo_bar_1_baz", CamelCaseToSnakeCase("fooBAR1Baz"))
	assert.Equal(t, "foo_bar_1", CamelCaseToSnakeCase("fooBAR1"))
	assert.Equal(t, "foo_b_4_r_1", CamelCaseToSnakeCase("fooB4R1"))
	assert.Equal(t, "foo_1_bar_1", CamelCaseToSnakeCase("foo1BAR1"))
	assert.Equal(t, "foo_123_bar", CamelCaseToSnakeCase("FOO123BAR"))
}
