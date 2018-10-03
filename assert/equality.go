package assert

import (
	"reflect"
	"testing"
	"time"
)

// assert.Equal aims to test equality of any two objects, and call t.Fatalf
// if they're not equal
func Equal(t *testing.T, expected interface{}, got interface{}) {
	t.Helper()

	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v got %v", expected, got)
	}
}

// EqualSliceOfStrings tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
func EqualSliceOfStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// AssertEqualSliceOfStrings compares two string slices and calls t.Fatalf
// with a message if they differ.
func AssertEqualSliceOfStrings(t *testing.T, expected, got []string) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected length %d, got %d. expected: %v, got: %v",
			len(expected), len(got), expected, got)
	}
	for i := range expected {
		if expected[i] != got[i] {
			t.Fatalf("expected[%d] differs, expected '%s', got '%s'", i, expected[i], got[i])
		}
	}

}

// AssertEqualSliceOfInts compares two slices of ints and calls t.Fatalf
// with a message if they differ.
func AssertEqualSliceOfInts(t *testing.T, expected, got []int) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected length %d, got %d. expected: %v, got: %v",
			len(expected), len(got), expected, got)
	}
	for i := range expected {
		if expected[i] != got[i] {
			t.Fatalf("expected[%d] differs, expected '%d', got '%d'", i, expected[i], got[i])
		}
	}

}

// AssertEqualTime compares two times and calls t.Fatalf. Different timezones
// are treated as different times, even if they correspond to the same moment
// in time.
func AssertEqualTimes(t *testing.T, expected time.Time, got time.Time) {
	t.Helper()
	if expected != got {
		t.Fatalf("expected %v, got %v", expected, got)
	}

}
