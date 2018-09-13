package assert

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
