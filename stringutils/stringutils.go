package stringutils

// ContainsDisallowedRune checks whether the given input contains a disallowed rune
func ContainsDisallowedRune(input string) bool {
	for _, r := range input {
		switch {
		case 0 <= r && r <= 8:
			return true
		case r == '\t': // 9
			continue
		case 11 <= r && r <= 12:
			return true
		case r == '\n': // 10
			continue
		case r == '\r': // 13
			continue
		case 14 <= r && r <= 31:
			return true
		case r == 127: // DEL
			return true
		default:
			continue
		}
	}
	return false
}
