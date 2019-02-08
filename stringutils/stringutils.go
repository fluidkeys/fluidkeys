package stringutils

// ContainsDisallowedRune checks whether the given input contains a disallowed rune
func ContainsDisallowedRune(input string) bool {
	for _, r := range input {
		if isTerminalControlCharacter(r) {
			return true

		}
	}
	return false
}

func isTerminalControlCharacter(r rune) bool {

	switch r {
	default:
		// any character not in this list is not a terminal control character
		return false

	case 0: // NUL Null char
		return true

	case 1: // SOH Start of Heading
		return true

	case 2: // STX Start of Text
		return true

	case 3: // ETX End of Text
		return true

	case 4: // EOT End of Transmission
		return true

	case 5: // ENQ Enquiry
		return true

	case 6: // ACK Acknowledgment
		return true

	case 7: // BEL Bell
		return true

	case 8: // BS  Back Space
		return true

		// 9: HT  Horizontal Tab

		// 10: LF Line Feed

	case 11: // VT  Vertical Tab
		return true

	case 12: // FF  Form Feed
		return true

		// 13: Carriage Return

	case 14: // SO  Shift Out / X-On
		return true

	case 15: // SI  Shift In / X-Off
		return true

	case 16: // DLE Data Line Escape
		return true

	case 17: // DC1 Device Control 1 (oft. XON)
		return true

	case 18: // DC2 Device Control 2
		return true

	case 19: // DC3 Device Control 3 (oft. XOFF)
		return true

	case 20: // DC4 Device Control 4
		return true

	case 21: // NAK Negative Acknowledgement
		return true

	case 22: // SYN Synchronous Idle
		return true

	case 23: // ETB End of Transmit Block
		return true

	case 24: // CAN Cancel
		return true

	case 25: // EM  End of Medium
		return true

	case 26: // SUB Substitute
		return true

	case 27: // ESC Escape
		return true

	case 28: // FS  File Separator
		return true

	case 29: // GS  Group Separator
		return true

	case 30: // RS  Record Separator
		return true

	case 31: // US  Unit Separator
		return true

	// 32 - 126 are ASCII printable characters

	case 127: // Delete
		return true
	}

	// 128 - 255 are extended ASCII codes e.g. euro sign
}
