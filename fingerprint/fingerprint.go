package fingerprint

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type fingerprintBytes = [20]byte

// Fingerprint represents a 20-character OpenPGP fingerprint.
type Fingerprint struct {
	fingerprintBytes

	isSet bool
}

// Parse takes a string and returns a Fingerprint.
// Accepts fingerprints with spaces, uppercase, lowercase etc.
func Parse(fp string) (Fingerprint, error) {
	var nilFingerprint Fingerprint
	withoutSpaces := strings.Replace(fp, " ", "", -1)

	expectedPattern := `^(0x)?[A-Fa-f0-9]{40}$`
	if matched, err := regexp.MatchString(expectedPattern, withoutSpaces); !matched || err != nil {
		return nilFingerprint, fmt.Errorf("fingerprint doesn't match pattern '%v', err=%v", expectedPattern, err)
	}

	withoutLeading0x := strings.TrimLeft(withoutSpaces, "0x")

	bytes, err := hex.DecodeString(withoutLeading0x)
	if err != nil {
		return nilFingerprint, err
	}
	var f Fingerprint
	for i, b := range bytes {
		f.fingerprintBytes[i] = b
	}
	f.isSet = true
	return f, nil
}

// MustParse takes a string and returns a Fingerprint. If the
// string is not a valid fingerprint (e.g. 40 hex characters) it will panic.
func MustParse(fp string) Fingerprint {
	result, err := Parse(fp)
	if err != nil {
		panic(err)
	}
	return result
}

// Return a human-friendly version of the fingerprint, which should be a 40
// character hex string.
// `AB01 AB01 AB01 AB01 AB01  AB01 AB01 AB01 AB01 AB01`
// String() returns the fingerprint in the "human friendly" format, for example
// `AB01 AB01 AB01 AB01 AB01  AB01 AB01 AB01 AB01 AB01`

func (f Fingerprint) String() string {
	f.assertIsSet()
	b := f.fingerprintBytes

	return fmt.Sprintf(
		"%0X %0X %0X %0X %0X  %0X %0X %0X %0X %0X",
		b[0:2], b[2:4], b[4:6], b[6:8], b[8:10],
		b[10:12], b[12:14], b[14:16], b[16:18], b[18:20],
	)
}

// Return the fingerprint as uppercase hex (20 bytes, 40 characters) without
// spaces, for example:
// `AB01AB01AB01AB01AB01AB01AB01AB01AB01AB01`

func (f Fingerprint) Hex() string {
	f.assertIsSet()
	b := f.fingerprintBytes

	return fmt.Sprintf("%0X", b)
}

func (f Fingerprint) Bytes() [20]byte {
	f.assertIsSet()
	return f.fingerprintBytes
}

func (f Fingerprint) IsSet() bool {
	return f.isSet

}

func (f Fingerprint) assertIsSet() {
	if !f.IsSet() {
		panic(fmt.Errorf("Fingerprint.String() called when fingerprint hasn't been set."))
	}
}
