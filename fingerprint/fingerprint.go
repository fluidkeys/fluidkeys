// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package fingerprint

import (
	"encoding/hex"
	"fmt"
	"log"
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

	if withoutSpaces == "" {
		return nilFingerprint, fmt.Errorf("invalid fingerprint: empty")
	}

	expectedPattern := `^(0x)?[A-Fa-f0-9]{40}$`
	if matched, err := regexp.MatchString(expectedPattern, withoutSpaces); !matched || err != nil {
		return nilFingerprint, fmt.Errorf("invalid v4 fingerprint: not 40 hex characters")
	}

	withoutLeading0x := strings.TrimPrefix(withoutSpaces, "0x")

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
// string is not a valid fingerprint (e.g. 40 hex characters) it will log.Panic.
func MustParse(fp string) Fingerprint {
	result, err := Parse(fp)
	if err != nil {
		log.Panic(err)
	}
	return result
}

// UnmarshalText implements encoding.TextUnmarshaler which can parse (unmarshal) a textual
// version of itself. It allows JSON / toml etc decoders to create a Fingerprint from a string.
func (f *Fingerprint) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}

	*f = parsed
	return nil
}

// MarshalText implements encoding.TextUnmarshaler, converting a Fingerprint into bytes for
// encoders like JSON, TOML etc.
func (f Fingerprint) MarshalText() ([]byte, error) {
	return []byte(f.Hex()), nil
}

// FromBytes takes 20 bytes and returns a Fingerprint.
func FromBytes(bytes [20]byte) Fingerprint {
	return Fingerprint{
		fingerprintBytes: bytes,
		isSet:            true,
	}
}

// Contains returns true if the given needle (Fingerprint) is present in the
// given haystack, or false if not.
func Contains(haystack []Fingerprint, needle Fingerprint) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

// String return a human-friendly version of the fingerprint, which should be a 40
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

// Hex return the fingerprint as uppercase hex (20 bytes, 40 characters) without
// spaces, for example:
// `AB01AB01AB01AB01AB01AB01AB01AB01AB01AB01`
func (f Fingerprint) Hex() string {
	f.assertIsSet()
	b := f.fingerprintBytes

	return fmt.Sprintf("%0X", b)
}

// Uri returns the uppercase hex fingerprint prepended with `OPENPGP4FPR:`,
// as implemented by OpenKeychain:
// https://github.com/open-keychain/open-keychain/issues/1281#issuecomment-103580789
// for example:
// `OPENPGP4FPR:AB01AB01AB01AB01AB01AB01AB01AB01AB01AB01`
func (f Fingerprint) Uri() string {
	return fmt.Sprintf("OPENPGP4FPR:%s", f.Hex())
}

func (f Fingerprint) Bytes() [20]byte {
	f.assertIsSet()
	return f.fingerprintBytes
}

// IsSet returns whether the fingerprint has been parsed correctly, and therefore is set
func (f Fingerprint) IsSet() bool {
	return f.isSet
}

func (f Fingerprint) assertIsSet() {
	if !f.IsSet() {
		log.Panic("Fingerprint.String() called when fingerprint hasn't been set.")
	}
}
