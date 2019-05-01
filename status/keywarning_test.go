package status

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/colour"
)

// TestString tests only the strings with arguments
func TestString(t *testing.T) {
	var tests = []struct {
		warning        KeyWarning
		expectedOutput string
	}{
		{
			KeyWarning{Type: PrimaryKeyOverdueForRotation, DaysUntilExpiry: 5},
			colour.Danger("Primary key needs extending now (expires in 5 days)"),
		},
		{
			KeyWarning{Type: PrimaryKeyOverdueForRotation, DaysUntilExpiry: 1},
			colour.Danger("Primary key needs extending now (expires tomorrow!)"),
		},
		{
			KeyWarning{Type: PrimaryKeyOverdueForRotation, DaysUntilExpiry: 0},
			colour.Danger("Primary key needs extending now (expires today!)"),
		},
		{
			KeyWarning{Type: SubkeyOverdueForRotation, DaysUntilExpiry: 5},
			colour.Danger("Encryption subkey needs extending now (expires in 5 days)"),
		},
		{
			KeyWarning{Type: PrimaryKeyExpired, DaysSinceExpiry: 0},
			colour.Danger("Primary key expired today"),
		},
		{
			KeyWarning{Type: PrimaryKeyExpired, DaysSinceExpiry: 1},
			colour.Danger("Primary key expired yesterday"),
		},
		{
			KeyWarning{Type: PrimaryKeyExpired, DaysSinceExpiry: 9},
			colour.Danger("Primary key expired 9 days ago"),
		},
		{
			KeyWarning{Type: PrimaryKeyExpired, DaysSinceExpiry: 10},
			colour.Danger("Primary key has expired"),
		},
		{
			KeyWarning{Type: WeakPreferredSymmetricAlgorithms, Detail: "AES123, DES"},
			"Cipher preferences could be stronger (currently: AES123, DES)",
		},
		{
			KeyWarning{Type: UnsupportedPreferredSymmetricAlgorithm, Detail: "AES123"},
			"Fluidkeys doesn't support AES123 cipher",
		},
		{
			KeyWarning{Type: WeakPreferredHashAlgorithms, Detail: "SHA1, MD5"},
			"Hash preferences could be stronger (currently: SHA1, MD5)",
		},
		{
			KeyWarning{Type: UnsupportedPreferredHashAlgorithm, Detail: "SHA60"},
			"Fluidkeys doesn't support SHA60 hash",
		},
		{
			KeyWarning{Type: UnsupportedPreferredCompressionAlgorithm, Detail: "BZIP2"},
			"Fluidkeys doesn't support BZIP2 compression",
		},
		{
			KeyWarning{Type: WeakSelfSignatureHash, Detail: "SHA1"},
			"Weak hash SHA1 used for self signature",
		},
		{
			KeyWarning{Type: WeakSubkeyBindingSignatureHash, Detail: "SHA1"},
			"Weak hash SHA1 used for subkey binding signature",
		},
		{
			KeyWarning{Type: ConfigMaintainAutomaticallyNotSet},
			"Key not maintained automatically",
		},
		{
			KeyWarning{Type: ConfigPublishToAPINotSet},
			"Key not uploaded, unable to receive secrets",
		},
		{
			KeyWarning{Type: ConfigMaintainAutomaticallyButDontPublish},
			"Key maintained automatically but not uploaded, unable to receive secrets",
		},
		{
			KeyWarning{}, // unspecified type
			"",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for status %v", test.warning), func(t *testing.T) {
			gotOutput := test.warning.String()

			assert.Equal(t, test.expectedOutput, gotOutput)
		})
	}
}
