package status

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/colour"
)

func TestContainsWarningsAboutPrimaryKey(t *testing.T) {
	var tests = []struct {
		warnings       []KeyWarning
		expectedOutput bool
	}{
		{
			[]KeyWarning{
				KeyWarning{Type: SubkeyOverdueForRotation},
				KeyWarning{Type: PrimaryKeyLongExpiry},
			},
			true,
		},
		{
			[]KeyWarning{
				KeyWarning{Type: SubkeyOverdueForRotation},
				KeyWarning{Type: SubkeyLongExpiry},
			},
			false,
		},
		{
			[]KeyWarning{
				KeyWarning{Type: NoValidEncryptionSubkey},
			},
			false,
		},
		{
			[]KeyWarning{},
			false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for warnings %v", test.warnings), func(t *testing.T) {
			gotOutput := ContainsWarningAboutPrimaryKey(test.warnings)

			if gotOutput != test.expectedOutput {
				t.Fatalf("expected %v, got %v", test.expectedOutput, gotOutput)
			}
		})
	}

}

// TestString tests only the strings with arguments
func TestString(t *testing.T) {
	var tests = []struct {
		warning        KeyWarning
		expectedOutput string
	}{
		{
			KeyWarning{Type: PrimaryKeyOverdueForRotation, DaysUntilExpiry: 5},
			colour.Danger("Primary key overdue for rotation, expires in 5 days"),
		},
		{
			KeyWarning{Type: PrimaryKeyOverdueForRotation, DaysUntilExpiry: 1},
			colour.Danger("Primary key overdue for rotation, expires tomorrow!"),
		},
		{
			KeyWarning{Type: PrimaryKeyOverdueForRotation, DaysUntilExpiry: 0},
			colour.Danger("Primary key overdue for rotation, expires today!"),
		},
		{
			KeyWarning{Type: SubkeyOverdueForRotation, DaysUntilExpiry: 5},
			colour.Danger("Encryption subkey overdue for rotation, expires in 5 days"),
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
			KeyWarning{Type: WeakPreferredSymmetricAlgorithms, Detail: "some algo"},
			"Primary key has weak preferred symmetric algorithms (some algo)",
		},
		{
			KeyWarning{Type: UnsupportedPreferredSymmetricAlgorithm, Detail: "some algo"},
			"Primary key has unsupported preferred symmetric algorithm (some algo)",
		},
		{
			KeyWarning{Type: WeakPreferredHashAlgorithms, Detail: "some algo"},
			"Primary key has weak preferred hash algorithms (some algo)",
		},
		{
			KeyWarning{Type: UnsupportedPreferredHashAlgorithm, Detail: "some algo"},
			"Primary key has unsupported preferred hash algorithm (some algo)",
		},
		{
			KeyWarning{Type: UnsupportedPreferredCompressionAlgorithm, Detail: "some algo"},
			"Primary key has unsupported preferred compression algorithm (some algo)",
		},
		{
			KeyWarning{Type: WeakSelfSignatureHash, Detail: "some algo"},
			"Primary key has weak self signature hash (some algo)",
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
