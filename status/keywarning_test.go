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

func TestString(t *testing.T) {
	var tests = []struct {
		warning        KeyWarning
		expectedOutput string
	}{
		{
			KeyWarning{Type: PrimaryKeyDueForRotation},
			"Primary key due for rotation",
		},
		{
			KeyWarning{Type: SubkeyDueForRotation},
			"Encryption subkey due for rotation",
		},
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
			KeyWarning{Type: PrimaryKeyNoExpiry},
			"Primary key never expires",
		},
		{
			KeyWarning{Type: SubkeyNoExpiry},
			"Encryption subkey never expires",
		},
		{
			KeyWarning{Type: PrimaryKeyLongExpiry},
			"Primary key set to expire too far in the future",
		},
		{
			KeyWarning{Type: SubkeyLongExpiry},
			"Encryption subkey set to expire too far in the future",
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
			KeyWarning{Type: NoValidEncryptionSubkey},
			colour.Danger("Missing encryption subkey"),
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
