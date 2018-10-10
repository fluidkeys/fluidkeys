package keytableprinter

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/status"
)

func TestFormatKeyWarningLines(t *testing.T) {
	var tests = []struct {
		warning        status.KeyWarning
		indent         bool
		expectedOutput []string
	}{
		{
			status.KeyWarning{Type: status.PrimaryKeyDueForRotation},
			false,
			[]string{
				colour.Warning("Primary key due for rotation"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyDueForRotation},
			true,
			[]string{
				colour.Warning(" └─ Encryption subkey due for rotation"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 5},
			false,
			[]string{
				colour.Danger("Primary key overdue for rotation"),
				colour.Danger("Expires in 5 days!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 1},
			false,
			[]string{
				colour.Danger("Primary key overdue for rotation"),
				colour.Danger("Expires tomorrow!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 0},
			false,
			[]string{
				colour.Danger("Primary key overdue for rotation"),
				colour.Danger("Expires today!"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyOverdueForRotation, DaysUntilExpiry: 5},
			true,
			[]string{
				colour.Danger(" └─ Encryption subkey overdue for rotation"),
				colour.Danger("    Expires in 5 days!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyNoExpiry},
			false,
			[]string{
				colour.Danger("Primary key never expires"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyNoExpiry},
			true,
			[]string{
				colour.Danger(" └─ Encryption subkey never expires"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyLongExpiry},
			false,
			[]string{
				colour.Warning("Primary key set to expire too far in the future"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyLongExpiry},
			true,
			[]string{
				colour.Warning(" └─ Encryption subkey set to expire too far in the future"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyLongExpiry},
			false,
			[]string{
				colour.Warning("Encryption subkey set to expire too far in the future"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 0},
			false,
			[]string{
				"Expired today",
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 1},
			false,
			[]string{
				"Expired yesterday",
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 9},
			false,
			[]string{
				"Expired 9 days ago",
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 10},
			false,
			[]string{
				"Expired",
			},
		},
		{
			status.KeyWarning{Type: status.NoValidEncryptionSubkey},
			false,
			[]string{
				colour.Warning("Missing encryption subkey"),
			},
		},
		{
			status.KeyWarning{Type: status.NoValidEncryptionSubkey},
			true,
			[]string{
				colour.Warning("Missing encryption subkey"),
			},
		},
		{
			status.KeyWarning{}, // unspecified type
			false,
			[]string{},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for status %v", test.warning), func(t *testing.T) {
			gotOutput := formatKeyWarningLines(test.warning, test.indent)

			assert.AssertEqualSliceOfStrings(t, test.expectedOutput, gotOutput)
		})
	}
}

func TestKeyWarningLines(t *testing.T) {

	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
	if err != nil {
		t.Fatalf("failed to load example PgpKey: %v", err)
	}

	want := []string{colour.Success("Good ✔")}
	got := keyWarningLines(*pgpKey, []status.KeyWarning{})

	assert.AssertEqualSliceOfStrings(t, want, got)
}
