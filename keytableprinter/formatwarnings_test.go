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
				colour.Yellow("Primary key due for rotation"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyDueForRotation},
			true,
			[]string{
				colour.Yellow(" └─ Encryption subkey due for rotation"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 5},
			false,
			[]string{
				colour.Red("Primary key overdue for rotation"),
				colour.Red("Expires in 5 days!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 1},
			false,
			[]string{
				colour.Red("Primary key overdue for rotation"),
				colour.Red("Expires tomorrow!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 0},
			false,
			[]string{
				colour.Red("Primary key overdue for rotation"),
				colour.Red("Expires today!"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyOverdueForRotation, DaysUntilExpiry: 5},
			true,
			[]string{
				colour.Red(" └─ Encryption subkey overdue for rotation"),
				colour.Red("    Expires in 5 days!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyNoExpiry},
			false,
			[]string{
				colour.Red("Primary key never expires"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyNoExpiry},
			true,
			[]string{
				colour.Red(" └─ Encryption subkey never expires"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyLongExpiry},
			false,
			[]string{
				colour.Yellow("Primary key set to expire too far in the future"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyLongExpiry},
			true,
			[]string{
				colour.Yellow(" └─ Encryption subkey set to expire too far in the future"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyLongExpiry},
			false,
			[]string{
				colour.Yellow("Encryption subkey set to expire too far in the future"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 0},
			false,
			[]string{
				colour.Grey("Expired today"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 1},
			false,
			[]string{
				colour.Grey("Expired yesterday"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 9},
			false,
			[]string{
				colour.Grey("Expired 9 days ago"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 10},
			false,
			[]string{
				colour.Grey("Expired"),
			},
		},
		{
			status.KeyWarning{Type: status.NoValidEncryptionSubkey},
			false,
			[]string{
				colour.Yellow("Missing encryption subkey"),
			},
		},
		{
			status.KeyWarning{Type: status.NoValidEncryptionSubkey},
			true,
			[]string{
				colour.Yellow("Missing encryption subkey"),
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

	want := []string{colour.Green("Good ✔")}
	got := keyWarningLines(*pgpKey, []status.KeyWarning{})

	assert.AssertEqualSliceOfStrings(t, want, got)
}
