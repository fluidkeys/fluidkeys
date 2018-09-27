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
		expectedOutput []string
	}{
		{
			status.KeyWarning{Type: status.PrimaryKeyDueForRotation},
			[]string{
				colour.Yellow("Primary key due for rotation 🔄"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyDueForRotation},
			[]string{
				colour.Yellow(" └─ Subkey due for rotation 🔄"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 5},
			[]string{
				colour.Red("Primary key overdue for rotation ⏰"),
				colour.Red("Expires in 5 days!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 1},
			[]string{
				colour.Red("Primary key overdue for rotation ⏰"),
				colour.Red("Expires tomorrow!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyOverdueForRotation, DaysUntilExpiry: 0},
			[]string{
				colour.Red("Primary key overdue for rotation ⏰"),
				colour.Red("Expires today!"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyOverdueForRotation, DaysUntilExpiry: 5},
			[]string{
				colour.Red(" └─ Subkey overdue for rotation ⏰"),
				colour.Red("    Expires in 5 days!"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyNoExpiry},
			[]string{
				colour.Red("Primary key never expires 📅"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyNoExpiry},
			[]string{
				colour.Red(" └─ Subkey never expires 📅"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyLongExpiry},
			[]string{
				colour.Yellow("Primary key set to expire too far in the future 🔮"),
			},
		},
		{
			status.KeyWarning{Type: status.SubkeyLongExpiry},
			[]string{
				colour.Yellow(" └─ Subkey set to expire too far in the future 🔮"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 0},
			[]string{
				colour.Grey("Expired today ⚰️"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 1},
			[]string{
				colour.Grey("Expired yesterday ⚰️"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 9},
			[]string{
				colour.Grey("Expired 9 days ago ⚰️"),
			},
		},
		{
			status.KeyWarning{Type: status.PrimaryKeyExpired, DaysSinceExpiry: 10},
			[]string{
				colour.Grey("Expired"),
			},
		},
		{
			status.KeyWarning{Type: status.NoValidEncryptionSubkey},
			[]string{
				colour.Yellow("Missing encryption subkey"),
			},
		},
		{
			status.KeyWarning{}, // unspecified type
			[]string{},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for status %v", test.warning), func(t *testing.T) {
			gotOutput := formatKeyWarningLines(test.warning)

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
