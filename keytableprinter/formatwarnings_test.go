package keytableprinter

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/status"
)

func TestFormatKeyWarningLines(t *testing.T) {
	var tests = []struct {
		warning        status.KeyWarning
		expectedOutput []string
	}{
		{
			status.DueForRotation{},
			[]string{
				colour.Yellow("Due for rotation 🔄"),
			},
		},
		{
			status.OverdueForRotation{DaysUntilExpiry: 5},
			[]string{
				colour.Red("Overdue for rotation ⏰"),
				colour.Red("Expires in 5 days!"),
			},
		},
		{
			status.OverdueForRotation{DaysUntilExpiry: 1},
			[]string{
				colour.Red("Overdue for rotation ⏰"),
				colour.Red("Expires tomorrow!"),
			},
		},
		{
			status.OverdueForRotation{DaysUntilExpiry: 0},
			[]string{
				colour.Red("Overdue for rotation ⏰"),
				colour.Red("Expires today!"),
			},
		},
		{
			status.NoExpiry{},
			[]string{
				colour.Red("No expiry date set 📅"),
			},
		},
		{
			status.LongExpiry{},
			[]string{
				colour.Yellow("Expiry date too far off 📅"),
			},
		},
		{
			status.Expired{DaysSinceExpiry: 0},
			[]string{
				colour.Grey("Expired today ⚰️"),
			},
		},
		{
			status.Expired{DaysSinceExpiry: 1},
			[]string{
				colour.Grey("Expired yesterday ⚰️"),
			},
		},
		{
			status.Expired{DaysSinceExpiry: 9},
			[]string{
				colour.Grey("Expired 9 days ago ⚰️"),
			},
		},
		{
			status.Expired{DaysSinceExpiry: 10},
			[]string{
				colour.Grey("Expired"),
			},
		},
		{
			nil,
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
