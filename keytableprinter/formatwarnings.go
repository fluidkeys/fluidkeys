package keytableprinter

import (
	"fmt"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/status"
)

func keyWarningLines(key pgpkey.PgpKey, keyWarnings []status.KeyWarning) []string {
	keyWarningLines := []string{}
	if len(keyWarnings) > 0 {
		for _, keyWarning := range keyWarnings {
			keyWarningLines = append(keyWarningLines, formatKeyWarningLines(keyWarning)...)
		}
	} else {
		keyWarningLines = append(keyWarningLines, colour.Green("Good ✔"))
	}
	return keyWarningLines
}

// FormatKeyWarningLines takes a status.KeyWarning and returns an array of
// human friendly messages coloured appropriately for printing to the
// terminal.
func formatKeyWarningLines(warning status.KeyWarning) []string {
	switch warning.(type) {

	case status.DueForRotation:
		return []string{colour.Yellow("Due for rotation 🔄")}

	case status.OverdueForRotation:
		warnings := []string{
			colour.Red("Overdue for rotation ⏰"),
		}
		var additionalMessage string
		switch days := warning.(status.OverdueForRotation).DaysUntilExpiry; days {
		case 0:
			additionalMessage = "Expires today!"
		case 1:
			additionalMessage = "Expires tomorrow!"
		default:
			additionalMessage = fmt.Sprintf("Expires in %d days!", days)
		}
		return append(warnings, colour.Red(additionalMessage))

	case status.NoExpiry:
		return []string{colour.Red("No expiry date set 📅")}

	case status.LongExpiry:
		return []string{colour.Yellow("Expiry date too far off 📅")}

	case status.Expired:
		var message string
		switch days := warning.(status.Expired).DaysSinceExpiry; days {
		case 0:
			message = "Expired today ⚰️"
		case 1:
			message = "Expired yesterday ⚰️"
		case 2, 3, 4, 5, 6, 7, 8, 9:
			message = fmt.Sprintf("Expired %d days ago ⚰️", days)
		default:
			message = "Expired"
		}
		return []string{colour.Grey(message)}

	default:
		// TODO: log this but silently swallow the error
		return []string{}
	}
}
