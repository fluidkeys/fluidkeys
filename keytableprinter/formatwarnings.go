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
			keyWarningLines = append(
				keyWarningLines,
				formatKeyWarningLines(
					keyWarning,
					status.ContainsWarningAboutPrimaryKey(keyWarnings),
				)...,
			)
		}
	} else {
		keyWarningLines = append(keyWarningLines, colour.Green("Good ✔"))
	}
	return keyWarningLines
}

// FormatKeyWarningLines takes a status.KeyWarning and returns an array of
// human friendly messages coloured appropriately for printing to the
// terminal.
func formatKeyWarningLines(warning status.KeyWarning, indent bool) []string {
	var prefix string
	if indent && warning.IsAboutSubkey() {
		prefix = " └─ "
	}

	switch warning.Type {
	case status.NoValidEncryptionSubkey:
		return []string{colour.Yellow("Missing encryption subkey")}

	case status.PrimaryKeyDueForRotation:
		return []string{colour.Yellow("Primary key due for rotation")}

	case status.SubkeyDueForRotation:
		return []string{colour.Yellow(prefix + "Subkey due for rotation")}

	case status.PrimaryKeyOverdueForRotation:
		warnings := []string{colour.Red("Primary key overdue for rotation")}
		return append(warnings, colour.Red(countdownUntilExpiry(warning.DaysUntilExpiry, 0)))

	case status.SubkeyOverdueForRotation:
		warnings := []string{colour.Red(prefix + "Subkey overdue for rotation")}
		return append(warnings, colour.Red(countdownUntilExpiry(warning.DaysUntilExpiry, len([]rune(prefix)))))

	case status.PrimaryKeyNoExpiry:
		return []string{colour.Red("Primary key never expires")}

	case status.SubkeyNoExpiry:
		return []string{colour.Red(prefix + "Subkey never expires")}

	case status.PrimaryKeyLongExpiry:
		return []string{colour.Yellow("Primary key set to expire too far in the future")}

	case status.SubkeyLongExpiry:
		// This message might be confusing if the primary key has a
		// reasonable expiry, but the subkey has a long one.
		return []string{colour.Yellow(prefix + "Subkey set to expire too far in the future")}

	case status.PrimaryKeyExpired:
		var message string
		switch days := warning.DaysSinceExpiry; days {
		case 0:
			message = "Expired today"
		case 1:
			message = "Expired yesterday"
		case 2, 3, 4, 5, 6, 7, 8, 9:
			message = fmt.Sprintf("Expired %d days ago", days)
		default:
			message = "Expired"
		}
		return []string{colour.Grey(message)}

	default:
		// TODO: log this but silently swallow the error
		return []string{}
	}
}

func countdownUntilExpiry(days uint, indent int) string {
	switch days {
	case 0:
		return "Expires today!"
	case 1:
		return "Expires tomorrow!"
	default:
		return fmt.Sprintf("%*sExpires in %d days!", indent, "", days)
	}
}
