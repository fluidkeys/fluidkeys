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
		keyWarningLines = append(keyWarningLines, colour.Success("Good ✔"))
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
	case status.UnsetType:
		// TODO: log that we got an invalid KeyWarning as it shouldn't
		// ever happen.
		return []string{}

	case status.NoValidEncryptionSubkey:
		return []string{colour.Warning("Missing encryption subkey")}

	case status.PrimaryKeyDueForRotation:
		return []string{colour.Warning("Primary key due for rotation")}

	case status.SubkeyDueForRotation:
		return []string{colour.Warning(prefix + "Encryption subkey due for rotation")}

	case status.PrimaryKeyOverdueForRotation:
		warnings := []string{colour.Danger("Primary key overdue for rotation")}
		return append(warnings, colour.Danger(countdownUntilExpiry(warning.DaysUntilExpiry, 0)))

	case status.SubkeyOverdueForRotation:
		warnings := []string{colour.Danger(prefix + "Encryption subkey overdue for rotation")}
		return append(
			warnings,
			colour.Danger(countdownUntilExpiry(
				warning.DaysUntilExpiry,
				uint(len([]rune(prefix))),
			)),
		)

	case status.PrimaryKeyNoExpiry:
		return []string{colour.Danger("Primary key never expires")}

	case status.SubkeyNoExpiry:
		return []string{colour.Danger(prefix + "Encryption subkey never expires")}

	case status.PrimaryKeyLongExpiry:
		return []string{colour.Warning("Primary key set to expire too far in the future")}

	case status.SubkeyLongExpiry:
		// This message might be confusing if the primary key has a
		// reasonable expiry, but the subkey has a long one.
		return []string{colour.Warning(prefix + "Encryption subkey set to expire too far in the future")}

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
		return []string{message}

	default:
		// TODO: log that we're falling back to a default description
		// for the KeyWarning
		return []string{fmt.Sprintf("[%s]", warning.String())}
	}
}

func countdownUntilExpiry(days uint, indent uint) string {
	switch days {
	case 0:
		return "Expires today!"
	case 1:
		return "Expires tomorrow!"
	default:
		return fmt.Sprintf("%*sExpires in %d days!", indent, "", days)
	}
}
