package status

import (
	"fmt"
)

type WarningType int

const (
	PrimaryKeyDueForRotation     WarningType = 1
	PrimaryKeyOverdueForRotation WarningType = 2
	PrimaryKeyExpired            WarningType = 3
	PrimaryKeyNoExpiry           WarningType = 4
	PrimaryKeyLongExpiry         WarningType = 5

	NoValidEncryptionSubkey  WarningType = 6
	SubkeyDueForRotation     WarningType = 7
	SubkeyOverdueForRotation WarningType = 8
	SubkeyNoExpiry           WarningType = 9
	SubkeyLongExpiry         WarningType = 10
)

type KeyWarning struct {
	Type WarningType

	SubkeyId        uint64
	DaysUntilExpiry uint
	DaysSinceExpiry uint
}

func (w KeyWarning) String() string {
	switch w.Type {
	case PrimaryKeyDueForRotation:
		return "PrimaryKeyDueForRotation"

	case PrimaryKeyOverdueForRotation:
		return "PrimaryKeyOverdueForRotation"

	case PrimaryKeyExpired:
		return "PrimaryKeyExpired"

	case PrimaryKeyNoExpiry:
		return "PrimaryKeyNoExpiry"

	case PrimaryKeyLongExpiry:
		return "PrimaryKeyLongExpiry"

	case NoValidEncryptionSubkey:
		return "NoValidEncryptionSubkey"

	case SubkeyDueForRotation:
		return addSubkeyId("SubkeyDueForRotation", w.SubkeyId)

	case SubkeyOverdueForRotation:
		return addSubkeyId("SubkeyOverdueForRotation", w.SubkeyId)

	case SubkeyNoExpiry:
		return addSubkeyId("SubkeyNoExpiry", w.SubkeyId)

	case SubkeyLongExpiry:
		return addSubkeyId("SubkeyLongExpiry", w.SubkeyId)
	}

	return "KeyWarning[unknown]"
}

func addSubkeyId(warningName string, subkeyId uint64) string {
	return fmt.Sprintf("%s [0x%X]", warningName, subkeyId)
}
