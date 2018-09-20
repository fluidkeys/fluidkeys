package status

type WarningType int

const (
	PrimaryKeyDueForRotation     WarningType = 1
	PrimaryKeyOverdueForRotation WarningType = 2
	PrimaryKeyExpired            WarningType = 3
	PrimaryKeyNoExpiry           WarningType = 4
	PrimaryKeyLongExpiry         WarningType = 5
)

type KeyWarning struct {
	Type WarningType

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

	return "KeyWarning[unknown]"
}
