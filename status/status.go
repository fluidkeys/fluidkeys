package status

import (
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

type DueForRotation struct {
	KeyWarning
}

type OverdueForRotation struct {
	KeyWarning

	DaysUntilExpiry int
}

type Expired struct {
	KeyWarning

	DaysSinceExpiry uint // 0 means less than 24 hours ago, 1 means yesterday
}

type NoExpiry struct {
	KeyWarning
}

type LongExpiry struct {
	KeyWarning
}

type KeyWarning interface {
}

func GetKeyWarnings(pgpkey.PgpKey) ([]KeyWarning, error) {
	return []KeyWarning{
	}, nil
}
