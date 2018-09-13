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
