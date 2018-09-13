package status

import (
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"time"
)

type DueForRotation struct {
	KeyWarning
}

type OverdueForRotation struct {
	KeyWarning

	DaysUntilExpiry uint // 0 means within 24 hours from now, 1 means tomorrow
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

const thirtyDays time.Duration = time.Duration(time.Hour * 24 * 30)
const fortyFiveDays time.Duration = time.Duration(time.Hour * 24 * 45)

func GetKeyWarnings(pgpkey.PgpKey) ([]KeyWarning, error) {
	return []KeyWarning{}, nil
}

// nextExpiryDate returns the expiry time in UTC, according to the policy:
//     "30 days after the 1st of the next month"
// for example, if today is 15th September, nextExpiryDate would return
// 1st October + 30 days
func nextExpiryTime(today time.Time) time.Time {
	return firstOfNextMonth(today).Add(thirtyDays).In(time.UTC)
}

func firstOfNextMonth(today time.Time) time.Time {
	firstOfThisMonth := beginningOfMonth(today)
	return beginningOfMonth(firstOfThisMonth.Add(fortyFiveDays))
}

func beginningOfMonth(now time.Time) time.Time {
	y, m, _ := now.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, now.Location()).In(time.UTC)
}
