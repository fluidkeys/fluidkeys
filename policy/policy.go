package policy

import (
	"time"
)

const (
	tenDays       time.Duration = time.Duration(time.Hour * 24 * 10)
	thirtyDays    time.Duration = time.Duration(time.Hour * 24 * 30)
	fortyFiveDays time.Duration = time.Duration(time.Hour * 24 * 45)
)

// NextExpiryTime returns the expiry time in UTC, according to the policy:
//     "30 days after the 1st of the next month"
// for example, if today is 15th September, nextExpiryTime would return
// 1st October + 30 days
func NextExpiryTime(now time.Time) time.Time {
	return firstOfNextMonth(now).Add(thirtyDays).In(time.UTC)
}

// NextRotation returns 30 days before the earliest expiry time on
// the key.
// If the key doesn't expire, it returns nil.
func NextRotation(expiry time.Time) time.Time {
	return expiry.Add(-thirtyDays)
}

// IsExpiryTooLong returns true if the expiry is too far in the future.
//
// It's important not to raise this warning for expiries that we've set
// ourselves.
// We use `NextExpiryTime` such that when we set an expiry date it's *exactly*
// on the cusp of being too long, and can only get shorter after that point.
func IsExpiryTooLong(expiry time.Time, now time.Time) bool {
	latestAcceptableExpiry := NextExpiryTime(now)
	return expiry.After(latestAcceptableExpiry)
}

// IsOverdueForRotation returns true if `now` is more than 10 days after
// nextRotation
func IsOverdueForRotation(nextRotation time.Time, now time.Time) bool {
	overdueTime := nextRotation.Add(tenDays)
	return overdueTime.Before(now)
}

// IsDueForRotation returns true if `now` is any time after the key's next
// rotation time
func IsDueForRotation(nextRotation time.Time, now time.Time) bool {
	return nextRotation.Before(now)
}

func firstOfNextMonth(today time.Time) time.Time {
	firstOfThisMonth := beginningOfMonth(today)
	return beginningOfMonth(firstOfThisMonth.Add(fortyFiveDays))
}

func beginningOfMonth(now time.Time) time.Time {
	y, m, _ := now.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, now.Location()).In(time.UTC)
}
