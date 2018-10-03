package status

import (
	"fmt"
	"time"

	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/policy"
)

// GetKeyWarnings returns a slice of KeyWarnings indicating problems found
// with the given PgpKey.
func GetKeyWarnings(key pgpkey.PgpKey) []KeyWarning {
	var warnings []KeyWarning
	now := time.Now()

	warnings = append(warnings, getPrimaryKeyWarnings(key, now)...)
	warnings = append(warnings, getEncryptionSubkeyWarnings(key, now)...)
	return warnings
}

func getEncryptionSubkeyWarnings(key pgpkey.PgpKey, now time.Time) []KeyWarning {
	encryptionSubkey := key.EncryptionSubkey(now)

	if encryptionSubkey == nil {
		return []KeyWarning{KeyWarning{Type: NoValidEncryptionSubkey}}
	}

	subkeyId := encryptionSubkey.PublicKey.KeyId

	var warnings []KeyWarning

	hasExpiry, expiry := pgpkey.SubkeyExpiry(*encryptionSubkey)

	if hasExpiry {
		nextRotation := policy.NextRotation(*expiry)

		if isExpired(*expiry, now) {
			warning := KeyWarning{
				Type:              NoValidEncryptionSubkey,
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)

		} else if policy.IsOverdueForRotation(nextRotation, now) {
			warning := KeyWarning{
				Type:              SubkeyOverdueForRotation,
				SubkeyId:          subkeyId,
				DaysUntilExpiry:   getDaysUntilExpiry(*expiry, now),
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)

		} else if policy.IsDueForRotation(nextRotation, now) {
			warning := KeyWarning{
				Type:              SubkeyDueForRotation,
				SubkeyId:          subkeyId,
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)
		}

		if policy.IsExpiryTooLong(*expiry, now) {
			warning := KeyWarning{
				Type:              SubkeyLongExpiry,
				SubkeyId:          subkeyId,
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)
		}
	} else { // no expiry
		warning := KeyWarning{
			Type:     SubkeyNoExpiry,
			SubkeyId: subkeyId,
		}
		warnings = append(warnings, warning)
	}

	return warnings
}

func getPrimaryKeyWarnings(key pgpkey.PgpKey, now time.Time) []KeyWarning {
	var warnings []KeyWarning

	hasExpiry, expiry := getEarliestUidExpiry(key)

	if hasExpiry {
		nextRotation := policy.NextRotation(*expiry)

		if isExpired(*expiry, now) {
			warning := KeyWarning{
				Type:              PrimaryKeyExpired,
				DaysSinceExpiry:   getDaysSinceExpiry(*expiry, now),
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)

		} else if policy.IsOverdueForRotation(nextRotation, now) {
			warning := KeyWarning{
				Type:              PrimaryKeyOverdueForRotation,
				DaysUntilExpiry:   getDaysUntilExpiry(*expiry, now),
				CurrentValidUntil: expiry,
			}

			warnings = append(warnings, warning)

		} else if policy.IsDueForRotation(nextRotation, now) {
			warning := KeyWarning{
				Type:              PrimaryKeyDueForRotation,
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)
		}

		if policy.IsExpiryTooLong(*expiry, now) {
			warning := KeyWarning{
				Type:              PrimaryKeyLongExpiry,
				CurrentValidUntil: expiry,
			}
			warnings = append(warnings, warning)
		}
	} else { // no expiry
		warning := KeyWarning{Type: PrimaryKeyNoExpiry}
		warnings = append(warnings, warning)
	}

	return warnings
}

func isExpired(expiry time.Time, now time.Time) bool {
	return expiry.Before(now)
}

// getDaysSinceExpiry returns the number of whole 24-hour periods until the
// `expiry`
func getDaysUntilExpiry(expiry time.Time, now time.Time) uint {
	days := inDays(expiry.Sub(now))
	if days < 0 {
		panic(fmt.Errorf("getDaysUntilExpiry: expiry has already passed: %v", expiry))
	}
	return uint(days)
}

func inDays(duration time.Duration) int {
	return int(duration.Seconds() / 86400)
}

// getDaysSinceExpiry returns the number of whole 24-hour periods that have
// elapsed since `expiry`
func getDaysSinceExpiry(expiry time.Time, now time.Time) uint {
	days := inDays(now.Sub(expiry))
	if days < 0 {
		panic(fmt.Errorf("getDaysSinceExpiry: expiry is in the future: %v", expiry))
	}
	return uint(days)
}

// getEarliestUidExpiry is roughly equivalent to "the expiry of the primary key"
//
// returns (hasExpiry, expiryTime) where hasExpiry is a bool indicating if
// an expiry is actually set
//
// Each User ID is signed with an expiry. When the last one is expired, the
// primary key is treated as expired (even though it's just the UIDs).
//
// If there are multiple UIDs we choose the earliest expiry, since that'll
// disrupt the working of the key (plus, Keyflow advises not to use multiple
// UIDs at all, let alone different expiry dates, so this is an edge-case)
func getEarliestUidExpiry(key pgpkey.PgpKey) (bool, *time.Time) {
	var allExpiryTimes []time.Time

	for _, id := range key.Identities {
		hasExpiry, expiryTime := pgpkey.CalculateExpiry(
			key.PrimaryKey.CreationTime, // not to be confused with the time of the *signature*
			id.SelfSignature.KeyLifetimeSecs,
		)
		if hasExpiry {
			allExpiryTimes = append(allExpiryTimes, *expiryTime)
		}
	}

	if len(allExpiryTimes) > 0 {
		earliestExpiry := earliest(allExpiryTimes)
		return true, &earliestExpiry
	} else {
		return false, nil
	}
}

// getEarliestExpiryTime returns the soonest expiry time from the key that
// would cause it to lose functionality.
//
// There are 3 types of self-signatures: (https://tools.ietf.org/html/rfc4880#section-5.2.3.3)
//
// 1. certification self-signatures (0x10, 0x11, 0x12, 0x13)
//    * user ID 1 + preferences
//    * user ID 2 + preferences
//
// 2. subkey binding signatures (0x18)
//    * subkey
//
// 3. direct key signatures (0x1F)
//
// * the primary key
// * all subkeys "subkey binding signatures"
// * self signatures / UIDs (?)
//
// There are also *signature expiration times* - the validity period of the
// signature. https://tools.ietf.org/html/rfc4880#section-5.2.3.10
// this is in Signature.SigLifetimeSecs

func getEarliestExpiryTime(key pgpkey.PgpKey) (bool, *time.Time) {
	var allExpiryTimes []time.Time

	for _, id := range key.Identities {
		hasExpiry, expiryTime := pgpkey.CalculateExpiry(
			key.PrimaryKey.CreationTime, // not to be confused with the time of the *signature*
			id.SelfSignature.KeyLifetimeSecs,
		)
		if hasExpiry {
			allExpiryTimes = append(allExpiryTimes, *expiryTime)
		}
	}

	for _, subkey := range key.Subkeys {
		hasExpiry, expiryTime := pgpkey.SubkeyExpiry(subkey)
		if hasExpiry {
			allExpiryTimes = append(allExpiryTimes, *expiryTime)
		}
	}

	if len(allExpiryTimes) > 0 {
		earliestExpiry := earliest(allExpiryTimes)
		return true, &earliestExpiry
	} else {
		return false, nil
	}
}

func earliest(times []time.Time) time.Time {
	if len(times) == 0 {
		panic(fmt.Errorf("earliest called with empty slice"))
	}

	set := false
	var earliestSoFar time.Time

	for _, t := range times {
		if !set || t.Before(earliestSoFar) {
			earliestSoFar = t
			set = true
		}
	}
	return earliestSoFar
}
