package pgpkey

import (
	"github.com/fluidkeys/crypto/openpgp"
	"time"
)

// CalculateExpiry takes a creationtime and a key lifetime in seconds (pointer)
// and returns a corresponding time.Time
//
// From https://tools.ietf.org/html/rfc4880#section-5.2.3.6
// "If this is not present or has a value of zero, the key never expires."
func CalculateExpiry(creationTime time.Time, lifetimeSecs *uint32) (bool, *time.Time) {
	//
	if lifetimeSecs == nil {
		return false, nil
	}

	if *lifetimeSecs == 0 {
		return false, nil
	}

	expiry := creationTime.Add(time.Duration(*lifetimeSecs) * time.Second).In(time.UTC)
	return true, &expiry
}

// SubkeyExpiry returns true and a time if the subkey has an expiry time set,
// or false if it has no expiry.
func SubkeyExpiry(subkey openpgp.Subkey) (bool, *time.Time) {
	return CalculateExpiry(
		subkey.PublicKey.CreationTime, // not to be confused with the time of the *signature*
		subkey.Sig.KeyLifetimeSecs,
	)
}
