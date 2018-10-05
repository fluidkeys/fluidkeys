package policy

import (
	"crypto"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/compression"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/hash"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/symmetric"
	"time"
)

var (
	// AdvertiseCipherPreferences is added to the self signature to tell
	// others which symmetric ciphers (in order) that we prefer to receive.
	//
	// When a client is choosing a cipher to use, it looks for the
	// strongest supported by *all* recipients, and it falls back to
	// TripleDES *even* if that's no-one's preferences.
	//
	// This is equivalent to this GnuPG config from Riseup's OpenPGP
	// best practice:
	//
	// > personal-cipher-preferences AES256 AES192 AES CAST5
	//
	// https://tools.ietf.org/html/rfc4880#section-9.2
	// https://help.riseup.net/en/security/message-security/openpgp/best-practices

	AdvertiseCipherPreferences = []uint8{
		symmetric.AES256,
		symmetric.AES192,
		symmetric.AES128,
		symmetric.CAST5,
		// TripleDES is *implicitly* supported but don't advertise
		// it explicity in the hope that future versions ofthe spec
		// deprecate it.
	}

	// AcceptablePreferredSymmetricAlgorithms defines what combinations of
	// symmetric key ciphers we consider OK (e.g. we don't warn about).
	// Note that order matters.
	AcceptablePreferredSymmetricAlgorithms = [][]uint8{
		[]uint8{symmetric.AES256, symmetric.AES192, symmetric.AES128, symmetric.CAST5},
		[]uint8{symmetric.AES256, symmetric.AES192, symmetric.AES128},
	}

	// SupportedSymmetricKeyAlgorithms defines what algorithms we can
	// technically decrypt (but doesn't mean they're encouraged.)
	SupportedSymmetricKeyAlgorithms = []uint8{
		symmetric.AES128,
		symmetric.AES192,
		symmetric.AES256,
		symmetric.CAST5,
		symmetric.TripleDES,
	}

	// AdvertiseCompressionPreferences is added to the self signature to tell others
	// which compression (in order) that we prefer to use. Note that Golang
	// doesn't support BZIP, so we don't specify that.
	//
	// Riseup's OpenPGP best practice settings specify:
	//
	// > default-preference-list [...] ZLIB BZIP2 ZIP Uncompressed
	//
	// https://tools.ietf.org/html/rfc4880#section-9.3
	AdvertiseCompressionPreferences = []uint8{
		compression.ZLIB,
		compression.ZIP,
		compression.Uncompressed,
		// No Bzip as Go doesn't support it.
	}

	// AdvertiseHashPreferences is added to the self signature to tell
	// others which hashes (in order) that we prefer to use.
	//
	// Note that clients implicity support SHA1 if no other digest is
	// available.
	//
	// Riseup's OpenPGP best practice settings specify:
	//
	// > personal-digest-preferences SHA512 SHA384 SHA256 SHA224
	//
	// https://tools.ietf.org/html/rfc4880#section-9.4
	AdvertiseHashPreferences = []uint8{
		hash.Sha512,
		hash.Sha384,
		hash.Sha256,
		hash.Sha224,
	}

	// AcceptablePreferredHashAlgorithms defines what combinations of
	// hash algorithms we consider OK (e.g. we don't warn about).
	// Note that order matters.
	AcceptablePreferredHashAlgorithms = [][]uint8{
		[]uint8{hash.Sha512, hash.Sha384, hash.Sha256, hash.Sha224},
		[]uint8{hash.Sha512, hash.Sha384, hash.Sha256, hash.Sha224, hash.Ripemd160},
	}

	// SupportedHashAlgorithms defines what hash algorithms we can
	// technically support (but doesn't mean they're encouraged.)
	SupportedHashAlgorithms = []uint8{
		hash.Md5,
		hash.Sha1,
		hash.Ripemd160,
		hash.Sha224,
		hash.Sha256,
		hash.Sha384,
		hash.Sha512,
	}

	// AcceptableSignatureHashes defines the hash functions we consider
	// acceptable for self signatures (on UIDs) and subkey binding
	// signatures.
	AcceptableSignatureHashes = []crypto.Hash{
		crypto.SHA512,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA224,
	}
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

const (
	tenDays       time.Duration = time.Duration(time.Hour * 24 * 10)
	thirtyDays    time.Duration = time.Duration(time.Hour * 24 * 30)
	fortyFiveDays time.Duration = time.Duration(time.Hour * 24 * 45)
)
