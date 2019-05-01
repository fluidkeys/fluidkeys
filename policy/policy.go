// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

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
	// Note that the order of algorithms matters, e.g. {AES256, CAST5} is
	// different from {CAST5, AES256}
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
	// Note that the order of algorithms matters, e.g. {SHA256, RIPEMD160}
	// is different from {RIPEMD160, SHA256}
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

	// SignatureHashFunction is the hash algorithm used for generating
	// subkey binding signatures and self signatures.
	SignatureHashFunction = crypto.SHA512
)

const (
	// Use Mozilla infosec team's recommendation for long lived keys:
	// https://infosec.mozilla.org/guidelines/key_management#recommended---generally-valid-for-up-to-10-years-default
	PrimaryKeyRsaKeyBits = 4096

	// EncryptionSubkeyRsaKeyBits is the number of bits to use for an
	// encryption subkey. These are short-lived so don't need to be as
	// large as the primary key.
	EncryptionSubkeyRsaKeyBits = 2048

	// SecretMaxSizeBytes is the maximum allowable size of the plaintext of a secret
	// sent with `fk secret send ...`
	SecretMaxSizeBytes = 10 * 1024
)

// NextExpiryTime returns the expiry time in UTC, according to the policy:
//     "1 year from now, rounded forward to the 1st of the next Feb, May, Aug or Nov
// for example, if today is 15th September 2018, nextExpiryTime would return
// 1st November 2019
func NextExpiryTime(now time.Time) time.Time {
	oneYearFromNow := now.In(time.UTC).Add(oneYear)
	return followingQuarter(oneYearFromNow)
}

// NextRotation returns 60 days before the earliest expiry time on the key.
// If the key doesn't expire, it returns nil.
func NextRotation(expiry time.Time) time.Time {
	return expiry.Add(-sixtyDays)
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

func followingQuarter(from time.Time) time.Time {
	lookup := map[time.Month]int{
		time.January:   1,
		time.February:  3,
		time.March:     2,
		time.April:     1,
		time.May:       3,
		time.June:      2,
		time.July:      1,
		time.August:    3,
		time.September: 2,
		time.October:   1,
		time.November:  3,
		time.December:  2,
	}

	firstOfThisMonth := beginningOfMonth(from.In(time.UTC))
	monthsToAdvance, _ := lookup[firstOfThisMonth.Month()]
	daysToAdvance := (30 * monthsToAdvance) + 15

	return beginningOfMonth(
		firstOfThisMonth.Add(time.Duration(24*daysToAdvance) * time.Hour),
	)
}

func beginningOfMonth(now time.Time) time.Time {
	y, m, _ := now.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, now.Location()).In(time.UTC)
}

const (
	tenDays       time.Duration = time.Duration(time.Hour * 24 * 10)
	thirtyDays    time.Duration = time.Duration(time.Hour * 24 * 30)
	fortyFiveDays time.Duration = time.Duration(time.Hour * 24 * 45)
	sixtyDays     time.Duration = time.Duration(time.Hour * 24 * 60)
	oneYear       time.Duration = time.Duration(time.Hour * 24 * 365)
)
