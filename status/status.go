package status

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/compression"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/hash"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/symmetric"
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

	for _, selfSignature := range getIdentitySelfSignatures(&key) {
		warnings = append(warnings, getSelfSignatureHashWarnings(selfSignature)...)
		warnings = append(warnings, getCipherPreferenceWarnings(selfSignature.PreferredSymmetric)...)
		warnings = append(warnings, getHashPreferenceWarnings(selfSignature.PreferredHash)...)
		warnings = append(warnings, getCompressionPreferenceWarnings(selfSignature.PreferredHash)...)
	}

	for _, bindingSignature := range getSubkeyBindingSignatures(&key) {
		warnings = append(warnings, getSelfSignatureHashWarnings(bindingSignature)...)
		// TODO: check preferences (tho if missing, it's acceptable)
	}

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

func getIdentitySelfSignatures(key *pgpkey.PgpKey) []*packet.Signature {
	var selfSigs []*packet.Signature
	for name, _ := range key.Identities {
		identity := key.Identities[name]
		selfSigs = append(selfSigs, identity.SelfSignature)
	}
	return selfSigs
}

func getSubkeyBindingSignatures(key *pgpkey.PgpKey) []*packet.Signature {
	var sigs []*packet.Signature
	for _, subkey := range key.Subkeys {
		sigs = append(sigs, subkey.Sig)
	}

	return sigs
}

func getCipherPreferenceWarnings(prefs []uint8) []KeyWarning {
	if len(prefs) == 0 {
		return []KeyWarning{KeyWarning{Type: MissingPreferredSymmetricAlgorithms}}
	}

	var warnings []KeyWarning

	for _, cipherByte := range prefs {
		if !contains(policy.SupportedSymmetricKeyAlgorithms, cipherByte) {
			warning := KeyWarning{
				Type:   UnsupportedPreferredSymmetricAlgorithm,
				Detail: symmetric.Name(cipherByte),
			}
			warnings = append(warnings, warning)
		}
	}

	var preferencesAreAcceptable = false

	for _, acceptableCombination := range policy.AcceptablePreferredSymmetricAlgorithms {
		if equal(prefs, acceptableCombination) {
			preferencesAreAcceptable = true
		}
	}

	if !preferencesAreAcceptable {
		warnings = append(warnings, KeyWarning{
			Type:   WeakPreferredSymmetricAlgorithms,
			Detail: joinCipherNames(prefs),
		})
	}

	return warnings
}

func getHashPreferenceWarnings(prefs []uint8) []KeyWarning {
	if len(prefs) == 0 {
		return []KeyWarning{
			KeyWarning{Type: MissingPreferredHashAlgorithms},
		}
	}

	var warnings []KeyWarning

	for _, hashByte := range prefs {
		if !contains(policy.SupportedHashAlgorithms, hashByte) {
			warning := KeyWarning{
				Type:   UnsupportedPreferredHashAlgorithm,
				Detail: hash.Name(hashByte),
			}
			warnings = append(warnings, warning)
		}
	}

	var preferencesAreAcceptable = false

	for _, acceptableCombination := range policy.AcceptablePreferredHashAlgorithms {
		if equal(prefs, acceptableCombination) {
			preferencesAreAcceptable = true
		}
	}

	if !preferencesAreAcceptable {
		warnings = append(warnings, KeyWarning{
			Type:   WeakPreferredHashAlgorithms,
			Detail: joinHashNames(prefs),
		})
	}

	return warnings
}

func joinHashNames(hashes []uint8) string {
	var hashNames []string
	for _, hashByte := range hashes {
		hashNames = append(hashNames, hash.Name(hashByte))
	}
	return strings.Join(hashNames, " ")
}

func joinCipherNames(cipheres []uint8) string {
	var cipherNames []string
	for _, cipherByte := range cipheres {
		cipherNames = append(cipherNames, symmetric.Name(cipherByte))
	}
	return strings.Join(cipherNames, " ")
}

func getCompressionPreferenceWarnings(prefs []uint8) []KeyWarning {
	if len(prefs) == 0 {
		return []KeyWarning{
			KeyWarning{Type: MissingPreferredCompressionAlgorithms},
		}
	}

	warnings := []KeyWarning{}

	if !contains(prefs, compression.Uncompressed) {
		warnings = append(warnings, KeyWarning{Type: MissingUncompressedPreference})
	}

	if contains(prefs, compression.BZIP2) {
		warnings = append(warnings, KeyWarning{Type: UnsupportedPreferredCompressionAlgorithm, Detail: "BZIP2"})
	}

	return warnings

}
func getSelfSignatureHashWarnings(signature *packet.Signature) []KeyWarning {
	if !acceptableSignatureHash(&signature.Hash) {
		return []KeyWarning{
			KeyWarning{
				Type:   WeakSelfSignatureHash,
				Detail: nameOfHash(signature.Hash),
			},
		}
	} else {
		return []KeyWarning{}
	}
}

func getSubkeyBindingSignatureHashWarnings(signature *packet.Signature) []KeyWarning {
	if !acceptableSignatureHash(&signature.Hash) {
		return []KeyWarning{
			KeyWarning{
				Type:   WeakSubkeyBindingSignatureHash,
				Detail: nameOfHash(signature.Hash),
			},
		}
	} else {
		return []KeyWarning{}
	}
}

func acceptableSignatureHash(hash *crypto.Hash) bool {
	hasAcceptableHash := false
	for _, acceptableHash := range policy.AcceptableSignatureHashes {
		if *hash == acceptableHash {
			hasAcceptableHash = true
		}
	}

	return hasAcceptableHash
}

func contains(haystack []uint8, needle uint8) bool {
	for _, thing := range haystack {
		if thing == needle {
			return true
		}
	}
	return false
}

func equal(left []uint8, right []uint8) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
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

// nameOfHash returns the OpenPGP name for the given hash, or the empty string
// if the name isn't known. See RFC 4880, section 9.4.
func nameOfHash(h crypto.Hash) string {
	switch h {
	case crypto.MD5:
		return "MD5"
	case crypto.SHA1:
		return "SHA1"
	case crypto.RIPEMD160:
		return "RIPEMD160"
	case crypto.SHA224:
		return "SHA224"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	}
	return ""
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
