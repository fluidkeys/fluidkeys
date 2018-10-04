package status

import (
	"fmt"
	"time"
)

type WarningType int

const (
	// If you add a type, remember to handle it in all the switch statements.
	PrimaryKeyDueForRotation     WarningType = 1
	PrimaryKeyOverdueForRotation             = 2
	PrimaryKeyExpired                        = 3
	PrimaryKeyNoExpiry                       = 4
	PrimaryKeyLongExpiry                     = 5

	NoValidEncryptionSubkey  = 6
	SubkeyDueForRotation     = 7
	SubkeyOverdueForRotation = 8
	SubkeyNoExpiry           = 9
	SubkeyLongExpiry         = 10

	MissingPreferredSymmetricAlgorithms    = 11
	WeakPreferredSymmetricAlgorithms       = 12
	UnsupportedPreferredSymmetricAlgorithm = 13

	MissingPreferredHashAlgorithms    = 14
	WeakPreferredHashAlgorithms       = 15
	UnsupportedPreferredHashAlgorithm = 16

	MissingPreferredCompressionAlgorithms    = 17
	UnsupportedPreferredCompressionAlgorithm = 18
	MissingUncompressedPreference            = 19 // Implementations MUST implement uncompressed data.

	WeakSelfSignatureHash          = 20
	WeakSubkeyBindingSignatureHash = 21
)

type KeyWarning struct {
	Type WarningType

	SubkeyId          uint64
	DaysUntilExpiry   uint
	DaysSinceExpiry   uint
	CurrentValidUntil *time.Time
	Detail            string
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

	case NoValidEncryptionSubkey:
		return "NoValidEncryptionSubkey"

	case SubkeyDueForRotation:
		return addSubkeyId("SubkeyDueForRotation", w.SubkeyId)

	case SubkeyOverdueForRotation:
		return addSubkeyId("SubkeyOverdueForRotation", w.SubkeyId)

	case SubkeyNoExpiry:
		return addSubkeyId("SubkeyNoExpiry", w.SubkeyId)

	case SubkeyLongExpiry:
		return addSubkeyId("SubkeyLongExpiry", w.SubkeyId)

	case MissingPreferredSymmetricAlgorithms:
		return "MissingPreferredSymmetricAlgorithms"

	case WeakPreferredSymmetricAlgorithms:
		return fmt.Sprintf("WeakPreferredSymmetricAlgorithms (%s)", w.Detail)

	case UnsupportedPreferredSymmetricAlgorithm:
		return fmt.Sprintf("UnsupportedPreferredSymmetricAlgorithm (%s)", w.Detail)

	case MissingPreferredHashAlgorithms:
		return "MissingPreferredHashAlgorithms"

	case WeakPreferredHashAlgorithms:
		return fmt.Sprintf("WeakPreferredHashAlgorithms (%s)", w.Detail)

	case UnsupportedPreferredHashAlgorithm:
		return fmt.Sprintf("UnsupportedPreferredHashAlgorithm (%s)", w.Detail)

	case MissingPreferredCompressionAlgorithms:
		return "MissingPreferredCompressionAlgorithms"

	case MissingUncompressedPreference:
		return "MissingUncompressedPreference"

	case UnsupportedPreferredCompressionAlgorithm:
		return fmt.Sprintf("UnsupportedPreferredCompressionAlgorithm (%s)", w.Detail)

	case WeakSelfSignatureHash:
		return fmt.Sprintf("WeakSelfSignatureHash (%s)", w.Detail)

	case WeakSubkeyBindingSignatureHash:
		return addSubkeyId("WeakSubkeyBindingSignatureHash", w.SubkeyId)
	}

	return "KeyWarning[unknown]"
}

func (w KeyWarning) IsAboutSubkey() bool {
	switch w.Type {
	case
		SubkeyDueForRotation,
		SubkeyOverdueForRotation,
		SubkeyNoExpiry,
		SubkeyLongExpiry,
		WeakSubkeyBindingSignatureHash:
		return true
	}
	return false
}

func (w KeyWarning) IsAboutPrimaryKey() bool {
	switch w.Type {
	case
		PrimaryKeyDueForRotation,
		PrimaryKeyOverdueForRotation,
		PrimaryKeyExpired,
		PrimaryKeyNoExpiry,
		PrimaryKeyLongExpiry,
		MissingPreferredSymmetricAlgorithms,
		WeakPreferredSymmetricAlgorithms,
		UnsupportedPreferredSymmetricAlgorithm,
		MissingPreferredHashAlgorithms,
		WeakPreferredHashAlgorithms,
		UnsupportedPreferredHashAlgorithm,
		MissingPreferredCompressionAlgorithms,
		UnsupportedPreferredCompressionAlgorithm,
		WeakSelfSignatureHash:
		return true
	}
	return false
}

func ContainsWarningAboutPrimaryKey(warnings []KeyWarning) bool {
	for _, warning := range warnings {
		if warning.IsAboutPrimaryKey() {
			return true
		}
	}
	return false
}

func addSubkeyId(warningName string, subkeyId uint64) string {
	return fmt.Sprintf("%s [0x%X]", warningName, subkeyId)
}
