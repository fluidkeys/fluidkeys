package status

import (
	"fmt"
	"sort"
	"time"

	"github.com/fluidkeys/fluidkeys/policy"
)

// MakeActionsFromWarnings returns a list of actions that can be performed on
// the key to fix the warning.
// Call `KeyAction.Enact(key)` to actually carry out the action.
func MakeActionsFromWarnings(warnings []KeyWarning, now time.Time) []KeyAction {
	var actions []KeyAction
	for _, warning := range warnings {
		actions = append(actions, makeActionsFromSingleWarning(warning, now)...)
	}
	return deduplicateAndOrder(actions)
}

func deduplicateAndOrder(actions []KeyAction) []KeyAction {
	actionsSeen := make(map[string]bool)
	var deduped []KeyAction

	for _, action := range actions {
		actionAsString := getUniqueStringForAction(action)

		if _, inMap := actionsSeen[actionAsString]; !inMap {
			deduped = append(deduped, action)
			actionsSeen[actionAsString] = true
		}
	}
	sort.Sort(ByActionType(deduped))
	return deduped
}

// getUniqueStringForAction returns a string that can be used to disambiguate
// between two actions, for example:
// "SetPreferredCompressionAlgorithms{NewPreferences: []uint8{0x01}}"
func getUniqueStringForAction(action KeyAction) string {
	return fmt.Sprintf("%#v", action)
}

func makeActionsFromSingleWarning(warning KeyWarning, now time.Time) []KeyAction {
	nextExpiry := policy.NextExpiryTime(now)

	switch warning.Type {
	case PrimaryKeyDueForRotation, PrimaryKeyOverdueForRotation, PrimaryKeyNoExpiry, PrimaryKeyLongExpiry, PrimaryKeyExpired:

		return []KeyAction{
			ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry, PreviouslyValidUntil: warning.CurrentValidUntil},
		}

	case SubkeyDueForRotation, SubkeyOverdueForRotation, SubkeyLongExpiry, SubkeyNoExpiry:
		return []KeyAction{
			CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
			ExpireSubkey{SubkeyId: warning.SubkeyId},
		}

	case NoValidEncryptionSubkey:
		return []KeyAction{
			CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
		}

	case MissingPreferredSymmetricAlgorithms,
		WeakPreferredSymmetricAlgorithms,
		UnsupportedPreferredSymmetricAlgorithm:

		return []KeyAction{
			SetPreferredSymmetricAlgorithms{NewPreferences: policy.AdvertiseCipherPreferences},
		}

	case MissingPreferredHashAlgorithms,
		WeakPreferredHashAlgorithms,
		UnsupportedPreferredHashAlgorithm:

		return []KeyAction{
			SetPreferredHashAlgorithms{NewPreferences: policy.AdvertiseHashPreferences},
		}

	case MissingPreferredCompressionAlgorithms,
		UnsupportedPreferredCompressionAlgorithm,
		MissingUncompressedPreference:

		return []KeyAction{
			SetPreferredCompressionAlgorithms{NewPreferences: policy.AdvertiseCompressionPreferences},
		}

	case WeakSelfSignatureHash:
		return []KeyAction{
			RefreshUserIdSelfSignatures{},
		}

	case WeakSubkeyBindingSignatureHash:
		return []KeyAction{
			RefreshSubkeyBindingSignature{
				SubkeyId: warning.SubkeyId,
			},
		}

	default: // don't know how to remedy this KeyWarning
		// TODO: log that we don't know how to remedy this type of
		// KeyWarning
		return []KeyAction{}
	}
}
