package status

import (
	"fmt"
	"time"

	"github.com/fluidkeys/fluidkeys/policy"
)

// MakeActionsFromWarnings returns a list of actions that can be performed on
// the key to fix the warning.
// Call `KeyAction.Enact(key)` to actually carry out the action.
func MakeActionsFromWarnings(warnings []KeyWarning) []KeyAction {
	now := time.Now()

	var actions []KeyAction
	for _, warning := range warnings {
		actions = append(actions, makeActionsFromSingleWarning(warning, now)...)
	}
	return actions
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
			RevokeSubkey{SubkeyId: warning.SubkeyId},
		}

	case NoValidEncryptionSubkey:
		return []KeyAction{
			CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
		}
	}
	panic(fmt.Errorf("Unhandled KeyWarning.Type: %v", warning.Type))
}
