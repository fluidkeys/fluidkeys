package status

import (
	"fmt"
	"testing"
	"time"
)

func TestMakeActionsForSingleWarning(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	nextExpiry := nextExpiryTime(now)

	var tests = []struct {
		warningType     WarningType
		subkeyId        uint64
		expectedActions []KeyAction
	}{
		{
			PrimaryKeyDueForRotation,
			0,
			[]KeyAction{
				ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry},
			},
		},
		{
			PrimaryKeyDueForRotation,
			0,
			[]KeyAction{
				ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry},
			},
		},
		{
			PrimaryKeyOverdueForRotation,
			0,
			[]KeyAction{
				ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry},
			},
		},
		{
			PrimaryKeyExpired,
			0,
			[]KeyAction{
				ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry},
			},
		},
		{
			PrimaryKeyNoExpiry,
			0,
			[]KeyAction{
				ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry},
			},
		},
		{
			PrimaryKeyLongExpiry,
			0,
			[]KeyAction{
				ModifyPrimaryKeyExpiry{ValidUntil: nextExpiry},
			},
		},
		{
			NoValidEncryptionSubkey,
			0,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
			},
		},
		{
			SubkeyDueForRotation,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				RevokeSubkey{SubkeyId: 9999},
			},
		},
		{
			SubkeyOverdueForRotation,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				RevokeSubkey{SubkeyId: 9999},
			},
		},
		{
			SubkeyNoExpiry,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				RevokeSubkey{SubkeyId: 9999},
			},
		},
		{
			SubkeyLongExpiry,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				RevokeSubkey{SubkeyId: 9999},
			},
		},
	}

	for _, test := range tests {
		warning := KeyWarning{
			Type:     test.warningType,
			SubkeyId: test.subkeyId,
		}

		t.Run(fmt.Sprintf("%s subkey=%v", warning, test.subkeyId), func(t *testing.T) {
			gotActions := makeActionsFromSingleWarning(warning, now)
			fmt.Sprintf("gotActions: %v\n", gotActions)
			assertActionsEqual(t, test.expectedActions, gotActions)
		})
	}
}

func assertActionsEqual(t *testing.T, expected []KeyAction, got []KeyAction) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected %d actions, got %d. expected: %v, got: %v", len(expected), len(got), expected, got)
	}

	for i := range expected {
		if expected[i] != got[i] {
			t.Fatalf("expected[%d] = %v, got[%d] = %v", i, expected[i], i, got[i])
		}

	}
}
