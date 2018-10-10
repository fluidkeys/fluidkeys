package status

import (
	"fmt"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/policy"
)

func TestMakeActionsFromSingleWarning(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	nextExpiry := policy.NextExpiryTime(now)

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
				ExpireSubkey{SubkeyId: 9999},
			},
		},
		{
			SubkeyOverdueForRotation,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				ExpireSubkey{SubkeyId: 9999},
			},
		},
		{
			SubkeyNoExpiry,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				ExpireSubkey{SubkeyId: 9999},
			},
		},
		{
			SubkeyLongExpiry,
			9999,
			[]KeyAction{
				CreateNewEncryptionSubkey{ValidUntil: nextExpiry},
				ExpireSubkey{SubkeyId: 9999},
			},
		},
		{
			MissingPreferredSymmetricAlgorithms,
			0,
			[]KeyAction{
				SetPreferredSymmetricAlgorithms{
					NewPreferences: policy.AdvertiseCipherPreferences,
				},
			},
		},
		{
			WeakPreferredSymmetricAlgorithms,
			0,
			[]KeyAction{
				SetPreferredSymmetricAlgorithms{
					NewPreferences: policy.AdvertiseCipherPreferences,
				},
			},
		},
		{
			UnsupportedPreferredSymmetricAlgorithm,
			0,
			[]KeyAction{
				SetPreferredSymmetricAlgorithms{
					NewPreferences: policy.AdvertiseCipherPreferences,
				},
			},
		},
		{
			MissingPreferredHashAlgorithms,
			0,
			[]KeyAction{
				SetPreferredHashAlgorithms{
					NewPreferences: policy.AdvertiseHashPreferences,
				},
			},
		},
		{
			WeakPreferredHashAlgorithms,
			0,
			[]KeyAction{
				SetPreferredHashAlgorithms{
					NewPreferences: policy.AdvertiseHashPreferences,
				},
			},
		},
		{
			UnsupportedPreferredHashAlgorithm,
			0,
			[]KeyAction{
				SetPreferredHashAlgorithms{
					NewPreferences: policy.AdvertiseHashPreferences,
				},
			},
		},

		{
			MissingPreferredCompressionAlgorithms,
			0,
			[]KeyAction{
				SetPreferredCompressionAlgorithms{
					NewPreferences: policy.AdvertiseCompressionPreferences,
				},
			},
		},
		{
			UnsupportedPreferredCompressionAlgorithm,
			0,
			[]KeyAction{
				SetPreferredCompressionAlgorithms{
					NewPreferences: policy.AdvertiseCompressionPreferences,
				},
			},
		},
		{
			MissingUncompressedPreference,
			0,
			[]KeyAction{
				SetPreferredCompressionAlgorithms{
					NewPreferences: policy.AdvertiseCompressionPreferences,
				},
			},
		},
		{
			WeakSelfSignatureHash,
			0,
			[]KeyAction{
				RefreshUserIdSelfSignatures{},
			},
		},
		{
			WeakSubkeyBindingSignatureHash,
			9999,
			[]KeyAction{
				RefreshSubkeyBindingSignature{
					SubkeyId: 9999,
				},
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

func TestDeduplicateAndOrder(t *testing.T) {

	t.Run("should de-duplicate identical actions", func(t *testing.T) {
		algos := policy.AdvertiseCompressionPreferences
		inputActions := []KeyAction{
			SetPreferredCompressionAlgorithms{NewPreferences: algos},
			SetPreferredCompressionAlgorithms{NewPreferences: algos},
		}

		expectedActions := []KeyAction{
			SetPreferredCompressionAlgorithms{NewPreferences: algos},
		}
		gotActions := deduplicateAndOrder(inputActions)
		assertActionsEqual(t, expectedActions, gotActions)
	})

	t.Run("order should be primary key actions > preferences > subkey actions", func(t *testing.T) {
		inputActions := []KeyAction{
			ExpireSubkey{SubkeyId: 9999},
			SetPreferredCompressionAlgorithms{},
			ModifyPrimaryKeyExpiry{},
		}

		expectedActions := []KeyAction{
			ModifyPrimaryKeyExpiry{},
			SetPreferredCompressionAlgorithms{},
			ExpireSubkey{SubkeyId: 9999},
		}
		gotActions := deduplicateAndOrder(inputActions)
		assertActionsEqual(t, expectedActions, gotActions)
	})

	t.Run("doesn't de-duplicate actions for different subkeys", func(t *testing.T) {
		inputActions := []KeyAction{
			ExpireSubkey{SubkeyId: 1234},
			ExpireSubkey{SubkeyId: 4567},
		}

		expectedActions := []KeyAction{
			ExpireSubkey{SubkeyId: 1234},
			ExpireSubkey{SubkeyId: 4567},
		}

		gotActions := deduplicateAndOrder(inputActions)
		assertActionsEqual(t, expectedActions, gotActions)

	})
}

func TestMakeActionsFromWarnings(t *testing.T) {
	warnings := []KeyWarning{
		KeyWarning{Type: MissingPreferredSymmetricAlgorithms},
		KeyWarning{Type: MissingPreferredCompressionAlgorithms},
		KeyWarning{Type: PrimaryKeyDueForRotation},
		KeyWarning{Type: PrimaryKeyOverdueForRotation},
		KeyWarning{Type: PrimaryKeyExpired},
		KeyWarning{Type: PrimaryKeyNoExpiry},
		KeyWarning{Type: PrimaryKeyLongExpiry},
		KeyWarning{Type: NoValidEncryptionSubkey},
		KeyWarning{Type: SubkeyDueForRotation, SubkeyId: 0x1111},
		KeyWarning{Type: SubkeyDueForRotation, SubkeyId: 0x2222},
		KeyWarning{Type: SubkeyOverdueForRotation, SubkeyId: 0x1111},
		KeyWarning{Type: SubkeyOverdueForRotation, SubkeyId: 0x2222},
		KeyWarning{Type: SubkeyNoExpiry, SubkeyId: 0x1111},
		KeyWarning{Type: SubkeyLongExpiry, SubkeyId: 0x2222},
		KeyWarning{Type: MissingPreferredSymmetricAlgorithms},
		KeyWarning{Type: WeakPreferredSymmetricAlgorithms},
		KeyWarning{Type: UnsupportedPreferredSymmetricAlgorithm},
		KeyWarning{Type: MissingPreferredHashAlgorithms},
		KeyWarning{Type: WeakPreferredHashAlgorithms},
		KeyWarning{Type: UnsupportedPreferredHashAlgorithm},
		KeyWarning{Type: MissingPreferredCompressionAlgorithms},
		KeyWarning{Type: UnsupportedPreferredCompressionAlgorithm},
		KeyWarning{Type: MissingUncompressedPreference},
		KeyWarning{Type: WeakSelfSignatureHash},
		KeyWarning{Type: WeakSubkeyBindingSignatureHash, SubkeyId: 0x1111},
	}

	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	expectedActions := []KeyAction{
		ModifyPrimaryKeyExpiry{ValidUntil: time.Date(2018, 7, 31, 0, 0, 0, 0, time.UTC)},
		SetPreferredSymmetricAlgorithms{NewPreferences: policy.AdvertiseCipherPreferences},
		SetPreferredHashAlgorithms{NewPreferences: policy.AdvertiseHashPreferences},
		SetPreferredCompressionAlgorithms{NewPreferences: policy.AdvertiseCompressionPreferences},
		CreateNewEncryptionSubkey{ValidUntil: time.Date(2018, 7, 31, 0, 0, 0, 0, time.UTC)},
		ExpireSubkey{SubkeyId: 0x1111},
		ExpireSubkey{SubkeyId: 0x2222},
		RefreshUserIdSelfSignatures{},
		RefreshSubkeyBindingSignature{SubkeyId: 0x1111},
	}
	gotActions := MakeActionsFromWarnings(warnings, now)
	assertActionsEqual(t, expectedActions, gotActions)
}

func assertActionsEqual(t *testing.T, expected []KeyAction, got []KeyAction) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected %d actions, got %d. expected: %v, got: %v", len(expected), len(got), expected, got)
	}

	for i := range expected {
		if !actionsEqual(expected[i], got[i]) {
			t.Fatalf("expected[%d] = %v, got[%d] = %v", i, expected[i], i, got[i])
		}

	}
}

func actionsEqual(l, r KeyAction) bool {
	return getUniqueStringForAction(l) == getUniqueStringForAction(r)
}
