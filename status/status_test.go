package status

import (
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"testing"
	"time"
)

var (
	feb1st           = time.Date(2018, 2, 1, 0, 0, 0, 0, time.UTC)
	march1st         = time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)
	march1stLeapYear = time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC)

	anotherTimezone = time.FixedZone("UTC+8", 8*60*60)
)

func TestGetEarliestExpiryTime(t *testing.T) {
	key, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	if err != nil {
		t.Fatal(err)
	}
	hasExpiry, earliestExpiry := getEarliestExpiryTime(*key)

	if !hasExpiry {
		t.Fatalf("expected hasExpiry=true")
	}

	expected := time.Date(2038, 9, 7, 9, 5, 3, 0, time.UTC)

	if *earliestExpiry != expected {
		t.Fatalf("expected earliestExpiry=%v, got %v", expected, *earliestExpiry)
	}
}

func TestEarliest(t *testing.T) {
	times := []time.Time{feb1st, march1st}

	expected := feb1st

	got := earliest(times)
	if got != expected {
		t.Fatalf("earliest(): expected '%v', got '%v'", expected, got)
	}
}

func TestDateHelpers(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	expiryInFuture := now.Add(time.Duration(1) * time.Hour)
	expiryInPast := now.Add(time.Duration(-1) * time.Hour)

	t.Run("isExpired with past date", func(t *testing.T) {
		if isExpired(expiryInPast, now) != true {
			t.Errorf("expected isExpired(%v, %v) to return true", expiryInPast, now)
		}

	})

	t.Run("isExpired with future date", func(t *testing.T) {
		if isExpired(expiryInFuture, now) != false {
			t.Errorf("expected isExpired(%v, %v) to return true", expiryInFuture, now)
		}
	})

	t.Run("getDaysSinceExpiry 1 hour in the past", func(t *testing.T) {
		expected := uint(0)
		got := getDaysSinceExpiry(now.Add(time.Duration(-1)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("getDaysSinceExpiry 25 hours in the past", func(t *testing.T) {
		expected := uint(1)
		got := getDaysSinceExpiry(now.Add(time.Duration(-25)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("getDaysUntilExpiry 1 hour in the future", func(t *testing.T) {
		expected := uint(0)
		got := getDaysUntilExpiry(now.Add(time.Duration(1)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("getDaysUntilExpiry 25 hours in the future", func(t *testing.T) {
		expected := uint(1)
		got := getDaysUntilExpiry(now.Add(time.Duration(25)*time.Hour), now)

		if got != expected {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})
}

func TestGetEncryptionSubkeyWarnings(t *testing.T) {
	t.Run("with a primary key with long expiry date and a subkey overdue for rotation", func(t *testing.T) {
		pgpKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey2, "test2")
		if err != nil {
			t.Fatalf("Failed to load example test data: %v", err)
		}

		now := time.Date(2018, 9, 24, 18, 0, 0, 0, time.UTC)
		verySoon := now.Add(time.Duration(6) * time.Hour)
		veryFarAway := now.Add(time.Duration(100*24) * time.Hour)

		err = pgpKey.UpdateSubkeyValidUntil(pgpKey.EncryptionSubkey().PublicKey.KeyId, verySoon)
		if err != nil {
			t.Fatalf("failed to update expiry on test subkey")
		}

		err = pgpKey.UpdateExpiryForAllUserIds(veryFarAway)
		if err != nil {
			t.Fatalf("failed to update expiry on test key")
		}

		t.Run("test we get subkey overdue for rotation warning", func(t *testing.T) {
			expected := []KeyWarning{
				KeyWarning{Type: SubkeyOverdueForRotation},
			}

			got := getEncryptionSubkeyWarnings(*pgpKey, now)

			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})

		t.Run("test we get primary key long expiry warning", func(t *testing.T) {
			expected := []KeyWarning{
				KeyWarning{Type: PrimaryKeyLongExpiry},
			}

			now := time.Date(2018, 9, 24, 18, 0, 0, 0, time.UTC)
			got := getPrimaryKeyWarnings(*pgpKey, now)

			assertEqualSliceOfKeyWarningTypes(t, expected, got)
		})
	})
}

// assertEqualSliceOfKeyWarnings compares two slices of keywarnings and calls
// t.Fatalf with a message if they differ.
func assertEqualSliceOfKeyWarningTypes(t *testing.T, expected, got []KeyWarning) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("expected length %d, got %d. expected: %v, got: %v",
			len(expected), len(got), expected, got)
	}
	for i := range expected {
		if expected[i].Type != got[i].Type {
			t.Fatalf("expected[%d].Type differs, expected '%d', got '%d'", i, expected[i].Type, got[i].Type)
		}
	}

}
