package pgpkey

import (
	"testing"
	"time"
)

var (
	feb1st = time.Date(2018, 2, 1, 0, 0, 0, 0, time.UTC)
)

func TestCalculateExpiry(t *testing.T) {
	createdTime := feb1st

	t.Run("with nil lifetimeSecs", func(t *testing.T) {
		hasExpiry, _ := CalculateExpiry(createdTime, nil)
		if hasExpiry {
			t.Fatalf("expected hasExpiry=false for nil lifetimeSecs")
		}
	})

	t.Run("with zero lifetimeSecs", func(t *testing.T) {
		var lifetimeSecs uint32 = 0
		hasExpiry, _ := CalculateExpiry(createdTime, &lifetimeSecs)
		if hasExpiry {
			t.Fatalf("expected hasExpiry=false for zero lifetimeSecs")
		}
	})

	t.Run("with valid lifetimeSecs", func(t *testing.T) {
		var lifetimeSecs uint32 = 3600
		hasExpiry, expiryTime := CalculateExpiry(createdTime, &lifetimeSecs)
		if !hasExpiry {
			t.Fatalf("expected hasExpiry=true for valid lifetimeSecs")
		}

		expected := createdTime.Add(time.Duration(3600) * time.Second)

		if *expiryTime != expected {
			t.Fatalf("expected expiryTime: %v, got %v", expected, *expiryTime)
		}
	})
}
