package status

import (
	"fmt"
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

func TestFirstOfNextMonth(t *testing.T) {
	var tests = []struct {
		today          time.Time
		expectedOutput time.Time
	}{
		{
			time.Date(2018, 1, 1, 18, 0, 0, 0, time.UTC), // start of Jan
			feb1st,
		},
		{
			time.Date(2018, 1, 15, 18, 0, 0, 0, time.UTC), // middle of Jan
			feb1st,
		},
		{
			time.Date(2018, 1, 31, 23, 59, 59, 0, time.UTC), // end of Jan
			feb1st,
		},
		{
			time.Date(2018, 2, 1, 18, 0, 0, 0, time.UTC), // start of Feb
			march1st,
		},
		{
			time.Date(2018, 2, 15, 18, 0, 0, 0, time.UTC), // middle of Feb
			march1st,
		},
		{
			time.Date(2018, 2, 28, 23, 59, 59, 0, time.UTC), // end of Feb
			march1st,
		},
		{
			time.Date(2020, 2, 29, 23, 59, 59, 0, time.UTC), // end of Feb, leap year
			march1stLeapYear,
		},
		{
			time.Date(2020, 2, 29, 23, 59, 59, 0, time.UTC), // end of Feb, leap year
			march1stLeapYear,
		},
		{
			time.Date(2018, 2, 15, 12, 0, 0, 0, anotherTimezone), // non-UTC
			time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC),          // should convert timezone
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("today = %v", test.today), func(t *testing.T) {
			gotOutput := firstOfNextMonth(test.today)

			if test.expectedOutput != gotOutput {
				t.Fatalf("expected '%s', got '%s'", test.expectedOutput, gotOutput)
			}
		})
	}
}

func TestNextExpiryTime(t *testing.T) {

	var tests = []struct {
		today          time.Time
		expectedOutput time.Time
	}{
		{
			time.Date(2018, 1, 1, 18, 0, 0, 0, time.UTC), // start of Jan
			feb1st.Add(thirtyDays),
		},
		{
			time.Date(2018, 1, 15, 18, 0, 0, 0, time.UTC), // middle of Jan
			feb1st.Add(thirtyDays),
		},
		{
			time.Date(2018, 1, 31, 23, 59, 59, 0, time.UTC), // end of Jan
			feb1st.Add(thirtyDays),
		},
		{
			time.Date(2018, 2, 1, 18, 0, 0, 0, time.UTC), // start of Feb
			march1st.Add(thirtyDays),
		},
		{
			time.Date(2018, 2, 15, 18, 0, 0, 0, time.UTC), // middle of Feb
			march1st.Add(thirtyDays),
		},
		{
			time.Date(2018, 2, 28, 23, 59, 59, 0, time.UTC), // end of Feb
			march1st.Add(thirtyDays),
		},
		{
			time.Date(2020, 2, 29, 23, 59, 59, 0, time.UTC), // end of Feb, leap year
			march1stLeapYear.Add(thirtyDays),
		},
		{
			time.Date(2018, 2, 15, 18, 0, 0, 0, anotherTimezone), // non-UTC
			time.Date(2018, 3, 31, 0, 0, 0, 0, time.UTC),         // should convert to UTC
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("today = %v", test.today), func(t *testing.T) {
			gotOutput := nextExpiryTime(test.today)

			if test.expectedOutput != gotOutput {
				t.Fatalf("expected '%s', got '%s'", test.expectedOutput, gotOutput)
			}
		})
	}
}

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

func TestCalculateExpiry(t *testing.T) {
	createdTime := feb1st

	t.Run("with nil lifetimeSecs", func(t *testing.T) {
		hasExpiry, _ := calculateExpiry(createdTime, nil)
		if hasExpiry {
			t.Fatalf("expected hasExpiry=false for nil lifetimeSecs")
		}
	})

	t.Run("with zero lifetimeSecs", func(t *testing.T) {
		var lifetimeSecs uint32 = 0
		hasExpiry, _ := calculateExpiry(createdTime, &lifetimeSecs)
		if hasExpiry {
			t.Fatalf("expected hasExpiry=false for zero lifetimeSecs")
		}
	})

	t.Run("with valid lifetimeSecs", func(t *testing.T) {
		var lifetimeSecs uint32 = 3600
		hasExpiry, expiryTime := calculateExpiry(createdTime, &lifetimeSecs)
		if !hasExpiry {
			t.Fatalf("expected hasExpiry=true for valid lifetimeSecs")
		}

		expected := createdTime.Add(time.Duration(3600) * time.Second)

		if *expiryTime != expected {
			t.Fatalf("expected expiryTime: %v, got %v", expected, *expiryTime)
		}
	})
}

func TestDateHelpers(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	expiryInFuture := now.Add(time.Duration(1) * time.Hour)
	expiryInPast := now.Add(time.Duration(-1) * time.Hour)
	rotationInFuture := now.Add(time.Duration(1) * time.Hour)
	rotationInPast := now.Add(time.Duration(-1) * time.Hour)

	nineDaysInPast := now.Add(time.Duration(-9*24) * time.Hour)
	tenDaysInPast := now.Add(time.Duration(-10*24) * time.Hour)
	tenDaysOneSecondInPast := tenDaysInPast.Add(time.Duration(1) * time.Second)
	elevenDaysInPast := now.Add(time.Duration(-11*24) * time.Hour)

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

	t.Run("isDueForRotation with future date", func(t *testing.T) {
		if isDueForRotation(rotationInFuture, now) != false {
			t.Errorf("expected isDueForRotation(%v, %v) to return false", rotationInFuture, now)
		}
	})

	t.Run("isDueForRotation with past date", func(t *testing.T) {
		if isDueForRotation(rotationInPast, now) != true {
			t.Errorf("expected isDueForRotation(%v, %v) to return true", rotationInPast, now)
		}
	})

	t.Run("isOverdueForRotation with 9 days", func(t *testing.T) {
		if isOverdueForRotation(nineDaysInPast, now) != false {
			t.Errorf("expected isOverdueForRotation(%v, %v) to return false", nineDaysInPast, now)
		}
	})

	t.Run("isOverdueForRotation with exactly 10 days", func(t *testing.T) {
		if isOverdueForRotation(tenDaysInPast, now) != false {
			t.Errorf("expected isOverdueForRotation(%v, %v) to return false", tenDaysInPast, now)
		}
	})

	t.Run("isOverdueForRotation with 10 days + 1 second", func(t *testing.T) {
		if isOverdueForRotation(tenDaysOneSecondInPast, now) != false {
			t.Errorf("expected isOverdueForRotation(%v, %v) to return false", tenDaysOneSecondInPast, now)
		}
	})

	t.Run("isOverdueForRotation with 11 days", func(t *testing.T) {
		if isOverdueForRotation(elevenDaysInPast, now) != true {
			t.Errorf("expected isOverdueForRotation(%v, %v) to return true", elevenDaysInPast, now)
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
