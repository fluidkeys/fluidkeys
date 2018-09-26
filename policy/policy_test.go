package policy

import (
	"fmt"
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
			gotOutput := NextExpiryTime(test.today)

			if test.expectedOutput != gotOutput {
				t.Fatalf("expected '%s', got '%s'", test.expectedOutput, gotOutput)
			}
		})
	}
}

func TestDueOverdueFunctions(t *testing.T) {
	now := time.Date(2018, 6, 15, 0, 0, 0, 0, time.UTC)
	rotationInFuture := now.Add(time.Duration(1) * time.Hour)
	rotationInPast := now.Add(time.Duration(-1) * time.Hour)

	nineDaysInPast := now.Add(time.Duration(-9*24) * time.Hour)
	tenDaysInPast := now.Add(time.Duration(-10*24) * time.Hour)
	tenDaysOneSecondInPast := tenDaysInPast.Add(time.Duration(1) * time.Second)
	elevenDaysInPast := now.Add(time.Duration(-11*24) * time.Hour)

	t.Run("IsDueForRotation with future date", func(t *testing.T) {
		if IsDueForRotation(rotationInFuture, now) != false {
			t.Errorf("expected IsDueForRotation(%v, %v) to return false", rotationInFuture, now)
		}
	})

	t.Run("IsDueForRotation with past date", func(t *testing.T) {
		if IsDueForRotation(rotationInPast, now) != true {
			t.Errorf("expected IsDueForRotation(%v, %v) to return true", rotationInPast, now)
		}
	})

	t.Run("IsOverdueForRotation with 9 days", func(t *testing.T) {
		if IsOverdueForRotation(nineDaysInPast, now) != false {
			t.Errorf("expected IsOverdueForRotation(%v, %v) to return false", nineDaysInPast, now)
		}
	})

	t.Run("IsOverdueForRotation with exactly 10 days", func(t *testing.T) {
		if IsOverdueForRotation(tenDaysInPast, now) != false {
			t.Errorf("expected IsOverdueForRotation(%v, %v) to return false", tenDaysInPast, now)
		}
	})

	t.Run("IsOverdueForRotation with 10 days + 1 second", func(t *testing.T) {
		if IsOverdueForRotation(tenDaysOneSecondInPast, now) != false {
			t.Errorf("expected IsOverdueForRotation(%v, %v) to return false", tenDaysOneSecondInPast, now)
		}
	})

	t.Run("IsOverdueForRotation with 11 days", func(t *testing.T) {
		if IsOverdueForRotation(elevenDaysInPast, now) != true {
			t.Errorf("expected IsOverdueForRotation(%v, %v) to return true", elevenDaysInPast, now)
		}
	})

}
