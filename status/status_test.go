package status

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
			gotOutput := nextExpiryTime(test.today)

			if test.expectedOutput != gotOutput {
				t.Fatalf("expected '%s', got '%s'", test.expectedOutput, gotOutput)
			}
		})
	}
}
