package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
)

func TestSecretKeyListingsForEmail(t *testing.T) {
	var tests = []struct {
		availableListings []gpgwrapper.SecretKeyListing
		email             string
		expectedToBeFound bool
		matchingIndex     int
	}{
		{
			[]gpgwrapper.SecretKeyListing{
				gpgwrapper.SecretKeyListing{
					Fingerprint: fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"),
					Uids:        []string{"test@example.com"},
					Created:     time.Date(2018, 8, 22, 12, 8, 23, 0, time.UTC),
				},
			},
			"test@example.com",
			true,
			0,
		},
		{
			[]gpgwrapper.SecretKeyListing{
				gpgwrapper.SecretKeyListing{
					Fingerprint: fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"),
					Uids:        []string{"test@example.com", "another@example.com"},
					Created:     time.Date(2018, 8, 22, 12, 8, 23, 0, time.UTC),
				},
			},
			"test@example.com",
			false,
			0,
		},
		{
			[]gpgwrapper.SecretKeyListing{
				gpgwrapper.SecretKeyListing{
					Fingerprint: fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"),
					Uids:        []string{"nowhere@example.com"},
					Created:     time.Date(2018, 8, 22, 12, 8, 23, 0, time.UTC),
				},
				gpgwrapper.SecretKeyListing{
					Fingerprint: fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"),
					Uids:        []string{"Test User <test@example.com>"},
					Created:     time.Date(2018, 8, 22, 12, 8, 23, 0, time.UTC),
				},
			},
			"test@example.com",
			true,
			1,
		},
	}

	for _, test := range tests {
		fmt.Printf("Test!\n")
		t.Run(fmt.Sprintf("secretKeyListingsForEmail(%s)", test.email), func(t *testing.T) {
			got := secretKeyListingsForEmail(test.availableListings, test.email)
			fmt.Printf("got != nil? %v\n", (got != nil))
			if got != nil {
				if test.expectedToBeFound == false {
					t.Fatalf("expected not to find an email, but found one!")
				} else {
					assert.Equal(t, test.availableListings[test.matchingIndex], *got)
				}
			} else {
				if test.expectedToBeFound == true {
					t.Fatalf("expected to find an email, but didn't!")
				}
			}
		})
	}

}
