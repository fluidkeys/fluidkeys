// Copyright 2019 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package humanize

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestRoughDuration(t *testing.T) {

	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "1 second",
			duration: time.Duration(1) * time.Second,
			expected: "just now",
		},
		{
			name:     "1 minute",
			duration: time.Duration(1) * time.Minute,
			expected: "1 minute",
		},
		{
			name:     "2 minutes",
			duration: time.Duration(2) * time.Minute,
			expected: "2 minutes",
		},
		{
			name:     "59 minutes",
			duration: time.Duration(59) * time.Minute,
			expected: "59 minutes",
		},
		{
			name:     "60 minutes",
			duration: time.Duration(60) * time.Minute,
			expected: "1 hour",
		},
		{
			name:     "1 hour 29",
			duration: time.Duration(89) * time.Minute,
			expected: "1 hour",
		},
		{
			name:     "1 hour 30",
			duration: time.Duration(90) * time.Minute,
			expected: "2 hours",
		},
		{
			name:     "23 hours",
			duration: time.Duration(23) * time.Hour,
			expected: "23 hours",
		},
		{
			name:     "24 hours",
			duration: time.Duration(24) * time.Hour,
			expected: "1 day",
		},
		{
			name:     "6 days",
			duration: time.Duration(6*24) * time.Hour,
			expected: "6 days",
		},
		{
			name:     "7 days",
			duration: time.Duration(7*24) * time.Hour,
			expected: "7 days",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, RoughDuration(test.duration))

		})

	}

}
