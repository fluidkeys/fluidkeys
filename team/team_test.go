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

package team

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

func TestValidate(t *testing.T) {
	t.Run("with valid roster, returns no error", func(t *testing.T) {
		team := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.NewV4()),
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		err := team.Validate()
		assert.ErrorIsNil(t, err)
	})

	t.Run("missing UUID", func(t *testing.T) {
		team := Team{
			Name: "Kiffix",
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		err := team.Validate()
		assert.Equal(t, fmt.Errorf("invalid roster: invalid UUID"), err)
	})

	t.Run("with duplicated email address", func(t *testing.T) {
		team := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.NewV4()),
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
				{
					Email:       "test@example.com",
					Fingerprint: fingerprint.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
				},
			},
		}

		err := team.Validate()
		assert.Equal(t, fmt.Errorf("email listed more than once: test@example.com"), err)
	})

	t.Run("with duplicated fingerprint", func(t *testing.T) {
		team := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.NewV4()),
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
				{
					Email:       "another@example.com",
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		err := team.Validate()
		assert.Equal(t, fmt.Errorf("fingerprint listed more than once: "+
			"AAAA BBBB AAAA BBBB AAAA  AAAA BBBB AAAA BBBB AAAA"), err)
	})
}
