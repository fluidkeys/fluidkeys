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

package teamroster

import (
	"fmt"
	"strings"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

func TestParse(t *testing.T) {
	reader := strings.NewReader(validRoster)
	team, err := Parse(reader)

	assert.ErrorIsNil(t, err)
	expectedPeople := []Person{
		{
			Email:       "paul@fluidkeys.com",
			Fingerprint: fingerprint.MustParse("B79F0840DEF12EBBA72FF72D7327A44C2157A758"),
		},
		{
			Email:       "ian@fluidkeys.com",
			Fingerprint: fingerprint.MustParse("E63AF0E74EB5DE3FB72DC981C991709318ECBDE7"),
		},
	}
	assert.Equal(t, expectedPeople, team.People)

	assert.Equal(t, uuid.Must(uuid.FromString("38be2a70-23d8-11e9-bafd-7f97f2e239a3")), team.UUID)
	assert.Equal(t, "Fluidkeys CIC", team.Name)
}

func TestValidateRoster(t *testing.T) {
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

		err := team.ValidateRoster()
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

		err := team.ValidateRoster()
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

		err := team.ValidateRoster()
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

		err := team.ValidateRoster()
		assert.Equal(t, fmt.Errorf("fingerprint listed more than once: "+
			"AAAA BBBB AAAA BBBB AAAA  AAAA BBBB AAAA BBBB AAAA"), err)
	})
}

const validRoster = `# Fluidkeys team roster

uuid = "38be2a70-23d8-11e9-bafd-7f97f2e239a3"
name = "Fluidkeys CIC"

[[person]]
email = "paul@fluidkeys.com"
fingerprint = "B79F 0840 DEF1 2EBB A72F  F72D 7327 A44C 2157 A758"

[[person]]
email = "ian@fluidkeys.com"
fingerprint = "E63A F0E7 4EB5 DE3F B72D  C981 C991 7093 18EC BDE7"
`
