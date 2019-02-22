package team

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fluidkeys/fluidkeys/exampledata"

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

func TestSerialize(t *testing.T) {
	t.Run("for a valid team", func(t *testing.T) {
		testTeam := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			People: []Person{
				Person{
					Email:       "test2@example.com",
					Fingerprint: exampledata.ExampleFingerprint2,
				},
				Person{
					Email:       "test3@example.com",
					Fingerprint: exampledata.ExampleFingerprint3,
				},
			},
		}

		output := bytes.NewBuffer(nil)
		err := testTeam.serialize(output)
		assert.ErrorIsNil(t, err)

		expected := `# Fluidkeys team roster
uuid = "6caa3730-2ca3-47b9-b671-5dc326100431"
name = "Kiffix"

[[person]]
  email = "test2@example.com"
  fingerprint = "5C78E71F6FEFB55829654CC5343CC240D350C30C"

[[person]]
  email = "test3@example.com"
  fingerprint = "7C18DE4DE47813568B243AC8719BD63EF03BDC20"
`
		assert.Equal(t, expected, output.String())
	})

	t.Run("for a invalid team (same person twice)", func(t *testing.T) {
		person := Person{
			Email:       "test2@example.com",
			Fingerprint: exampledata.ExampleFingerprint2,
		}
		testTeam := Team{
			Name:   "Kiffix",
			UUID:   uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			People: []Person{person, person},
		}

		output := bytes.NewBuffer(nil)
		err := testTeam.serialize(output)
		assert.ErrorIsNotNil(t, err)
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
