package team

import (
	"testing"

	"github.com/fluidkeys/fluidkeys/exampledata"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/gofrs/uuid"
)

func TestSerialize(t *testing.T) {
	t.Run("for a valid team", func(t *testing.T) {
		testTeam := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			People: []Person{
				Person{
					Email:       "test2@example.com",
					Fingerprint: exampledata.ExampleFingerprint2,
					IsAdmin:     true,
				},
				Person{
					Email:       "test3@example.com",
					Fingerprint: exampledata.ExampleFingerprint3,
					IsAdmin:     false,
				},
			},
		}

		got, err := testTeam.serialize()
		assert.NoError(t, err)

		expected := `# Kiffix team roster. Everyone in the team has a copy of this file.
#
# It is used to look up which key to use for an email address and fetch keys
# automatically.
uuid = "6caa3730-2ca3-47b9-b671-5dc326100431"
name = "Kiffix"

[[person]]
  email = "test2@example.com"
  fingerprint = "5C78E71F6FEFB55829654CC5343CC240D350C30C"
  is_admin = true

[[person]]
  email = "test3@example.com"
  fingerprint = "7C18DE4DE47813568B243AC8719BD63EF03BDC20"
  is_admin = false
`
		assert.Equal(t, expected, got)
	})

	t.Run("missing IsAdmin is OK and serializes as false", func(t *testing.T) {
		testTeam := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			People: []Person{
				Person{
					Email:       "test2@example.com",
					Fingerprint: exampledata.ExampleFingerprint2,
					IsAdmin:     true,
				},
				Person{
					Email:       "test3@example.com",
					Fingerprint: exampledata.ExampleFingerprint3,
					// missing IsAdmin should default to false
				},
			},
		}

		got, err := testTeam.serialize()
		assert.NoError(t, err)

		expected := `# Kiffix team roster. Everyone in the team has a copy of this file.
#
# It is used to look up which key to use for an email address and fetch keys
# automatically.
uuid = "6caa3730-2ca3-47b9-b671-5dc326100431"
name = "Kiffix"

[[person]]
  email = "test2@example.com"
  fingerprint = "5C78E71F6FEFB55829654CC5343CC240D350C30C"
  is_admin = true

[[person]]
  email = "test3@example.com"
  fingerprint = "7C18DE4DE47813568B243AC8719BD63EF03BDC20"
  is_admin = false
`
		assert.Equal(t, expected, got)
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

		_, err := testTeam.serialize()
		assert.GotError(t, err)
	})
}
