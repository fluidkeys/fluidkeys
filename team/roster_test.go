package team

import (
	"fmt"
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

	assert.NoError(t, err)
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

func TestRoster(t *testing.T) {
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

		got, err := testTeam.Roster()
		assert.NoError(t, err)

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

		_, err := testTeam.Roster()
		assert.ErrorIsNotNil(t, err)
	})
}

func TestSlugify(t *testing.T) {
	var tests = []struct {
		input    string
		expected string
	}{
		{
			"Hello world",
			"hello-world",
		},
		{
			"Marks & Spencers",
			"marks-and-spencers",
		},
		{
			"Digit@l Wizards",
			"digital-wizards",
		},
		{
			"Between [Worlds]",
			"between-worlds",
		},
		{
			"--Future--",
			"future",
		},
		{
			"😁 Happy Cleaners 💦",
			"happy-cleaners",
		},
		{
			"déjà vu",
			"d-j-vu",
		},
		{
			"\n\000\037 \041\176\177\200\377\n",
			"",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("slugifying `%s`", test.input), func(t *testing.T) {
			assert.Equal(t, test.expected, slugify(test.input))
		})
	}
}

func TestSubDirectory(t *testing.T) {
	var tests = []struct {
		team     Team
		expected string
	}{
		{
			Team{
				Name: "kiffix",
				UUID: uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			},
			"kiffix-6caa3730-2ca3-47b9-b671-5dc326100431",
		},
		{
			Team{
				Name: "😁 Happy Cleaners 💦",
				UUID: uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			},
			"happy-cleaners-6caa3730-2ca3-47b9-b671-5dc326100431",
		},
		{
			Team{
				Name: "😁",
				UUID: uuid.Must(uuid.FromString("6caa3730-2ca3-47b9-b671-5dc326100431")),
			},
			"6caa3730-2ca3-47b9-b671-5dc326100431",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("get directory for `%s`", test.team.Name), func(t *testing.T) {

			assert.Equal(t, test.expected, test.team.subDirectory())
		})
	}
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
