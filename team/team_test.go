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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
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
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
					IsAdmin:     true,
				},
			},
		}

		err := team.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing UUID", func(t *testing.T) {
		team := Team{
			Name: "Kiffix",
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
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
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
				{
					Email:       "test@example.com",
					Fingerprint: fpr.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
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
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
				{
					Email:       "another@example.com",
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		err := team.Validate()
		assert.Equal(t, fmt.Errorf("fingerprint listed more than once: "+
			"AAAA BBBB AAAA BBBB AAAA  AAAA BBBB AAAA BBBB AAAA"), err)
	})

	t.Run("with no admins", func(t *testing.T) {
		team := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.NewV4()),
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
					IsAdmin:     false,
				},
				{
					Email:       "another@example.com",
					Fingerprint: fpr.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
					IsAdmin:     false,
				},
			},
		}

		err := team.Validate()
		assert.Equal(t, fmt.Errorf("team has no administrators"), err)
	})
}

func TestIsAdmin(t *testing.T) {
	adminPerson := Person{
		Email:       "admin@example.com",
		Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
		IsAdmin:     true,
	}
	normalPerson := Person{
		Email:       "normal@example.com",
		Fingerprint: fpr.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
		IsAdmin:     false,
	}

	team := Team{
		Name:   "Kiffix",
		UUID:   uuid.Must(uuid.NewV4()),
		People: []Person{adminPerson, normalPerson},
	}

	t.Run("IsAdmin returns true for admin person", func(t *testing.T) {
		got := team.IsAdmin(adminPerson.Fingerprint)

		assert.Equal(t, true, got)
	})

	t.Run("IsAdmin returns false for normal person", func(t *testing.T) {
		got := team.IsAdmin(normalPerson.Fingerprint)

		assert.Equal(t, false, got)
	})
}

func TestGetPersonForFingerprint(t *testing.T) {
	personOne := Person{
		Email:       "test@example.com",
		Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
	}
	personTwo := Person{
		Email:       "another@example.com",
		Fingerprint: fpr.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
	}

	team := Team{
		Name:   "Kiffix",
		UUID:   uuid.Must(uuid.NewV4()),
		People: []Person{personOne, personTwo},
	}

	t.Run("with a team member with matching fingerprint", func(t *testing.T) {
		got, err := team.GetPersonForFingerprint(fpr.MustParse(
			"AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"))

		assert.NoError(t, err)
		assert.Equal(t, &personOne, got)
	})

	t.Run("with no matching fingerprints", func(t *testing.T) {
		_, err := team.GetPersonForFingerprint(fpr.MustParse(
			"EEEEFFFFEEEEFFFFEEEEFFFFEEEEFFFFEEEEFFFF"))

		assert.Equal(t, fmt.Errorf("person not found"), err)
	})
}

func TestSignAndSave(t *testing.T) {
	dir, err := ioutil.TempDir("", "fluidkey.team_test_directory.")
	if err != nil {
		t.Fatalf("error creating temporary directory")
	}

	teamSubdir := filepath.Join(
		dir, "teams", "kiffix-74bb40b4-3510-11e9-968e-53c38df634be",
	)
	rosterFilename := filepath.Join(teamSubdir, "roster.toml")
	signatureFilename := filepath.Join(teamSubdir, "roster.toml.asc")

	signingKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(
		exampledata.ExamplePrivateKey2, "test2")
	if err != nil {
		t.Fatalf("couldn't load signing key")
	}

	t.Run("for a valid team", func(t *testing.T) {
		validTeam := Team{
			Name: "Kiffix",
			UUID: uuid.Must(uuid.FromString("74bb40b4-3510-11e9-968e-53c38df634be")),
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: signingKey.Fingerprint(),
					IsAdmin:     true,
				},
			},
		}

		roster, signature, err := SignAndSave(validTeam, dir, signingKey)
		assert.NoError(t, err)

		t.Run("creates a team subdirectory", func(t *testing.T) {
			if _, err := os.Stat(teamSubdir); os.IsNotExist(err) {
				t.Fatalf(teamSubdir + " wasn't created (doesn't exist)")
			}
		})

		t.Run("writes a roster.toml file", func(t *testing.T) {
			if !fileExists(rosterFilename) {
				t.Fatalf(rosterFilename + " wasn't written (doesn't exist)")
			}
		})

		t.Run("writes roster.toml.asc (armored signature)", func(t *testing.T) {
			if !fileExists(signatureFilename) {
				t.Fatalf(signatureFilename + " wasn't written (doesn't exist)")
			}
		})

		t.Run("write a valid signature", func(t *testing.T) {
			roster, err := ioutil.ReadFile(rosterFilename)
			if err != nil {
				t.Fatalf("couldn't read " + rosterFilename)
			}

			readSignature, err := ioutil.ReadFile(signatureFilename)
			if err != nil {
				t.Fatalf("couldn't read " + signatureFilename)
			}

			verifyRosterSignature(t, roster, readSignature, signingKey)
		})

		t.Run("returns the roster", func(t *testing.T) {
			expectedRoster := `# Fluidkeys team roster
uuid = "74bb40b4-3510-11e9-968e-53c38df634be"
name = "Kiffix"

[[person]]
  email = "test@example.com"
  fingerprint = "5C78E71F6FEFB55829654CC5343CC240D350C30C"
  is_admin = true
`
			if roster != expectedRoster {
				t.Fatalf("roster wasn't as expected.\n\n--- Got ---\n%s\n---------\n"+
					"--- Expected ---\n%s\n---------\n", roster, expectedRoster)
			}
		})

		t.Run("returns the signature, and the sig is valid", func(t *testing.T) {
			verifyRosterSignature(t, []byte(roster), []byte(signature), signingKey)
		})

		t.Run("allows the file to be overwritten", func(t *testing.T) {
			updatedTeam := validTeam
			updatedTeam.People = []Person{validTeam.People[0]}

			// re-run Save, since a roster
			updatedRoster, updatedSignature, err := SignAndSave(updatedTeam, dir, signingKey)
			assert.NoError(t, err)

			files, _ := ioutil.ReadDir(teamSubdir)
			assert.Equal(t, 2, len(files)) // still only roster.toml and roster.toml.asc

			t.Run("read back roster matches return value of SignAndSave", func(t *testing.T) {
				readBackRoster, err := ioutil.ReadFile(rosterFilename)
				assert.NoError(t, err)

				assert.Equal(t, updatedRoster, string(readBackRoster))
			})

			t.Run("read back signature matches return value of SignAndSave", func(t *testing.T) {
				readBackSignature, err := ioutil.ReadFile(signatureFilename)
				assert.NoError(t, err)

				assert.Equal(t, updatedSignature, string(readBackSignature))
			})
		})
	})

	t.Run("returns an error for invalid team", func(t *testing.T) {
		invalidTeam := Team{
			Name: "Missing UUID",
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		_, _, err := SignAndSave(invalidTeam, dir, signingKey)
		assert.Equal(t, fmt.Errorf("invalid team: invalid roster: invalid UUID"), err)
	})
}

func TestGetAddPersonWarnings(t *testing.T) {

	var tests = []struct {
		name          string
		person        Person
		team          Team
		expectedError error
		expectedTeam  Team
	}{
		{
			"adding a new person",
			Person{
				Email:       "person@example.com",
				Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				IsAdmin:     false,
			},
			Team{
				UUID:   uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name:   "Kiffix",
				People: nil,
			},
			nil,
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
		},
		{
			"adding a person with email that's already in roster",
			Person{
				Email:       "person@example.com",
				Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				IsAdmin:     false,
			},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
						IsAdmin:     false,
					},
				},
			},
			ErrEmailAlreadyInRoster{},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					Person{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
		},
		{
			"adding a person with fingerprint that's already in roster",
			Person{
				Email:       "person@example.com",
				Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				IsAdmin:     false,
			},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "another@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
			ErrFingerprintAlreadyInRoster{},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
		},
		{
			"adding a person who already is in roster",
			Person{
				Email:       "person@example.com",
				Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				IsAdmin:     false,
			},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
			ErrPersonAlreadyInRoster{},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
		},
		{
			"adding a non admin who already is in roster as an admin",
			Person{
				Email:       "person@example.com",
				Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				IsAdmin:     false,
			},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     true,
					},
				},
			},
			ErrPersonAlreadyInRosterAsAdmin{},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
		},
		{
			"adding an admin who already is in roster but not as an admin",
			Person{
				Email:       "person@example.com",
				Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				IsAdmin:     true,
			},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     false,
					},
				},
			},
			ErrPersonAlreadyInRosterNotAsAdmin{},
			Team{
				UUID: uuid.Must(uuid.FromString("8e26e4df0d474f7f9a07a37b2aa92104")),
				Name: "Kiffix",
				People: []Person{
					{
						Email:       "person@example.com",
						Fingerprint: fpr.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
						IsAdmin:     true,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run("GetAddPersonWarnings for "+test.name, func(t *testing.T) {
			err, _ := test.team.GetAddPersonWarnings(test.person)
			assert.Equal(t, test.expectedError, err)
		})
	}

	for _, test := range tests {
		t.Run("UpsertPerson for "+test.name, func(t *testing.T) {
			test.team.UpsertPerson(test.person)
			assert.Equal(t, test.expectedTeam.People, test.team.People)
		})
	}
}

func verifyRosterSignature(
	t *testing.T, roster []byte, armoredSignature []byte, signerKey *pgpkey.PgpKey) {
	var keyring openpgp.EntityList = []*openpgp.Entity{&signerKey.Entity}
	if _, err := openpgp.CheckArmoredDetachedSignature(
		keyring,
		bytes.NewReader(roster),
		bytes.NewReader(armoredSignature),
	); err != nil {
		t.Fatalf("signature is invalid")
	}
}
