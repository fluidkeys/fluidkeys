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
	"github.com/fluidkeys/fluidkeys/fingerprint"
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

func TestGetPersonForFingerprint(t *testing.T) {
	personOne := Person{
		Email:       "test@example.com",
		Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
	}
	personTwo := Person{
		Email:       "another@example.com",
		Fingerprint: fingerprint.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
	}

	team := Team{
		Name:   "Kiffix",
		UUID:   uuid.Must(uuid.NewV4()),
		People: []Person{personOne, personTwo},
	}

	t.Run("with a team member with matching fingerprint", func(t *testing.T) {
		got, err := team.GetPersonForFingerprint(fingerprint.MustParse(
			"AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"))

		assert.ErrorIsNil(t, err)
		assert.Equal(t, &personOne, got)
	})

	t.Run("with no matching fingerprints", func(t *testing.T) {
		_, err := team.GetPersonForFingerprint(fingerprint.MustParse(
			"EEEEFFFFEEEEFFFFEEEEFFFFEEEEFFFFEEEEFFFF"))

		assert.Equal(t, fmt.Errorf("person not found"), err)
	})
}

func TestSignAndSave(t *testing.T) {
	dir, err := ioutil.TempDir("", "fluidkey.team_test_directory.")
	if err != nil {
		t.Fatalf("error creating temporary directory")
	}

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
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		roster, signature, err := SignAndSave(validTeam, dir, signingKey)
		assert.ErrorIsNil(t, err)

		t.Run("creates a team subdirectory", func(t *testing.T) {
			expectedRosterDirectory := filepath.Join(
				dir, "teams", "kiffix-74bb40b4-3510-11e9-968e-53c38df634be",
			)
			if _, err := os.Stat(expectedRosterDirectory); os.IsNotExist(err) {
				t.Fatalf(expectedRosterDirectory + " doesn't exist")
			}
		})

		t.Run("writes a roster.toml file", func(t *testing.T) {
			expectedFilename := filepath.Join(
				dir, "teams", "kiffix-74bb40b4-3510-11e9-968e-53c38df634be", "roster.toml")
			if !fileExists(expectedFilename) {
				t.Fatalf(expectedFilename + " doesn't exist")
			}
		})

		t.Run("writes roster.toml.asc (armored signature)", func(t *testing.T) {
			expectedFilename := filepath.Join(
				dir, "teams", "kiffix-74bb40b4-3510-11e9-968e-53c38df634be", "roster.toml.asc")
			if !fileExists(expectedFilename) {
				t.Fatalf(expectedFilename + " doesn't exist")
			}
		})

		t.Run("write a valid signature", func(t *testing.T) {
			teamSubdir := filepath.Join(dir, "teams", "kiffix-74bb40b4-3510-11e9-968e-53c38df634be")
			rosterFilepath := filepath.Join(teamSubdir, "roster.toml")
			roster, err := ioutil.ReadFile(rosterFilepath)
			if err != nil {
				t.Fatalf("couldn't read " + rosterFilepath)
			}

			signatureFilepath := filepath.Join(teamSubdir, "roster.toml.asc")
			readSignature, err := ioutil.ReadFile(signatureFilepath)
			if err != nil {
				t.Fatalf("couldn't read " + signatureFilepath)
			}

			verifyRosterSignature(t, roster, readSignature, signingKey)
		})

		t.Run("returns the roster", func(t *testing.T) {
			expectedRoster := `# Fluidkeys team roster
uuid = "74bb40b4-3510-11e9-968e-53c38df634be"
name = "Kiffix"

[[person]]
  email = "test@example.com"
  fingerprint = "AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"
`
			if roster != expectedRoster {
				t.Fatalf("roster wasn't as expected.\n\n--- Got ---\n%s\n---------\n"+
					"--- Expected ---\n%s\n---------\n", roster, expectedRoster)
			}
		})

		t.Run("returns the signature", func(t *testing.T) {
			verifyRosterSignature(t, []byte(roster), []byte(signature), signingKey)
		})

		t.Run("allows the file to be overwritten", func(t *testing.T) {
			validTeam := Team{
				Name: "Kiffix",
				UUID: uuid.Must(uuid.FromString("74bb40b4-3510-11e9-968e-53c38df634be")),
				People: []Person{
					{
						Email:       "test@example.com",
						Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
					},
					{
						Email:       "new-member@example.com",
						Fingerprint: fingerprint.MustParse("CCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDDCCCCDDDD"),
					},
				},
			}

			// re-run Save, since a roster
			_, _, err = SignAndSave(validTeam, dir, signingKey)
			assert.ErrorIsNil(t, err)

			rosterDirectory := filepath.Join(
				dir, "teams", "kiffix-74bb40b4-3510-11e9-968e-53c38df634be")

			files, _ := ioutil.ReadDir(rosterDirectory)
			assert.Equal(t, 2, len(files)) // still only roster.toml and roster.toml.asc
		})
	})

	t.Run("returns an error for invalid team", func(t *testing.T) {
		invalidTeam := Team{
			Name: "Missing UUID",
			People: []Person{
				{
					Email:       "test@example.com",
					Fingerprint: fingerprint.MustParse("AAAABBBBAAAABBBBAAAAAAAABBBBAAAABBBBAAAA"),
				},
			},
		}

		_, _, err := SignAndSave(invalidTeam, dir, signingKey)
		assert.Equal(t, fmt.Errorf("invalid team: invalid roster: invalid UUID"), err)
	})
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
