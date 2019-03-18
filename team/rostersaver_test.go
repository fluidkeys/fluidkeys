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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestCommitDraft(t *testing.T) {

	t.Run("saves files when they don't already exist", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)
		defer os.RemoveAll(rosterSaver.Directory)

		err := rosterSaver.SaveDraft("fake roster", "fake signature")
		assert.NoError(t, err)

		err = rosterSaver.CommitDraft()
		assert.NoError(t, err)

		t.Run("roster.toml", func(t *testing.T) {
			assert.Equal(t,
				"fake roster",
				readFile(t, filepath.Join(rosterSaver.Directory, "roster.toml")),
			)
		})

		t.Run("roster.toml.asc", func(t *testing.T) {
			assert.Equal(t,
				"fake signature",
				readFile(t, filepath.Join(rosterSaver.Directory, "roster.toml.asc")),
			)
		})

		t.Run("clears the draft filename", func(t *testing.T) {
			assert.Equal(t, "", rosterSaver.draftRosterFilename)
			assert.Equal(t, "", rosterSaver.draftSignatureFilename)
		})
	})

	t.Run("overwrites if a file already exists", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)
		defer os.RemoveAll(rosterSaver.Directory)

		err := rosterSaver.SaveDraft("roster 1", "signature 1")
		assert.NoError(t, err)

		err = rosterSaver.CommitDraft()
		assert.NoError(t, err)

		err = rosterSaver.SaveDraft("roster 2", "signature 2")
		assert.NoError(t, err)

		err = rosterSaver.CommitDraft()
		assert.NoError(t, err)

		t.Run("roster.toml", func(t *testing.T) {
			assert.Equal(t,
				"roster 2",
				readFile(t, filepath.Join(rosterSaver.Directory, "roster.toml")),
			)
		})

		t.Run("roster.toml.asc", func(t *testing.T) {
			assert.Equal(t,
				"signature 2",
				readFile(t, filepath.Join(rosterSaver.Directory, "roster.toml.asc")),
			)
		})
	})

	t.Run("returns error if roster can't be written", func(t *testing.T) {

		t.Run("leaves original roster intact", func(t *testing.T) {
		})
	})

	t.Run("deletes new roster if signature can't be saved", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)
		defer os.RemoveAll(rosterSaver.Directory)

		rosterFilename := filepath.Join(rosterSaver.Directory, "roster.toml")
		//sigFilename := filepath.Join(rosterSaver.Directory, "roster.toml.asc")

		err := rosterSaver.SaveDraft("roster 1", "signature 1")
		assert.NoError(t, err)

		// fudge it so the attempt fails to move draft signature -> roster.toml.asc
		assert.NoError(t, os.Remove(rosterSaver.draftSignatureFilename))

		err = rosterSaver.CommitDraft()
		assert.GotError(t, err)

		if fileExists(rosterFilename) {
			t.Fatalf("%s should have been deleted, but it exists", rosterFilename)
		}

	})

	t.Run("rolls back to previous existing roster if signature can't be saved", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)
		defer os.RemoveAll(rosterSaver.Directory)

		err := rosterSaver.Save("original roster", "original signature")
		assert.NoError(t, err)

		err = rosterSaver.SaveDraft("updated roster", "updated signature")
		assert.NoError(t, err)

		// fudge it so the attempt fails to move draft signature -> roster.toml.asc
		assert.NoError(t, os.Remove(rosterSaver.draftSignatureFilename))

		err = rosterSaver.CommitDraft()
		assert.GotError(t, err)

		assert.Equal(t,
			"original roster",
			readFile(t, filepath.Join(rosterSaver.Directory, "roster.toml")),
		)

		assert.Equal(t,
			"original signature",
			readFile(t, filepath.Join(rosterSaver.Directory, "roster.toml.asc")),
		)

	})

	t.Run("errors if a draft isn't in progress", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)
		defer os.RemoveAll(rosterSaver.Directory)

		err := rosterSaver.CommitDraft()
		assert.GotError(t, err)
		assert.Equal(t, fmt.Errorf("no draft in progress"), err)
	})
}

func TestDiscardDraft(t *testing.T) {

	t.Run("deletes temp files and clears variables", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)
		defer os.RemoveAll(rosterSaver.Directory)

		rosterSaver.SaveDraft("roster", "signature")

		rosterTmpFilename := rosterSaver.draftRosterFilename
		signatureTmpFilename := rosterSaver.draftSignatureFilename

		err := rosterSaver.DiscardDraft()
		assert.NoError(t, err)

		assert.Equal(t, "", rosterSaver.draftRosterFilename)
		assert.Equal(t, "", rosterSaver.draftSignatureFilename)

		if fileExists(rosterTmpFilename) {
			t.Fatalf("discard hasn't deleted %s", rosterTmpFilename)
		}

		if fileExists(signatureTmpFilename) {
			t.Fatalf("discard hasn't deleted %s", signatureTmpFilename)
		}
	})

	t.Run("deletes directory if it's empty", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)

		rosterSaver.SaveDraft("roster", "signature")

		assert.Equal(t, true, directoryExists(rosterSaver.Directory))

		err := rosterSaver.DiscardDraft() // should delete rosterSaver.Directory
		assert.NoError(t, err)

		assert.Equal(t, false, directoryExists(rosterSaver.Directory))
	})

	t.Run("doesn't delete directory if it's not empty", func(t *testing.T) {
		rosterSaver := makeRosterSaveInTmpDirectory(t)

		assert.NoError(t,
			ioutil.WriteFile(filepath.Join(rosterSaver.Directory, "file.txt"), []byte{}, 0600),
		)

		rosterSaver.SaveDraft("roster", "signature")

		assert.Equal(t, true, directoryExists(rosterSaver.Directory))

		err := rosterSaver.DiscardDraft() // should *not* delete non-empty rosterSaver.Directory
		assert.NoError(t, err)

		assert.Equal(t, true, directoryExists(rosterSaver.Directory))
	})
}

func makeRosterSaveInTmpDirectory(t *testing.T) RosterSaver {
	t.Helper()
	tmpDirectory, err := ioutil.TempDir("", "fktest")
	assert.NoError(t, err)

	return RosterSaver{
		Directory: tmpDirectory,
	}
}

func readFile(t *testing.T, filename string) string {
	content, err := ioutil.ReadFile(filename)
	assert.NoError(t, err)
	return string(content)
}

func directoryExists(directory string) bool {
	fileInfo, err := os.Stat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("directory doesn't exist: %s", directory)
			return false
		}
		log.Printf("os.Stat(%s) error: %v", directory, err)
		return false
	}
	return fileInfo.IsDir()
}
