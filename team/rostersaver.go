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
)

// RosterSaver provides a way to do a 2-part save where a roster is saved as a "draft"
// which can be either committed or discarded.
type RosterSaver struct {
	Directory string

	draftRosterFilename    string
	draftSignatureFilename string
}

// Save saves the roster and signature straight to disk.
func (rs *RosterSaver) Save(roster string, signature string) error {
	if err := rs.SaveDraft(roster, signature); err != nil {
		return err
	}
	if err := rs.CommitDraft(); err != nil {
		return err
	}
	return nil
}

// SaveDraft saves the roster and signature to temporary files. This call should be followed by
// either CommitDraft() or DiscardDraft() to actually write or delete the roster & signature.
func (rs *RosterSaver) SaveDraft(roster string, signature string) error {
	if rs.draftRosterFilename != "" || rs.draftSignatureFilename != "" {
		return fmt.Errorf("already have a draft in progress")
	}

	if err := os.MkdirAll(rs.Directory, 0700); err != nil {
		return fmt.Errorf("failed to make directory %s: %v", rs.Directory, err)
	}

	rosterTmp, err := ioutil.TempFile(rs.Directory, ".tmp."+rosterFilename)
	if err != nil {
		return err
	}
	defer rosterTmp.Close()

	if _, err := rosterTmp.Write([]byte(roster)); err != nil {
		_ = os.Remove(rosterTmp.Name()) // best effort to clean up, but don't check error
		return err
	}

	sigTmp, err := ioutil.TempFile(rs.Directory, ".tmp."+signatureFilename)
	if err != nil {
		_ = os.Remove(rosterTmp.Name()) // best effort to clean up, but don't check error
		return err
	}
	defer sigTmp.Close()

	if _, err := sigTmp.Write([]byte(signature)); err != nil {
		_ = os.Remove(rosterTmp.Name()) // best effort to clean up, but don't check error
		_ = os.Remove(sigTmp.Name())
		return err
	}

	rs.draftRosterFilename = rosterTmp.Name()
	rs.draftSignatureFilename = sigTmp.Name()
	return nil
}

// CommitDraft actually saves the previously saved draft roster and signature
func (rs *RosterSaver) CommitDraft() error {
	if rs.draftRosterFilename == "" || rs.draftSignatureFilename == "" {
		return fmt.Errorf("no draft in progress")
	}

	rosterFilename := filepath.Join(rs.Directory, rosterFilename)
	rosterBackupFilename := filepath.Join(rs.Directory, rosterBackupFilename)
	signatureFilename := filepath.Join(rs.Directory, signatureFilename)

	isUpdate := fileExists(rosterFilename)

	if isUpdate {
		// backup roster.toml to roster.toml.BAK
		if err := os.Rename(rosterFilename, rosterBackupFilename); err != nil {
			return err
		}
	}

	// move draft roster -> roster.toml
	if err := os.Rename(rs.draftRosterFilename, rosterFilename); err != nil {
		// failed to write new roster.toml, so try to restore backup (if we made one)

		if isUpdate {
			if err2 := os.Rename(rosterBackupFilename, rosterFilename); err2 != nil {
				return fmt.Errorf("failed to write %s (%v) and failed to restore backup %s (%v)",
					rosterFilename, err, rosterBackupFilename, err2)
			}
		}
		return err
	}
	rs.draftRosterFilename = ""

	// move draft signature -> roster.toml.asc
	if err := os.Rename(rs.draftSignatureFilename, signatureFilename); err != nil {
		log.Printf("failed to mv %s -> %s: %v", rs.draftSignatureFilename, signatureFilename, err)

		// signature failed to write, so now the roster and the signature are out of sync.
		// try to restore the backup of the roster

		if isUpdate {
			log.Printf("attempting to restore %s -> %s", rosterBackupFilename, rosterFilename)

			if err2 := os.Rename(rosterBackupFilename, rosterFilename); err2 != nil {
				return fmt.Errorf("failed to write %s (%v) *and* then failed to roll back %s (%v)",
					signatureFilename, err, rosterBackupFilename, err2)
			}
		} else {
			// the roster was brand new (it didn't exist at the start of the call) so now delete it
			// to be back in sync with the signature

			log.Printf("attempting to delete (new) %s", rosterFilename)

			_ = os.Remove(rosterFilename)
		}

		return err
	}
	rs.draftSignatureFilename = ""

	return nil
}

// DiscardDraft deletes the previously saved draft roster and signature
func (rs *RosterSaver) DiscardDraft() error {
	if rs.draftRosterFilename == "" || rs.draftSignatureFilename == "" {
		return fmt.Errorf("no draft in progress")
	}

	_ = os.Remove(rs.draftRosterFilename)
	_ = os.Remove(rs.draftSignatureFilename)

	rs.draftRosterFilename = ""
	rs.draftSignatureFilename = ""
	return nil
}

const (
	rosterFilename       = "roster.toml"
	rosterBackupFilename = "roster.toml.BAK"
	signatureFilename    = "roster.toml.asc"
)
