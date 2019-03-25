// Copyright 2018 Paul Furley and Ian Drysdale
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

package fk

import (
	"fmt"
	"log"

	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"golang.org/x/crypto/ssh/terminal"
)

// getDecryptedPrivateKeyAndPassword prompts the user for a password, tests it
// and if successful, returns a decrypted private key and the password they
// provided.
// If the password is incorrect, it loops until they get it right.
func getDecryptedPrivateKeyAndPassword(publicKey *pgpkey.PgpKey, prompter promptForPasswordInterface) (*pgpkey.PgpKey, string, error) {
	shouldStore := Config.ShouldStorePassword(publicKey.Fingerprint())

	if shouldStore {
		if loadedPassword, gotPassword := Keyring.LoadPassword(publicKey.Fingerprint()); gotPassword == true {
			log.Printf("found password in Keyring")
			return tryPassword(loadedPassword, publicKey, prompter, shouldStore, 0)
		} // else fall-through to prompting
		log.Printf("looked for password in Keyring but couldn't find one")
	} else {
		log.Printf("key isn't supposed to have password saved (purging from Keyring)")
		if err := Keyring.PurgePassword(publicKey.Fingerprint()); err != nil {
			log.Printf("failed to purge password: %v", err)
		}

	}

	if password, err := prompter.promptForPassword(publicKey); err != nil {
		return nil, "", err
	} else {
		return tryPassword(password, publicKey, prompter, shouldStore, 0)
	}
}

func tryPassword(password string, publicKey *pgpkey.PgpKey, prompter promptForPasswordInterface, shouldStore bool, attempt int) (*pgpkey.PgpKey, string, error) {
	if privateKey, err := loadPrivateKey(publicKey.Fingerprint(), password, &gpg, &pgpkey.Loader{}); err == nil {
		if !shouldStore {
			// TODO: don't assume we can use an interactivePasswordPrompter (we might be in
			// unattended mode.) By the current logic we can't get here in unattended mode,
			// but this whole lot needs refatoring.
			prompter := interactiveYesNoPrompter{}
			if prompter.promptYesNo("Save password to "+Keyring.Name()+"?", "y", nil) {
				shouldStore = true
				Config.SetStorePassword(publicKey.Fingerprint(), true)
			}
		}
		if shouldStore {
			// save back the password since we've confirmed that it
			// was correct.
			err := Keyring.SavePassword(publicKey.Fingerprint(), password)
			if err != nil {
				log.Printf("got good password but failed to save it: %v", err)
			}
		}
		return privateKey, password, nil

	} else if isBadPasswordError(err) {
		out.Print("Password appeared to be incorrect.\n")

		if attempt < 5 {
			if password, err := prompter.promptForPassword(publicKey); err != nil {
				return nil, "", err
			} else {
				return tryPassword(password, publicKey, prompter, shouldStore, attempt+1)
			}
		} else {
			return nil, "", fmt.Errorf("too many bad password attempts")
		}
	} else {
		// different type of error
		return nil, "", fmt.Errorf("error loading private key: %v", err)
	}
}

func isBadPasswordError(err error) bool {
	switch err {
	case err.(*IncorrectPassword):
		return true
	}
	return false
}

type promptForPasswordInterface interface {
	promptForPassword(key *pgpkey.PgpKey) (string, error)
}

type interactivePasswordPrompter struct{}

// promptForPassword asks the user for a password and returns the result
func (p *interactivePasswordPrompter) promptForPassword(key *pgpkey.PgpKey) (string, error) {
	out.Print(fmt.Sprintf("Enter password for %s: ", displayName(key)))
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Panicf("Error reading password: %v", err)
	} else {
		out.Print("\n\n")
	}
	return string(password), nil
}
