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
	"os"

	"path/filepath"

	"github.com/fluidkeys/fluidkeys/apiclient"
	"github.com/fluidkeys/fluidkeys/config"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/keyring"
	"github.com/fluidkeys/fluidkeys/out"
	userpackage "github.com/fluidkeys/fluidkeys/user"
	"github.com/mitchellh/go-homedir"
)

func init() {
	initFluidkeysDirectory()
	initOutput()
	initConfig()
	initKeyring()
	initDatabase()
	initGpgWrapper()
	initAPIClient()
	initUser()
}

func initFluidkeysDirectory() {
	var err error
	fluidkeysDirectory, err = getFluidkeysDirectory()
	if err != nil {
		fmt.Printf("Failed to get fluidkeys directory: %v\n", err)
		os.Exit(1)
	}
}

func initConfig() {
	configPointer, err := config.Load(fluidkeysDirectory)
	if err != nil {
		fmt.Printf("Failed to open config file: %v\n", err)
		os.Exit(2)
	} else {
		Config = *configPointer
	}
}

func initKeyring() {
	keyringPointer, err := keyring.Load()
	if err != nil {
		fmt.Printf("Failed to load keyring: %v\n", err)
		os.Exit(3)
	} else {
		Keyring = *keyringPointer
	}
}

func initDatabase() {
	db = database.New(fluidkeysDirectory)
}

func initGpgWrapper() {
	gpgPointer, err := gpgwrapper.Load()
	if err != nil {
		fmt.Printf("Failed to load GnuPG: %v\n", err)
		os.Exit(4)
	} else {
		gpg = *gpgPointer
	}
}

func initOutput() {
	if err := out.Load(fluidkeysDirectory); err != nil {
		log.Panic(err)
	}
}

func initAPIClient() {
	client = apiclient.New(Version)
}

func initUser() {
	user = userpackage.New(fluidkeysDirectory, &db)
}

func getFluidkeysDirectory() (string, error) {
	dirFromEnv := os.Getenv("FLUIDKEYS_DIR")

	if dirFromEnv != "" {
		return dirFromEnv, nil
	} else {
		return makeFluidkeysHomeDirectory()
	}
}

func makeFluidkeysHomeDirectory() (string, error) {
	homeDirectory, err := homedir.Dir()

	if err != nil {
		return "", err
	}

	fluidkeysDir := filepath.Join(homeDirectory, ".config", "fluidkeys")
	err = os.MkdirAll(fluidkeysDir, 0700)
	if err != nil {
		return "", err
	}

	return fluidkeysDir, nil
}
