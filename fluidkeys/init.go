package main

import (
	"fmt"
	"os"

	"github.com/fluidkeys/fluidkeys/config"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/keyring"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/mitchellh/go-homedir"
	"path/filepath"
)

func init() {
	initFluidkeysDirectory()
	initConfig()
	initKeyring()
	initDatabase()
	initGpgWrapper()
	initOutput()
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
	gpg = gpgwrapper.GnuPG{}
}

func initOutput() {
	out.SetOutputToTerminal()
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
	os.MkdirAll(fluidkeysDir, 0700)
	return fluidkeysDir, nil
}
