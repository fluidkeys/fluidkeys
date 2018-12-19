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

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/fluidkeys/fluidkeys/keytable"
	"github.com/fluidkeys/fluidkeys/status"

	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/fingerprint"

	"github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/config"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/keyring"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/scheduler"
)

const Version = "0.2.6"

var (
	gpg                gpgwrapper.GnuPG
	fluidkeysDirectory string
	db                 database.Database
	Config             config.Config
	Keyring            keyring.Keyring
	client             *api.Client
)

type exitCode = int

func main() {
	usage := fmt.Sprintf(`Fluidkeys %s

Configuration file: %s

Usage:
	fk secret send <recipient-email-address>
	fk secret receive
	fk key create
	fk key from-gpg
	fk key list
	fk key maintain [--dry-run]
	fk key maintain automatic [--cron-output]
	fk key publish

Options:
	-h --help         Show this screen
	   --dry-run      Don't change anything: only output what would happen
	   --cron-output  Only print output on errors`, // TODO: Document `automatic`
		Version,
		Config.GetFilename(),
	)

	log.Print("$ " + strings.Join(os.Args, " "))
	args, _ := docopt.ParseDoc(usage)

	ensureCrontabStateMatchesConfig()

	switch getSubcommand(args, []string{"key", "secret"}) {
	case "key":
		os.Exit(keySubcommand(args))
	case "secret":
		os.Exit(secretSubcommand(args))
	}
}

func ensureCrontabStateMatchesConfig() {
	if Config.RunFromCron() {
		crontabWasAdded, err := scheduler.Enable()
		if err != nil {
			log.Panic(err)
		}

		if crontabWasAdded {
			printInfo(fmt.Sprintf("Added Fluidkeys to crontab.  Edit %s to remove.", Config.GetFilename()))
		}
	} else {
		crontabWasRemoved, err := scheduler.Disable()
		if err != nil {
			log.Panic(err)
		}

		if crontabWasRemoved {
			printInfo(fmt.Sprintf("Removed Fluidkeys from crontab.  Edit %s to add again.", Config.GetFilename()))
		}
	}
}

func getSubcommand(args docopt.Opts, subcommands []string) string {
	for _, subcommand := range subcommands {
		value, err := args.Bool(subcommand)
		if err != nil {
			log.Panic(err)
		}
		if value {
			return subcommand
		}
	}
	log.Panicf("expected to find one of these subcommands: %v", subcommands)
	panic(nil)
}

func keySubcommand(args docopt.Opts) exitCode {
	switch getSubcommand(args, []string{
		"create", "from-gpg", "list", "maintain", "publish",
	}) {
	case "create":
		os.Exit(keyCreate())
	case "from-gpg":
		os.Exit(keyFromGpg())
	case "list":
		os.Exit(keyList())
	case "maintain":
		dryRun, err := args.Bool("--dry-run")
		if err != nil {
			log.Panic(err)
		}
		automatic, err := args.Bool("automatic")
		if err != nil {
			log.Panic(err)
		}
		cronOutput, err := args.Bool("--cron-output")
		if err != nil {
			log.Panic(err)
		}
		os.Exit(keyMaintain(dryRun, automatic, cronOutput))
	case "publish":
		os.Exit(keyPublish())
	}
	log.Panicf("keySubcommand got unexpected arguments: %v", args)
	panic(nil)
}

func loadPgpKeys() ([]pgpkey.PgpKey, error) {
	fingerprints, err := db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	var keys []pgpkey.PgpKey

	for _, fingerprint := range fingerprints {
		pgpKey, err := loadPgpKey(fingerprint)
		if err != nil {
			log.Printf("error loading key with fingerprint '%s': %v", fingerprint.Hex(), err)
			continue // skip this key. TODO: log?
		}
		keys = append(keys, *pgpKey)
	}
	sort.Sort(pgpkey.ByCreated(keys))
	return keys, nil
}

func loadPgpKey(fingerprint fingerprint.Fingerprint) (*pgpkey.PgpKey, error) {
	armoredPublicKey, err := gpg.ExportPublicKey(fingerprint)
	if err != nil {
		return nil, err
	}

	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
	if err != nil {
		return nil, err
	}
	return pgpKey, nil
}

func keyList() exitCode {
	keys, err := loadPgpKeys()
	if err != nil {
		log.Panic(err)
	}

	out.Print("\n")

	keysWithWarnings := []keytable.KeyWithWarnings{}

	for i := range keys {
		key := &keys[i]

		keyWithWarnings := keytable.KeyWithWarnings{
			Key:      key,
			Warnings: status.GetKeyWarnings(*key, &Config),
		}
		keysWithWarnings = append(keysWithWarnings, keyWithWarnings)
	}

	out.Print(keytable.Format(keysWithWarnings))
	return 0
}

func displayName(key *pgpkey.PgpKey) string {
	displayName, err := key.Email()
	if err != nil {
		displayName = fmt.Sprintf("%s", key.Fingerprint())
	}
	return colour.Info(displayName)
}

func promptForInputWithPipes(prompt string, reader *bufio.Reader) string {
	out.Print(prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Panic(err)
	}
	out.Print("\n")
	return strings.TrimRight(response, "\n")
}

func promptForInput(prompt string) string {
	return promptForInputWithPipes(prompt, bufio.NewReader(os.Stdin))
}

func secretSubcommand(args docopt.Opts) exitCode {
	switch getSubcommand(args, []string{
		"send", "receive",
	}) {
	case "send":
		emailAddress, err := args.String("<recipient-email-address>")
		if err != nil {
			log.Panic(err)
		}
		os.Exit(secretSend(emailAddress))
	case "receive":
		os.Exit(secretReceive())
	}
	log.Panicf("secretSubcommand got unexpected arguments: %v", args)
	panic(nil)
}
