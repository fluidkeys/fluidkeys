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
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/fluidkeys/fluidkeys/emailutils"
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

const Version = "0.4.0"

var (
	gpg                gpgwrapper.GnuPG
	fluidkeysDirectory string
	db                 database.Database
	Config             config.Config
	Keyring            keyring.Keyring
	client             *api.Client
)

type exitCode = int

func Main() exitCode {
	usage := fmt.Sprintf(`Fluidkeys %s

Configuration file: %s
          Log file: %s

Usage:
	fk setup
	fk setup <email>
	fk secret send <recipient-email>
	fk secret send [<filename>] --to=<email>
	fk secret receive
	fk key create
	fk key from-gpg
	fk key list
	fk key maintain [--dry-run]
	fk key maintain automatic [--cron-output]
	fk key upload

Options:
	-h --help         Show this screen
	   --dry-run      Don't change anything: only output what would happen
	   --cron-output  Only print output on errors`, // TODO: Document `automatic`
		Version,
		Config.GetFilename(),
		out.GetLogFilename(),
	)

	log.Print("$ " + strings.Join(os.Args, " "))
	args, _ := docopt.ParseDoc(usage)

	ensureCrontabStateMatchesConfig()

	cronOutput, err := args.Bool("--cron-output")
	if err != nil {
		log.Panic(err)
	}

	if cronOutput {
		out.SetOutputToBuffer()
	}
	var code exitCode

	switch getSubcommand(args, []string{"key", "secret", "setup"}) {
	case "key":
		code = keySubcommand(args)

	case "secret":
		code = secretSubcommand(args)

	case "setup":
		code = setupSubcommand(args)

	default:
		out.Print("unhandled subcommand")
		code = 1
	}

	if cronOutput && code != 0 {
		// cron treats no output to stdout as success. if a command outputs anything
		// it treats this as a failure and typically sends an email.
		// so, when running in cron mode, only print anything to terminal in the event of
		// an error, eg the command was unsuccessful.
		out.PrintTheBuffer()
	}

	return code
}

func ensureCrontabStateMatchesConfig() {
	shouldEnable, err := shouldEnableScheduler()
	if err != nil {
		log.Panic(err)
	}

	if shouldEnable {
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
			printInfo(fmt.Sprintf("Removed Fluidkeys from crontab.  Edit %s to add again.",
				Config.GetFilename()))
		}
	}
}

// shouldEnableScheduler returns true if both the config allows 'run from cron' *and* at least
// one key is set to maintain automatically
func shouldEnableScheduler() (bool, error) {
	if !Config.RunFromCron() {
		return false, nil
	}

	keys, err := loadPgpKeys()
	if err != nil {
		return false, err
	}

	for _, key := range keys {
		if Config.ShouldMaintainAutomatically(key.Fingerprint()) {
			return true, nil
		}
	}
	return false, nil
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
		"create", "from-gpg", "list", "maintain", "upload",
	}) {
	case "create":
		exitCode, _ := keyCreate("")
		return exitCode

	case "from-gpg":
		return keyFromGpg()

	case "list":
		return keyList()

	case "maintain":
		dryRun, err := args.Bool("--dry-run")
		if err != nil {
			log.Panic(err)
		}
		automatic, err := args.Bool("automatic")
		if err != nil {
			log.Panic(err)
		}
		return keyMaintain(dryRun, automatic)

	case "upload":
		return keyUpload()
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
		emailAddress, err := args.String("<recipient-email>")
		if err == nil {
			// They used the deprecated single-argument form, e.g.
			// `fk secret send <email>`

			if !emailutils.RoughlyValidateEmail(emailAddress) {
				// They probably passed a filename rather than an email address:
				// `fk secret send secret.txt`

				printFailed("That doesn't look like an email address.")
				out.Print("     Were you trying to send a file?\n\n")
				out.Print("     > " + colour.CommandLineCode(
					"fk secret send "+emailAddress+" --to=<email>\n\n"))
				return 1
			} else {
				// They used the deprecated form for an email: warn them that
				// it's deprecated, but work anyway.

				out.Print("\n")
				printFailed("That format is deprecated and will be removed.")
				out.Print("     Please run this command next time:\n")

				out.Print("     > " + colour.CommandLineCode(
					"fk secret send --to="+emailAddress+"\n\n"))
			}
		} else if emailAddress, err = args.String("--to"); err != nil {
			log.Panic(err)
		}

		filename, err := args.String("<filename>")
		if err != nil {
			// Case 1: `fk secret send --to=someone@example.com`
			// ... read from stdin

			return secretSend(emailAddress, "")
		} else {
			// Case 2: `fk secret send secret.txt --to=someone@example.com`
			// ... read from secret.txt

			return secretSend(emailAddress, filename)
		}

	case "receive":
		return secretReceive()
	}
	log.Panicf("secretSubcommand got unexpected arguments: %v", args)
	panic(nil)
}

func setupSubcommand(args docopt.Opts) exitCode {
	if args["<email>"] == nil {
		return setup("")
	}
	email, err := args.String("<email>")
	if err != nil {
		log.Panic(err)
	}
	if email != "" && !emailutils.RoughlyValidateEmail(email) {
		printFailed(email + " isn't a valid email address")
		return 1
	}
	return setup(email)
}
