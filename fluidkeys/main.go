package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/fluidkeys/fluidkeys/api"
	"github.com/fluidkeys/fluidkeys/fingerprint"

	"github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/config"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/keyring"
	"github.com/fluidkeys/fluidkeys/keytableprinter"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/scheduler"
)

const Version = "0.2.5"

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
	case "init":
		os.Exit(initSubcommand(args))
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
			panic(err)
		}

		if crontabWasAdded {
			printInfo(fmt.Sprintf("Added Fluidkeys to crontab.  Edit %s to remove.", Config.GetFilename()))
		}
	} else {
		crontabWasRemoved, err := scheduler.Disable()
		if err != nil {
			panic(err)
		}

		if crontabWasRemoved {
			printInfo(fmt.Sprintf("Removed Fluidkeys from crontab.  Edit %s to add again.", Config.GetFilename()))
		}
	}
}

func getSubcommand(args docopt.Opts, subcommands []string) string {
	// subcommands := []string{"init", "key"}

	for _, subcommand := range subcommands {
		value, err := args.Bool(subcommand)
		if err != nil {
			panic(err)
		}
		if value {
			return subcommand
		}
	}
	panic(fmt.Errorf("expected to find one of these subcommands: %v", subcommands))
}

func initSubcommand(args docopt.Opts) exitCode {
	out.Print("`init` subcommand not currently implemented.\n")
	return 1
}

func keySubcommand(args docopt.Opts) exitCode {
	switch getSubcommand(args, []string{
		"create", "from-gpg", "list", "maintain",
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
			panic(err)
		}
		automatic, err := args.Bool("automatic")
		if err != nil {
			panic(err)
		}
		cronOutput, err := args.Bool("--cron-output")
		if err != nil {
			panic(err)
		}
		os.Exit(keyMaintain(dryRun, automatic, cronOutput))
	}
	panic(fmt.Errorf("keySubcommand got unexpected arguments: %v", args))
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
		panic(err)
	}

	out.Print("\n")
	keytableprinter.Print(keys)
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
		panic(err)
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
			panic(err)
		}
		os.Exit(secretSend(emailAddress))
	case "receive":
		os.Exit(secretReceive())
	}
	panic(fmt.Errorf("secretSubcommand got unexpected arguments: %v", args))
}
