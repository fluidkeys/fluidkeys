package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fluidkeys/fluidkeys/fingerprint"

	"github.com/mitchellh/go-homedir"

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

const GPGMissing string = "GPG isn't working on your system 🤒\n"
const ContinueWithoutGPG string = "You can still use FluidKeys to make a key and then later import it from your backup.\n\nAlternatively, quit now [ctrl-c], install GPG then run FluidKeys again.\n"

const PromptWhichKeyFromGPG string = "Which key would you like to import?"

const Version = "0.1.5"

var (
	gpg                gpgwrapper.GnuPG
	fluidkeysDirectory string
	db                 database.Database
	Config             config.Config
	Keyring            keyring.Keyring
)

type DicewarePassword struct {
	words     []string
	separator string
}

func (d DicewarePassword) AsString() string {
	return strings.Join(d.words, d.separator)
}

type generatePgpKeyResult struct {
	pgpKey *pgpkey.PgpKey
	err    error
}

type exitCode = int

func init() {
	var err error
	fluidkeysDirectory, err = getFluidkeysDirectory()
	if err != nil {
		fmt.Printf("Failed to get fluidkeys directory: %v\n", err)
		os.Exit(1)
	}

	configPointer, err := config.Load(fluidkeysDirectory)
	if err != nil {
		fmt.Printf("Failed to open config file: %v\n", err)
		os.Exit(2)
	} else {
		Config = *configPointer
	}

	keyringPointer, err := keyring.Load()
	if err != nil {
		fmt.Printf("Failed to load keyring: %v\n", err)
		os.Exit(3)
	} else {
		Keyring = *keyringPointer
	}

	db = database.New(fluidkeysDirectory)
	gpg = gpgwrapper.GnuPG{}
	out.SetOutputToTerminal()
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

func main() {
	usage := fmt.Sprintf(`Fluidkeys %s

Configuration file: %s

Usage:
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

	args, _ := docopt.ParseDoc(usage)

	ensureCrontabStateMatchesConfig()

	switch getSubcommand(args, []string{"key"}) {
	case "init":
		os.Exit(initSubcommand(args))
	case "key":
		os.Exit(keySubcommand(args))
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
