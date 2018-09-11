package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"

	"github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/backupzip"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/database"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/sethvargo/go-diceware/diceware"
)

const DicewareNumberOfWords int = 6
const DicewareSeparator string = "."

const GPGMissing string = "GPG isn't working on your system 🤒\n"
const ContinueWithoutGPG string = "You can still use FluidKeys to make a key and then later import it from your backup.\n\nAlternatively, quit now [ctrl-c], install GPG then run FluidKeys again.\n"
const PromptPressEnter string = "Press enter to continue"

const PromptEmail string = "To start using Fluidkeys, first you'll need to create a key.\n\nEnter your email address, this will help other people find your key.\n"
const PromptFirstPassword string = "This is your password.\n\n* If you use a password manager, save it there now\n* Otherwise write it on a piece of paper and keep it with you\n"
const PromptLastPassword string = "That didn't match 🤷🏽 This is your last chance!\n"
const FailedToConfirmPassword string = "That didn't match. Quitting...\n"

const PromptWhichKeyFromGPG string = "Which key would you like to import?"

const Version = "0.1.1"

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

func main() {
	usage := fmt.Sprintf(`Fluidkeys %s

Usage:
	fk key create
	fk key from-gpg
	fk key list

Options:
	-h --help    Show this screen`, Version)

	args, _ := docopt.ParseDoc(usage)

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
	fmt.Println("`init` subcommand not currently implemented.")
	return 1
}

func keySubcommand(args docopt.Opts) exitCode {
	switch getSubcommand(args, []string{"create", "from-gpg", "list"}) {
	case "create":
		os.Exit(keyCreate())
	case "from-gpg":
		os.Exit(keyFromGpg())
	case "list":
		os.Exit(keyList())
	}
	panic(fmt.Errorf("keySubcommand got unexpected arguments: %v", args))
}

func keyFromGpg() exitCode {
	fluidkeysDirectory, err := getFluidkeysDirectory()
	if err != nil {
		fmt.Printf("Failed to get fluidkeys directory: %v\n", err)
		return 1
	}
	db := database.New(fluidkeysDirectory)
	gpg := gpgwrapper.GnuPG{}

	availableKeys, err := keysAvailableToGetFromGpg(db, gpg)
	if err != nil {
		fmt.Printf("Failed to list available keys: %v", err)
		return 1
	}

	if len(availableKeys) == 0 {
		fmt.Printf("No secret keys found in GPG\n")
		return 1
	}

	fmt.Printf(formatListedKeysForImportingFromGpg(availableKeys))
	keyToImport := promptForKeyToImportFromGpg(availableKeys)

	if keyToImport == nil {
		fmt.Printf("No key selected to link\n")
		return 0
	}

	db.RecordFingerprintImportedIntoGnuPG(keyToImport.Fingerprint)
	fmt.Printf("The key has been linked to Fluidkeys\n")
	return 0
}

// keysAvailableToGetFromGpg returns a filtered slice of SecretKeyListings, removing
// any keys that Fluidkeys is already managing.
func keysAvailableToGetFromGpg(db database.Database, gpg gpgwrapper.GnuPG) ([]gpgwrapper.SecretKeyListing, error) {

	importedFingerprints, err := db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, fmt.Errorf("Failed to get fingerprints from database: %v\n", err)
	}

	var availableKeys []gpgwrapper.SecretKeyListing

	allGpgKeys, err := gpg.ListSecretKeys()
	if err != nil {
		return nil, fmt.Errorf("Error getting secret keys from GPG: %v", err)
	}

	for _, key := range allGpgKeys {
		if !fingerprint.Contains(importedFingerprints, key.Fingerprint) {
			availableKeys = append(availableKeys, key)
		}
	}
	return availableKeys, nil
}

func loadPgpKeys(db database.Database) ([]pgpkey.PgpKey, error) {
	fingerprints, err := db.GetFingerprintsImportedIntoGnuPG()
	if err != nil {
		return nil, err
	}

	gpg := gpgwrapper.GnuPG{}

	var keys []pgpkey.PgpKey

	for _, fingerprint := range fingerprints {
		armoredPublicKey, err := gpg.ExportPublicKey(fingerprint)
		if err != nil {
			continue // skip this key. TODO: log?
		}

		pgpKey, err := pgpkey.LoadFromArmoredPublicKey(armoredPublicKey)
		if err != nil {
			continue // skip this key. TODO: log?
		}
		keys = append(keys, *pgpKey)
	}
	return keys, nil
}

func keyCreate() exitCode {

	gpg := gpgwrapper.GnuPG{}
	if !gpg.IsWorking() {
		fmt.Printf(colour.Warn("\n" + GPGMissing + "\n"))
		fmt.Printf(ContinueWithoutGPG)
		promptForInput("Press enter to continue. ")
	}
	email := promptForEmail()
	channel := make(chan generatePgpKeyResult)
	go generatePgpKey(email, channel)

	password := generatePassword(DicewareNumberOfWords, DicewareSeparator)

	displayPassword(PromptFirstPassword, password)
	if !userConfirmedRandomWord(password) {
		displayPassword(PromptLastPassword, password)
		if !userConfirmedRandomWord(password) {
			fmt.Printf(FailedToConfirmPassword)
			os.Exit(1)
		}
	}

	fmt.Println("Generating key for", email)
	fmt.Println()

	generateJob := <-channel

	if generateJob.err != nil {
		panic(fmt.Sprint("Failed to generate key: ", generateJob.err))
	}

	publicKey, err := generateJob.pgpKey.Armor()
	if err != nil {
		panic(fmt.Sprint("Failed to output public key: ", err))
	}

	privateKey, err := generateJob.pgpKey.ArmorPrivate(password.AsString())
	if err != nil {
		panic(fmt.Sprint("Failed to output private key: ", err))
	}

	revocationCert, err := generateJob.pgpKey.ArmorRevocationCertificate()
	if err != nil {
		panic(fmt.Sprint("Failed to output revocation cert: ", err))
	}

	fluidkeysDirectory, err := getFluidkeysDirectory()

	if err != nil {
		fmt.Printf("Failed to get fluidkeys directory")
	}

	keySlug, err := generateJob.pgpKey.Slug()
	if err != nil {
		panic(fmt.Sprintf("Failed to get slug for key to work out backup location"))
	}

	_, err = backupzip.OutputZipBackupFile(
		fluidkeysDirectory,
		keySlug,
		publicKey,
		privateKey,
		revocationCert,
	)
	if err != nil {
		fmt.Printf("Failed to create backup ZIP file: %s", err)
	}
	fmt.Printf("Full key backup saved to %s\n", fluidkeysDirectory)

	gpg.ImportArmoredKey(publicKey)
	gpg.ImportArmoredKey(privateKey)
	fmt.Println("The new key has been imported into GnuPG, inspect it with:")
	fmt.Printf(" > gpg --list-keys '%s'\n", email)

	db := database.New(fluidkeysDirectory)
	db.RecordFingerprintImportedIntoGnuPG(generateJob.pgpKey.Fingerprint())
	return 0
}

func keyList() exitCode {
	fluidkeysDirectory, err := getFluidkeysDirectory()
	if err != nil {
		fmt.Printf("Failed to get fluidkeys directory")
	}
	db := database.New(fluidkeysDirectory)

	keys, err := loadPgpKeys(db)
	if err != nil {
		panic(err)
	}

	emailAddressColumnWidth := len("Email address")

	for _, key := range keys {
		for _, id := range key.Identities {
			emailAddressColumnWidth = Max(emailAddressColumnWidth, len(id.Name))
		}
	}

	createdColumnWidth := len("31 May 2018")
	nextRotationColumnWidth := len("Next rotation")

	header := fmt.Sprintf("%-*s  ", emailAddressColumnWidth, "Email address")
	header += fmt.Sprintf("%-*s  ", createdColumnWidth, "Created")
	header += fmt.Sprintf("%-*s  ", nextRotationColumnWidth, "Next rotation")

	fmt.Printf("%s\n", colour.LightBlue(header))

	printHorizontalRule(emailAddressColumnWidth, createdColumnWidth, nextRotationColumnWidth)

	for _, key := range keys {
		firstRow := true
		for id := range key.Identities {
			if firstRow {
				fmt.Printf("%-*s  ", emailAddressColumnWidth, id)
				fmt.Printf("%-*s  ", createdColumnWidth, key.PrimaryKey.CreationTime.Format("2 Jan 2006"))
				fmt.Printf("\n")
				firstRow = false
			} else {
				fmt.Printf("%s\n", id)
			}

		}
		printHorizontalRule(emailAddressColumnWidth, createdColumnWidth, nextRotationColumnWidth)
	}

	return 0
}

func printHorizontalRule(columnWidths ...int) {
	for _, columnWidth := range columnWidths {
		fmt.Printf("%s  ", strings.Repeat("─", columnWidth))
	}
	fmt.Printf("\n")
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

func generatePgpKey(email string, channel chan generatePgpKeyResult) {
	key, err := pgpkey.Generate(email)

	channel <- generatePgpKeyResult{key, err}
}

func formatListedKeysForImportingFromGpg(secretKeyListings []gpgwrapper.SecretKeyListing) string {
	str := fmt.Sprintf("Found %s in GnuPG:\n\n", humanize.Pluralize(len(secretKeyListings), "key", "keys"))
	for index, key := range secretKeyListings {
		str += printSecretKeyListing(index+1, key)
	}
	return str
}

func printSecretKeyListing(listNumber int, key gpgwrapper.SecretKeyListing) string {
	formattedListNumber := colour.LightBlue(fmt.Sprintf("%-4s", (strconv.Itoa(listNumber) + ".")))
	output := fmt.Sprintf("%s%s\n", formattedListNumber, key.Fingerprint)
	output += fmt.Sprintf("    Created on %s\n", key.Created.Format("2 January 2006"))
	for _, uid := range key.Uids {
		output += fmt.Sprintf("      %v\n", uid)
	}
	output += fmt.Sprintf("\n")
	return output
}

func promptForKeyToImportFromGpg(secretKeyListings []gpgwrapper.SecretKeyListing) *gpgwrapper.SecretKeyListing {
	var selectedKey int
	if len(secretKeyListings) == 1 {
		onlyKey := secretKeyListings[0]
		if promptToConfirmImportKeyFromGpg(onlyKey) {
			return &onlyKey
		} else {
			return nil
		}
	} else {
		invalidEntry := fmt.Sprintf("Please select between 1 and %v.\n", len(secretKeyListings))
		for validInput := false; !validInput; {
			rangePrompt := colour.LightBlue(fmt.Sprintf("[1-%v]", len(secretKeyListings)))
			input := promptForInput(fmt.Sprintf(PromptWhichKeyFromGPG + " " + rangePrompt + " "))
			if integerSelected, err := strconv.Atoi(input); err != nil {
				fmt.Print(invalidEntry)
			} else {
				if (integerSelected >= 1) && (integerSelected <= len(secretKeyListings)) {
					selectedKey = integerSelected - 1
					validInput = true
				} else {
					fmt.Print(invalidEntry)
				}
			}
		}
		return &secretKeyListings[selectedKey]
	}
}

func promptToConfirmImportKeyFromGpg(key gpgwrapper.SecretKeyListing) bool {
	for {
		input := promptForInput("Import key? [Y/n] ")
		switch strings.ToLower(input) {
		case "":
			return true
		case "y":
			return true
		case "n":
			return false
		default:
			fmt.Printf("Please select only Y or N.\n")
		}
	}
}

func promptForInputWithPipes(prompt string, reader *bufio.Reader) string {
	fmt.Printf("\n" + prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	fmt.Print("\n")
	return strings.TrimRight(response, "\n")
}

func promptForInput(prompt string) string {
	return promptForInputWithPipes(prompt, bufio.NewReader(os.Stdin))
}

func promptForEmail() string {
	fmt.Print(PromptEmail)
	return promptForInput("[email] : ")
}

func generatePassword(numberOfWords int, separator string) DicewarePassword {
	return DicewarePassword{
		words:     diceware.MustGenerate(numberOfWords),
		separator: separator,
	}
}

func displayPassword(message string, password DicewarePassword) {
	fmt.Printf(message)
	fmt.Printf("\n  %v\n", colour.LightBlue(password.AsString()))

	promptForInput("Press enter when you've written it down. ")
}

func userConfirmedRandomWord(password DicewarePassword) bool {
	clearScreen()
	rand.Seed(time.Now().UnixNano())
	randomIndex := rand.Intn(len(password.words))
	correctWord := password.words[randomIndex]
	wordOrdinal := humanize.Ordinal(randomIndex + 1)

	fmt.Printf("Enter the %s word from your password\n", wordOrdinal)
	givenWord := promptForInput("[" + wordOrdinal + " word] : ")
	return givenWord == correctWord
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// Max returns the larger of x or y.
func Max(x, y int) int {
	if x < y {
		return y
	}
	return x
}
