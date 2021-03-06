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
	"math/rand"
	"path/filepath"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/backupzip"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/emailutils"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/scheduler"
	"github.com/fluidkeys/fluidkeys/ui"
	spin "github.com/tj/go-spin"

	"github.com/sethvargo/go-diceware/diceware"
)

const DicewareNumberOfWords int = 6
const DicewareSeparator string = "."

type dicewarePassword struct {
	words     []string
	separator string
}

func (d dicewarePassword) AsString() string {
	return strings.Join(d.words, d.separator)
}

type generatePgpKeyResult struct {
	pgpKey *pgpkey.PgpKey
	err    error
}

// keyCreate creates a new pgp key and returns it.
// If email is empty, it prompts the user for an email address
func keyCreate(email string) (exitCode, *pgpkey.PgpKey) {

	if !gpg.IsWorking() {
		out.Print(colour.Warning("\nGPG isn't working on your system 🤒\n\n"))
		out.Print("You can still use FluidKeys to make a key and then " +
			"later import it from your backup.\n\n" +
			"Alternatively, quit now [ctrl-c], install GPG then " +
			"run FluidKeys again.\n\n")
		promptForInput("Press enter to continue. ")
	}
	out.Print("\n")

	if email == "" {
		printHeader("What's your team email address?")

		out.Print("This is how other people using Fluidkeys will find you.\n\n")
		out.Print("We'll send you an email to verify your address.\n\n")

		email = promptForInput("[email] : ")
		for !emailutils.RoughlyValidateEmail(email) {
			printWarning("Not a valid email address")
			out.Print("\n")
			email = promptForInput("[email] : ")
		}
	} else {
		printHeader("Setting up " + email)

		out.Print("Other people using Fluidkeys will find you at " + email + ".\n\n")
		out.Print("We'll send you an email to verify your address.\n\n")
	}

	channel := make(chan generatePgpKeyResult)
	go generatePgpKey(email, channel)

	printHeader("Store your password")

	password := generatePassword(DicewareNumberOfWords, DicewareSeparator)

	out.Print("We've made you a strong password to protect your secrets:\n\n")
	displayPassword(password)
	if !userConfirmedRandomWord(password) {
		out.Print("Those words did not match. Here it is again:\n\n")
		displayPassword(password)
		if !userConfirmedRandomWord(password) {
			out.Print("Those words didn't match again. Quitting...\n")
			return 1, nil
		}
	}

	generateJob := <-channel

	if generateJob.err != nil {
		log.Panicf("Failed to generate key: %v", generateJob.err)
	}

	err := Config.SetPublishToAPI(generateJob.pgpKey.Fingerprint(), true)
	if err != nil {
		log.Panicf("Failed to set key to publish to API: %v", err)
	}
	err = publishKeyToAPI(generateJob.pgpKey)
	if err != nil {
		log.Panicf("Failed to publish key: %v", err)
	}

	printHeader("Verify your email")

	out.Print("You should have received a confirmation link emailed to " + email + ".\n\n")

	s := spin.New()
	spinnerTimeDelay := 100 * time.Millisecond

	timeStartedPolling := time.Now()
	timeLastPolled := time.Now()
	verifiedEmailResult := false

	log.Printf("Waiting for link to be clicked...")
	for !verifiedEmailResult {
		out.PrintDontLog("\r  " + colour.Waiting("Waiting for you to click the link") + " " + s.Next())
		time.Sleep(spinnerTimeDelay)
		if time.Since(timeLastPolled).Seconds() > 5 {
			verifiedEmailResult, err = verifyEmailMatchesKeyInAPI(
				email, generateJob.pgpKey.Fingerprint(), api)
			if err != nil {
				out.Print("\n\n")
				printFailed(fmt.Sprintf("Failed to verify email: %s", err))
				return 1, nil
			}
			timeLastPolled = time.Now()
		}
		if time.Since(timeStartedPolling).Minutes() > 15 {
			out.Print("\n")
			printFailed("Failed to detect a clicked link. Stopping waiting.")
			return 1, nil
		}
	}

	out.Print("\n\n")

	printSuccess("Successfully verified email address")
	print("\n")

	printHeader("Finishing setup")

	out.Print("🛠️  Carrying out the following tasks:\n\n")

	ui.PrintCheckboxSuccess("Generate key for " + email)

	if err = pushPrivateKeyBackToGpg(generateJob.pgpKey, password.AsString(), &gpg); err == nil {
		ui.PrintCheckboxSuccess("Store key in gpg")
	} else {
		log.Panicf("error pushing key back to gpg: %v", err)
	}

	fingerprint := generateJob.pgpKey.Fingerprint()
	if err = db.RecordFingerprintImportedIntoGnuPG(fingerprint); err != nil {
		log.Panicf("failed to record fingerprint imported into gpg: %v", err)
	}

	ui.PrintCheckboxPending("Store password in " + Keyring.Name())

	if err := tryStorePassword(generateJob.pgpKey.Fingerprint(), password.AsString()); err == nil {
		ui.PrintCheckboxSuccess("Store password in " + Keyring.Name())
	} else {
		ui.PrintCheckboxFailure("Store password in "+Keyring.Name(), err)
	}

	ui.PrintCheckboxPending("Read back password from " + Keyring.Name() +
		" " + Keyring.PermissionsInstructions())
	_, gotPassword := Keyring.LoadPassword(generateJob.pgpKey.Fingerprint())
	if gotPassword == true {
		ui.PrintCheckboxSuccess("Read back password from " + Keyring.Name())
	} else {
		ui.PrintCheckboxFailure("Read back password from "+Keyring.Name(),
			fmt.Errorf("automatic maintenance won't work"))
	}

	ui.PrintCheckboxPending("Automatically extend key annually using " + scheduler.Name())

	if err := tryMaintainAutomatically(generateJob.pgpKey.Fingerprint()); err == nil {
		ui.PrintCheckboxSuccess("Automatically extend key annually using " + scheduler.Name())
	} else {
		ui.PrintCheckboxFailure("Automatically extend key annually using "+scheduler.Name(), err)
	}

	filename, err := backupzip.OutputZipBackupFile(fluidkeysDirectory, generateJob.pgpKey, password.AsString())
	if err != nil {
		ui.PrintCheckboxFailure("Make a backup ZIP file", err)
	}
	directory, _ := filepath.Split(filename)
	ui.PrintCheckboxSuccess("Make a backup ZIP file in")
	out.Print("        " + directory + "\n")

	ui.PrintCheckboxSuccess("Register " + email + " so others can send you secrets")
	out.Print("\n")

	printSuccess("Successfully created key and registered " + email)
	out.Print("\n")

	return 0, generateJob.pgpKey
}

func generatePgpKey(email string, channel chan generatePgpKeyResult) {
	key, err := pgpkey.Generate(email, time.Now(), nil)

	channel <- generatePgpKeyResult{key, err}
}

func generatePassword(numberOfWords int, separator string) dicewarePassword {
	return dicewarePassword{
		words:     diceware.MustGenerate(numberOfWords),
		separator: separator,
	}
}

func displayPassword(password dicewarePassword) {
	out.Print(out.NoLogCharacter + "   " + colour.Info(password.AsString()) + "\n\n")
	out.Print("The password will be saved to your " + Keyring.Name() +
		" so you don't have to keep\ntyping it.\n\n")
	out.Print(colour.Warning("You should save a copy in your own password manager as a backup.\n\n"))

	promptForInput("Press enter when you've saved the password. ")
}

func userConfirmedRandomWord(password dicewarePassword) bool {
	clearScreen()
	rand.Seed(time.Now().UnixNano())
	randomIndex := rand.Intn(len(password.words))
	correctWord := password.words[randomIndex]
	wordOrdinal := humanize.Ordinal(randomIndex + 1)

	out.Print(fmt.Sprintf("Enter the %s word from your password\n\n", wordOrdinal))
	givenWord := promptForInput("[" + wordOrdinal + " word] : ")
	return givenWord == correctWord
}

type getPublicKeyInterface interface {
	GetPublicKey(email string) (string, error)
}

func verifyEmailMatchesKeyInAPI(
	email string, fingerprint fpr.Fingerprint,
	publicKeyGetter getPublicKeyInterface) (verified bool, err error) {

	armoredKey, err := publicKeyGetter.GetPublicKey(email)
	if err != nil {
		// Swallow all errors to accomodate events like intermitent wifi,
		// temporary problems with the API, etc.
		log.Printf("error polling api for public key: %v", err)
		return false, nil
	}

	retrievedKey, err := pgpkey.LoadFromArmoredPublicKey(armoredKey)
	if err != nil {
		return false, fmt.Errorf("failed to load armored key: %v", err)
	}
	if retrievedKey.Fingerprint() != fingerprint {
		return false, fmt.Errorf("a key for %s is already verified\n     Please email security@fluidkeys.com and we can manually remove the old key\n", email)
	}
	return true, nil
}

func clearScreen() {
	out.Print("\033[H\033[2J")
}
