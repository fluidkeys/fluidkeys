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
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/archiver"
	"github.com/fluidkeys/fluidkeys/backupzip"
	"github.com/fluidkeys/fluidkeys/colour"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/scheduler"
	"github.com/fluidkeys/fluidkeys/status"
	"github.com/fluidkeys/fluidkeys/ui"
)

func keyMaintain(dryRun bool, automatic bool) exitCode {
	keys, err := loadPgpKeys()
	if err != nil {
		log.Panic(err)
	}

	if dryRun {
		return runKeyMaintainDryRun(keys)
	} else {
		var yesNoPrompter promptYesNoInterface
		var passwordPrompter promptForPasswordInterface

		if automatic {
			yesNoPrompter = &automaticResponder{}
			passwordPrompter = &alwaysFailPasswordPrompter{}
		} else {
			yesNoPrompter = &interactiveYesNoPrompter{}
			passwordPrompter = &interactivePasswordPrompter{}
		}

		return runKeyMaintain(keys, yesNoPrompter, passwordPrompter)
	}
}

var (
	nothingToDo string = colour.Success("✔ All keys look good — nothing to do.\n")
)

func runKeyMaintainDryRun(keys []pgpkey.PgpKey) exitCode {
	out.Print("\n")
	keyTasks := makeKeyTasks(keys)

	if len(keyTasks) == 0 {
		out.Print(nothingToDo)
		return 0 // success! nothing to do
	}

	for i := range keyTasks {
		var keyTask *keyTask = keyTasks[i]
		addImportExportActions(keyTask, nil)
		out.Print(formatKeyWarnings(*keyTask))
		out.Print(formatKeyActions(*keyTask))
	}

	if len(keyTasks) > 1 {
		out.Print("You’ll be asked to confirm for each key.\n\n")
	}

	out.Print("Before running these actions, Fluidkeys makes a backup of " + colour.Cmd("gpg") + ".\n")
	out.Print(colour.Warning("Changes can only be undone by restoring from the backup.\n\n"))

	out.Print("Fix these issues by running:\n")
	out.Print("    " + colour.Cmd("fk key maintain") + "\n\n")
	return 0
}

type keyTask struct {
	key      *pgpkey.PgpKey
	warnings []status.KeyWarning
	actions  []status.KeyAction
	password string

	// err is used to record any errors encountered while running actions
	// if nil, no errors were encountered
	err error
}

var (
	promptBackupAndRunActions   = "Make a backup of " + colour.Cmd("gpg") + " and run these actions?"
	promptRunActions            = "Run these actions?"
	promptMaintainAutomatically = "Automatically maintain this key from now on?"
)

type promptYesNoInterface interface {
	promptYesNo(message string, defaultResponse string, key *pgpkey.PgpKey) bool
}

type interactiveYesNoPrompter struct{}

func (iP *interactiveYesNoPrompter) promptYesNo(message string, defaultInput string, key *pgpkey.PgpKey) bool {
	var options string
	switch strings.ToLower(defaultInput) {
	case "y":
		options = "[Y/n]"
	case "n":
		options = "[y/N]"
	default:
		options = "[y/n]"
	}
	messageWithOptions := message + " " + options + " "
	for {
		input := promptForInput(messageWithOptions)
		if input == "" {
			input = defaultInput
		}
		switch strings.ToLower(input) {
		case "y":
			return true
		case "n":
			return false
		default:
			out.Print("Please select only Y or N.\n")
		}
	}
}

type automaticResponder struct{}

func (aR *automaticResponder) promptYesNo(message string, defaultResponse string, key *pgpkey.PgpKey) bool {
	switch message {

	case promptBackupAndRunActions, promptRunActions:
		if key == nil {
			log.Panic("promptYesNo called with nil key pointer")
		}
		return Config.ShouldStorePassword(key.Fingerprint()) &&
			Config.ShouldMaintainAutomatically(key.Fingerprint())

	case promptMaintainAutomatically:
		log.Panic("prompting to maintain key automatically, but it should be set and therefore not prompt")
		panic(nil)

	default:
		log.Panicf("don't know how to automatically respond to: '%s'", message)
		panic(nil)
	}
}

// alwaysFailPasswordPrompter can be used for automatic running, where it's
// impossible to prompt for a password. If a password prompt is required
// (because we didn't get it from the keychain or config), it falls through to
// here, which fails.
type alwaysFailPasswordPrompter struct{}

// promptForPassword always returns an empty string
func (p *alwaysFailPasswordPrompter) promptForPassword(key *pgpkey.PgpKey) (string, error) {
	return "", fmt.Errorf("can't prompt for password when running unattended")
}

func runKeyMaintain(keys []pgpkey.PgpKey, prompter promptYesNoInterface, passwordPrompter promptForPasswordInterface) exitCode {
	out.Print("\n")
	keyTasks := makeKeyTasks(keys)

	if len(keyTasks) == 0 {
		out.Print(nothingToDo)
		return 0 // success! nothing to do
	}

	for i := range keyTasks {
		var keyTask *keyTask = keyTasks[i]
		addImportExportActions(keyTask, passwordPrompter)
	}

	var backupCreatedAlready bool = false

	for i := range keyTasks {
		var keyTask *keyTask = keyTasks[i]

		out.Print(formatKeyWarnings(*keyTask))
		out.Print(formatKeyActions(*keyTask))

		skipBackup := backupCreatedAlready
		ranActionsSuccesfully := promptToBackupAndRunActions(prompter, keyTask, skipBackup)

		if ranActionsSuccesfully {
			backupCreatedAlready = true
		}

		if ranActionsSuccesfully && !Config.ShouldMaintainAutomatically(keyTask.key.Fingerprint()) {
			promptAndTurnOnMaintainAutomatically(prompter, *keyTask)
		}
	}

	if anyTasksHaveErrors(keyTasks) {
		out.Print(colour.Error("Encountered errors while running maintain:\n\n"))

		for _, keyTask := range keyTasks {
			if keyTask.err != nil {
				out.Print("    " + displayName(keyTask.key) + ": " + colour.Error(keyTask.err.Error()) + "\n")
			}
		}
		out.Print("\n")
		return 1
	} else {
		out.Print(colour.Success("Maintenance complete.") + "\n\n")

		var numKeysNotPublished = 0
		for _, keyTask := range keyTasks {
			if !Config.ShouldPublishToAPI(keyTask.key.Fingerprint()) {
				numKeysNotPublished += 1
			}
		}
		if numKeysNotPublished > 0 {

			out.Print(
				fmt.Sprintf(" " + colour.Warning("▸   "+
					humanize.Pluralize(numKeysNotPublished, "key hasn't", "keys haven't")+
					" been uploaded to Fluidkeys.\n\n")))
			out.Print("Make sure others can send you secrets by running:\n")
			out.Print("    " + colour.Cmd("fk key upload") + "\n\n")
		}

		return 0
	}
}

func addImportExportActions(keytask *keyTask, passwordPrompter promptForPasswordInterface) {
	keytask.actions = prepend(keytask.actions, loadPrivateKeyFromGnupg{passwordGetter: passwordPrompter})
	keytask.actions = append(keytask.actions, pushIntoGnupg{})
	keytask.actions = append(keytask.actions, updateBackupZIP{})

	if Config.ShouldPublishToAPI(keytask.key.Fingerprint()) {
		keytask.actions = append(keytask.actions, publishToAPI{})
	}
}

func prepend(actions []status.KeyAction, actionToPrepend status.KeyAction) []status.KeyAction {
	return append([]status.KeyAction{actionToPrepend}, actions...)
}

func anyTasksHaveErrors(keyTasks []*keyTask) bool {
	for _, keyTask := range keyTasks {
		if keyTask.err != nil {
			return true
		}
	}

	return false
}

func makeKeyTasks(keys []pgpkey.PgpKey) []*keyTask {
	var keyTasks []*keyTask

	for i := range keys {
		key := &keys[i] // get a pointer here, not in the `for` expression
		warnings := status.GetKeyWarnings(*key, &Config)
		actions := status.MakeActionsFromWarnings(warnings, time.Now())

		if len(actions) > 0 {
			keyTask := keyTask{
				key:      key,
				warnings: warnings,
				actions:  actions,
			}
			keyTasks = append(keyTasks, &keyTask)
		}
	}
	return keyTasks
}

func promptToBackupAndRunActions(prompter promptYesNoInterface, keyTask *keyTask, skipBackup bool) (ranActionsSuccessfully bool) {
	skipDueToError := func(err error) {
		keyTask.err = err
		out.Print("     " + colour.Warning("Skipping remaining actions for") + " " + displayName(keyTask.key) + "\n\n")
		ranActionsSuccessfully = false
	}

	skip := func() {
		out.Print(colour.Disabled(" ▸   OK, skipped.\n\n"))
		ranActionsSuccessfully = false
	}

	if skipBackup {
		if prompter.promptYesNo(promptRunActions, "y", keyTask.key) == false {
			skip()
			return
		}
	} else {
		if prompter.promptYesNo(promptBackupAndRunActions, "y", keyTask.key) == false {
			skip()
			return
		}

		if err := backupGpg(); err != nil {
			skipDueToError(err)
			return
		}
	}

	if err := runActions(keyTask); err != nil {
		skipDueToError(err)
		return

	} else {
		out.Print(colour.Success(" ▸   Successfully updated keys for " + displayName(keyTask.key) + "\n\n"))
		ranActionsSuccessfully = true
		return
	}
}

func backupGpg() error {
	filename, err := makeGnupgBackup(time.Now())
	if err != nil {
		printFailed("Failed to make a backup:")
		out.Print("     " + colour.Failure(err.Error()) + "\n\n")
		return err
	} else {
		printSuccess("Successfully made a backup to:")
		out.Print("     " + colour.Info(filename) + "\n\n")
		return nil
	}
}

func promptAndTurnOnMaintainAutomatically(prompter promptYesNoInterface, keyTask keyTask) {

	out.Print("Fluidkeys can maintain this key automatically using " + colour.Cmd("cron") + ".\n")
	out.Print("This requires storing the password in the system keyring.\n\n")

	if prompter.promptYesNo(promptMaintainAutomatically, "", keyTask.key) == true {
		if err := tryStorePassword(keyTask.key.Fingerprint(), keyTask.password); err == nil {
			printSuccess("Stored password in " + Keyring.Name())
		} else {
			printFailed("Failed to store password in " + Keyring.Name())
			return
		}

		if err := tryMaintainAutomatically(keyTask.key.Fingerprint()); err == nil {
			printSuccess("Successfully set up automatic maintenance")
			out.Print("\n")
		} else {
			printFailed("Failed to set up automatic maintenance")
			out.Print("\n")
		}
	} else {
		out.Print(colour.Disabled(" ▸   OK, skipped.\n\n"))
	}
}

func runActions(keyTask *keyTask) error {
	for _, action := range keyTask.actions {
		ui.PrintCheckboxPending(action.String())

		var err error
		err = action.Enact(keyTask.key, time.Now(), &keyTask.password)
		if err != nil {
			ui.PrintCheckboxFailure(action.String(), err)
			return err // don't run any more actions

		} else {
			ui.PrintCheckboxSuccess(action.String())
		}
	}
	out.Print("\n")
	return nil
}

func makeGnupgBackup(now time.Time) (string, error) {
	filepath, err := archiver.MakeFilePath("gpghome", "tgz", fluidkeysDirectory, now)
	if err != nil {
		return "", err
	}

	filename, err := gpg.BackupHomeDir(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to call gpg.BackupHomeDir: %v", err)
	}
	return filename, err
}

// formatKeyWarnings outputs a header for the key as follows:
//
// 2 issues for foo@example.com:
//
// ▸   Encryption subkey overdue for rotation, expires in 5 days
// ▸   Primary key set to expire too far in the future
func formatKeyWarnings(keyTask keyTask) (header string) {
	if len(keyTask.warnings) == 0 {
		return
	}

	header += "Fluidkeys found " + humanize.Pluralize(len(keyTask.warnings), "issue", "issues") +
		" for " + colour.Info(displayName(keyTask.key)) + ":\n\n"

	for _, warning := range keyTask.warnings {
		header += fmt.Sprintf(" "+colour.Warning("▸")+"   %s\n", warning)
	}
	header += "\n"

	return
}

// formatKeyActions outputs a list as follows:
//    [ ] Shorten the primary key expiry to 31 Oct 18
//    [ ] Expire the encryption subkey now (ID: 0xC52C5BD9719C9F00)
//    [ ] Create a new encryption subkey valid until 31 Oct 18
func formatKeyActions(keyTask keyTask) (header string) {
	if len(keyTask.actions) == 0 {
		return
	}

	header += "Fluidkeys will run the following actions:\n\n"

	for _, action := range keyTask.actions {
		header += fmt.Sprintf("     [ ] %s\n", action)
	}
	header += "\n"

	return
}

func tryStorePassword(fingerprint fpr.Fingerprint, password string) error {
	if err := Config.SetStorePassword(fingerprint, true); err != nil {
		return err
	}
	if err := Keyring.SavePassword(fingerprint, password); err != nil {
		return err
	}
	return nil
}

func tryMaintainAutomatically(fpr fpr.Fingerprint) error {
	if err := Config.SetMaintainAutomatically(fpr, true); err != nil {
		return err
	}
	if _, err := scheduler.Enable(); err != nil {
		return err
	}
	return nil
}

type loadPrivateKeyFromGnupg struct {
	passwordGetter promptForPasswordInterface
}

func (a loadPrivateKeyFromGnupg) String() string {
	return "Load private key from " + colour.Cmd("gpg")
}

func (a loadPrivateKeyFromGnupg) Enact(key *pgpkey.PgpKey, now time.Time, returnPassword *string) error {
	if returnPassword == nil {
		return fmt.Errorf("returnPassword was nil, but it's required")
	}

	if privateKey, password, err := getDecryptedPrivateKeyAndPassword(key, a.passwordGetter); err != nil {
		return err
	} else {
		// copy the value of privateKey to replace key
		*key = *privateKey
		*returnPassword = password
		return nil
	}

}

func (a loadPrivateKeyFromGnupg) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}

type pushIntoGnupg struct {
}

func (a pushIntoGnupg) String() string {
	return "Store updated key in " + colour.Cmd("gpg")
}

type passwordMap = map[fpr.Fingerprint]string

func (a pushIntoGnupg) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	if password == nil {
		return fmt.Errorf("password was nil, but it's required")
	}

	return pushPrivateKeyBackToGpg(key, *password, &gpg)
}

func (a pushIntoGnupg) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}

type updateBackupZIP struct {
}

func (a updateBackupZIP) String() string {
	return "Make backup ZIP file"
}

func (a updateBackupZIP) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	if password == nil {
		return fmt.Errorf("password was nil, but it's required")
	}
	_, err := backupzip.OutputZipBackupFile(fluidkeysDirectory, key, *password)
	return err
}

func (a updateBackupZIP) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}

type publishToAPI struct {
}

func (a publishToAPI) String() string {
	return "Upload updated key to Fluidkeys"
}

func (a publishToAPI) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return publishKeyToAPI(key)
}

func (a publishToAPI) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}
