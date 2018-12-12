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
	"fmt"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/archiver"
	"github.com/fluidkeys/fluidkeys/backupzip"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/scheduler"
	"github.com/fluidkeys/fluidkeys/status"
)

func keyMaintain(dryRun bool, automatic bool, cronOutput bool) exitCode {
	keys, err := loadPgpKeys()
	if err != nil {
		panic(err)
	}

	if dryRun {
		return runKeyMaintainDryRun(keys)
	} else {
		var yesNoPrompter promptYesNoInterface
		var passwordPrompter promptForPasswordInterface

		if !automatic {
			yesNoPrompter = &interactiveYesNoPrompter{}
			passwordPrompter = &interactivePasswordPrompter{}
		} else {
			yesNoPrompter = &automaticResponder{}
			passwordPrompter = &alwaysFailPasswordPrompter{}
		}

		if cronOutput {
			out.SetOutputToBuffer()
		}
		exitCode := runKeyMaintain(keys, yesNoPrompter, passwordPrompter)
		if exitCode != 0 {
			out.PrintTheBuffer()
		}
		return exitCode
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

	out.Print("Before running these actions, Fluidkeys makes a backup of " + colour.CommandLineCode("gpg") + ".\n")
	out.Print(colour.Warning("Changes can only be undone by restoring from the backup.\n\n"))

	out.Print("Fix these issues by running:\n")
	out.Print("    " + colour.CommandLineCode("fk key maintain") + "\n\n")
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
	promptBackupAndRunActions   = "Make a backup of " + colour.CommandLineCode("gpg") + " and run these actions?"
	promptRunActions            = "Run these actions?"
	promptMaintainAutomatically = "Automatically maintain this key from now on?"
	promptPublishToAPI          = "Publish this key?"
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
			panic("promptYesNo called with nil key pointer")
		}
		return Config.ShouldStorePassword(key.Fingerprint()) &&
			Config.ShouldMaintainAutomatically(key.Fingerprint())

	case promptMaintainAutomatically:
		panic("prompting to maintain key automatically, but it should be set and therefore not prompt")

	case promptPublishToAPI:
		if key == nil {
			panic("expected *key but got nil pointer")
		}
		return Config.ShouldPublishToAPI(key.Fingerprint())

	default:
		panic(fmt.Errorf("don't know how to automatically respond to : %s\n", message))
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
		if ranActionsSuccesfully && !Config.ShouldPublishToAPI(keyTask.key.Fingerprint()) {
			promptAndTurnOnPublishToAPI(prompter, keyTask.key)
		}

		if Config.ShouldPublishToAPI(keyTask.key.Fingerprint()) {
			err := publishKeyToAPI(keyTask.key)
			if err != nil {
				printFailed("Failed to publish key")
				out.Print(err.Error())
			} else {
				printSuccess("Published key to API")
			}
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
		out.Print(colour.Success("Maintenance complete.") + "\n")
		return 0
	}
}

func addImportExportActions(keytask *keyTask, passwordPrompter promptForPasswordInterface) {
	keytask.actions = prepend(keytask.actions, LoadPrivateKeyFromGnupg{passwordGetter: passwordPrompter})
	keytask.actions = append(keytask.actions, PushIntoGnupg{})
	keytask.actions = append(keytask.actions, UpdateBackupZIP{})
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

	out.Print("Fluidkeys can maintain this key automatically using " + colour.CommandLineCode("cron") + ".\n")
	out.Print("This requires storing the password in the system keyring.\n\n")

	if prompter.promptYesNo(promptMaintainAutomatically, "", keyTask.key) == true {
		if err := tryEnableMaintainAutomatically(keyTask.key, keyTask.password); err == nil {
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
		printCheckboxPending(action.String())

		var err error
		err = action.Enact(keyTask.key, time.Now(), &keyTask.password)
		if err != nil {
			printCheckboxFailure(action.String(), err)
			return err // don't run any more actions

		} else {
			printCheckboxSuccess(action.String())
		}
	}
	out.Print("\n")
	return nil
}

func makeGnupgBackup(now time.Time) (string, error) {
	filepath := archiver.MakeFilePath("gpghome", "tgz", fluidkeysDirectory, now)
	filename, err := gpg.BackupHomeDir(filepath, now)
	if err != nil {
		return "", fmt.Errorf("failed to call gpg.BackupHomeDir: %v", err)
	}
	return filename, err
}

func printCheckboxPending(actionText string) {
	out.Print(fmt.Sprintf("     [.] %s\n", actionText))
	moveCursorUpLines(1)
}

func printCheckboxSuccess(actionText string) {
	out.Print(fmt.Sprintf("     [%s] %s\n", colour.Success("✔"), actionText))
}

func printCheckboxSkipped(actionText string) {
	out.Print(fmt.Sprintf("     [%s] %s\n", colour.Info("-"), actionText))
}

func printCheckboxFailure(actionText string, err error) {
	out.Print(fmt.Sprintf("     %s %s\n", colour.Error("[!]"), actionText))
	out.Print(fmt.Sprintf("         %s\n", colour.Error(fmt.Sprintf("%s", err))))
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

func tryEnableMaintainAutomatically(key *pgpkey.PgpKey, password string) (err error) {
	if err = Keyring.SavePassword(key.Fingerprint(), password); err != nil {
		return
	}

	if err = Config.SetStorePassword(key.Fingerprint(), true); err != nil {
		return
	}
	if err = Config.SetMaintainAutomatically(key.Fingerprint(), true); err != nil {
		return
	}

	if _, err = scheduler.Enable(); err != nil {
		return
	}
	return nil
}

func moveCursorUpLines(numLines int) {
	for i := 0; i < numLines; i++ {
		out.Print("\033[1A")
	}
}

type LoadPrivateKeyFromGnupg struct {
	passwordGetter promptForPasswordInterface
}

func (a LoadPrivateKeyFromGnupg) String() string {
	return "Load private key from " + colour.CommandLineCode("gpg")
}

func (a LoadPrivateKeyFromGnupg) Enact(key *pgpkey.PgpKey, now time.Time, returnPassword *string) error {
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

func (a LoadPrivateKeyFromGnupg) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}

type PushIntoGnupg struct {
}

func (a PushIntoGnupg) String() string {
	return "Store updated key in " + colour.CommandLineCode("gpg")
}

type passwordMap = map[fingerprint.Fingerprint]string

func (a PushIntoGnupg) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	if password == nil {
		return fmt.Errorf("password was nil, but it's required")
	}

	return pushPrivateKeyBackToGpg(key, *password, &gpg)
}

func (a PushIntoGnupg) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}

type UpdateBackupZIP struct {
}

func (a UpdateBackupZIP) String() string {
	return "Make backup ZIP file"
}

func (a UpdateBackupZIP) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	if password == nil {
		return fmt.Errorf("password was nil, but it's required")
	}
	_, err := backupzip.OutputZipBackupFile(fluidkeysDirectory, key, *password)
	return err
}

func (a UpdateBackupZIP) SortOrder() int {
	return 0 // unimportant since actions are already sorted
}
