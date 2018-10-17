package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fluidkeys/fluidkeys/archiver"
	"github.com/fluidkeys/fluidkeys/backupzip"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/fluidkeys/fluidkeys/status"
)

func keyRotate(dryRun bool) exitCode {
	keys, err := loadPgpKeys()
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n")
	if dryRun {
		return runKeyRotateDryRun(keys)
	} else {
		return runKeyRotate(keys)
	}
}

func runKeyRotateDryRun(keys []pgpkey.PgpKey) exitCode {
	var keysWithActions []*pgpkey.PgpKey

	for i := range keys {
		key := &keys[i]
		warnings := status.GetKeyWarnings(*key)
		actions := status.MakeActionsFromWarnings(warnings, time.Now())
		fmt.Printf(makeKeyWarningsAndActions(key, warnings, actions))

		if len(actions) > 0 {
			keysWithActions = append(keysWithActions, key)
		}
	}

	printImportBackIntoGnupgAndBackup(keysWithActions)

	fmt.Print("To start run\n")
	fmt.Print(" >   " + colour.CommandLineCode("fk key rotate") + "\n\n")
	fmt.Print("You’ll be asked at each stage to confirm before making any changes.\n\n")
	return 0
}

func runKeyRotate(keys []pgpkey.PgpKey) exitCode {
	fmt.Print("Fluidkeys will perform the following actions.\n\n")
	fmt.Print(colour.Warning("Take time to review these actions.") + "\n\n")

	var anyKeysHadActions = false
	var keysModifiedSuccessfully []*pgpkey.PgpKey
	passwords := make(map[fingerprint.Fingerprint]string)

	numErrorsEncountered := 0

	for i := range keys {
		key := &keys[i] // get a pointer here, not in the `for` expression
		warnings := status.GetKeyWarnings(*key)
		actions := status.MakeActionsFromWarnings(warnings, time.Now())
		fmt.Printf(makeKeyWarningsAndActions(key, warnings, actions))

		numberOfActions := len(actions)
		if numberOfActions > 0 {
			anyKeysHadActions = true
		} else {
			continue // nothing to do. next key.
		}

		var prompt string
		switch numberOfActions {
		case 1:
			prompt = "     Run this action?"
		default:
			prompt = fmt.Sprintf("     Run these %d actions?", numberOfActions)
		}

		if promptYesOrNo(prompt, "y") == false {
			fmt.Print(colour.Disabled(" ▸   OK, skipped.\n\n"))
			continue // next key
		}

		key, password, err := getDecryptedPrivateKeyAndPassword(key)

		action := "Load private key from GnuPG" // TODO: factor into func
		if err != nil {
			printCheckboxFailure(action, err)
			fmt.Printf("\n")
			numErrorsEncountered += 1
			continue
		} else {
			printCheckboxSuccess(action)
		}

		err = runActions(key, actions)
		if err != nil {
			numErrorsEncountered += 1
			fmt.Print("\n")
			fmt.Print("     " + colour.Warning("Skipping remaining actions for") + " " + displayName(key) + "\n\n")
			continue // Don't run any more actions
		} else {
			fmt.Printf(colour.Success(" ▸   Successfully updated keys for " + displayName(key) + "\n\n"))
			keysModifiedSuccessfully = append(keysModifiedSuccessfully, key)

			if Config.ShouldRotateAutomaticallyForKey(key.Fingerprint()) == false {
				fmt.Print("Fluidkeys can configure a " + colour.CommandLineCode("cron") + " task to automatically rotate this key for you from now on ♻️\n")
				fmt.Print("To do this requires storing the key's password in your operating system's keyring.\n\n")
				if promptYesOrNo("Automatically rotate this key from now on?", "") == true {
					Keyring.SavePassword(key.Fingerprint(), password)
					Config.SetStorePassword(key.Fingerprint(), true)
					Config.SetRotateAutomatically(key.Fingerprint(), true)
					fmt.Print(colour.Success(" ▸   Successfully configured key to automatically rotate\n\n"))
				} else {
					fmt.Print(colour.Disabled(" ▸   OK, skipped.\n\n"))
				}
			}
			passwords[key.Fingerprint()] = password
		}
	}

	if !anyKeysHadActions {
		fmt.Print(colour.Success("✔ All keys look good — nothing to do.\n"))
		return 0 // success! nothing to do
	}

	if !runImportBackIntoGnupg(keysModifiedSuccessfully, passwords) {
		numErrorsEncountered += 1
	}

	if numErrorsEncountered > 0 {
		message := fmt.Sprintf("%s while running rotate.", humanize.Pluralize(numErrorsEncountered, "error", "errors"))
		fmt.Print(colour.Error(message) + "\n")
		return 1
	} else {
		fmt.Print(colour.Success("Rotate complete") + "\n")
		return 0
	}
}

func runActions(privateKey *pgpkey.PgpKey, actions []status.KeyAction) error {
	for _, action := range actions {
		printCheckboxPending(action.String())

		var err error
		err = action.Enact(privateKey, time.Now())
		if err != nil {
			printCheckboxFailure(action.String(), err)
			return err // don't run any more actions

		} else {
			printCheckboxSuccess(action.String())
		}
	}
	fmt.Print("\n")
	return nil
}

func runImportBackIntoGnupg(keys []*pgpkey.PgpKey, passwords map[fingerprint.Fingerprint]string) (success bool) {
	if len(keys) == 0 {
		success = true
		return
	}

	printImportBackIntoGnupgAndBackup(keys)

	fmt.Print("While fluidkeys is in alpha, it backs up GnuPG (~/.gnupg) each time.\n")

	action := "Backup GnuPG directory (~/.gnupg)"

	if promptYesOrNo("Automatically create backup now?", "y") == true {
		printCheckboxPending(action)
		filename, err := makeGnupgBackup()
		if err != nil {
			printCheckboxFailure(action, err)
			fmt.Printf("\n")
		} else {
			printCheckboxSuccess(fmt.Sprintf("GnuPG backed up to %v", filename))
			fmt.Printf("\n")
		}
	} else {
		printCheckboxSkipped(action)
	}

	if promptYesOrNo("Push all updated keys to GnuPG?", "y") == false {
		printCheckboxSkipped("Imported keys back into GnuPG")
		success = true
	} else {

		for _, key := range keys {
			action := fmt.Sprintf("Import %s back into GnuPG", displayName(key))
			printCheckboxPending(action)

			err := pushPrivateKeyBackToGpg(key, passwords[key.Fingerprint()], &gpg)

			if err != nil {
				printCheckboxFailure(action, err)
				success = false
			} else {
				printCheckboxSuccess(action)
			}
		}
	}

	for _, key := range keys {
		action := fmt.Sprintf("Backup %s", displayName(key))
		printCheckboxPending(action)

		filename, err := backupzip.OutputZipBackupFile(fluidkeysDirectory, key, passwords[key.Fingerprint()])

		if err != nil {
			printCheckboxFailure(action, err)
			success = false
		} else {
			directory, _ := filepath.Split(filename)
			printCheckboxSuccess("Full key backup saved in " + directory)
		}
	}
	fmt.Print("\n")
	return
}

func makeGnupgBackup() (string, error) {
	directory := archiver.DateStampedDirectory(fluidkeysDirectory, time.Now())
	filepath := filepath.Join(directory, "gpghome.tgz")
	filename, err := gpg.BackupHomeDir(filepath, time.Now())
	return filename, err
}

func printImportBackIntoGnupgAndBackup(keys []*pgpkey.PgpKey) {
	if len(keys) == 0 {
		return
	}
	fmt.Print("Import updated keys back into GnuPG:\n\n")
	fmt.Print("     [ ] Backup GnuPG directory (~/.gnupg)\n")

	for _, key := range keys {
		fmt.Printf("     [ ] Import %s back into GnuPG\n", displayName(key))
		fmt.Printf("     [ ] Backup %s\n", displayName(key))
	}
	fmt.Print("\n")
}

func printCheckboxPending(actionText string) {
	fmt.Printf("     [.] %s\n", actionText)
	moveCursorUpLines(1)
}

func printCheckboxSuccess(actionText string) {
	fmt.Printf("     [%s] %s\n", colour.Success("✔"), actionText)
}

func printCheckboxSkipped(actionText string) {
	fmt.Printf("     [%s] %s\n", colour.Info("-"), actionText)
}

func printCheckboxFailure(actionText string, err error) {
	fmt.Printf("     %s %s\n", colour.Error("[!]"), actionText)
	fmt.Printf("         %s\n", colour.Error(fmt.Sprintf("%s", err)))
}

// makeKeyWarningsAndActions outputs a header for each key as follows:
//
// 2 issues for foo@example.com:
//
// ▸   Encryption subkey overdue for rotation, expires in 5 days
// ▸   Primary key set to expire too far in the future
//
//    [ ] Shorten the primary key expiry to 31 Oct 18
//    [ ] Expire the encryption subkey now (ID: 0xC52C5BD9719C9F00)
//    [ ] Create a new encryption subkey valid until 31 Oct 18

func makeKeyWarningsAndActions(
	key *pgpkey.PgpKey,
	warnings []status.KeyWarning,
	actions []status.KeyAction,
) (header string) {
	if len(actions) == 0 {
		return
	}

	header += humanize.Pluralize(len(warnings), "warning", "warnings") + " for " +
		colour.Info(displayName(key)) + "\n\n"

	for _, warning := range warnings {
		header += fmt.Sprintf(" "+colour.Warning("▸")+"   %s\n", warning)
	}
	header += fmt.Sprintln()

	for _, action := range actions {
		header += fmt.Sprintf("     [ ] %s\n", action)
	}
	header += "\n"

	return
}

func moveCursorUpLines(numLines int) {
	for i := 0; i < numLines; i++ {
		fmt.Printf("\033[1A")
	}
}
