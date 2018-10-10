package main

import (
	"fmt"
	"time"

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

	printImportBackIntoGnupg(keysWithActions)

	fmt.Printf("\nTo start run\n")
	fmt.Printf(" >  %s\n\n", colour.CommandLineCode("fk key rotate"))
	fmt.Printf("You’ll be asked at each stage to confirm before making any changes.\n\n")
	return 0
}

func runKeyRotate(keys []pgpkey.PgpKey) exitCode {
	fmt.Printf("\nFluidkeys will perform the following actions.\n")
	fmt.Printf("\n%s\n", colour.Warning("Take time to review these actions."))

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
			prompt = "     Run this action? [Y/n] "
		default:
			prompt = fmt.Sprintf("     Run these %d actions? [Y/n] ", numberOfActions)
		}

		if promptYesOrNo(prompt, true) == false {
			fmt.Printf(colour.Disabled(" ▸   OK, skipped.\n"))
			continue // next key
		}

		key, password, err := getDecryptedPrivateKeyAndPassword(key)

		action := "Load private key from GnuPG" // TODO: factor into func
		if err != nil {
			printCheckboxFailure(action, err)
			numErrorsEncountered += 1
			continue
		} else {
			printCheckboxSuccess(action)
		}

		err = runActions(key, actions)
		if err != nil {
			numErrorsEncountered += 1
			fmt.Printf("\n    Skipping remaining actions for %s\n", displayName(key))
			continue // Don't run any more actions
		} else {
			message := fmt.Sprintf("Successfully updated keys for %s", displayName(key))
			fmt.Printf(colour.Success("\n ▸   " + message + "\n\n"))
			keysModifiedSuccessfully = append(keysModifiedSuccessfully, key)
			passwords[key.Fingerprint()] = password
		}
	}

	if !anyKeysHadActions {
		fmt.Printf("\n%s\n", colour.Success("✔ All keys look good — nothing to do."))
		return 0 // success! nothing to do
	}

	if !runImportBackIntoGnupg(keysModifiedSuccessfully, passwords) {
		numErrorsEncountered += 1
	}

	if numErrorsEncountered > 0 {
		message := fmt.Sprintf("%s while running rotate.", humanize.Pluralize(numErrorsEncountered, "error", "errors"))
		fmt.Printf("\n%s\n", colour.Error(message))
		return 1
	} else {
		fmt.Printf("\n%s\n", colour.Success("Rotate complete"))
		return 0
	}
}

func runActions(privateKey *pgpkey.PgpKey, actions []status.KeyAction) error {
	for _, action := range actions {
		printCheckboxPending(action.String())

		var err error
		err = action.Enact(privateKey)
		if err != nil {
			printCheckboxFailure(action.String(), err)
			return err // don't run any more actions

		} else {
			printCheckboxSuccess(action.String())
		}
	}
	return nil
}

func runImportBackIntoGnupg(keys []*pgpkey.PgpKey, passwords map[fingerprint.Fingerprint]string) (success bool) {
	if len(keys) == 0 {
		success = true
		return
	}

	printImportBackIntoGnupg(keys)

	fmt.Printf("\nWhile fluidkeys is in alpha, it backs up GnuPG (~/.gnupg) each time.")

	action := "Backup GnuPG directory (~/.gnupg)"

	if promptYesOrNo("\nAutomatically create backup now? [Y/n] ", true) == true {
		printCheckboxPending(action)
		err := makeGnupgBackup()
		if err != nil {
			printCheckboxFailure(action, err)
		} else {
			printCheckboxSuccess(action)
		}
	} else {
		printCheckboxSkipped(action)
	}

	if promptYesOrNo("Push all updated keys to GnuPG? [Y/n] ", true) == false {
		printCheckboxSkipped("Imported keys back into GnuPG")
		success = true
		return
	}

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
	return
}

func makeGnupgBackup() error {
	return fmt.Errorf("not implemented")
}

func printImportBackIntoGnupg(keys []*pgpkey.PgpKey) {
	if len(keys) == 0 {
		return
	}
	fmt.Printf("Import updated keys back into GnuPG:\n\n")
	fmt.Printf("     [ ] Backup GnuPG directory (~/.gnupg)\n")

	for _, key := range keys {
		fmt.Printf("     [ ] Import %s back into GnuPG\n", displayName(key))
	}
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
	fmt.Printf("\r     %s %s\n", colour.Error("[!]"), actionText)
	fmt.Printf("\r        %s\n", colour.Error(fmt.Sprintf("%s", err)))
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

	header += fmt.Sprintf(
		"\n%s for %s:\n\n",
		humanize.Pluralize(len(warnings), "warning", "warnings"),
		colour.Info(displayName(key)),
	)

	for _, warning := range warnings {
		header += fmt.Sprintf(" %s   %s\n", colour.Warning("▸"), warning)
	}
	header += fmt.Sprintln()

	for _, action := range actions {
		header += fmt.Sprintf("     [ ] %s\n", action)
	}

	return
}

func moveCursorUpLines(numLines int) {
	for i := 0; i < numLines; i++ {
		fmt.Printf("\033[1A")
	}
}
