package fk

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/team"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamEdit() exitCode {
	allMemberships, err := user.Memberships()
	if err != nil {
		out.Print(ui.FormatFailure("Failed to list teams", nil, err))
		return 1
	}

	adminMemberships := filterByAdmin(allMemberships)

	switch len(adminMemberships) {
	case 0:
		out.Print(ui.FormatFailure("You aren't an admin of any teams", nil, nil))
		return 1

	case 1:
		return doEditTeam(adminMemberships[0].Team, adminMemberships[0].Me)

	default:
		out.Print(ui.FormatFailure("Choosing from multiple teams not implemented", nil, nil))
		return 1
	}
}

func doEditTeam(myTeam team.Team, me team.Person) exitCode {
	printHeader("Edit team " + myTeam.Name)

	existingRoster, signature := myTeam.Roster()

	if err := fetchAdminKeysVerifyRoster(myTeam, existingRoster, signature); err != nil {
		out.Print(ui.FormatWarning(
			"Failed to verify team roster", []string{
				"Before editing the team roster, Fluidkeys checked the signature of the team ",
				"roster, but encountered a problem.",
			},
			err))

		prompter := interactiveYesNoPrompter{}
		if !prompter.promptYesNo("Edit team roster anyway?", "n", nil) {
			return 1
		}
	}

	tmpfile, err := writeRosterToTempfile(existingRoster)
	if err != nil {
		out.Print(ui.FormatFailure("Error writing team roster to temporary file", nil, err))
		return 1
	}
	defer os.Remove(tmpfile)

	err = runEditor(getEditor(), tmpfile)
	if err != nil {
		out.Print(ui.FormatFailure("failed to open editor for text file", nil, err))
		return 1
	}

	newRoster, err := ioutil.ReadFile(tmpfile)
	if err != nil {
		out.Print(ui.FormatFailure("Error reading temp file", nil, err))
		return 1
	}

	updatedTeam, err := team.Load(string(newRoster), "")
	if err != nil {
		out.Print(ui.FormatFailure("Problem with new team roster", nil, err))
		return 1
	}

	if err := team.ValidateUpdate(&myTeam, updatedTeam, &me); err != nil {
		out.Print(ui.FormatFailure("Problem with new team roster", nil, err))
		return 1
	}

	if err := promptAndSignAndUploadRoster(*updatedTeam, me.Fingerprint); err != nil {
		if err != errUserDeclinedToSign {
			out.Print(ui.FormatFailure("Failed to sign and upload roster", nil, err))
		}
		return 1
	}

	return 0
}

func writeRosterToTempfile(roster string) (tmpFilename string, err error) {
	tmpfile, err := ioutil.TempFile("", "roster.toml_")
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %v", err)
	}

	if _, err := tmpfile.Write([]byte(roster)); err != nil {
		return "", fmt.Errorf("error writing %s: %v", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		return "", fmt.Errorf("error closing %s: %v", tmpfile.Name(), err)
	}
	return tmpfile.Name(), nil
}

// getEditor reads the user's VISUAL or EDITOR environment variable (in that order) or "vi"
// if neither is set it returns the default "vi"
func getEditor() string {
	const defaultEditor = "vi"

	visual := os.Getenv("VISUAL")
	if visual != "" {
		return visual
	}

	editor := os.Getenv("EDITOR")
	if editor != "" {
		return editor
	}

	out.Print(ui.FormatInfo(
		"Using default editor `"+defaultEditor+"`",
		[]string{
			"You can change this by setting the EDITOR environment variable:",
			"",
			"> export EDITOR=\"nano\"",
		}))

	return defaultEditor
}

// runEditor runs the given `editor` (which can be e.g. "vim", "vim -R", "/usr/bin/vim").
// it returns when the editor exits, passing up any error it receives.
// if `editor` contains arguments e.g. "vim -R" these will be passed through.
func runEditor(editor, filename string) error {
	editorSplit := strings.Split(editor, " ")
	binary := editorSplit[0]
	args := append(editorSplit[1:len(editorSplit)], filename)

	out.Print("Running " + colour.Cmd(binary+" "+strings.Join(args, " ")+"\n"))
	cmd := exec.Command(binary, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start editor: %v", err)
	}

	if err = cmd.Wait(); err != nil {
		return fmt.Errorf("failed to start editor: %v", err)
	}
	return nil
}
