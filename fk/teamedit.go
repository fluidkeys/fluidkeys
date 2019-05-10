package fk

import (
	"os"

	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/ui"
)

func teamEdit() exitCode {
	out.Print(ui.FormatFailure("not implemented", nil, nil))
	return 1
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
