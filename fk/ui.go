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
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
)

func printInfo(message string) {
	out.Print(" " + colour.Info("▸") + "   " + message + "\n")
}

func printSuccess(message string) {
	out.Print(" " + colour.Success("▸   "+message) + "\n")
}

func printFailed(message string) {
	out.Print(" " + colour.Failure("▸   "+message) + "\n")
}

func printWarning(message string) {
	out.Print(" " + colour.Warning("▸   "+message) + "\n")
}

func printSuccessfulAction(message string) {
	out.Print("    [" + colour.Success("✔") + "] " + message + "\n")
}

func printFailedAction(message string) {
	out.Print("    [" + colour.Failure("✘") + "] " + message + "\n")
}

func printHeader(message string) {
	out.Print(colour.Header(fmt.Sprintf(" %-79s", message)) + "\n\n")
}

// formatFileDivider takes a message, and returns it 'decorated' with lines either side.
// i.e. `end of file` -> `── end of file ─────────────────────────────────────────`
// If no message is provided, it returns a single, unbroken line.
func formatFileDivider(message string) string {
	if message == "" {
		return strings.Repeat(fileDividerRune, fileDividerLength)
	}

	if utf8.RuneCountInString(message) > maxMessageLength {
		extension := filepath.Ext(message)
		if extension == "" {
			message = message[:(maxMessageLength-1)] + "…"
		} else {
			remainingCharacters := maxMessageLength - (utf8.RuneCountInString(extension) + 1) // '…'
			message = message[:remainingCharacters] + "…" + extension
		}
	}

	leftDecoration := strings.Repeat(fileDividerRune, fileDividerMinRepeat) + " "

	rightDecoration := " " + strings.Repeat(
		fileDividerRune,
		fileDividerLength-(utf8.RuneCountInString(leftDecoration+message)+1),
	)

	return leftDecoration + colour.File(message) + rightDecoration
}

// formatFirstTwentyLines takes an input string and returns the first 20 lines of it plus a boolean
// of whether it was truncated.
// The return string always ends with a trailing new line `\n`: i.e. if input was `line 1\nline2`,
// it returns `line 1\nline\n`
func formatFirstTwentyLines(input string) (string, bool) {
	lines := strings.SplitN(input, "\n", 21)
	if len(lines) == 21 && lines[20] != "" {
		return strings.Join(lines[0:20], "\n") + "\n", true
	}
	return appendNewlineIfMissing(input), false
}

func appendNewlineIfMissing(input string) string {
	if input[len(input)-1:] == "\n" {
		return input
	}
	return input + "\n"
}

const (
	fileDividerRune      = "─"
	fileDividerMinRepeat = 2
	fileDividerLength    = 80
)

var (
	maxMessageLength = fileDividerLength - (2 * (fileDividerMinRepeat + 1))
)
