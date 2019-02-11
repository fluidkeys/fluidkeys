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

// formatFileDivider returns a divider string, including a filename if given, e.g.:
// ── readme.txt ──────────────────────────────────────────────────
func formatFileDivider(filename string) string {
	if filename == "" {
		return strings.Repeat(fileDividerRune, fileDividerLength)
	}

	if utf8.RuneCountInString(filename) > maxFilenameLength {
		extension := filepath.Ext(filename)
		remainingCharacters := maxFilenameLength - (utf8.RuneCountInString(extension) + 1) // '…'
		filename = filename[:remainingCharacters] + "…" + extension
	}

	leftDecoration := strings.Repeat(fileDividerRune, fileDividerMinRepeat) + " "

	rightDecoration := " " + strings.Repeat(
		fileDividerRune,
		fileDividerLength-(utf8.RuneCountInString(leftDecoration+filename)+1),
	)

	return leftDecoration + colour.File(filename) + rightDecoration
}

const (
	fileDividerRune      = "─"
	fileDividerMinRepeat = 2
	fileDividerLength    = 80
)

var (
	maxFilenameLength = fileDividerLength - (2 * (fileDividerMinRepeat + 1))
)
