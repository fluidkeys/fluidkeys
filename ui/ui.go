// Copyright 2019 Paul Furley and Ian Drysdale
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

package ui

import (
	"github.com/fluidkeys/fluidkeys/colour"
	"strings"
)

// FormatFailure prints a formatted failure message. It should be used for errors where the program
// is going to terminate.
func FormatFailure(headline string, extraLines []string, err error) string {
	msg := ""

	msg += "\n"
	msg += colour.Error("│ 🔥 " + headline + "\n")

	if err != nil {
		extraLines = append(extraLines, "", colour.ErrorDetail(capitalize(err.Error())))
	}

	if len(extraLines) > 0 && extraLines[0] != "" {
		extraLines = append([]string{""}, extraLines...) // prepend a "" to extraLines
	}

	for _, line := range extraLines {
		msg += colour.Error("│ ") + line + "\n"
	}
	msg += "\n"
	return msg
}

// FormatWarning prints a formatted failure message. It should be used for errors where the program
// is going to continue.
func FormatWarning(headline string, extraLines []string, err error) string {
	msg := ""

	msg += "\n"
	msg += colour.Warning("│ ⚠️  " + headline + "\n")

	if err != nil {
		extraLines = append(extraLines, "", colour.ErrorDetail(capitalize(err.Error())))
	}

	if len(extraLines) > 0 && extraLines[0] != "" {
		extraLines = append([]string{""}, extraLines...) // prepend a "" to extraLines
	}

	for _, line := range extraLines {
		msg += colour.Warning("│ ") + line + "\n"
	}
	msg += "\n"
	return msg
}

// FormatInfo prints a formatted info message. It should be used for useful information that you
// want to draw to the readers attention
func FormatInfo(headline string, extraLines []string) string {
	msg := ""

	msg += "\n"
	msg += colour.Info("│") + " ℹ️  " + headline + "\n"

	if len(extraLines) > 0 {
		extraLines = append([]string{""}, extraLines...) // prepend a "" to extraLines
	}

	for _, line := range extraLines {
		msg += colour.Info("│ ") + line + "\n"
	}
	msg += "\n"
	return msg
}

// capitalize returns text with the first rune capitalized
func capitalize(text string) string {
	switch len([]rune(text)) {
	case 0:
		return ""

	case 1:
		return strings.ToUpper(text)

	default:
		return strings.ToUpper(text[0:1]) + text[1:]
	}
}
