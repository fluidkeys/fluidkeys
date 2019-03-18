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
	"errors"
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/colour"
)

func TestFormatFailure(t *testing.T) {
	var tests = []struct {
		name     string
		input    testCase
		expected string
	}{
		{
			"with only a headline",
			testCase{
				headline:   "Something has failed",
				extralines: nil,
				err:        nil,
			},
			"\n" + colour.Error("│ 🔥 Something has failed\n") +
				"\n",
		},
		{
			"with a headline and two extra lines",
			testCase{
				headline: "Something has failed",
				extralines: []string{
					"First extra line",
					"Second extra line",
				},
				err: nil,
			},
			"\n" + colour.Error("│ 🔥 Something has failed\n") +
				colour.Error("│ ") + "\n" +
				colour.Error("│ ") + "First extra line\n" +
				colour.Error("│ ") + "Second extra line\n" +
				"\n",
		},
		{
			"with a headline and an error",
			testCase{
				headline:   "Something has failed",
				extralines: nil,
				err:        errors.New("a system error"),
			},
			"\n" + colour.Error("│ 🔥 Something has failed\n") +
				colour.Error("│ ") + "\n" +
				colour.Error("│ ") + colour.ErrorDetail("A system error") + "\n" +
				"\n",
		},
		{
			"with a headline, some extra lines and an error",
			testCase{
				headline: "Something has failed",
				extralines: []string{
					"First extra line",
					"Second extra line",
				},
				err: errors.New("a system error"),
			},
			"\n" + colour.Error("│ 🔥 Something has failed\n") +
				colour.Error("│ ") + "\n" +
				colour.Error("│ ") + "First extra line\n" +
				colour.Error("│ ") + "Second extra line\n" +
				colour.Error("│ ") + "\n" +
				colour.Error("│ ") + colour.ErrorDetail("A system error") + "\n" +
				"\n",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("FormatFailure %s", test.name), func(t *testing.T) {
			got := FormatFailure(test.input.headline, test.input.extralines, test.input.err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestFormatWarning(t *testing.T) {
	var tests = []struct {
		name     string
		input    testCase
		expected string
	}{
		{
			"with only a headline",
			testCase{
				headline:   "Warning, something is up",
				extralines: nil,
				err:        nil,
			},
			"\n" + colour.Warning("│ ⚠️  Warning, something is up\n") +
				"\n",
		},
		{
			"with a headline and two extra lines",
			testCase{
				headline: "Warning, something is up",
				extralines: []string{
					"First extra line",
					"Second extra line",
				},
				err: nil,
			},
			"\n" + colour.Warning("│ ⚠️  Warning, something is up\n") +
				colour.Warning("│ ") + "\n" +
				colour.Warning("│ ") + "First extra line\n" +
				colour.Warning("│ ") + "Second extra line\n" +
				"\n",
		},
		{
			"with a headline and an error",
			testCase{
				headline:   "Warning, something is up",
				extralines: nil,
				err:        errors.New("a system error"),
			},
			"\n" + colour.Warning("│ ⚠️  Warning, something is up\n") +
				colour.Warning("│ ") + "\n" +
				colour.Warning("│ ") + colour.ErrorDetail("A system error") + "\n" +
				"\n",
		},
		{
			"with a headline, some extra lines and an error",
			testCase{
				headline: "Warning, something is up",
				extralines: []string{
					"First extra line",
					"Second extra line",
				},
				err: errors.New("a system error"),
			},
			"\n" + colour.Warning("│ ⚠️  Warning, something is up\n") +
				colour.Warning("│ ") + "\n" +
				colour.Warning("│ ") + "First extra line\n" +
				colour.Warning("│ ") + "Second extra line\n" +
				colour.Warning("│ ") + "\n" +
				colour.Warning("│ ") + colour.ErrorDetail("A system error") + "\n" +
				"\n",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("FormatWarning %s", test.name), func(t *testing.T) {
			got := FormatWarning(test.input.headline, test.input.extralines, test.input.err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestFormatInfo(t *testing.T) {
	var tests = []struct {
		name     string
		input    testCase
		expected string
	}{
		{
			"with only a headline",
			testCase{
				headline:   "Here's some helpful info",
				extralines: nil,
			},
			"\n" + colour.Info("│") + " ℹ️  Here's some helpful info\n" +
				"\n",
		},
		{
			"with a headline and two extra lines",
			testCase{
				headline: "Here's some helpful info",
				extralines: []string{
					"First extra line",
					"Second extra line",
				},
				err: nil,
			},
			"\n" + colour.Info("│") + " ℹ️  Here's some helpful info\n" +
				colour.Info("│ ") + "\n" +
				colour.Info("│ ") + "First extra line\n" +
				colour.Info("│ ") + "Second extra line\n" +
				"\n",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("FormatWarning %s", test.name), func(t *testing.T) {
			got := FormatInfo(test.input.headline, test.input.extralines)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestFormatSuccess(t *testing.T) {
	var tests = []struct {
		name     string
		input    testCase
		expected string
	}{
		{
			"with only a headline",
			testCase{
				headline:   "Here's some helpful info",
				extralines: nil,
			},
			"\n" + colour.Success("│ ✔ ") + "Here's some helpful info\n" +
				"\n",
		},
		{
			"with a headline and two extra lines",
			testCase{
				headline: "Here's some helpful info",
				extralines: []string{
					"First extra line",
					"Second extra line",
				},
				err: nil,
			},
			"\n" + colour.Success("│ ✔ ") + "Here's some helpful info\n" +
				colour.Success("│ ") + "\n" +
				colour.Success("│ ") + "First extra line\n" +
				colour.Success("│ ") + "Second extra line\n" +
				"\n",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("FormatSuccess %s", test.name), func(t *testing.T) {
			got := FormatSuccess(test.input.headline, test.input.extralines)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestCapitalize(t *testing.T) {
	var tests = []struct {
		input    string
		expected string
	}{
		{
			"quick, run",
			"Quick, run",
		},
		{
			"Capital Hill",
			"Capital Hill",
		},
		{
			"| pipe",
			"| pipe",
		},
		{
			"",
			"",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("capitalize(%s)", test.input), func(t *testing.T) {
			assert.Equal(t, test.expected, capitalize(test.input))
		})
	}
}

type testCase struct {
	headline   string
	extralines []string
	err        error
}
