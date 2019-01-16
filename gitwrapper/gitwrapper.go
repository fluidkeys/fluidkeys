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

// gitwrapper calls out to the system git binary

package gitwrapper

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"regexp"
	"strings"
)

type Git struct {
}

func Load() (*Git, error) {
	return &Git{}, nil
}

// Returns the Git version string, e.g. "1.2.3"
func (g *Git) Version() (string, error) {
	outString, _, err := g.run("", "--version")

	if err != nil {
		return "", err
	}

	version, err := parseVersionString(outString)

	if err != nil {
		err = fmt.Errorf("problem parsing version string, %v", err)
		return "", err
	}

	return version, nil
}

// Checks whether GPG is working
func (g *Git) IsWorking() bool {
	_, err := g.Version()

	if err != nil {
		return false
	}

	return true
}

// GetConfig calls git and returns  the value of the config parameter, e.g.
// `git config --global user.email` where configKey is `user.email`
func (g *Git) GetConfig(configKey string) (string, error) {
	stdout, _, err := g.run("", "config", "--global", configKey)

	stdout = strings.TrimRight(stdout, "\n\r")

	return stdout, err
}

// SetConfig calls git to set the value of the config parameter, e.g.
// `git config --global user.email` where configKey is `user.email`
func (g *Git) SetConfig(configKey string, newValue string) error {
	_, _, err := g.run("", "config", "--global", configKey, newValue)
	return err
}

func parseVersionString(gpgStdout string) (string, error) {
	match := versionRegexp.FindStringSubmatch(gpgStdout)

	if match == nil {
		return "", fmt.Errorf("no version string found")
	}

	return match[1], nil
}

// run runs the given command, sends textToSend via stdin, and returns
// stdout, stderr and any error encountered
func (g *Git) run(textToSend string, arguments ...string) (
	stdout string, stderr string, returnErr error) {
	cmd := exec.Command(gitBinary, arguments...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		returnErr = fmt.Errorf("Failed to get stdout pipe '%s'", err)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		returnErr = fmt.Errorf("Failed to get stderr pipe '%s'", err)
		return
	}

	if textToSend != "" {
		stdin, err := cmd.StdinPipe() // used to send textToSend
		if err != nil {
			returnErr = fmt.Errorf("Failed to get stdin pipe '%s'", err)
			return
		}

		io.WriteString(stdin, textToSend)
		stdin.Close()
	}

	if err = cmd.Start(); err != nil {
		returnErr = fmt.Errorf("error starting gpg: %v", err)
		return
	}

	if stdoutBytes, err := ioutil.ReadAll(stdoutPipe); err != nil {
		returnErr = fmt.Errorf("error reading stdout: %v", err)
		return
	} else {
		stdout = string(stdoutBytes)
	}

	if stderrBytes, err := ioutil.ReadAll(stderrPipe); err != nil {
		returnErr = fmt.Errorf("error reading stderr: %v", err)
		return
	} else {
		stderr = string(stderrBytes)
	}

	if err := cmd.Wait(); err != nil {
		// a non-zero exit code error from .Wait() looks like:
		// "exit status 2"

		stderrLines := strings.Split(
			strings.TrimRight(stderr, "\n\r"),
			"\n",
		)
		extraErr := ""

		switch len(stderrLines) {
		case 0:
			extraErr = ""

		case 1:
			extraErr = fmt.Sprintf(", stderr: %s", stderrLines[0])

		default:
			extraErr = fmt.Sprintf(", stderr: %s [see fluidkeys log for more]", stderrLines[0])
		}

		log.Printf("command failed: `%s %s` : %s", gitBinary, strings.Join(arguments, " "), err)
		for _, line := range stderrLines {
			log.Print(line)
		}

		returnErr = fmt.Errorf("%v%s", err, extraErr)
		return
	}

	return
}

const gitBinary string = "git"

var versionRegexp = regexp.MustCompile(`git version \d+\.\d+\.\d+`)
