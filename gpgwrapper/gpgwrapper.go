// gpgwrapper calls out to the system GnuPG binary

package gpgwrapper

import (
	"errors"
	"os/exec"
	"regexp"
)

const GpgPath = "gpg"

var VersionRegexp = regexp.MustCompile(`gpg \(GnuPG.*\) (\d+\.\d+\.\d+)`)

func Version() (string, error) {
	// Returns the GnuPG version string, e.g. "1.2.3"

	outString, err := runGpg("--version")

	if err != nil {
		return "", err
	}

	version, err := parseVersionString(outString)

	if err != nil {
		return "", err
	}

	return version, nil
}

// Checks whether GPG is working
func IsWorking() bool {
	_, err := Version()

	if err != nil {
		return false
	}

	return true
}

func parseVersionString(gpgStdout string) (string, error) {
	match := VersionRegexp.FindStringSubmatch(gpgStdout)

	if match == nil {
		return "", errors.New("version string not found in GPG output")
	}

	return match[1], nil
}

func runGpg(arguments string) (string, error) {
	out, err := exec.Command(GpgPath, "--version").Output()

	if err != nil {
		// TODO: it would be kinder if we interpreted GPG's
		// output and returned a specific Error type.
		return "", err
	}
	outString := string(out)
	return outString, nil
}
