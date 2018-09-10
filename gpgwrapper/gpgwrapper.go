// gpgwrapper calls out to the system GnuPG binary

package gpgwrapper

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const GpgPath = "gpg"

var ErrNoVersionStringFound = errors.New("version string not found in GPG output")

func ErrProblemExecutingGPG(gpgStdout string, arguments ...string) error {
	return fmt.Errorf("error executing GPG with %s: %s", arguments, gpgStdout)
}

var VersionRegexp = regexp.MustCompile(`gpg \(GnuPG.*\) (\d+\.\d+\.\d+)`)

type GnuPG struct {
	homeDir string
}

// SecretKeyListing refers to a key parsed from running `gpg --list-secret-keys`
type SecretKeyListing struct {

	// Fingerprint is the human-readable format of the fingerprint of the
	// primary key, for example:
	// `AB01 AB01 AB01 AB01 AB01  AB01 AB01 AB01 AB01 AB01`
	Fingerprint string

	// Uids is a list of UTF-8 user ID strings as defined in
	// https://tools.ietf.org/html/rfc4880#section-5.11
	Uids []string

	// Created is the time the key was apparently created in UTC.
	Created time.Time
}

func (g *GnuPG) Version() (string, error) {
	// Returns the GnuPG version string, e.g. "1.2.3"

	outString, err := g.run("--version")

	if err != nil {
		err = fmt.Errorf("problem running GPG, %v", err)
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
func (g *GnuPG) IsWorking() bool {
	_, err := g.Version()

	if err != nil {
		return false
	}

	return true
}

// Import an armored key into the GPG key ring
func (g *GnuPG) ImportArmoredKey(armoredKey string) (string, error) {
	output, err := g.runWithStdin(armoredKey, "--import")
	if err != nil {
		err = fmt.Errorf("problem importing key, %v", err)
		return "", err
	}

	return output, nil
}

func (g *GnuPG) ListSecretKeys() ([]SecretKeyListing, error) {
	args := []string{
		"--with-colons",
		"--with-fingerprint",
		"--fixed-list-mode",
		"--list-secret-keys",
	}
	outString, err := g.run(args...)
	if err != nil {
		return nil, fmt.Errorf("error running 'gpg %s': %v", strings.Join(args, " "), err)
	}

	return parseListSecretKeys(outString)
}

func parseVersionString(gpgStdout string) (string, error) {
	match := VersionRegexp.FindStringSubmatch(gpgStdout)

	if match == nil {
		return "", ErrNoVersionStringFound
	}

	return match[1], nil
}

func (g *GnuPG) run(arguments ...string) (string, error) {
	fullArguments := g.prependGlobalArguments(arguments...)
	out, err := exec.Command(GpgPath, fullArguments...).CombinedOutput()

	if err != nil {
		error := ErrProblemExecutingGPG(string(out), fullArguments...)
		return "", error
	}
	outString := string(out)
	return outString, nil
}

func (g *GnuPG) runWithStdin(textToSend string, arguments ...string) (string, error) {
	fullArguments := g.prependGlobalArguments(arguments...)
	cmd := exec.Command(GpgPath, fullArguments...)
	stdin, err := cmd.StdinPipe()

	if err != nil {
		return "", errors.New(fmt.Sprintf("Failed to get stdin pipe '%s'", err))
	}

	io.WriteString(stdin, textToSend)
	stdin.Close()

	stdoutAndStderr, err := cmd.CombinedOutput()

	if err != nil {
		return "", errors.New(fmt.Sprintf("GPG failed with error '%s', stdout said '%s'", err, stdoutAndStderr))
	}

	output := string(stdoutAndStderr)
	return output, nil
}

func (g *GnuPG) prependGlobalArguments(arguments ...string) []string {
	var globalArguments = []string{
		"--keyid-format", "0xlong",
		"--batch",
		"--no-tty",
	}
	if g.homeDir != "" {
		homeDirArgs := []string{"--homedir", g.homeDir}
		globalArguments = append(globalArguments, homeDirArgs...)
	}
	return append(globalArguments, arguments...)
}
