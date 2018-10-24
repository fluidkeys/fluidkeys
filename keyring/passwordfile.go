package keyring

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/out"
)

// This is a *temporary* workaround to the issue here:
//
// https://trello.com/c/iwwtzNbt/223-on-macos-keychain-access-prompts-every-time-fluidkeys-tries-to-access-a-password
//
// In order to allow automated key rotation in v0.2 for macOS users, we support
// reading passwords for keys from a file specified by the user.
//
// In your ~/.bashrc, set the following:
// > export FLUIDKEYS_PASSWORDS_TOML_FILE="$HOME/.fluidkeys_passwords.toml"
//
// Then add these lines to that file (replacing AAAA... with your key fingerprint)
//
//     [pgpkeys]
//         [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
//         password = "the quick brown fox"
//
// Finally, ensure that file isn't readable to other users:
// > chmod 0600 $HOME/.fluidkeys_passwords.toml
//

// tryLoadFromPasswordFile looks in the environment for
// FLUIDKEYS_PASSWORDS_TOML_FILE and if present, tries to parse it and extract
// a password for the given key.
// Returns (password, gotPassword)
func tryLoadFromPasswordFile(fp fingerprint.Fingerprint) (string, bool) {
	passwordFile := os.Getenv(environmentVariable)

	if passwordFile != "" {
		out.Print(fmt.Sprintf("Reading passwords from '%s'\n", passwordFile))
		return loadPasswordFromFile(passwordFile, fp)
	}
	return "", false
}

// Returns (password, gotPassword)
func loadPasswordFromFile(filename string, fp fingerprint.Fingerprint) (string, bool) {
	var parsedConfig tomlConfig
	_, err := toml.DecodeFile(filename, &parsedConfig)

	if err != nil {
		panic(fmt.Errorf("failed to parse TOML file %s: %v\nUnset the environment variable %s to stop using it\n", filename, err, environmentVariable))
	}

	passwords := make(map[fingerprint.Fingerprint]string)

	for configFingerprint, key := range parsedConfig.PgpKeys {
		if parsedFingerprint, err := fingerprint.Parse(configFingerprint); err == nil {
			passwords[parsedFingerprint] = key.Password
		} else {
			panic(fmt.Errorf("TOML file %s contained invalid OpenPGP fingerprint: '%s'\n", filename, configFingerprint))
		}
	}

	password, gotPassword := passwords[fp]

	return password, gotPassword
}

type tomlConfig struct {
	PgpKeys map[string]key
}

type key struct {
	Password string
}

const environmentVariable = "FLUIDKEYS_PASSWORDS_TOML_FILE"
