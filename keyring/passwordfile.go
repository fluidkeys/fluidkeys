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

package keyring

import (
	"fmt"
	"log"
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
		log.Panicf("failed to parse TOML file %s: %v\nUnset the environment variable %s to stop using it", filename, err, environmentVariable)
	}

	passwords := make(map[fingerprint.Fingerprint]string)

	for configFingerprint, key := range parsedConfig.PgpKeys {
		if parsedFingerprint, err := fingerprint.Parse(configFingerprint); err == nil {
			passwords[parsedFingerprint] = key.Password
		} else {
			log.Panicf("TOML file %s contained invalid OpenPGP fingerprint: '%s'", filename, configFingerprint)
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
