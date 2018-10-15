package config

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"io"
	"os"
	"path"
)

// Load attempts to load `config.toml` from inside the given
// fluidKeysDirectory.
// If the file is not present, Load will try to create it and will return an
// error if it can't.
// If the file is present but doesn't parse correctly, it will return an error.
func Load(fluidkeysDirectory string) (*Config, error) {
	return load(fluidkeysDirectory, &fileFunctionsPassthrough{})
}

func load(fluidkeysDirectory string, helper fileFunctionsInterface) (*Config, error) {
	configFilename := path.Join(fluidkeysDirectory, "config.toml")

	if _, err := helper.OsStat(configFilename); os.IsNotExist(err) {
		// file does not exist, write out default config file
		err = helper.IoutilWriteFile(configFilename, []byte(defaultConfigFile), 0600)

		if err != nil {
			return nil, fmt.Errorf("%s didn't exist and failed to create it: %v", configFilename, err)
		}
	}

	f, err := helper.OsOpen(configFilename)

	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", configFilename, err)
	}
	return parse(f)
}

type Config struct {
	parsedConfig   tomlConfig
	parsedMetadata toml.MetaData
}

func (c *Config) ShouldStorePasswordForKey(fingerprint fingerprint.Fingerprint) bool {
	fp := fingerprint.Hex()

	if c.parsedMetadata.IsDefined("pgpkeys", fp, "store_password") {
		return c.parsedConfig.PgpKeys[fp].StorePassword
	} else {
		// fmt.Printf("slug '%s' *not* defined: %v\n", fp, c.parsedConfig)
		// PgpKey's fingerprint wasn't in the config file
		return true
	}
}

func parse(r io.Reader) (*Config, error) {
	var parsedConfig tomlConfig
	metadata, err := toml.DecodeReader(r, &parsedConfig)

	if err != nil {
		return nil, fmt.Errorf("error in toml.DecodeReader: %v", err)
	}

	config := Config{
		parsedConfig:   parsedConfig,
		parsedMetadata: metadata,
	}
	return &config, nil
}

type tomlConfig struct {
	PgpKeys map[string]key
}

type key struct {
	StorePassword bool `toml:"store_password"`
}

const defaultConfigFile string = `# Fluidkeys default configuration file.

[pgpkeys]

# To prevent the password being saved in the keyring for one of your PGP keys,
# add the following configuration lines using the key's fingerprint:
#
#     [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
#     store_password = false
`
