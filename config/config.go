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

// ShouldStorePasswordForKey returns whether the given key's password should
// be stored in the system keyring when successfully entered (avoiding future
// password prompts).
// The default is false.
func (c *Config) ShouldStorePasswordForKey(fingerprint fingerprint.Fingerprint) bool {
	if keyConfig, gotConfig := c.getConfig(fingerprint); gotConfig {
		return keyConfig.StorePassword
	} else {
		return defaultStorePassword
	}
}

// ShouldRotateAutomaticallyForKey returns whether the given key should be
// rotated in the background. The default is false.
func (c *Config) ShouldRotateAutomaticallyForKey(fingerprint fingerprint.Fingerprint) bool {
	if keyConfig, gotConfig := c.getConfig(fingerprint); gotConfig {
		return keyConfig.RotateAutomatically
	} else {
		return defaultRotateAutomatically
	}
}

// getConfig returns a `key` struct for the given Fingerprint
func (c *Config) getConfig(fp fingerprint.Fingerprint) (*key, bool) {
	keyConfigs := make(map[fingerprint.Fingerprint]key)

	for configFingerprint, keyConfig := range c.parsedConfig.PgpKeys {
		parsedFingerprint, err := fingerprint.Parse(configFingerprint)
		if err != nil {
			panic(fmt.Errorf("got invalid openpgp fingerprint: '%s'", configFingerprint))
		}

		keyConfigs[parsedFingerprint] = keyConfig
	}

	keyConfig, inMap := keyConfigs[fp]
	return &keyConfig, inMap
}

func parse(r io.Reader) (*Config, error) {
	var parsedConfig tomlConfig
	metadata, err := toml.DecodeReader(r, &parsedConfig)

	if err != nil {
		return nil, fmt.Errorf("error in toml.DecodeReader: %v", err)
	}

	// validate fingerprints
	for configFingerprint, _ := range parsedConfig.PgpKeys {
		_, err := fingerprint.Parse(configFingerprint)
		if err != nil {
			return nil, fmt.Errorf("got invalid openpgp fingerprint: '%s'", configFingerprint)
		}
	}

	if len(metadata.Undecoded()) > 0 {
		// found config variables that we don't know how to match to
		// the tomlConfig structure
		return nil, fmt.Errorf("encountered unrecognised config keys: %v", metadata.Undecoded())
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
	StorePassword       bool `toml:"store_password"`
	RotateAutomatically bool `toml:"rotate_automatically"`
}

const defaultStorePassword bool = false
const defaultRotateAutomatically bool = false
const defaultConfigFile string = `# Fluidkeys default configuration file.

[pgpkeys]

# To prevent the password being saved in the keyring for one of your PGP keys,
# add the following configuration lines using the key's fingerprint:
#
#     [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
#     store_password = true
#     rotate_automatically = true
`
