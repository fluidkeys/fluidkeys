package config

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/natefinch/atomic"
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
	config, err := parse(f)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %v", configFilename, err)
	}
	config.filename = configFilename
	return config, nil
}

type Config struct {
	parsedConfig   tomlConfig
	parsedMetadata toml.MetaData

	// keyConfigs map[fingerprint.Fingerprint]key
	filename string
}

func (c *Config) GetFilename() string {
	return c.filename
}

func (c *Config) RunFromCron() bool {
	if !c.parsedMetadata.IsDefined("run_from_cron") {
		c.parsedConfig.RunFromCron = defaultRunFromCron
		err := c.save()
		if err != nil {
			panic(err)
		}
	}

	return c.parsedConfig.RunFromCron
}

// ShouldStorePasswordForKey returns whether the given key's password should
// be stored in the system keyring when successfully entered (avoiding future
// password prompts).
// The default is false.
func (c *Config) ShouldStorePasswordForKey(fingerprint fingerprint.Fingerprint) bool {
	return c.getConfig(fingerprint).StorePassword
}

func (c *Config) SetStorePassword(fingerprint fingerprint.Fingerprint, value bool) error {
	return c.setProperty(fingerprint, storePassword, value)
}

// ShouldRotateAutomaticallyForKey returns whether the given key should be
// rotated in the background. The default is false.
func (c *Config) ShouldRotateAutomaticallyForKey(fingerprint fingerprint.Fingerprint) bool {
	return c.getConfig(fingerprint).RotateAutomatically
}

// SetRotateAutomatically sets whether the given key should be rotated in the
// background.
func (c *Config) SetRotateAutomatically(fingerprint fingerprint.Fingerprint, value bool) error {
	return c.setProperty(fingerprint, rotateAutomatically, value)
}

func (c *Config) setProperty(fingerprint fingerprint.Fingerprint, property keyConfigProperty, value interface{}) error {
	if c.parsedConfig.PgpKeys == nil { // initialize the map if empty
		c.parsedConfig.PgpKeys = make(map[string]key)
	}

	var keyConfig key
	var inMap bool

	if keyConfig, inMap = c.parsedConfig.PgpKeys[fingerprint.Hex()]; !inMap {
		keyConfig = defaultKeyConfig()
	}

	switch property {
	case storePassword:
		keyConfig.StorePassword = value.(bool)

	case rotateAutomatically:
		keyConfig.RotateAutomatically = value.(bool)

	default:
		return fmt.Errorf("invalid property: %v", property)
	}

	c.parsedConfig.PgpKeys[fingerprint.Hex()] = keyConfig
	return c.save()
}

func (c *Config) save() error {
	if c.filename == "" {
		return fmt.Errorf("can't save, empty config filename")
	}
	configContent := bytes.NewBuffer(nil)
	err := c.serialize(configContent)
	if err != nil {
		return err
	}
	return atomic.WriteFile(c.filename, configContent)
}

// getConfig returns a `key` struct for the given Fingerprint
// If no config is found for the fingerprint, return the default config
func (c *Config) getConfig(fp fingerprint.Fingerprint) key {
	keyConfigs := make(map[fingerprint.Fingerprint]key)

	for configFingerprint, keyConfig := range c.parsedConfig.PgpKeys {
		parsedFingerprint, err := fingerprint.Parse(configFingerprint)
		if err != nil {
			panic(fmt.Errorf("got invalid openpgp fingerprint: '%s'", configFingerprint))
		}

		keyConfigs[parsedFingerprint] = keyConfig
	}

	if keyConfig, inMap := keyConfigs[fp]; inMap {
		return keyConfig
	} else {
		return defaultKeyConfig()
	}
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

func (c *Config) serialize(w io.Writer) error {
	w.Write([]byte(defaultConfigFile))
	encoder := toml.NewEncoder(w)
	return encoder.Encode(c.parsedConfig)
}

func defaultKeyConfig() key {
	return key{
		StorePassword:       false,
		RotateAutomatically: false,
	}
}

type keyConfigProperty int

const (
	storePassword keyConfigProperty = iota
	rotateAutomatically
)

type tomlConfig struct {
	RunFromCron bool           `toml:"run_from_cron"`
	PgpKeys     map[string]key `toml:"pgpkeys"`
}

type key struct {
	StorePassword       bool `toml:"store_password"`
	RotateAutomatically bool `toml:"rotate_automatically"`
}

const defaultRunFromCron = true
const defaultConfigFile string = `# Fluidkeys default configuration file.

# To prevent the password being saved in the keyring for one of your PGP keys,
# add the following configuration lines using the key's fingerprint:
#
# [pgpkeys]
#   [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
#     store_password = true
#     rotate_automatically = true

`
