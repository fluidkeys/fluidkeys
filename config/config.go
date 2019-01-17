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

package config

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"github.com/BurntSushi/toml"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/natefinch/atomic"
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
			log.Panic(err)
		}
	}

	return c.parsedConfig.RunFromCron
}

// GithubPersonalAccessToken returns a stored github personal access token, or an empty string
func (c *Config) GithubPersonalAccessToken() string {
	if !c.parsedMetadata.IsDefined("github_personal_access_token") {
		c.parsedConfig.GithubPersonalAccessToken = ""
		err := c.save()
		if err != nil {
			log.Panic(err)
		}
	}

	return c.parsedConfig.GithubPersonalAccessToken
}

// SetGithubPersonalAccessToken saves a github personal access token. Pass in an empty string
// to clear it.
func (c *Config) SetGithubPersonalAccessToken(token string) error {
	c.parsedConfig.GithubPersonalAccessToken = token
	return c.save()
}

// ShouldStorePassword returns whether the given key's password should
// be stored in the system keyring when successfully entered (avoiding future
// password prompts).
// The default is false.
func (c *Config) ShouldStorePassword(fingerprint fingerprint.Fingerprint) bool {
	return c.getConfig(fingerprint).StorePassword
}

func (c *Config) SetStorePassword(fingerprint fingerprint.Fingerprint, value bool) error {
	return c.setProperty(fingerprint, storePassword, value)
}

// ShouldMaintainAutomatically returns whether the given key should be
// maintained in the background. The default is false.
func (c *Config) ShouldMaintainAutomatically(fingerprint fingerprint.Fingerprint) bool {
	return c.getConfig(fingerprint).MaintainAutomatically
}

// SetMaintainAutomatically sets whether the given key should be maintained in the
// background.
func (c *Config) SetMaintainAutomatically(fingerprint fingerprint.Fingerprint, value bool) error {
	return c.setProperty(fingerprint, maintainAutomatically, value)
}

// ShouldPublishToAPI returns whether the given key should be uploaded to the
// Fluidkeys directory to allow others to search for it by email address.
// The default is false.
func (c *Config) ShouldPublishToAPI(fingerprint fingerprint.Fingerprint) bool {
	return c.getConfig(fingerprint).PublishToAPI
}

// SetShouldPublishToAPI sets whether the given key should be uploaded to the
// Fluidkeys directory to allow others to search for it by email address.
func (c *Config) SetPublishToAPI(fingerprint fingerprint.Fingerprint, value bool) error {
	return c.setProperty(fingerprint, publishToAPI, value)
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

	case maintainAutomatically:
		keyConfig.MaintainAutomatically = value.(bool)

	case publishToAPI:
		keyConfig.PublishToAPI = value.(bool)

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
			log.Panicf("got invalid openpgp fingerprint: '%s'", configFingerprint)
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
		StorePassword:         false,
		MaintainAutomatically: false,
		PublishToAPI:          false,
	}
}

type keyConfigProperty int

const (
	storePassword keyConfigProperty = iota
	maintainAutomatically
	publishToAPI
)

type tomlConfig struct {
	RunFromCron               bool           `toml:"run_from_cron"`
	GithubPersonalAccessToken string         `toml:"github_personal_access_token"`
	PgpKeys                   map[string]key `toml:"pgpkeys"`
}

type key struct {
	StorePassword         bool `toml:"store_password"`
	MaintainAutomatically bool `toml:"maintain_automatically"`
	PublishToAPI          bool `toml:"publish_to_api"`
}

const defaultRunFromCron = true

const defaultConfigFile string = `# Fluidkeys configuration file for 'fk' command
#
# # run_from_cron allows Fluidkeys to add itself to your crontab in order to
# # periodically run 'key maintain --automatic'
# # - run 'crontab -l' to see the lines added to crontab
# # - set to false and re-run fk to remove the lines from crontab
#
# run_from_cron = true
#
# github_personal_access_token = "..."
#
# [pgpkeys]
#   [pgpkeys."AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"]
#
#             ^^ keys are referenced by their OpenPGP fingerprint, see:
#                $ gpg --list-secret-keys
#
#     # store_password tells Fluidkeys to use the system keychain to store
#     # the password for this key and look for it before prompting.
#     store_password = true
#
#     # maintain_automatically specifies that key rotation tasks should be
#     # carried out without prompting when running 'fk key maintain automatic'
#     # store_password must also be true to maintain keys automatically.
#     maintain_automatically = true
#
#     # publish_to_api specifies that key will be uploaded to the Fluidkeys server and that others
#     # will be able to search for the key by email address
#     publish_to_api = true
#
# THIS FILE IS OVERWRITTEN BY FLUIDKEYS.
# Any comments you add will be lost.

`
