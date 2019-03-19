package config

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/testhelpers"
)

func TestLoad(t *testing.T) {
	t.Run("Load actually works from a real config file", func(t *testing.T) {
		tmpdir := testhelpers.Maketemp(t)
		err := ioutil.WriteFile(path.Join(tmpdir, "config.toml"), []byte(exampleTomlDocument), 0600)
		assert.NoError(t, err)

		config, err := Load(tmpdir)
		assert.NoError(t, err)

		assert.Equal(t, 0, len(config.parsedMetadata.Undecoded()))
	})

	t.Run("default config file actually parses", func(t *testing.T) {
		_, err := parse(strings.NewReader(defaultConfigFile))
		assert.NoError(t, err)
	})

	t.Run("load successfully if file is present and reads OK", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError: nil,
			OsOpenReturnError: nil,
			TomlContents:      exampleTomlDocument,
		}
		config, err := load("/tmp/", &mockFileHelper)
		assert.NoError(t, err)

		t.Run("Config has filename set correctly", func(t *testing.T) {
			assert.Equal(t, "/tmp/config.toml", config.filename)
		})
	})

	t.Run("load successfully if file is missing but was created OK", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist,
			IoutilWriteFileReturnError: nil,
			OsOpenReturnError:          nil,
			TomlContents:               exampleTomlDocument,
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.NoError(t, err)
	})

	t.Run("load writes out default file content with correct mode if file is missing", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist,
			IoutilWriteFileReturnError: nil,
			OsOpenReturnError:          nil,
			TomlContents:               exampleTomlDocument,
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.NoError(t, err)
		assert.Equal(t, defaultConfigFile, string(mockFileHelper.IoutilWriteFileGotData))
		assert.Equal(t, os.FileMode(0600), mockFileHelper.IoutilWriteFileGotMode)
	})

	t.Run("error if file is missing and couldn't be created due to permission error", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist,
			IoutilWriteFileReturnError: os.ErrPermission,
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.GotError(t, err)
		assert.Equal(t, "/tmp/config.toml didn't exist and failed to create it: permission denied", err.Error())
	})

	t.Run("error if file existed but couldn't be read", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError: nil,              // file exists
			OsOpenReturnError: os.ErrPermission, // file couldn't be read
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.GotError(t, err)
		assert.Equal(t, "error reading /tmp/config.toml: permission denied", err.Error())
	})

	t.Run("error if file existed but couldn't parse", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			TomlContents: "invalid toml content",
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.GotError(t, err)
		assert.Equal(t, "error parsing /tmp/config.toml: error in toml.DecodeReader: Near line 1 (last key parsed 'invalid'): expected key separator '=', but got 't' instead", err.Error())
	})
}

func TestParse(t *testing.T) {

	t.Run("with valid example config.toml", func(t *testing.T) {
		str := strings.NewReader(exampleTomlDocument)
		config, err := parse(str)
		assert.NoError(t, err)
		t.Run("parsedMetadata.IsDefined('keys') should be true", func(t *testing.T) {
			assert.Equal(t, true, config.parsedMetadata.IsDefined("pgpkeys"))
		})

		t.Run("parsedMetadata.IsDefined('keys', '<fingerprint>') should be true", func(t *testing.T) {
			assert.Equal(t, true, config.parsedMetadata.IsDefined(
				"pgpkeys", "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111",
			))
		})

		t.Run("metadata.Undecoded() should be empty", func(t *testing.T) {
			assert.Equal(t, 0, len(config.parsedMetadata.Undecoded()))
		})

		t.Run("parsedConfig has 2 PgpKeys", func(t *testing.T) {
			assert.Equal(t, 2, len(config.parsedConfig.PgpKeys))
		})

		t.Run("first PgpKey should have store_password=true", func(t *testing.T) {
			firstKey, inMap := config.parsedConfig.PgpKeys["AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"]

			if !inMap {
				t.Fatalf("key wasn't in the map")
			}
			assert.Equal(t, true, firstKey.StorePassword)
		})

		t.Run("first PgpKey should have maintain_automatically=false", func(t *testing.T) {
			firstKey, inMap := config.parsedConfig.PgpKeys["AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"]

			if !inMap {
				t.Fatalf("key wasn't in the map")
			}
			assert.Equal(t, false, firstKey.MaintainAutomatically)
		})

		t.Run("first PgpKey should have allow_search_by_email=true", func(t *testing.T) {
			firstKey, inMap := config.parsedConfig.PgpKeys["AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"]

			if !inMap {
				t.Fatalf("key wasn't in the map")
			}
			assert.Equal(t, true, firstKey.PublishToAPI)
		})
	})

	t.Run("return an error if an invalid fingerprint is encountered", func(t *testing.T) {
		_, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.invalid-fingerprint]
		store_password = false
		`))
		assert.GotError(t, err)
	})

	t.Run("return an error if an unrecognised config variable is encountered", func(t *testing.T) {
		_, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		unrecognised_option = false
		`))
		assert.GotError(t, err)
		assert.Equal(t, "encountered unrecognised config keys: [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111.unrecognised_option]", err.Error())
	})
}

func TestSerialize(t *testing.T) {
	testFingerprint := fpr.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("from an empty config file", func(t *testing.T) {
		emptyConfig, err := parse(strings.NewReader(""))
		assert.NoError(t, err)

		emptyConfig.SetStorePassword(testFingerprint, true)

		output := bytes.NewBuffer(nil)
		err = emptyConfig.serialize(output)
		assert.NoError(t, err)

		expected := defaultConfigFile +
			"run_from_cron = false\n" +
			"\n" +
			"[pgpkeys]\n" +
			"  [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]\n" +
			"    store_password = true\n" +
			"    maintain_automatically = false\n" +
			"    publish_to_api = false\n"
		assertEqualStrings(t, expected, output.String())
	})
}

func TestGetConfig(t *testing.T) {
	fingerprint := fpr.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("getConfig recognises 0xAAAA... fingerprint format rather than returning default config", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.0xAAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		store_password = true  # use a non-default value to test this
		`))
		assert.NoError(t, err)

		keyConfig := config.getConfig(fingerprint)
		// store_password = true would show that it hasn't returned the default value
		assert.Equal(t, true, keyConfig.StorePassword)
	})
	t.Run("getConfig recognises 'AAAA 1111...' fingerprint format", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys."AAAA 1111 AAAA 1111 AAAA 1111 AAAA 1111 AAAA 1111"]
		store_password = true  # use a non-default value to test this
		`))
		assert.NoError(t, err)

		keyConfig := config.getConfig(fingerprint)
		// store_password = true would show that it hasn't returned the default value
		assert.Equal(t, true, keyConfig.StorePassword)
	})
}

func TestSettersAndGetters(t *testing.T) {
	testFingerprint := fpr.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("MaintainAutomatically", func(t *testing.T) {
		config := Config{filename: "/tmp/config.toml"}

		t.Run("true", func(t *testing.T) {
			err := config.SetMaintainAutomatically(testFingerprint, true)
			assert.NoError(t, err)
			assert.Equal(t, true, config.ShouldMaintainAutomatically(testFingerprint))
		})

		t.Run("false", func(t *testing.T) {
			err := config.SetMaintainAutomatically(testFingerprint, false)
			assert.NoError(t, err)
			assert.Equal(t, false, config.ShouldMaintainAutomatically(testFingerprint))
		})
	})

	t.Run("StorePassword", func(t *testing.T) {
		config := Config{filename: "/tmp/config.toml"}

		t.Run("true", func(t *testing.T) {
			err := config.SetStorePassword(testFingerprint, true)
			assert.NoError(t, err)
			assert.Equal(t, true, config.ShouldStorePassword(testFingerprint))
		})

		t.Run("false", func(t *testing.T) {
			err := config.SetStorePassword(testFingerprint, false)
			assert.NoError(t, err)
			assert.Equal(t, false, config.ShouldStorePassword(testFingerprint))
		})
	})

	t.Run("StorePassword", func(t *testing.T) {
		config := Config{filename: "/tmp/config.toml"}

		t.Run("true", func(t *testing.T) {
			err := config.SetPublishToAPI(testFingerprint, true)
			assert.NoError(t, err)
			assert.Equal(t, true, config.ShouldPublishToAPI(testFingerprint))
		})

		t.Run("false", func(t *testing.T) {
			err := config.SetPublishToAPI(testFingerprint, false)
			assert.NoError(t, err)
			assert.Equal(t, false, config.ShouldPublishToAPI(testFingerprint))
		})
	})
}

func TestShouldStorePasswordInKeyring(t *testing.T) {
	testFingerprint := fpr.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("default to false for missing whole [pgpkeys] table", func(t *testing.T) {
		config, err := parse(strings.NewReader(""))
		assert.NoError(t, err)

		got := config.ShouldStorePassword(testFingerprint)
		assert.Equal(t, false, got)
	})
	t.Run("default to false for missing key fingerprint", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.0000000000000000000000000000000000000000]
		store_password = false
		`))
		assert.NoError(t, err)

		got := config.ShouldStorePassword(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("default to false for missing store_password key", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		`))
		assert.NoError(t, err)

		got := config.ShouldStorePassword(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return false if store_password key is false", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		store_password = false
		`))
		assert.NoError(t, err)

		got := config.ShouldStorePassword(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return true if store_password key is true", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		store_password = true
		`))
		assert.NoError(t, err)

		got := config.ShouldStorePassword(testFingerprint)
		assert.Equal(t, true, got)
	})
}

func TestShouldMaintainAutomaticallyInKeyring(t *testing.T) {
	testFingerprint := fpr.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("default to false for missing whole [pgpkeys] table", func(t *testing.T) {
		config, err := parse(strings.NewReader(""))
		assert.NoError(t, err)

		got := config.ShouldMaintainAutomatically(testFingerprint)
		assert.Equal(t, false, got)
	})
	t.Run("default to false for missing key fingerprint", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.0000000000000000000000000000000000000000]
		maintain_automatically = false
		`))
		assert.NoError(t, err)

		got := config.ShouldMaintainAutomatically(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("default to false for missing maintain_automatically key", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		`))
		assert.NoError(t, err)

		got := config.ShouldMaintainAutomatically(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return false if maintain_automatically key is false", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		maintain_automatically = false
		`))
		assert.NoError(t, err)

		got := config.ShouldMaintainAutomatically(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return true if maintain_automatically key is true", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		maintain_automatically = true
		`))
		assert.NoError(t, err)

		got := config.ShouldMaintainAutomatically(testFingerprint)
		assert.Equal(t, true, got)
	})
}

type mockFileFunctions struct {
	// provides fake versions of os.Stat etc.
	// implements fileFunctionsInterface

	OsStatReturnError          error
	IoutilWriteFileReturnError error
	OsOpenReturnError          error
	TomlContents               string

	// IoutilWriteFileGotData stores whatever data was was writeen to WriteFile()
	IoutilWriteFileGotData []byte
	IoutilWriteFileGotMode os.FileMode
}

func (m *mockFileFunctions) OsStat(filename string) (os.FileInfo, error) {
	return nil, m.OsStatReturnError
}

func (m *mockFileFunctions) OsOpen(filename string) (io.Reader, error) {
	return strings.NewReader(m.TomlContents), m.OsOpenReturnError
}

func (m *mockFileFunctions) IoutilWriteFile(filename string, data []byte, mode os.FileMode) (int error) {
	m.IoutilWriteFileGotData = data
	m.IoutilWriteFileGotMode = mode

	return m.IoutilWriteFileReturnError
}

func assertEqualStrings(t *testing.T, expected string, got string) {
	t.Helper()
	if expected != got {
		fmt.Printf("expected:\n----\n%s\n----\ngot:\n----\n%s\n----\n", expected, got)
		t.Fatalf("strings weren't equal")
	}
}

const exampleTomlDocument string = `
# Fluidkeys config file

[pgpkeys]
    [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
    store_password = true
    maintain_automatically = false
    publish_to_api = true
    
    [pgpkeys.BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222]
    store_password = false
    maintain_automatically = false
    publish_to_api = false
`
