package config

import (
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Run("Load actually works from a real config file", func(t *testing.T) {
		tmpdir := makeTempDir(t)
		err := ioutil.WriteFile(path.Join(tmpdir, "config.toml"), []byte(exampleTomlDocument), 0600)
		assert.ErrorIsNil(t, err)

		config, err := Load(tmpdir)
		assert.ErrorIsNil(t, err)

		assert.Equal(t, 0, len(config.parsedMetadata.Undecoded()))
	})

	t.Run("default config file actually parses", func(t *testing.T) {
		_, err := parse(strings.NewReader(defaultConfigFile))
		assert.ErrorIsNil(t, err)
	})

	t.Run("load successfully if file is present and reads OK", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError: nil,
			OsOpenReturnError: nil,
			TomlContents:      exampleTomlDocument,
		}
		config, err := load("/tmp/", &mockFileHelper)
		assert.ErrorIsNil(t, err)

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
		assert.ErrorIsNil(t, err)
	})

	t.Run("load writes out default file content with correct mode if file is missing", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist,
			IoutilWriteFileReturnError: nil,
			OsOpenReturnError:          nil,
			TomlContents:               exampleTomlDocument,
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, defaultConfigFile, string(mockFileHelper.IoutilWriteFileGotData))
		assert.Equal(t, os.FileMode(0600), mockFileHelper.IoutilWriteFileGotMode)
	})

	t.Run("error if file is missing and couldn't be created due to permission error", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist,
			IoutilWriteFileReturnError: os.ErrPermission,
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, "/tmp/config.toml didn't exist and failed to create it: permission denied", err.Error())
	})

	t.Run("error if file existed but couldn't be read", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError: nil,              // file exists
			OsOpenReturnError: os.ErrPermission, // file couldn't be read
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, "error reading /tmp/config.toml: permission denied", err.Error())
	})

	t.Run("error if file existed but couldn't parse", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			TomlContents: "invalid toml content",
		}
		_, err := load("/tmp/", &mockFileHelper)
		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, "error in toml.DecodeReader: Near line 1 (last key parsed 'invalid'): expected key separator '=', but got 't' instead", err.Error())
	})
}

func TestParse(t *testing.T) {

	t.Run("with valid example config.toml", func(t *testing.T) {
		str := strings.NewReader(exampleTomlDocument)
		config, err := parse(str)
		assert.ErrorIsNil(t, err)
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

		t.Run("first PgpKey should have rotate_automatically=false", func(t *testing.T) {
			firstKey, inMap := config.parsedConfig.PgpKeys["AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"]

			if !inMap {
				t.Fatalf("key wasn't in the map")
			}
			assert.Equal(t, false, firstKey.RotateAutomatically)
		})
	})

	t.Run("return an error if an invalid fingerprint is encountered", func(t *testing.T) {
		_, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.invalid-fingerprint]
		store_password = false
		`))
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("return an error if an unrecognised config variable is encountered", func(t *testing.T) {
		_, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		unrecognised_option = false
		`))
		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, "encountered unrecognised config keys: [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111.unrecognised_option]", err.Error())
	})
}

func TestGetConfig(t *testing.T) {
	fingerprint := fingerprint.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("getConfig recognises 0xAAAA... fingerprint format", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.0xAAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		store_password = false
		`))
		assert.ErrorIsNil(t, err)

		_, gotConfig := config.getConfig(fingerprint)

		assert.ErrorIsNil(t, err)
		assert.Equal(t, true, gotConfig)
	})
	t.Run("getConfig recognises 'AAAA 1111...' fingerprint format", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys."AAAA 1111 AAAA 1111 AAAA 1111 AAAA 1111 AAAA 1111"]
		store_password = false
		`))
		assert.ErrorIsNil(t, err)

		_, gotConfig := config.getConfig(fingerprint)

		assert.ErrorIsNil(t, err)
		assert.Equal(t, true, gotConfig)
	})
}

func TestShouldStorePasswordInKeyring(t *testing.T) {
	testFingerprint := fingerprint.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("default to false for missing whole [pgpkeys] table", func(t *testing.T) {
		config, err := parse(strings.NewReader(""))
		assert.ErrorIsNil(t, err)

		got := config.ShouldStorePasswordForKey(testFingerprint)
		assert.Equal(t, false, got)
	})
	t.Run("default to false for missing key fingerprint", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.0000000000000000000000000000000000000000]
		store_password = false
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldStorePasswordForKey(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("default to false for missing store_password key", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldStorePasswordForKey(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return false if store_password key is false", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		store_password = false
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldStorePasswordForKey(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return true if store_password key is true", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		store_password = true
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldStorePasswordForKey(testFingerprint)
		assert.Equal(t, true, got)
	})
}

func TestShouldRotateAutomaticallyInKeyring(t *testing.T) {
	testFingerprint := fingerprint.MustParse("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111")

	t.Run("default to false for missing whole [pgpkeys] table", func(t *testing.T) {
		config, err := parse(strings.NewReader(""))
		assert.ErrorIsNil(t, err)

		got := config.ShouldRotateAutomaticallyForKey(testFingerprint)
		assert.Equal(t, false, got)
	})
	t.Run("default to false for missing key fingerprint", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.0000000000000000000000000000000000000000]
		rotate_automatically = false
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldRotateAutomaticallyForKey(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("default to false for missing rotate_automatically key", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldRotateAutomaticallyForKey(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return false if rotate_automatically key is false", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		rotate_automatically = false
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldRotateAutomaticallyForKey(testFingerprint)
		assert.Equal(t, false, got)
	})

	t.Run("return true if rotate_automatically key is true", func(t *testing.T) {
		config, err := parse(strings.NewReader(`
		[pgpkeys]
		[pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
		rotate_automatically = true
		`))
		assert.ErrorIsNil(t, err)

		got := config.ShouldRotateAutomaticallyForKey(testFingerprint)
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

func makeTempDir(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "fluidkey.config_test.")
	if err != nil {
		t.Fatalf("Failed to create temp GnuPG dir: %v", err)
	}
	return dir
}

const exampleTomlDocument string = `
# Fluidkeys config file

[pgpkeys]
    [pgpkeys.AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111]
    store_password = true
    rotate_automatically = false
    
    [pgpkeys.BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222]
    store_password = false
    rotate_automatically = false
`
