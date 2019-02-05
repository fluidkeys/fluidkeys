// Copyright 2019 Paul Furley and Ian Drysdale
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
package fk

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

type mockListSecrets struct {
	mockSecrets []v1structs.Secret
	mockError   error
}

func (m *mockListSecrets) ListSecrets(fingerprint fingerprint.Fingerprint) ([]v1structs.Secret, error) {
	return m.mockSecrets, m.mockError
}

func TestDownloadEncryptedSecrets(t *testing.T) {
	fingerprint := exampledata.ExampleFingerprint4

	t.Run("passes up errors from ListSecrets", func(t *testing.T) {
		secretLister := mockListSecrets{
			mockError: fmt.Errorf("can't connect to api"),
		}

		_, err := downloadEncryptedSecrets(fingerprint, &secretLister)
		expectedErr := fmt.Errorf("can't connect to api")
		assert.Equal(t, expectedErr.Error(), err.Error())
	})

	t.Run("returns a particular error (errNoSecretsFound) if no secrets are found", func(t *testing.T) {
		secretLister := mockListSecrets{}

		_, err := downloadEncryptedSecrets(fingerprint, &secretLister)
		assert.Equal(t, errNoSecretsFound{}, err)
	})

	t.Run("returns all encrypted secrets it finds from ListSecrets, with no error", func(t *testing.T) {
		mockSecrets := []v1structs.Secret{
			v1structs.Secret{
				EncryptedContent:  "mock content 1",
				EncryptedMetadata: "mock metadata 1",
			},
			v1structs.Secret{
				EncryptedContent:  "mock content 2",
				EncryptedMetadata: "mock metadata 2",
			},
		}

		secretLister := mockListSecrets{
			mockSecrets: mockSecrets,
			mockError:   nil,
		}

		gotSecrets, err := downloadEncryptedSecrets(fingerprint, &secretLister)
		assert.ErrorIsNil(t, err)
		assert.Equal(t, mockSecrets, gotSecrets)
	})
}

type mockDecryptor struct {
	decryptedArmoredResult              io.Reader
	decryptedArmoredLiteralData         *packet.LiteralData
	decryptedArmoredError               error
	decryptedArmoredToStringResult      string
	decryptedArmoredToStringLiteralData *packet.LiteralData
	decryptedArmoredToStringError       error
}

func (m *mockDecryptor) DecryptArmored(encrypted string) (
	io.Reader, *packet.LiteralData, error) {
	return m.decryptedArmoredResult, m.decryptedArmoredLiteralData, m.decryptedArmoredError
}

func (m *mockDecryptor) DecryptArmoredToString(encrypted string) (
	string, *packet.LiteralData, error) {
	return m.decryptedArmoredToStringResult, m.decryptedArmoredToStringLiteralData,
		m.decryptedArmoredToStringError
}

func TestDecryptAPISecret(t *testing.T) {
	t.Run("validates input", func(t *testing.T) {
		t.Run("rejects empty encrypted content", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "fake encrypted metadata",
				EncryptedContent:  "",
			}
			mockPrivateKey := &mockDecryptor{}
			_, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
			assert.Equal(t, fmt.Errorf("encryptedSecret.EncryptedContent can not be empty"), err)
		})

		t.Run("rejects empty encrypted metadata", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "",
				EncryptedContent:  "fake encrypted content",
			}
			mockPrivateKey := &mockDecryptor{}
			_, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
			assert.Equal(t, fmt.Errorf("encryptedSecret.EncryptedMetadata can not be empty"), err)
		})

		t.Run("rejects nil private key", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "fake encrypted metadata",
				EncryptedContent:  "fake encrypted content",
			}
			_, err := decryptAPISecret(encryptedSecret, nil)
			assert.Equal(t, fmt.Errorf("privateKey can not be nil"), err)
		})
	})

	encryptedSecret := v1structs.Secret{
		EncryptedMetadata: "fake encrypted metadata",
		EncryptedContent:  "fake encrypted content",
	}

	t.Run("passes up errors when decrypting content", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredToStringError: fmt.Errorf("fake error decrypting content"),
		}

		_, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
		assert.Equal(t, fmt.Errorf("error decrypting secret: "+
			"fake error decrypting content"), err)
	})

	t.Run("passes up errors when decrypting metadata", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredError: fmt.Errorf("fake error decrypting metadata"),
		}
		_, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
		expectedErr := fmt.Errorf("error decrypting secret metadata: " +
			"fake error decrypting metadata")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("passes up errors when json decoding metadata", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader("invalid json"),
		}
		_, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
		assert.ErrorIsNotNil(t, err)
		expectedErr := fmt.Errorf("error decoding secret metadata: " +
			"invalid character 'i' looking for beginning of value")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("passes up errors when parsing the uuid", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader(`{"secretUuid": "invalid uuid"}`),
		}
		_, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
		assert.ErrorIsNotNil(t, err)
		expectedErr := fmt.Errorf("error decoding secret metadata: " +
			"uuid: incorrect UUID length: invalid uuid")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("populates decrypted secret from stdin", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader(
				`{"secretUuid": "93d5ac5b-74e5-4f87-b117-b8d7576395d8"}`,
			),
			decryptedArmoredToStringResult: "decrypted content",
			decryptedArmoredToStringLiteralData: &packet.LiteralData{
				FileName: "_CONSOLE",
			},
		}
		decryptedSecret := secret{}

		err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
		assert.ErrorIsNil(t, err)

		t.Run("with decrypted content", func(t *testing.T) {
			assert.Equal(t, decryptedSecret.decryptedContent, "decrypted content")
		})

		t.Run("with decrypted uuid", func(t *testing.T) {
			uuid, err := uuid.FromString("93d5ac5b-74e5-4f87-b117-b8d7576395d8")
			assert.ErrorIsNil(t, err)
			assert.Equal(t, decryptedSecret.UUID, uuid)
		})

		t.Run("with an empty filename", func(t *testing.T) {
			assert.Equal(t, decryptedSecret.filename, "")
		})
	})

	t.Run("populates decrypted secret from a file", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader(
				`{"secretUuid": "93d5ac5b-74e5-4f87-b117-b8d7576395d8"}`,
			),
			decryptedArmoredToStringResult: "decrypted content",
			decryptedArmoredToStringLiteralData: &packet.LiteralData{
				FileName: "example.txt",
			},
		}
		decryptedSecret, err := decryptAPISecret(encryptedSecret, mockPrivateKey)
		assert.ErrorIsNil(t, err)

		t.Run("with decrypted content", func(t *testing.T) {
			assert.Equal(t, decryptedSecret.decryptedContent, "decrypted content")
		})

		t.Run("with decrypted uuid", func(t *testing.T) {
			uuid, err := uuid.FromString("93d5ac5b-74e5-4f87-b117-b8d7576395d8")
			assert.ErrorIsNil(t, err)
			assert.Equal(t, decryptedSecret.UUID, uuid)
		})

		t.Run("with a matching filename", func(t *testing.T) {
			assert.Equal(t, decryptedSecret.filename, "example.txt")
		})
	})
}

func mockDoesntExist(path string) bool {
	if path == "/fake/new_filename.txt" {
		return true
	}

	if path == "/fake/existing_filename.txt" || path == "/fake/existing_filename(1).txt" {
		return false
	}

	if path == "/fake/old_filename.txt.bak" {
		return false
	}

	return true
}

func TestGetNewUniqueFilename(t *testing.T) {
	t.Run("returns the same value if the filename doesn't exist", func(t *testing.T) {
		filename := getNewUniqueFilename("/fake/new_filename.txt", mockDoesntExist)
		fmt.Printf("file: %s\n", filename)
		assert.Equal(t, "new_filename.txt", filename)
	})

	t.Run("increments a counter to find a filename that doesn't exist", func(t *testing.T) {
		filename := getNewUniqueFilename("/fake/existing_filename.txt", mockDoesntExist)
		fmt.Printf("file: %s\n", filename)
		assert.Equal(t, "existing_filename(2).txt", filename)
	})

	t.Run("adds the counter before the last file extension", func(t *testing.T) {
		filename := getNewUniqueFilename("/fake/old_filename.txt.bak", mockDoesntExist)
		fmt.Printf("file: %s\n", filename)
		assert.Equal(t, "old_filename.txt(1).bak", filename)
	})
}
