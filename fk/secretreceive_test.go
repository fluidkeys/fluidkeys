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
	decryptedArmoredResult         io.Reader
	decryptedArmoredError          error
	decryptedArmoredToStringResult string
	decryptedArmoredToStringError  error
}

func (m *mockDecryptor) DecryptArmored(encrypted string) (io.Reader, error) {
	return m.decryptedArmoredResult, m.decryptedArmoredError
}

func (m *mockDecryptor) DecryptArmoredToString(encrypted string) (string, error) {
	return m.decryptedArmoredToStringResult, m.decryptedArmoredToStringError
}

func TestDecryptAPISecret(t *testing.T) {
	t.Run("validates input", func(t *testing.T) {
		t.Run("rejects empty encrypted content", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "fake encrypted metadata",
				EncryptedContent:  "",
			}
			mockPrivateKey := &mockDecryptor{}
			decryptedSecret := secret{}

			err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
			assert.Equal(t, fmt.Errorf("encryptedSecret.EncryptedContent can not be empty"), err)
		})

		t.Run("rejects empty encrypted metadata", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "",
				EncryptedContent:  "fake encrypted content",
			}
			mockPrivateKey := &mockDecryptor{}
			decryptedSecret := secret{}

			err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
			assert.Equal(t, fmt.Errorf("encryptedSecret.EncryptedMetadata can not be empty"), err)
		})

		t.Run("rejects nil decrypted secret", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "fake encrypted metadata",
				EncryptedContent:  "fake encrypted content",
			}
			mockPrivateKey := &mockDecryptor{}

			err := decryptAPISecret(encryptedSecret, nil, mockPrivateKey)
			assert.Equal(t, fmt.Errorf("decryptedSecret can not be nil"), err)
		})

		t.Run("rejects nil private key", func(t *testing.T) {
			encryptedSecret := v1structs.Secret{
				EncryptedMetadata: "fake encrypted metadata",
				EncryptedContent:  "fake encrypted content",
			}
			decryptedSecret := secret{}

			err := decryptAPISecret(encryptedSecret, &decryptedSecret, nil)
			assert.Equal(t, fmt.Errorf("privateKey can not be nil"), err)
		})
	})

	encryptedSecret := v1structs.Secret{
		EncryptedMetadata: "fake encrypted metadata",
		EncryptedContent:  "fake encrypted content",
	}
	decryptedSecret := secret{}

	t.Run("passes up errors when decrypting content", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredToStringError: fmt.Errorf("fake error decrypting content"),
		}

		err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
		assert.Equal(t, fmt.Errorf("fake error decrypting content"), err)
	})

	t.Run("passes up errors when decrypting metadata", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredError: fmt.Errorf("fake error decrypting metadata"),
		}
		decryptedSecret := secret{}

		err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
		assert.Equal(t, fmt.Errorf("fake error decrypting metadata"), err)
	})

	t.Run("passes up errors when json decoding metadata", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader("invalid json"),
		}
		decryptedSecret := secret{}

		err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("passes up errors when parsing the uuid", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader(`{"secretUuid": "invalid uuid"}`),
		}
		decryptedSecret := secret{}

		err := decryptAPISecret(encryptedSecret, &decryptedSecret, mockPrivateKey)
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("populates decrypted secret", func(t *testing.T) {
		mockPrivateKey := &mockDecryptor{
			decryptedArmoredResult: strings.NewReader(
				`{"secretUuid": "93d5ac5b-74e5-4f87-b117-b8d7576395d8"}`,
			),
			decryptedArmoredToStringResult: "decrypted content",
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
	})
}
