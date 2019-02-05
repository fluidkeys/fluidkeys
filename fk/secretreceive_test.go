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
package fk

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/api/v1structs"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

type mockListSecrets struct {
	mockSecrets []v1structs.Secret
	mockError   error
}

func (m *mockListSecrets) ListSecrets(fingerprint fingerprint.Fingerprint) ([]v1structs.Secret, error) {
	return m.mockSecrets, m.mockError
}

func TestDownloadAndDecryptSecrets(t *testing.T) {
	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey4)
	if err != nil {
		t.Fatalf("error loading private key: %s", err)
	}

	t.Run("passes up errors from ListSecrets", func(t *testing.T) {
		secretLister := mockListSecrets{
			mockError: fmt.Errorf("can't connect to api"),
		}

		_, _, err := downloadAndDecryptSecrets(*pgpKey, &secretLister)
		expectedErr := fmt.Errorf("can't connect to api")
		assert.Equal(t, expectedErr.Error(), err.Error())
	})

	t.Run("returns an error if no secrets are found", func(t *testing.T) {
		secretLister := mockListSecrets{}

		_, _, err := downloadAndDecryptSecrets(*pgpKey, &secretLister)
		assert.Equal(t, errNoSecretsFound{}, err)
	})

	// TODO: "gets a decrypted private key"
	//		 "decrypts an array of secrets"
	//		 "returns an array of errors it encounters while decrypting secrets"
}
