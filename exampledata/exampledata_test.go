package exampledata

import (
	"fmt"
	"strings"
	"testing"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestArmoredKeys(t *testing.T) {
	var tests = []struct {
		name                string
		armoredKey          string
		expectedFingerprint fingerprint.Fingerprint
	}{
		{
			`public key 2`,
			ExamplePublicKey2,
			ExampleFingerprint2,
		},
		{
			`private key 2`,
			ExamplePrivateKey2,
			ExampleFingerprint2,
		},
		{
			`public key 3`,
			ExamplePublicKey3,
			ExampleFingerprint3,
		},
		{
			`private key 3`,
			ExamplePrivateKey3,
			ExampleFingerprint3,
		},
		{
			`private key 4`,
			ExamplePrivateKey4,
			ExampleFingerprint4,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("can load %s", test.name), func(t *testing.T) {
			assertCanLoadKey(t, test.armoredKey)
		})
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s fingerprint", test.name), func(t *testing.T) {
			entity, _ := loadKey(test.armoredKey)
			gotFingerprint := fingerprint.FromBytes(entity.PrimaryKey.Fingerprint)

			if gotFingerprint != test.expectedFingerprint {
				t.Errorf("loaded %s, expected fingerprint '%s', got '%s'", test.name, test.expectedFingerprint, gotFingerprint)
			}
		})
	}
}

func assertCanLoadKey(t *testing.T, armoredKey string) {
	t.Helper()

	_, err := loadKey(armoredKey)
	if err != nil {
		t.Error(err)
	}
}

func loadKey(armoredKey string) (*openpgp.Entity, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredKey))
	if err != nil {
		return nil, fmt.Errorf("error reading armored key: %v", err)
	}
	if len(entityList) != 1 {
		return nil, fmt.Errorf("expected 1 openpgp.Entity, got %d!", len(entityList))
	}
	return entityList[0], nil
}
