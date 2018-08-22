package pgpkey

import (
	"bytes"
	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/crypto/openpgp/packet"
)

const (
	// Use Mozilla infosec team's recommendation: https://infosec.mozilla.org/guidelines/key_management#recommended---generally-valid-for-up-to-10-years-default
	RsaSizeSecureKeyBits = 4096

	// Use a small key insecure key for fast testing
	RsaSizeInsecureKeyBits = 1024
)

type PgpKey struct {
	openpgp.Entity
}

func Generate(email string) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeSecureKeyBits)
}

func GenerateInsecure(email string) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeInsecureKeyBits)
}

func generateKeyOfSize(email string, rsaBits int) (*PgpKey, error) {
	config := &packet.Config{RSABits: rsaBits}

	name, comment := "", ""
	entity, err := openpgp.NewEntity(name, comment, email, config)

	if err != nil {
		return nil, err
	}

	pgpKey := PgpKey{*entity}
	return &pgpKey, nil
}

// Armor returns the public part of a key in armored format.
// Adapted with thanks from https://github.com/alokmenghrajani/gpgeez/blob/master/gpgeez.go
func (key *PgpKey) Armor() (string, error) {
	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	key.Serialize(armor)
	armor.Close()

	return buf.String(), nil
}

// ArmorPrivate returns the private part of a key in armored format.
//
// Note: if you want to protect the string against varous low-level attacks,
// you should look at https://github.com/stouset/go.secrets and
// https://github.com/worr/secstring and then re-implement this function.
//
// Adapted with thanks from https://github.com/alokmenghrajani/gpgeez/blob/master/gpgeez.go
func (key *PgpKey) ArmorPrivate(password string) (string, error) {
	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", err
	}
	config := packet.Config{SerializePrivatePassword: password}
	key.SerializePrivate(armor, &config)
	armor.Close()

	return buf.String(), nil
}
