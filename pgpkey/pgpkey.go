package pgpkey

import (
	"bytes"
	"crypto"
	"fmt"
	"regexp"
	"time"

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

// Config for generating keys.
type Config struct {
	packet.Config
	// Expiry is the duration that the generated key will be valid for.
	Expiry time.Duration
}

type PgpKey struct {
	openpgp.Entity
}

func Generate(email string) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeSecureKeyBits)
}

func generateInsecure(email string) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeInsecureKeyBits)
}

func generateKeyOfSize(email string, rsaBits int) (*PgpKey, error) {
	config := Config{}
	config.Config.RSABits = rsaBits
	config.Expiry = time.Hour * 24 * 60 // 60 days

	name, comment := "", ""
	entity, err := openpgp.NewEntity(name, comment, email, &config.Config)

	if err != nil {
		return nil, err
	}

	keyLifetimeSeconds := uint32(config.Expiry.Seconds())

	for _, id := range entity.Identities {
		id.SelfSignature.KeyLifetimeSecs = &keyLifetimeSeconds
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, &config.Config)
		if err != nil {
			return nil, err
		}
	}

	for _, subkey := range entity.Subkeys {
		subkey.Sig.KeyLifetimeSecs = &keyLifetimeSeconds
		err := subkey.Sig.SignKey(subkey.PublicKey, entity.PrivateKey, &config.Config)
		if err != nil {
			return nil, err
		}
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

func (key *PgpKey) ArmorRevocationCertificate() (string, error) {
	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}

	reasonByte := uint8(0) // "no reason", see https://tools.ietf.org/html/rfc4880#section-5.2.3.23
	reasonText := "Revocation certificate was automatically generated by Fluidkeys when this key was created."

	signature, err := key.GetRevocationSignature(reasonByte, reasonText)
	if err != nil {
		return "", err
	}

	signature.Serialize(armor)
	armor.Close()
	return buf.String(), nil
}

func (key *PgpKey) GetRevocationSignature(reason uint8, reasonText string) (*packet.Signature, error) {
	hashFunc := crypto.SHA512
	config := packet.Config{}

	sig := &packet.Signature{
		CreationTime:         time.Now(),
		SigType:              packet.SigTypeKeyRevocation,
		PubKeyAlgo:           key.PrimaryKey.PubKeyAlgo,
		Hash:                 hashFunc,
		IssuerKeyId:          &key.PrimaryKey.KeyId,
		RevocationReason:     &reason,
		RevocationReasonText: reasonText,
	}

	h, err := packet.KeyRevocationHash(key.PrimaryKey, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to make key revocation hash: %v", err)
	}

	sig.Sign(h, key.PrivateKey, &config)
	return sig, nil
}

// Return a unique but friendlyish name for the key including the
// date, email address and public key long ID, e.g.
//
// "2018-08-12-test-example-com-309F635DAD1B5517"

func (key *PgpKey) Slug() (string, error) {
	email, err := key.Email()
	if err != nil {
		return "", err
	}
	emailSlug := slugify(email)

	dateString := key.PrimaryKey.CreationTime.Format("2006-01-02")

	return fmt.Sprintf(
		"%s-%s-%s",
		dateString,
		emailSlug,
		key.FingerprintString(),
	), nil
}

// Return the (single) email address associated with the key.
// This relies on the key having *one* User ID (as generated by Fluidkeys)
//
// If more than one User Id is found, an error is returned

func (key *PgpKey) Email() (string, error) {
	var emails []string

	for _, uid := range key.Identities {
		email := uid.UserId.Email
		emails = append(emails, email)
	}
	if len(emails) != 1 {
		return "", fmt.Errorf("expected identities map to have 1 element, has %d", len(emails))
	}

	return emails[0], nil
}

func (key *PgpKey) FingerprintString() string {
	return fmt.Sprintf("%X", key.PrimaryKey.Fingerprint)
}

func slugify(textToSlugify string) (slugified string) {
	var re = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	slugified = re.ReplaceAllString(textToSlugify, `-`)
	return
}
