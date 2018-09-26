package pgpkey

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/fingerprint"
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

type IncorrectPassword struct {
	decryptErrorMessage string
}

func (e *IncorrectPassword) Error() string {
	return fmt.Sprintf("incorrect password: %s", e.decryptErrorMessage)
}

func Generate(email string) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeSecureKeyBits)
}

// LoadFromArmoredPublicKey takes a single ascii-armored public key and
// returns a PgpKey
func LoadFromArmoredPublicKey(armoredPublicKey string) (*PgpKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return nil, fmt.Errorf("error reading armored key ring: %v", err)
	}
	if len(entityList) != 1 {
		return nil, fmt.Errorf("expected 1 openpgp.Entity, got %d!", len(entityList))
	}
	entity := entityList[0]

	pgpKey := PgpKey{*entity}
	return &pgpKey, nil
}

// LoadFromArmoredEncryptedPrivateKey takes a single ascii-armored, encrypted
// private key and returns PgpKey with a decrypted PrivateKey.
//
// If the password is wrong (at least, if .PrivateKey.Decrypt(password) returns
// an error), this function returns an error of type `IncorrectPassword`.
func LoadFromArmoredEncryptedPrivateKey(armoredPublicKey string, password string) (*PgpKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return nil, fmt.Errorf("error reading armored key ring: %v", err)
	}
	if len(entityList) != 1 {
		return nil, fmt.Errorf("expected 1 openpgp.Entity, got %d!", len(entityList))
	}
	entity := entityList[0]

	err = entity.PrivateKey.Decrypt([]byte(password))
	if err != nil {
		return nil, &IncorrectPassword{decryptErrorMessage: err.Error()}
	}

	pgpKey := PgpKey{*entity}
	return &pgpKey, nil
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
	err = key.Serialize(armor)
	if err != nil {
		return "", fmt.Errorf("error calling key.Serialize(..): %v", err)
	}
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

	err = key.SerializePrivate(armor, &config)
	if err != nil {
		return "", fmt.Errorf("error calling key.SerializePrivate: %v", err)
	}
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
		key.Fingerprint().Hex(),
	), nil
}

// Return the (single) email address associated with the key.
// This relies on the key having *one* User ID (as generated by Fluidkeys)
//
// If more than one User Id is found, an error is returned

func (key *PgpKey) Email() (string, error) {
	emails := key.Emails(true)

	if len(emails) != 1 {
		return "", fmt.Errorf("expected identities map to have 1 element, has %d", len(emails))
	}

	return emails[0], nil
}

// Emails returns an alphabetically sorted list of email addresses
//
// Set allowUnbracketed to true to accept (invalid) email-only UIDs from GnuPG.
//
// A UID with the form `example@example.com` is technically not a valid
// `name-addr` (https://tools.ietf.org/html/rfc2822#section-3.4)
// as it should have angle brackets: `<example@example.com>`
//
// Currently with GnuPG it's impossible to make a email-only UID that is a
// valid name-addr (it outputs as 'example@example.com' and won't allow you to
// force '<example@example.com>`
func (key *PgpKey) Emails(allowUnbracketed bool) []string {
	var emails []string

	for _, identity := range key.Identities {
		email := identity.UserId.Email
		if email == "" {
			// email will be blank if it wasn't inside < >
			// in the UID. if allowUnbracketed *and* the raw UID
			// looks like an email address, use that instead.
			if allowUnbracketed && roughlyValidateEmail(identity.UserId.Id) {
				email = identity.UserId.Id
			} else {
				continue // skip this whole UID
			}
		}

		emails = append(emails, email)
	}

	sort.Strings(emails)
	return emails
}

func roughlyValidateEmail(email string) bool {
	return strings.Contains(email, "@")
}

func (key *PgpKey) Fingerprint() fingerprint.Fingerprint {
	return fingerprint.FromBytes(key.PrimaryKey.Fingerprint)
}

func (key *PgpKey) UpdateExpiryForAllUserIds(validUntil time.Time) error {
	config := Config{}

	keyLifetimeSeconds := uint32(validUntil.Sub(key.PrimaryKey.CreationTime).Seconds())

	for _, id := range key.Identities {
		id.SelfSignature.CreationTime = time.Now()
		id.SelfSignature.KeyLifetimeSecs = &keyLifetimeSeconds
		err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, &config.Config)
		if err != nil {
			return fmt.Errorf("failed to make self signature: %v", err)
		}
	}
	return nil
}

// EncryptionSubkey returns either nil or a single openpgp.Subkey which:
//
// * has the valid flag set
// * has one or both of the capability flags: encrypt communications and encrypt storage
// * has a valid, in-date signature
// * has the latest CreationTime (e.g. most recent)

func (key *PgpKey) EncryptionSubkey() *openpgp.Subkey {
	return key.encryptionSubkey(time.Now())
}

func (key *PgpKey) encryptionSubkey(now time.Time) *openpgp.Subkey {
	subkeys := key.validEncryptionSubkeys(now)

	if len(subkeys) == 0 {
		return nil
	}

	sort.Sort(sort.Reverse(BySubkeyCreated(subkeys)))
	return &subkeys[0]
}

// CreateNewEncryptionSubkey creaates and signs a new encryption subkey for
// the primary key, valid until a specified time.
func (key *PgpKey) CreateNewEncryptionSubkey(validUntil time.Time) error {
	return key.createNewEncryptionSubkey(validUntil, time.Now())
}

func (key *PgpKey) createNewEncryptionSubkey(validUntil time.Time, now time.Time) error {
	config := packet.Config{
		RSABits: 2048,
	}

	encryptingPriv, err := rsa.GenerateKey(config.Random(), config.RSABits)
	if err != nil {
		return err
	}

	keyLifetimeSeconds := uint32(validUntil.Sub(now).Seconds())

	subkey := openpgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(now, &encryptingPriv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(now, encryptingPriv),
		Sig: &packet.Signature{
			CreationTime:              now,
			KeyLifetimeSecs:           &keyLifetimeSeconds,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &key.PrimaryKey.KeyId,
		},
	}
	subkey.PublicKey.IsSubkey = true
	subkey.PrivateKey.IsSubkey = true

	err = subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, &config)
	if err != nil {
		return err
	}
	key.Subkeys = append(key.Subkeys, subkey)
	return nil
}

// RevokeSubkey prevents the given subkey from being usable.
func (key *PgpKey) RevokeSubkey(subkeyId uint64) error {
	return key.updateSubkeyExpiryToNow(subkeyId, time.Now())
}

func (key *PgpKey) Subkey(subkeyId uint64) (*openpgp.Subkey, error) {
	for i, subkey := range key.Subkeys {
		if subkey.PublicKey.KeyId == subkeyId {
			return &key.Subkeys[i], nil
		}
	}

	return nil, fmt.Errorf("no subkey with subkeyID 0x%X", subkeyId)
}

func (key *PgpKey) updateSubkeyExpiryToNow(subkeyId uint64, now time.Time) error {
	subkey, err := key.Subkey(subkeyId)
	if err != nil {
		return err
	}

	keyLifetimeSeconds := uint32(now.Sub(subkey.PublicKey.CreationTime).Seconds())

	subkey.Sig.SigType = packet.SigTypeSubkeyBinding
	subkey.Sig.CreationTime = now // essential that this sig is the most recent
	subkey.Sig.KeyLifetimeSecs = &keyLifetimeSeconds

	err = subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, nil)
	if err != nil {
		return err
	}

	return nil
}

func (key *PgpKey) validEncryptionSubkeys(now time.Time) []openpgp.Subkey {
	var subkeys []openpgp.Subkey

	for _, subkey := range key.Subkeys {
		if isEncryptionSubkeyValid(subkey, now) {
			subkeys = append(subkeys, subkey)
		}
	}
	return subkeys
}

func isEncryptionSubkeyValid(subkey openpgp.Subkey, now time.Time) bool {
	isRevoked := subkey.Sig.SigType == packet.SigTypeSubkeyRevocation
	createdInThePast := !subkey.PublicKey.CreationTime.After(now)
	hasEncryptionFlag := subkey.Sig.FlagEncryptCommunications || subkey.Sig.FlagEncryptStorage

	hasExpiry, expiry := SubkeyExpiry(subkey)
	var inDate bool
	if hasExpiry {
		inDate = now.Before(*expiry)
	} else {
		inDate = true
	}

	valid := !isRevoked && createdInThePast && subkey.Sig.FlagsValid && hasEncryptionFlag && inDate
	return valid
}

func slugify(textToSlugify string) (slugified string) {
	var re = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	slugified = re.ReplaceAllString(textToSlugify, `-`)
	return
}
