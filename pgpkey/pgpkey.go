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
	"github.com/fluidkeys/fluidkeys/openpgpdefs/compression"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/hash"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/symmetric"
	"github.com/fluidkeys/fluidkeys/policy"
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

type IncorrectPassword struct {
	decryptErrorMessage string
}

func (e *IncorrectPassword) Error() string {
	return fmt.Sprintf("incorrect password: %s", e.decryptErrorMessage)
}

func Generate(email string, now time.Time) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeSecureKeyBits, now)
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
// private key and returns PgpKey with:
//
// * a decrypted PrivateKey.
// * all subkeys decrypted
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

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt([]byte(password))
			if err != nil {
				return nil, &IncorrectPassword{decryptErrorMessage: err.Error()}
			}
		}
	}

	pgpKey := PgpKey{*entity}
	return &pgpKey, nil
}

func generateInsecure(email string, creationTime time.Time) (*PgpKey, error) {
	return generateKeyOfSize(email, RsaSizeInsecureKeyBits, creationTime)
}

func generateKeyOfSize(email string, rsaBits int, creationTime time.Time) (key *PgpKey, err error) {
	config := packet.Config{
		RSABits:     policy.PrimaryKeyRsaKeyBits,
		Time:        func() time.Time { return creationTime },
		DefaultHash: policy.SignatureHashFunction,
		Rand:        randomNumberGenerator,
	}

	name, comment := "", ""

	entity, err := openpgp.NewEntity(name, comment, email, &config)
	if err != nil {
		return
	}

	key = &PgpKey{*entity}

	err = key.SetPreferredSymmetricAlgorithms(policy.AdvertiseCipherPreferences, creationTime)
	if err != nil {
		return
	}

	err = key.SetPreferredHashAlgorithms(policy.AdvertiseHashPreferences, creationTime)
	if err != nil {
		return
	}

	err = key.SetPreferredCompressionAlgorithms(policy.AdvertiseCompressionPreferences, creationTime)
	if err != nil {
		return
	}

	validUntil := policy.NextExpiryTime(creationTime)
	err = key.UpdateExpiryForAllUserIds(validUntil, creationTime)
	if err != nil {
		return
	}

	for _, subkey := range key.Subkeys {
		err = key.UpdateSubkeyValidUntil(subkey.PublicKey.KeyId, validUntil, creationTime)
		if err != nil {
			return
		}
	}

	return
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
func (key *PgpKey) ArmorPrivate(passwordToEncryptWith string) (string, error) {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", err
	}
	config := packet.Config{SerializePrivatePassword: passwordToEncryptWith}

	err = key.SerializePrivate(armor, &config)
	if err != nil {
		return "", fmt.Errorf("error calling key.SerializePrivate: %v", err)
	}
	armor.Close()

	return buf.String(), nil
}

func (key *PgpKey) ArmorRevocationCertificate(now time.Time) (string, error) {
	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}

	reasonByte := uint8(0) // "no reason", see https://tools.ietf.org/html/rfc4880#section-5.2.3.23
	reasonText := "Revocation certificate was automatically generated by Fluidkeys when this key was created."

	signature, err := key.GetRevocationSignature(reasonByte, reasonText, now)
	if err != nil {
		return "", err
	}

	signature.Serialize(armor)
	armor.Close()
	return buf.String(), nil
}

func (key *PgpKey) GetRevocationSignature(reason uint8, reasonText string, now time.Time) (*packet.Signature, error) {
	config := packet.Config{
		DefaultHash: crypto.SHA512,
	}

	sig := &packet.Signature{
		CreationTime:         now,
		SigType:              packet.SigTypeKeyRevocation,
		PubKeyAlgo:           key.PrimaryKey.PubKeyAlgo,
		Hash:                 config.Hash(),
		IssuerKeyId:          &key.PrimaryKey.KeyId,
		RevocationReason:     &reason,
		RevocationReasonText: reasonText,
	}

	h, err := packet.KeyRevocationHash(key.PrimaryKey, config.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to make key revocation hash: %v", err)
	}

	sig.Sign(h, key.PrivateKey, &config)
	return sig, nil
}

func (key *PgpKey) SetPreferredSymmetricAlgorithms(algos []symmetric.SymmetricAlgorithm, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	for _, selfSig := range key.getIdentitySelfSignatures() {
		selfSig.PreferredSymmetric = algos
	}
	return key.RefreshUserIdSelfSignatures(now)
}

func (key *PgpKey) SetPreferredHashAlgorithms(algos []hash.HashAlgorithm, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	for _, selfSig := range key.getIdentitySelfSignatures() {
		selfSig.PreferredHash = algos
	}
	return key.RefreshUserIdSelfSignatures(now)
}

func (key *PgpKey) SetPreferredCompressionAlgorithms(algos []compression.CompressionAlgorithm, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	for _, selfSig := range key.getIdentitySelfSignatures() {
		selfSig.PreferredCompression = algos
	}
	return key.RefreshUserIdSelfSignatures(now)
}

func (key *PgpKey) getIdentitySelfSignatures() []*packet.Signature {
	var selfSigs []*packet.Signature
	for name, _ := range key.Identities {
		identity := key.Identities[name]
		selfSigs = append(selfSigs, identity.SelfSignature)
	}
	return selfSigs
}

func (key *PgpKey) RefreshUserIdSelfSignatures(now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	config := packet.Config{
		DefaultHash: policy.SignatureHashFunction,
	}

	for name, id := range key.Identities {
		id.SelfSignature.CreationTime = now
		id.SelfSignature.Hash = config.Hash()

		err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, &config)
		if err != nil {
			return fmt.Errorf("error calling SignUserId(%s, ...): %v", name, err)
		}
	}
	return nil
}

func (key *PgpKey) RefreshSubkeyBindingSignature(subkeyId uint64, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	subkey, err := key.Subkey(subkeyId)
	if err != nil {
		return err
	}

	config := packet.Config{
		DefaultHash: policy.SignatureHashFunction,
	}

	subkey.Sig.CreationTime = now
	subkey.Sig.Hash = config.Hash()

	return subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, &config)
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

func (key *PgpKey) UpdateExpiryForAllUserIds(validUntil time.Time, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	keyLifetimeSeconds := uint32(validUntil.Sub(key.PrimaryKey.CreationTime).Seconds())

	for _, selfSig := range key.getIdentitySelfSignatures() {
		selfSig.KeyLifetimeSecs = &keyLifetimeSeconds
	}

	return key.RefreshUserIdSelfSignatures(now)
}

// EncryptionSubkey returns either nil or a single openpgp.Subkey which:
//
// * has the valid flag set
// * has one or both of the capability flags: encrypt communications and encrypt storage
// * has a valid, in-date signature
// * has the latest CreationTime (e.g. most recent)

func (key *PgpKey) EncryptionSubkey(now time.Time) *openpgp.Subkey {
	subkeys := key.validEncryptionSubkeys(now)

	if len(subkeys) == 0 {
		return nil
	}

	sort.Sort(sort.Reverse(BySubkeyCreated(subkeys)))
	return &subkeys[0]
}

// CreateNewEncryptionSubkey creaates and signs a new encryption subkey for
// the primary key, valid until a specified time.
func (key *PgpKey) CreateNewEncryptionSubkey(validUntil time.Time, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	config := packet.Config{
		RSABits:     policy.EncryptionSubkeyRsaKeyBits,
		DefaultHash: policy.SignatureHashFunction,
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

// ExpireSubkey prevents the given subkey from being usable.
func (key *PgpKey) ExpireSubkey(subkeyId uint64, now time.Time) error {
	validUntil := now
	return key.UpdateSubkeyValidUntil(subkeyId, validUntil, now)
}

func (key *PgpKey) Subkey(subkeyId uint64) (*openpgp.Subkey, error) {
	for i, subkey := range key.Subkeys {
		if subkey.PublicKey.KeyId == subkeyId {
			return &key.Subkeys[i], nil
		}
	}

	return nil, fmt.Errorf("no subkey with subkeyID 0x%X", subkeyId)
}

func (key *PgpKey) UpdateSubkeyValidUntil(subkeyId uint64, validUntil time.Time, now time.Time) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}
	subkey, err := key.Subkey(subkeyId)
	if err != nil {
		return err
	}

	config := packet.Config{
		DefaultHash: policy.SignatureHashFunction,
	}

	keyLifetimeSeconds := uint32(validUntil.Sub(subkey.PublicKey.CreationTime).Seconds())

	subkey.Sig.SigType = packet.SigTypeSubkeyBinding
	subkey.Sig.Hash = config.Hash()
	subkey.Sig.CreationTime = now // essential that this sig is the most recent
	subkey.Sig.KeyLifetimeSecs = &keyLifetimeSeconds

	err = subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, &config)
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

// ensureGotDecryptedPrivateKey returns an error if the primary key's private
// key is not present, or hasn't been decrypted
func (key *PgpKey) ensureGotDecryptedPrivateKey() error {
	if key.PrivateKey == nil {
		return fmt.Errorf("no private key for primary key")
	}

	if key.PrivateKey.Encrypted {
		return fmt.Errorf("private key for primary key is encrypted")
	}
	return nil
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
