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

package pgpkey

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
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

type PgpKey struct {
	openpgp.Entity
}

type IncorrectPassword struct {
	decryptErrorMessage string
}

func (e *IncorrectPassword) Error() string {
	return fmt.Sprintf("incorrect password: %s", e.decryptErrorMessage)
}

func Generate(email string, now time.Time, random io.Reader) (*PgpKey, error) {
	if random == nil {
		random = cryptorand.Reader
	}
	return generateKey(email, random, now)
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
func LoadFromArmoredEncryptedPrivateKey(armoredPrivateKey string, password string) (*PgpKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
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

// Email returns exactly one email address associated with the key.
// If the key has multiple user IDs with valid email addresses, return the
// first when sorted by:
//
// 1. whether it's a primary user id (primary come first)
// 2. the self signature creation time (oldest first)
// 3. the email address (domain part followed by name part)
//
// so if no primary user id is set, the oldest signature will be used instead.

func (key *PgpKey) Email() (string, error) {
	emails := key.Emails(true)

	if len(emails) == 0 {
		return "", fmt.Errorf("key has no identities")
	} else {
		return emails[0], nil
	}
}

// Emails returns a list of email addresses parsed from user ids, sorted by
// 1. whether it's a primary user id (primary come first)
// 2. the self signature creation time (oldest first)
// 3. the email address (domain part followed by name part)
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
	identities := []openpgp.Identity{}
	for _, identity := range key.Identities {
		identities = append(identities, *identity)
	}
	lessFunc := func(i, j int) bool { return identityLess(identities[i], identities[j]) }

	sort.Slice(identities, lessFunc)
	sortedEmails := []string{}

	for _, identity := range identities {
		if email, ok := getEmail(&identity, allowUnbracketed); ok {
			sortedEmails = append(sortedEmails, email)
		}
	}
	return sortedEmails
}

func getEmail(identity *openpgp.Identity, allowUnbracketed bool) (string, bool) {
	if email := identity.UserId.Email; roughlyValidateEmail(email) {
		return identity.UserId.Email, true

	} else if email == "" && allowUnbracketed && roughlyValidateEmail(identity.UserId.Id) {
		return identity.UserId.Id, true
	}
	return "", false
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
//
// The `random` parameter provides a source of entropy. If `nil`, a
// cryptographically secure source is used.
func (key *PgpKey) CreateNewEncryptionSubkey(validUntil time.Time, now time.Time, random io.Reader) error {
	err := key.ensureGotDecryptedPrivateKey()
	if err != nil {
		return err
	}

	config := packet.Config{
		RSABits:     policy.EncryptionSubkeyRsaKeyBits,
		DefaultHash: policy.SignatureHashFunction,
		Rand:        random,
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
