package pgpkey

import (
	"crypto/rsa"
	"io"
	"time"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/errors"
	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/policy"
)

func generateKey(email string, randomNumberGenerator io.Reader, creationTime time.Time) (key *PgpKey, err error) {
	config := packet.Config{
		RSABits:     policy.PrimaryKeyRsaKeyBits,
		Time:        func() time.Time { return creationTime },
		DefaultHash: policy.SignatureHashFunction,
		Rand:        randomNumberGenerator,
	}

	key, err = generateMakePrimaryKey(creationTime, &config)
	if err != nil {
		return nil, err
	}

	err = generateAddOneIdentity(key, email, creationTime, &config)
	if err != nil {
		return nil, err
	}

	err = generateAddOneEncryptionSubkey(key, creationTime, &config)
	if err != nil {
		return nil, err
	}

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

func generateMakePrimaryKey(creationTime time.Time, config *packet.Config) (key *PgpKey, err error) {

	primaryKey, err := rsa.GenerateKey(config.Random(), policy.PrimaryKeyRsaKeyBits)
	if err != nil {
		return
	}

	e := openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(creationTime, &primaryKey.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(creationTime, primaryKey),
		Identities: make(map[string]*openpgp.Identity),
		Subkeys:    make([]openpgp.Subkey, 0),
	}

	key = &PgpKey{e}
	return
}

func generateAddOneIdentity(key *PgpKey, email string, creationTime time.Time, config *packet.Config) error {
	name, comment := "", ""

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return errors.InvalidArgumentError("user id field contained invalid characters")
	}

	trueValue := true

	key.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: creationTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &trueValue,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &key.PrimaryKey.KeyId,
		},
	}
	return nil
}

func generateAddOneEncryptionSubkey(key *PgpKey, creationTime time.Time, config *packet.Config) error {
	return key.CreateNewEncryptionSubkey(policy.NextExpiryTime(creationTime), creationTime, config.Random())
}
