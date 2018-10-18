package main

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/gpgwrapper"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// loadPrivateKey exports a private key from GnuPG and returns it as a
// decrypted pgpkey.PgpKey
//
// Returns an IncorrectPassword error if either function call returns a bad
// password error
func loadPrivateKey(
	fingerprint fingerprint.Fingerprint,
	password string,
	exporter gpgwrapper.ExportPrivateKeyInterface,
	loader pgpkey.LoadFromArmoredEncryptedPrivateKeyInterface) (*pgpkey.PgpKey, error) {

	encryptedArmored, err := exporter.ExportPrivateKey(fingerprint, password)
	if err != nil {
		if _, ok := err.(*gpgwrapper.BadPasswordError); ok {
			return nil, &IncorrectPassword{
				message:       "gpg said the password was incorrect",
				originalError: err.Error(),
			}
		}
		return nil, fmt.Errorf("failed to export private key: %v", err)
	}

	outKey, err := loader.LoadFromArmoredEncryptedPrivateKey(encryptedArmored, password)

	if err != nil {
		if _, ok := err.(*pgpkey.IncorrectPassword); ok {
			return nil, &IncorrectPassword{
				message:       "the password was incorrect",
				originalError: err.Error(),
			}
		}
		fmt.Printf("armored output from GnuPG:\n%s\n", encryptedArmored)
		return nil, fmt.Errorf("failed to load key returned by GnuPG: %v", err)
	}

	return outKey, nil
}

// pushPrivateKeyBackToGpg takes a PgpKey with a decrypted PrivateKey and
// loads it back into GnuPG
func pushPrivateKeyBackToGpg(
	key pgpkey.ArmorInterface,
	password string,
	importer gpgwrapper.ImportArmoredKeyInterface) error {
	armoredPublicKey, err := key.Armor()
	if err != nil {
		return fmt.Errorf("failed to dump public key: %v\n", err)
	}

	armoredPrivateKey, err := key.ArmorPrivate(password)
	if err != nil {
		return fmt.Errorf("failed to dump private key: %v\n", err)
	}

	_, err = importer.ImportArmoredKey(armoredPublicKey)
	if err != nil {
		return err
	}

	_, err = importer.ImportArmoredKey(armoredPrivateKey)
	return err
}
