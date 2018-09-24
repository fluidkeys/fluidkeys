package main

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// loadPrivateKey exports a private key from GnuPG and returns it as a
// decrypted pgpkey.PgpKey
func loadPrivateKey(fingerprint fingerprint.Fingerprint, password string) (*pgpkey.PgpKey, error) {
	encryptedArmored, err := gpg.ExportPrivateKey(fingerprint, password)
	if err != nil {
		return nil, fmt.Errorf("failed to export private key: %v", err)
	}

	outKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(encryptedArmored, password)

	if outKey.PrivateKey.Encrypted {
		err = outKey.PrivateKey.Decrypt([]byte(password))
		if err != nil {
			return nil, decryptError{fmt.Sprintf("failed to decrypt primary key: %v", err)}
		}
	}

	for _, subkey := range outKey.Subkeys {
		if subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt([]byte(password))
			if err != nil {
				return nil, decryptError{fmt.Sprintf("failed to decrypt subkey: %v", err)}
			}
		}

	}
	return outKey, nil
}

// pushPrivateKeyBackToGpg takes a PgpKey with a decrypted PrivateKey and
// loads it back into GnuPG
func pushPrivateKeyBackToGpg(key *pgpkey.PgpKey, password string) error {
	armoredPublicKey, err := key.Armor()
	if err != nil {
		return fmt.Errorf("failed to dump public key: %v\n", err)
	}

	armoredPrivateKey, err := key.ArmorPrivate(password)
	if err != nil {
		return fmt.Errorf("failed to dump private key: %v\n", err)
	}

	_, err = gpg.ImportArmoredKey(armoredPublicKey)
	if err != nil {
		return err
	}

	_, err = gpg.ImportArmoredKey(armoredPrivateKey)
	return err
}
