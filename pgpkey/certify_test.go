package pgpkey

import (
	"fmt"
	"testing"
	"time"

	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/policy"
)

func TestCertifyEmail(t *testing.T) {
	now := time.Date(2019, 6, 15, 16, 35, 14, 0, time.UTC)
	later := now.Add(time.Duration(10) * time.Minute)

	certifier, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
	assert.NoError(t, err)

	t.Run("matching email", func(t *testing.T) {
		keyToCertify, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		err = keyToCertify.CertifyEmail("test2@example.com", certifier, now)
		assert.NoError(t, err)

		gotSigs := getSigsForIdentity(t, keyToCertify, "<test2@example.com>")
		assert.Equal(t, 1, len(gotSigs))

		gotSig := gotSigs[0]

		t.Run("exportable certification is false", func(t *testing.T) {
			if gotSig.ExportableCertification == nil {
				t.Fatalf("sig.ExportableCertification is nil (should be false)")
			} else if *gotSig.ExportableCertification == true {
				t.Fatalf("sig.ExportableCertification is true (should be false)")
			}
		})

		t.Run("hash function used matches policy", func(t *testing.T) {
			assert.Equal(t, gotSig.Hash, policy.SignatureHashFunction)
		})

		t.Run("signature verifies", func(t *testing.T) {
			// err = e.PrimaryKey.VerifyUserIdSignature(pkt.Id, e.PrimaryKey, sig); err != nil
			assert.NoError(t,
				certifier.PrimaryKey.VerifyUserIdSignature(
					"<test2@example.com>",
					keyToCertify.PrimaryKey,
					gotSig,
				),
			)
		})
	})

	t.Run("returns error if trying to certify own key", func(t *testing.T) {
		err = certifier.CertifyEmail("test2@example.com", certifier, now)
		assert.Equal(t, fmt.Errorf("key and certifier key are the same"), err)
	})

	t.Run("returns error if no identities match", func(t *testing.T) {
		keyToCertify, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		err = keyToCertify.CertifyEmail("nomatch@example.com", certifier, now)
		assert.Equal(t, fmt.Errorf("no identities match that email"), err)
	})

	t.Run("returns error if missing certifier private key", func(t *testing.T) {
		keyToCertify, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		publicKeyCertifier, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
		assert.NoError(t, err)

		err = keyToCertify.CertifyEmail("test2@example.com", publicKeyCertifier, now)
		assert.Equal(t, fmt.Errorf("signer must have PrivateKey"), err)
	})

	t.Run("returns error if locked certifier private key", func(t *testing.T) {
		// TODO: work out how to make a locked private key

		// keyToCertify, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
		// assert.NoError(t, err)
		// lockedCertifier, err := LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
		// assert.NoError(t, err)
		// err = keyToCertify.CertifyEmail("test2@example.com", publicKeyCertifier, now)
		// assert.Equal(t, fmt.Errorf("foo"), err)
	})

	t.Run("replaces existing certification from same certifier", func(t *testing.T) {
		keyToCertify, err := LoadFromArmoredPublicKey(exampledata.ExamplePublicKey2)
		assert.NoError(t, err)

		err = keyToCertify.CertifyEmail("test2@example.com", certifier, now)
		assert.NoError(t, err)

		err = keyToCertify.CertifyEmail("test2@example.com", certifier, later)
		assert.NoError(t, err)

		gotSigs := getSigsForIdentity(t, keyToCertify, "<test2@example.com>")
		assert.Equal(t, 1, len(gotSigs))

		assert.Equal(t, later, gotSigs[0].CreationTime)
	})

}

func getSigsForIdentity(t *testing.T, k *PgpKey, uid string) (signatures []*packet.Signature) {
	identity, ok := k.Identities[uid]
	if !ok {
		return nil
	}

	return identity.Signatures
}
