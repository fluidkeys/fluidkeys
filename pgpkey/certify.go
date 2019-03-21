package pgpkey

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fluidkeys/crypto/openpgp/packet"
	"github.com/fluidkeys/fluidkeys/policy"
)

// CertifyEmail finds user IDs which match the given email, and creates a certification
// signature using the unlocked key certifier.
func (p *PgpKey) CertifyEmail(email string, certifier *PgpKey, now time.Time) error {
	if p.PrimaryKey.KeyId == certifier.PrimaryKey.KeyId {
		return fmt.Errorf("key and certifier key are the same")
	}
	uids := identitiesMatchingEmail(p, email)
	if len(uids) == 0 {
		return fmt.Errorf("no identities match that email")
	}

	for _, userid := range uids {
		identity, ok := p.Identities[userid]
		if !ok {
			log.Panic(fmt.Sprintf("Identities[\"%s\"] does not exist", userid))
		}

		if certifier.PrivateKey == nil {
			return fmt.Errorf("signer must have PrivateKey")
		}

		config := packet.Config{
			DefaultHash: policy.SignatureHashFunction,
		}

		// Adapted from p.SignIdentity(userid, &signer.Entity, &config)
		exportable := false
		sig := &packet.Signature{
			CreationTime:            now,
			SigType:                 packet.SigTypeGenericCert,
			PubKeyAlgo:              certifier.PrivateKey.PubKeyAlgo,
			Hash:                    config.Hash(),
			IssuerKeyId:             &certifier.PrivateKey.KeyId,
			ExportableCertification: &exportable,
		}

		err := sig.SignUserId(userid, p.PrimaryKey, certifier.PrivateKey, &config)
		if err != nil {
			return err
		}

		newSigs := []*packet.Signature{}
		for _, existingSig := range identity.Signatures {
			if existingSig.SigType == sig.SigType && existingSig.IssuerKeyId == sig.IssuerKeyId {
				// drop this existing signature: the new one replaces it
				continue
			}
			newSigs = append(newSigs, existingSig)
		}

		newSigs = append(newSigs, sig)

		identity.Signatures = newSigs
	}
	return nil
}

func identitiesMatchingEmail(key *PgpKey, email string) (uids []string) {
	for _, identity := range key.Identities {
		if matches(identity.UserId.Email, email) {
			uids = append(uids, identity.Name)
		}
	}
	return uids
}

// matches performs a relaxed comparison of 2 email addresses, since the context in which it's used
// is on an existing key. We allow JOHNDOE@example.com to match equal to johndoe@example.com where
// in other contexts we probably wouldn't (e.g. doing a global key discovery, where those two
// mail names could actually be different :\
func matches(email1 string, email2 string) bool {
	return strings.ToLower(email1) == strings.ToLower(email2)
}
