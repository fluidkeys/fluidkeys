package pgpkey

import (
	"bytes"
	"fmt"
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
	PublicKey string
}

func Generate(email string) PgpKey {
	config := &packet.Config{RSABits: 4096}

	name, comment := "", ""
	entity, err := openpgp.NewEntity(name, comment, email, config)

	if err != nil {
		fmt.Println("shit")
	}

	buf := new(bytes.Buffer)
	write_closer, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	entity.Serialize(write_closer)
	write_closer.Close()

	publicKey := buf.String()
	k := PgpKey{publicKey}
	return k
}
