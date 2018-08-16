package pgpkey

import (
	"bytes"
	"fmt"
	"github.com/alokmenghrajani/gpgeez"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
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
