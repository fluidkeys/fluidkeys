package pgpkey

import (
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"os"
)

type PgpKey struct {
	PublicKey string
}

func Generate(email string) PgpKey {
	config := &packet.Config{RSABits: 4096}

	entity, err := openpgp.NewEntity("", email, "", config)
	if err != nil {
		fmt.Println("shit")
	}

	write_closer, err := armor.Encode(os.Stdout, openpgp.PublicKeyType, nil)
	defer write_closer.Close()

	entity.Serialize(write_closer)
	fmt.Println()

	k := PgpKey{email}
	return k
}
