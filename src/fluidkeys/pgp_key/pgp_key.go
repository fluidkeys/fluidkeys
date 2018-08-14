package pgp_key

import (
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"os"
)

type pgp_key struct {
	email string
}

func Generate(email string) pgp_key {
	config := &packet.Config{RSABits: 4096}

	entity, err := openpgp.NewEntity("", "ian@ian.com", "", config)
	if err != nil {
		fmt.Println("shit")
	}

	write_closer, err := armor.Encode(os.Stdout, openpgp.PublicKeyType, nil)
	defer write_closer.Close()

	entity.Serialize(write_closer)
	fmt.Println()

	k := pgp_key{email}
	return k
}
