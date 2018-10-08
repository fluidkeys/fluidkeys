package hash

import (
	"fmt"
)

type HashAlgorithm = uint8

const (
	// https://tools.ietf.org/html/rfc4880#section-9.4
	Md5       HashAlgorithm = 1
	Sha1                    = 2
	Ripemd160               = 3
	Sha256                  = 8
	Sha384                  = 9
	Sha512                  = 10
	Sha224                  = 11
)

func Name(hashByte uint8) string {
	switch hashByte {
	case Md5:
		return "MD5"

	case Sha1:
		return "SHA1"

	case Ripemd160:
		return "RIPEMD160"

	case Sha256:
		return "SHA256"

	case Sha384:
		return "SHA384"

	case Sha512:
		return "SHA512"

	case Sha224:
		return "SHA224"

	case 4, 5, 6, 7:
		return fmt.Sprintf("Reserved (%d)", hashByte)

	case 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110:
		return fmt.Sprintf("Private/experimental (%d)", hashByte)

	default:
		return fmt.Sprintf("Unknown (%d)", hashByte)
	}

}
