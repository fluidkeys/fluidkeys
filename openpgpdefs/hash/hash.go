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
	case 1:
		return "MD5"
	case 2:
		return "SHA1"
	case 3:
		return "RIPEMD160"
	case 4, 5, 6, 7:
		return fmt.Sprintf("Reserved (%d)", hashByte)

	case 8:
		return "SHA256"

	case 9:
		return "SHA384"

	case 10:
		return "SHA512"

	case 11:
		return "SHA224"

	case 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110:
		return fmt.Sprintf("Private/experimental (%d)", hashByte)

	default:
		return fmt.Sprintf("Unknown (%d)", hashByte)
	}

}
