package symmetric

import (
	"fmt"
)

type SymmetricAlgorithm = uint8

const (
	// https://tools.ietf.org/html/rfc4880#section-9.2
	IDEA       SymmetricAlgorithm = 1 // not defined in openpgp.packet CipherFunction
	TripleDES                     = 2
	CAST5                         = 3
	Blowfish                      = 4 // not defined in openpgp.packet CipherFunction
	AES128                        = 7
	AES192                        = 8
	AES256                        = 9
	Twofish256                    = 10 // not defined in openpgp.packet CipherFunction

	// https://tools.ietf.org/html/rfc5581#section-3
	Camellia128 = 11 // not defined in openpgp.packet CipherFunction
	Camellia192 = 12
	Camellia256 = 13
)

func Name(symmetricAlgorithm SymmetricAlgorithm) string {
	switch symmetricAlgorithm {
	case IDEA:
		return "IDEA"

	case TripleDES:
		return "TripleDES"

	case CAST5:
		return "CAST5"

	case Blowfish:
		return "Blowfish"

	case AES128:
		return "AES128"

	case AES192:
		return "AES192"

	case AES256:
		return "AES256"

	case Twofish256:
		return "Twofish"

	case Camellia128:
		return "Camellia128"

	case Camellia192:
		return "Camellia192"

	case Camellia256:
		return "Camellia256"

	case 5, 6:
		return fmt.Sprintf("Reserved (%d)", symmetricAlgorithm)

	case 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110:
		return fmt.Sprintf("Private/experimental (%d)", symmetricAlgorithm)

	default:
		return fmt.Sprintf("Unknown (%d)", symmetricAlgorithm)
	}

}
