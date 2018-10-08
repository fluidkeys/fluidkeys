package compression

import (
	"fmt"
)

type CompressionAlgorithm = uint8

const (
	// https://tools.ietf.org/html/rfc4880#section-9.3
	Uncompressed CompressionAlgorithm = 0
	ZIP                               = 1
	ZLIB                              = 2
	BZIP2                             = 3
)

func Name(compressionAlgorithm CompressionAlgorithm) string {
	switch compressionAlgorithm {
	case Uncompressed:
		return "Uncompressed"

	case ZIP:
		return "ZIP"

	case ZLIB:
		return "ZLIP"

	case BZIP2:
		return "BZIP2"

	case 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110:
		return fmt.Sprintf("Private/experimental (%d)", compressionAlgorithm)

	default:
		return fmt.Sprintf("Unknown (%d)", compressionAlgorithm)
	}

}
