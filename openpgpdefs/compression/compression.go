package compression

type CompressionAlgorithm = uint8

const (
	// https://tools.ietf.org/html/rfc4880#section-9.3
	Uncompressed CompressionAlgorithm = 0
	ZIP                               = 1
	ZLIB                              = 2
	BZIP2                             = 3
)
