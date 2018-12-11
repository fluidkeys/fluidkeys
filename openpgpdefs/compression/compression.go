// Copyright 2018 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

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
		return "ZLIB"

	case BZIP2:
		return "BZIP2"

	case 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110:
		return fmt.Sprintf("Private/experimental (%d)", compressionAlgorithm)

	default:
		return fmt.Sprintf("Unknown (%d)", compressionAlgorithm)
	}

}
