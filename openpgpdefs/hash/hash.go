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
