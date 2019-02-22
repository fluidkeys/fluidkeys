// Copyright 2019 Paul Furley and Ian Drysdale
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

package gpgwrapper

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestParseListPublicKeys(t *testing.T) {
	t.Run("test parsing example colon delimited data", func(t *testing.T) {
		result, err := parseListPublicKeys(exampleListPublicKeys)
		if err != nil {
			t.Fatalf("error running ParseListPublicKeys(..): %v", err)
		}

		if len(result) != 2 {
			t.Fatalf("expected 2 secret keys, got %d: %v", len(result), result)
		}

		expectedFirst := KeyListing{
			Fingerprint: fingerprint.MustParse("86FF 75A3 8CB4 756A 5DDC  E541 7A5F DAF6 E82A 2CC6"),
			Created:     time.Date(2019, 02, 21, 14, 34, 57, 0, time.UTC), // 21 Feb 2018 14:34:57
			Uids: []string{
				"Joe Smith <joe@example.com>",
				"<joe-work@example.com>",
			},
		}

		expectedSecond := KeyListing{
			Fingerprint: fingerprint.MustParse("CFA8 A534 0CCD E66D 633A  9F4E 61A2 89A5 106B 040C"),
			Created:     time.Date(2019, 02, 21, 14, 35, 15, 0, time.UTC), // 21 Feb 2018 14:35:15
			Uids:        []string{"<jane@example.com>"},
		}

		gotFirst := result[0]
		gotSecond := result[1]

		assertEqual(t, expectedFirst, gotFirst)
		assertEqual(t, expectedSecond, gotSecond)
	})

	t.Run("parser ignores keys with invalid creation time", func(t *testing.T) {
		result, err := parseListPublicKeys(exampleListPublicKeysInvalidCreationTime)
		if err != nil {
			t.Fatalf("error running ParseListPublicKeys(..): %v", err)
		}

		if len(result) != 0 {
			t.Fatalf("expected 0 secret keys, got %d: %v", len(result), result)
		}
	})

	t.Run("parser ignores keys with revoked flag", func(t *testing.T) {
		result, err := parseListPublicKeys(exampleListPublicKeysRevoked)
		if err != nil {
			t.Fatalf("error running ParseListPublicKeys(..): %v", err)
		}

		if len(result) != 0 {
			t.Fatalf("expected 0 secret keys, got %d: %v", len(result), result)
		}
	})
}

const exampleListPublicKeys = `pub:u:2048:1:7A5FDAF6E82A2CC6:1550759697:1613831697::u:::scESC::::::23::0:
fpr:::::::::86FF75A38CB4756A5DDCE5417A5FDAF6E82A2CC6:
uid:u::::1550760409::5317EC69F0E306292D6387EBBE963BF677A0256E::Joe Smith <joe@example.com>::::::::::0:
uid:u::::1550759697::B7C30333ADD309F60660D170326BAA027E51B68F::<joe-work@example.com>::::::::::0:
sub:u:2048:1:756E1B445E29D81D:1550759697::::::e::::::23:
fpr:::::::::2E839BC22948C456D22CA4D4756E1B445E29D81D:
sub:u:2048:1:DA974C5855E1F2D3:1550760419:1553352419:::::e::::::23:
fpr:::::::::10A0C4A9E75BDA3E612A0223DA974C5855E1F2D3:
pub:u:2048:1:61A289A5106B040C:1550759715:1613831715::u:::scESC::::::23::0:
fpr:::::::::CFA8A5340CCDE66D633A9F4E61A289A5106B040C:
uid:u::::1550759715::D0535A5433696A9AD9C60C92F31E63E90E62BF75::<jane@example.com>::::::::::0:
sub:u:2048:1:A9EF283407CA7724:1550759715::::::e::::::23:
fpr:::::::::3A762DC026AB117DA75EC9E2A9EF283407CA7724:`

const exampleListPublicKeysInvalidCreationTime = `pub:u:2048:1:61A289A5106B040C:1550759715XXX:1613831715::u:::scESC::::::23::0:
fpr:::::::::CFA8A5340CCDE66D633A9F4E61A289A5106B040C:
uid:u::::1550759715::D0535A5433696A9AD9C60C92F31E63E90E62BF75::<jane@example.com>::::::::::0:
sub:u:2048:1:A9EF283407CA7724:1550759715::::::e::::::23:
fpr:::::::::3A762DC026AB117DA75EC9E2A9EF283407CA7724:`

const exampleListPublicKeysRevoked = `pub:r:2048:1:61A289A5106B040C:1550759715:1613831715::u:::sc::::::23::0:
fpr:::::::::CFA8A5340CCDE66D633A9F4E61A289A5106B040C:
uid:r::::1550759715::D0535A5433696A9AD9C60C92F31E63E90E62BF75::<jane@example.com>::::::::::0:
sub:r:2048:1:A9EF283407CA7724:1550759715::::::e::::::23:
fpr:::::::::3A762DC026AB117DA75EC9E2A9EF283407CA7724:`
