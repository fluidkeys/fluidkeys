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

package gpgwrapper

import (
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestParseListSecretKeys(t *testing.T) {
	t.Run("test parsing example colon delimited data", func(t *testing.T) {
		result, err := parseListSecretKeys(exampleListSecretKeys)
		if err != nil {
			t.Fatalf("error running ParseListSecretKeys(..): %v", err)
		}

		if len(result) != 2 {
			t.Fatalf("expected 2 secret keys, got %d: %v", len(result), result)
		}

		expectedFirst := SecretKeyListing{
			Fingerprint: fingerprint.MustParse("A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517"),
			Created:     time.Date(2014, 10, 31, 21, 34, 34, 0, time.UTC), // 31 October 2014 21:34:34
			Uids: []string{
				"Paul Michael Furley <paul@paulfurley.com>",
				"Paul M Furley (http://paulfurley.com) <paul@paulfurley.com>",
			},
		}

		expectedSecond := SecretKeyListing{
			Fingerprint: fingerprint.MustParse("B79F 0840 DEF1 2EBB A72F  F72D 7327 A44C 2157 A758"),
			Created:     time.Date(2018, 9, 4, 16, 15, 46, 0, time.UTC), // Tue Sep  4 17:15:46 BST 2018
			Uids:        []string{"<paul@fluidkeys.com>"},
		}

		gotFirst := result[0]
		gotSecond := result[1]

		assertEqual(t, expectedFirst, gotFirst)
		assertEqual(t, expectedSecond, gotSecond)
	})

	t.Run("parser ignores keys with invalid creation time", func(t *testing.T) {
		result, err := parseListSecretKeys(exampleListSecretKeysInvalidCreationTime)
		if err != nil {
			t.Fatalf("error running ParseListSecretKeys(..): %v", err)
		}

		if len(result) != 0 {
			t.Fatalf("expected 0 secret keys, got %d: %v", len(result), result)
		}
	})

	t.Run("parser ignores keys with revoked flag", func(t *testing.T) {
		result, err := parseListSecretKeys(exampleListSecretKeysRevoked)
		if err != nil {
			t.Fatalf("error running ParseListSecretKeys(..): %v", err)
		}

		if len(result) != 0 {
			t.Fatalf("expected 0 secret keys, got %d: %v", len(result), result)
		}
	})
}

const exampleListSecretKeys = `sec:u:4096:1:309F635DAD1B5517:1414791274:1542012845::u:::scESC:::#:::23::0:
fpr:::::::::A999B7498D1A8DC473E53C92309F635DAD1B5517:
grp:::::::::D38C00EFE88C8E779D9318054320996065468794:
uid:u::::1534236845::38BE7958B7C6E0759B846025E16E993513464797::Paul Michael Furley <paul@paulfurley.com>::::::::::0:
uid:u::::1534236845::7E1BD05565F46274DE035907B610AAD20A5A8079::Paul M Furley (http\x3a//paulfurley.com) <paul@paulfurley.com>::::::::::0:
ssb:u:4096:1:627B1B4E8E532C34:1414791274:1542012904:::::e:::+:::23:
fpr:::::::::58B67D78347ACEAD63C0B185627B1B4E8E532C34:
grp:::::::::C0ADBA1B8590E50B2FCC1B20834B3CEA437C2CBF:
ssb:u:4096:1:0AC6AD63E8E8A9B0:1414792059:1542012904:::::s:::+:::23:
fpr:::::::::CF2954DA9D72255C217CF92A0AC6AD63E8E8A9B0:
grp:::::::::70C585727C0DEF68975055F28C752897DB84FC73:
sec:-:4096:1:7327A44C2157A758:1536077746:1541261746::-:::scESC:::+:::23::0:
fpr:::::::::B79F0840DEF12EBBA72FF72D7327A44C2157A758:
grp:::::::::225E673D5B6E04A75C95377F5856284AF748FC9B:
uid:-::::1536077746::45B589243F83642ED19A8BF02668D946D0182C7C::<paul@fluidkeys.com>::::::::::0:
ssb:-:4096:1:AC51B3BFA77D277A:1536077746:1541261746:::::e:::+:::23:
fpr:::::::::AE02CA144D5F7E91D245F038AC51B3BFA77D277A:
grp:::::::::F9B6EF16A8800449EE7598A73C14EA17962A68D3:`

const exampleListSecretKeysInvalidCreationTime = `sec:-:4096:1:7327A44C2157A758:1536077746XXX:1541261746::-:::scESC:::+:::23::0:
fpr:::::::::B79F0840DEF12EBBA72FF72D7327A44C2157A758:
grp:::::::::225E673D5B6E04A75C95377F5856284AF748FC9B:
uid:-::::1536077746::45B589243F83642ED19A8BF02668D946D0182C7C::<paul@fluidkeys.com>::::::::::0:
ssb:-:4096:1:AC51B3BFA77D277A:1536077746:1541261746:::::e:::+:::23:
fpr:::::::::AE02CA144D5F7E91D245F038AC51B3BFA77D277A:
grp:::::::::F9B6EF16A8800449EE7598A73C14EA17962A68D3:`

const exampleListSecretKeysRevoked = `sec:r:2048:1:638C78A5E281ACDB:1392480548:::-:::sc:::+:::23::0:
fpr:::::::::5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB:
grp:::::::::7DCA4CD7282D7447D0F6AA36109FF6E82FC864B0:
uid:r::::1392480548::7E1BD05565F46274DE035907B610AAD20A5A8079::Paul M Furley (http\x3a//paulfurley.com) <paul@paulfurley.com>::::::::::0:
ssb:r:2048:1:D023F7ED26F2E8C2:1392480548:1441742552:::::e:::+:::23:
fpr:::::::::95A1D6AF08EA03BE3A51D30BD023F7ED26F2E8C2:
grp:::::::::F38929556F4ACCC9EFD861A3286114D4AC9227AB:`
