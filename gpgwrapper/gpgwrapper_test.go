package gpgwrapper

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/fluidkeys/fluidkeys/fingerprint"
)

func TestParseGPGOutputVersion(t *testing.T) {
	t.Run("test GPG output from Ubuntu", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG) 2.2.4\nbar"
		assertParsesVersionCorrectly(t, gpgOutput, "2.2.4")
	})

	t.Run("test GPG output from macOS", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG/MacGPG2) 2.2.8\nbar"
		assertParsesVersionCorrectly(t, gpgOutput, "2.2.8")
	})

	t.Run("test long version numbers", func(t *testing.T) {
		gpgOutput := "foo\ngpg (GnuPG/MacGPG2) 111.222.333\nbar"
		assertParsesVersionCorrectly(t, gpgOutput, "111.222.333")
	})

	t.Run("test output not containing a version number", func(t *testing.T) {
		gpgOutput := "foo\ngpg\nbar"
		_, err := parseVersionString(gpgOutput)
		assertError(t, err, ErrNoVersionStringFound)
	})
}

func TestRunningGPG(t *testing.T) {
	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}

	t.Run("with valid arguments", func(t *testing.T) {
		arguments := "--version"
		_, err := gpg.run(arguments)
		assertNoError(t, err)
	})

	t.Run("with invalid arguments", func(t *testing.T) {
		arguments := "--foo"
		_, err := gpg.run(arguments)
		if err == nil {
			t.Fatalf("wanted an error but didn't get one")
		}
		got := err.Error()
		differentGPGErrors := []string{
			"gpg: invalid option \"--foo\"",
			"gpg: Invalid option \"--foo\"",
		}
		assertStringHasOneOfSlice(t, got, differentGPGErrors)
	})
}

func TestRunGpgWithStdin(t *testing.T) {
	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}

	t.Run("with a valid public key", func(t *testing.T) {
		successMessages := []string{
			"gpg: key 0x0BBD7E7E5B85C8D3: public key \"test@example.com\" imported",
			"gpg: key 0x0BBD7E7E5B85C8D3: \"test@example.com\" not changed",
		}

		arguments := []string{"--import"}

		output, err := gpg.runWithStdin(ExamplePublicKey, arguments...)

		if err != nil {
			t.Errorf("Test failed, returned error %s", err)
		}

		var sawSuccessMessage = false

		for _, successMessage := range successMessages {
			if strings.Contains(output, successMessage) {
				sawSuccessMessage = true
				break
			}
		}

		if !sawSuccessMessage {
			t.Errorf("GPGs output '%s' did not contain any success messages", output)
		}
	})
}

func TestImportPublicKey(t *testing.T) {
	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}

	t.Run("with valid public key", func(t *testing.T) {
		_, err := gpg.ImportArmoredKey(ExamplePublicKey)
		assertNoError(t, err)
	})

	t.Run("with valid private key", func(t *testing.T) {
		_, err := gpg.ImportArmoredKey(ExamplePrivateKey)
		assertNoError(t, err)
	})
}

func TestListSecretKeys(t *testing.T) {

	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}
	gpg.ImportArmoredKey(ExamplePublicKey)
	gpg.ImportArmoredKey(ExamplePrivateKey)
	secretKeys, err := gpg.ListSecretKeys()
	if err != nil {
		t.Fatalf("error calling gpg.ListSecretKeys(): %v", err)
	}

	if len(secretKeys) != 1 {
		t.Fatalf("expected 1 secret key, got %d: %v", len(secretKeys), secretKeys)
	}

	expectedKey := SecretKeyListing{
		Fingerprint: fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"),
		Uids:        []string{"test@example.com"},
		Created:     time.Date(2018, 8, 22, 12, 8, 23, 0, time.UTC),
	}

	assertEqual(t, expectedKey, secretKeys[0])

}

func TestExportPublicKey(t *testing.T) {
	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}
	gpg.ImportArmoredKey(ExamplePublicKey)
	gpg.ImportArmoredKey(ExamplePrivateKey)

	t.Run("with a valid fingerprint", func(t *testing.T) {
		_, err := gpg.ExportPublicKey(fingerprint.MustParse("8FBC 0768 76F2 B042 AE2B  A37B 0BBD 7E7E 5B85 C8D3"))

		if err != nil {
			t.Errorf("Failed to run ExportPublicKey: %v", err)
		}

	})

	t.Run("with an invalid fingerprint", func(t *testing.T) {
		_, err := gpg.ExportPublicKey(fingerprint.MustParse("0000 0000 0000 0000 0000 0000 0000 0000 0000 0000"))

		if err == nil {
			t.Errorf("ExportPublicKey should have returned an error but didnt")
		}
	})
}

func TestExportPrivateKey(t *testing.T) {
	gpg := GnuPG{homeDir: makeTempGnupgHome(t)}
	gpg.ImportArmoredKey(ExamplePublicKey)
	gpg.ImportArmoredKey(ExamplePrivateKey)

	t.Run("with a valid fingerprint and password", func(t *testing.T) {
		_, err := gpg.ExportPrivateKey(fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"), "foo")

		if err != nil {
			t.Errorf("Failed to run ExportPrivateKey: %v", err)
		}
	})

	t.Run("with an invalid password", func(t *testing.T) {
		// GnuPG versions 2.1+ require a password to export a secret key, even though it's
		// exported *encrypted* with the password.
		// Previous versions just output the encrypted key without a password.

		version, err := gpg.Version()
		if err != nil {
			t.Fatalf("failed to get version: %v", err)
		}

		fmt.Printf("gpg version: %s\n", version)

		if version[0:3] == "2.1" || version[0:3] == "2.0" {
			fmt.Printf("skipping test, GnuPG < 2.2 didn't require a valid password to export private keys\n")
			t.Skip()
		}

		output, err := gpg.ExportPrivateKey(fingerprint.MustParse("C16B 89AC 31CD F3B7 8DA3  3AAE 1D20 FC95 4793 5FC6"), "wrong password")

		if err == nil {
			t.Errorf("ExportPrivateKey should have returned an error but didnt. output: %s", output)
		}
	})

	t.Run("with an invalid fingerprint", func(t *testing.T) {
		_, err := gpg.ExportPrivateKey(fingerprint.MustParse("0000 0000 0000 0000 0000 0000 0000 0000 0000 0000"), "bar")

		if err == nil {
			t.Errorf("ExportPrivateKey should have returned an error but didnt")
		}
	})
}

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

func TestParseTimestamp(t *testing.T) {
	ignore := time.Now()

	var timestampTests = []struct {
		inputString       string
		expectedTime      time.Time
		shouldReturnError bool
	}{
		{
			"1536317435", // in BST
			time.Date(2018, 9, 7, 10, 50, 35, 0, time.UTC),
			false,
		},
		{
			"1516034100", // in GMT
			time.Date(2018, 1, 15, 16, 35, 0, 0, time.UTC),
			false,
		},
		{
			"-10",
			time.Date(1969, 12, 31, 23, 59, 50, 0, time.UTC),
			false,
		},
		{
			"1516034100a", // bad: not an int
			ignore,
			true, // should return error
		},
	}

	for _, test := range timestampTests {
		t.Run(fmt.Sprintf("parseTimestamp(%v)", test.inputString), func(t *testing.T) {
			gotTime, err := parseTimestamp(test.inputString)

			var gotError bool = (err != nil)

			if (gotError && !test.shouldReturnError) || (!gotError && test.shouldReturnError) {
				t.Fatalf("expected shouldReturnError=%v, got err=%v", test.shouldReturnError, err)
			}

			if gotError {
				if gotTime != nil {
					t.Fatalf("returned an error, expected *time.Time to be nil but it wasn't. err: %v, time: %v", err, gotTime)
				}

			} else {
				if gotTime == nil {
					t.Fatalf("got nil *time.Time but err wasn't set")
				}

				if test.expectedTime != *gotTime {
					t.Errorf("expected time: %v, got: %v", test.expectedTime, gotTime)
				}
			}

		})
	}
}

func TestUnquoteColons(t *testing.T) {
	var tests = []struct {
		inputString    string
		expectedOutput string
	}{
		{
			`http\x3a//`,
			"http://",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("unquoteColons(%v)", test.inputString), func(t *testing.T) {
			gotOutput := unquoteColons(test.inputString)
			if test.expectedOutput != gotOutput {
				t.Fatalf("expected '%s', got '%s'", test.expectedOutput, gotOutput)
			}
		})
	}
}

func assertEqual(t *testing.T, expected SecretKeyListing, got SecretKeyListing) {
	t.Helper()
	if expected.Fingerprint != got.Fingerprint {
		t.Fatalf("fingerprints don't match, expected '%s', got '%s'",
			expected.Fingerprint, got.Fingerprint)
	}

	if expected.Created != got.Created {
		t.Fatalf("created don't match, expected '%s', got '%s'", expected.Created, got.Created)
	}

	if len(expected.Uids) != len(got.Uids) {
		t.Fatalf("uids don't match, expected '%v', got '%v'", expected.Uids, got.Uids)
	}

	for i := range expected.Uids {
		if expected.Uids[i] != got.Uids[i] {
			t.Fatalf("uids don't match, expected '%v', got '%v'", expected.Uids, got.Uids)
		}
	}
}

func makeTempGnupgHome(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "gpg.test.")
	if err != nil {
		t.Fatalf("Failed to create temp GnuPG dir: %v", err)
	}
	return dir
}

func assertParsesVersionCorrectly(t *testing.T, gpgOutput string, want string) {
	t.Helper()
	got, err := parseVersionString(gpgOutput)

	if err != nil {
		t.Errorf("Test failed, returned error %s", err)
	}

	if got != want {
		t.Errorf("Test failed, wanted '%s', got '%s'", want, got)
	}
}

func assertError(t *testing.T, got error, want error) {
	t.Helper()

	if got == nil {
		t.Fatal("wanted an error but didnt get one")
	}

	if got.Error() != want.Error() {
		t.Errorf("wanted '%s', got '%s'", want, got)
	}
}

func assertNoError(t *testing.T, got error) {
	t.Helper()
	if got != nil {
		t.Fatalf("got an error but didnt want one '%s'", got)
	}
}

func assertStringHasOneOfSlice(t *testing.T, a string, list []string) {
	t.Helper()
	for _, b := range list {
		if strings.Contains(a, b) {
			return
		}
	}
	t.Errorf("expected '%v', to contain '%s'", list, a)
}

const ExamplePublicKey string = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
We0fI5qRW/I=
=MZEv
-----END PGP PUBLIC KEY BLOCK-----`

const ExamplePrivateKey string = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
gccR56G2L/PJK9su8t1NtZp3d8h/7yCJhyM=
=24gu
-----END PGP PRIVATE KEY BLOCK-----`

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
