package fingerprint

import (
	"fmt"
	"testing"
)

func TestFingerprint(t *testing.T) {
	var tests = []struct {
		inputString       string
		expectedOutput    string
		shouldReturnError bool
	}{
		{
			"A999B7498D1A8DC473E53C92309F635DAD1B5517",
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			false,
		},
		{
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			false,
		},
		{
			`0xA999B7498D1A8DC473E53C92309F635DAD1B5517`,
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			false,
		},
		{
			"a999b7498d1a8dc473e53c92309f635dad1b5517",
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			false,
		},
		{
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFD",
			"",
			true, // error: too long
		},
		{
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEE",
			"",
			true, // error: too long
		},
		{
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFG",
			"",
			true, // error, contains bad character G
		},
		{
			"",
			"",
			true, // error, empty
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Fingerprint.FromString(%v)", test.inputString), func(t *testing.T) {
			fingerprint, err := Parse(test.inputString)

			var gotError bool = err != nil

			if gotError != test.shouldReturnError {
				t.Errorf("expected shouldReturnError=%v, got err=%v", test.shouldReturnError, err)
			}

			if test.shouldReturnError {
				if err == nil {
					t.Errorf("expected shouldReturnError=%v, got err=%v", test.shouldReturnError, err)
				}

			} else {

				if err != nil {
					t.Fatalf("expected shouldReturnError=%v, got err=%v", test.shouldReturnError, err)
				}

				gotOutput := fingerprint.String()

				if test.expectedOutput != gotOutput {
					t.Errorf("expected output='%s', got='%s'", test.expectedOutput, gotOutput)
				}
			}

		})
	}

	t.Run("Hex method", func(t *testing.T) {
		fp := MustParse("A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517")
		expected := "A999B7498D1A8DC473E53C92309F635DAD1B5517"
		got := fp.Hex()

		if expected != got {
			t.Errorf("expected Hex='%s', got='%s'", expected, got)
		}
	})

	t.Run("IsSet method (when set)", func(t *testing.T) {
		fp := MustParse("A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517")
		expected := true
		got := fp.IsSet()

		if expected != got {
			t.Errorf("expected IsSet()='%v', got='%v'", expected, got)
		}
	})

	t.Run("IsSet method (not set)", func(t *testing.T) {
		var fp Fingerprint
		expected := false
		got := fp.IsSet()

		if expected != got {
			t.Errorf("expected IsSet()='%v', got='%v'", expected, got)
		}
	})

	t.Run("Bytes method", func(t *testing.T) {
		fp := MustParse("A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517")
		expected := [20]byte{0xA9, 0x99, 0xB7, 0x49, 0x8D, 0x1A, 0x8D, 0xC4, 0x73, 0xE5, 0x3C, 0x92, 0x30, 0x9F, 0x63, 0x5D, 0xAD, 0x1B, 0x55, 0x17}
		got := fp.Bytes()

		if expected != got {
			t.Errorf("expected Bytes='%v', got='%v'", expected, got)
		}
	})

}
