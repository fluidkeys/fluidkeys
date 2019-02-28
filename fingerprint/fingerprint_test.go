package fingerprint

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestFingerprint(t *testing.T) {
	var tests = []struct {
		inputString    string
		expectedOutput string
		expectedError  error
	}{
		{
			"A999B7498D1A8DC473E53C92309F635DAD1B5517",
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			nil, // good fingerprint: no error
		},
		{
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			nil, // good fingerprint: no error
		},
		{
			`0xA999B7498D1A8DC473E53C92309F635DAD1B5517`,
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			nil, // good fingerprint: no error
		},
		{
			`0C10 C4A2 6E9B 1B46 E713  C8D2 BEBF 0628 DAFF 9F4B`,
			`0C10 C4A2 6E9B 1B46 E713  C8D2 BEBF 0628 DAFF 9F4B`,
			nil, // good fingerprint: no error
		},
		{
			"a999b7498d1a8dc473e53c92309f635dad1b5517",
			"A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517",
			nil, // good fingerprint: no error
		},
		{
			// too long
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFD",
			"",
			fmt.Errorf("invalid v4 fingerprint: not 40 hex characters"),
		},
		{
			// too short
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEE",
			"",
			fmt.Errorf("invalid v4 fingerprint: not 40 hex characters"),
		},
		{
			// contains bad character G
			"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFG",
			"",
			fmt.Errorf("invalid v4 fingerprint: not 40 hex characters"),
		},
		{
			"",
			"",
			fmt.Errorf("invalid fingerprint: empty"),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("fingerprint.Parse(%v)", test.inputString), func(t *testing.T) {
			fingerprint, gotError := Parse(test.inputString)

			assert.Equal(t, test.expectedError, gotError)

			if gotError == nil {
				assert.Equal(t, test.expectedOutput, fingerprint.String())
			}

		})
	}

	for _, test := range tests {

		t.Run(fmt.Sprintf("Fingerprint.UnmarshalText(%v)", test.inputString), func(t *testing.T) {
			f := Fingerprint{}
			gotError := f.UnmarshalText([]byte(test.inputString))

			assert.Equal(t, test.expectedError, gotError)

			if gotError == nil {
				assert.Equal(t, test.expectedOutput, f.String())
			}
		})
	}

	t.Run("TextMarshaler interface (using JSON package)", func(t *testing.T) {
		fp := MustParse("A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517")

		t.Run("with Fingerprint value (not pointer)", func(t *testing.T) {
			got, err := json.Marshal(fp)
			assert.NoError(t, err)

			expected := "\"A999B7498D1A8DC473E53C92309F635DAD1B5517\""
			assert.Equal(t, expected, string(got))
		})

		t.Run("with *Fingerprint (pointer)", func(t *testing.T) {
			var p *Fingerprint = &fp
			got, err := json.Marshal(p)
			assert.NoError(t, err)

			expected := "\"A999B7498D1A8DC473E53C92309F635DAD1B5517\""
			assert.Equal(t, expected, string(got))
		})

		t.Run("with *Fingerprint of nil", func(t *testing.T) {
			var p *Fingerprint
			p = nil
			got, err := json.Marshal(p)
			assert.NoError(t, err)

			expected := "null"
			assert.Equal(t, expected, string(got))
		})
	})

	t.Run("FromBytes function", func(t *testing.T) {

		fp := FromBytes(exampleFingerprintBytes)
		if !fp.IsSet() {
			t.Fatalf("FromBytes did not set IsSet=true")
		}

		expected := "A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517"
		got := fp.String()

		if expected != got {
			t.Errorf("expected String='%s', got='%s'", expected, got)
		}
	})

	t.Run("Hex method", func(t *testing.T) {
		fp := MustParse("A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517")
		expected := "A999B7498D1A8DC473E53C92309F635DAD1B5517"
		got := fp.Hex()

		if expected != got {
			t.Errorf("expected Hex='%s', got='%s'", expected, got)
		}
	})

	t.Run("Uri method", func(t *testing.T) {
		fp := MustParse("0999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517")
		expected := "OPENPGP4FPR:0999B7498D1A8DC473E53C92309F635DAD1B5517"
		got := fp.Uri()

		if expected != got {
			t.Errorf("expected Uri='%s', got='%s'", expected, got)
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
		expected := exampleFingerprintBytes
		got := fp.Bytes()

		if expected != got {
			t.Errorf("expected Bytes='%v', got='%v'", expected, got)
		}
	})

}

var exampleFingerprintBytes = [20]byte{0xA9, 0x99, 0xB7, 0x49, 0x8D, 0x1A, 0x8D, 0xC4, 0x73, 0xE5, 0x3C, 0x92, 0x30, 0x9F, 0x63, 0x5D, 0xAD, 0x1B, 0x55, 0x17}
