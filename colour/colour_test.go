package colour

import (
	"fmt"
	"testing"
)

func TestStripAllColourCodes(t *testing.T) {
	var tests = []struct {
		inputString    string
		expectedOutput string
	}{
		{
			"23",
			"23",
		},
		{
			"Hello",
			"Hello",
		},
		{
			LightBlue("Hello"),
			"Hello",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for string '%v'", test.inputString), func(t *testing.T) {
			gotOutput := StripAllColourCodes(test.inputString)

			if gotOutput != test.expectedOutput {
				t.Fatalf("expected '%s', got '%s'", test.expectedOutput, gotOutput)
			}
		})
	}
}
