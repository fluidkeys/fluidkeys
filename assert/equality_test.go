package assert

import (
	"fmt"
	"testing"
)

func TestEqualSliceOfStrings(t *testing.T) {

	var tests = []struct {
		sliceA         []string
		sliceB         []string
		expectedOutput bool
	}{
		{
			[]string{"A", "B", "C"},
			[]string{"A", "B", "C"},
			true,
		},
		{
			[]string{"A", "B"},
			[]string{"A", "B", "C"},
			false,
		},
		{
			[]string{},
			[]string{"A", "B", "C"},
			false,
		},
		{
			nil,
			[]string{"A", "B", "C"},
			false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for slices '%v' and '%v'", test.sliceA, test.sliceB), func(t *testing.T) {
			actualOutput := EqualSliceOfStrings(test.sliceA, test.sliceB)

			if actualOutput != test.expectedOutput {
				t.Errorf("expected output '%v', got '%v'", test.expectedOutput, actualOutput)
			}
		})
	}

}
