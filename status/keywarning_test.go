package status

import (
	"fmt"
	"testing"
)

func TestContainsWarningsAboutPrimaryKey(t *testing.T) {
	var tests = []struct {
		warnings       []KeyWarning
		expectedOutput bool
	}{
		{
			[]KeyWarning{
				KeyWarning{Type: SubkeyOverdueForRotation},
				KeyWarning{Type: PrimaryKeyLongExpiry},
			},
			true,
		},
		{
			[]KeyWarning{
				KeyWarning{Type: SubkeyOverdueForRotation},
				KeyWarning{Type: SubkeyLongExpiry},
			},
			false,
		},
		{
			[]KeyWarning{
				KeyWarning{Type: NoValidEncryptionSubkey},
			},
			false,
		},
		{
			[]KeyWarning{},
			false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("for warnings %v", test.warnings), func(t *testing.T) {
			gotOutput := ContainsWarningAboutPrimaryKey(test.warnings)

			if gotOutput != test.expectedOutput {
				t.Fatalf("expected %v, got %v", test.expectedOutput, gotOutput)
			}
		})
	}

}
