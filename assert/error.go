package assert

import "testing"

func ErrorIsNil(t *testing.T, got error) {
	t.Helper()
	if got != nil {
		t.Fatalf("got an error but didnt want one '%s'", got)
	}
}

func ErrorIsNotNil(t *testing.T, got error) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected an error, but got none")
	}
}
