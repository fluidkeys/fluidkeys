package assert

import (
	"fmt"
	"testing"
)

func TestIsEqualForErrors(t *testing.T) {

	t.Run("two errors made with fmt.Errorf(..) compare equal", func(t *testing.T) {
		got := isEqual(fmt.Errorf("foo"), fmt.Errorf("foo"))

		if !got {
			t.Fatalf("expected errors to compare equal, but they didn't")
		}
	})

	t.Run("error made with fmt.Errorf(..) equal to custom typed error", func(t *testing.T) {
		customError := &customErrorType1{}
		got := isEqual(fmt.Errorf("foo"), customError)

		if got {
			t.Fatalf("didn't expect errors to compare true due to different types")
		}
	})

}

type customErrorType1 struct{}

func (e *customErrorType1) Error() string { return "foo" }
