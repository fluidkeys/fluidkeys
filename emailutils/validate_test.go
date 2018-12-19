package emailutils

import (
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestRoughlyValidateEmail(t *testing.T) {
	t.Run("with a roughly valid email address", func(t *testing.T) {
		email := "jane@example.com"
		assert.Equal(t, true, RoughlyValidateEmail(email))
	})
	t.Run("with a roughly invalid email address", func(t *testing.T) {
		email := "joe.example.com"
		assert.Equal(t, false, RoughlyValidateEmail(email))
	})
}
