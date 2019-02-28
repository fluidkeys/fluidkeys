package fk

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/colour"

	"github.com/fluidkeys/fluidkeys/assert"
)

func TestValidateTeamName(t *testing.T) {
	t.Run("returns the name as a string if valid", func(t *testing.T) {
		teamName := "Kiffix"

		got, err := validateTeamName(teamName)
		assert.NoError(t, err)
		assert.Equal(t, teamName, got)
	})

	t.Run("returns an empty string and error if blank", func(t *testing.T) {
		teamName := ""

		got, err := validateTeamName(teamName)
		assert.Equal(t, "", got)
		assert.Equal(t, fmt.Errorf("Team name was blank"), err)
	})

	t.Run("returns an empty string and error if contains disallowed runes", func(t *testing.T) {
		teamName := colour.Warning("Kiffix")

		got, err := validateTeamName(teamName)
		assert.Equal(t, "", got)
		assert.Equal(t, fmt.Errorf("Team name contained invalid characters"), err)
	})

	t.Run("returns an empty string and error if not valid utf-8", func(t *testing.T) {
		teamName := string([]byte{255})

		got, err := validateTeamName(teamName)
		assert.Equal(t, "", got)
		assert.Equal(t, fmt.Errorf("Team name contained invalid characters"), err)
	})
}
