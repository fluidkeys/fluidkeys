package team

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/gofrs/uuid"
)

func TestValidateUpate(t *testing.T) {
	tina := Person{
		Email:       "tina@example.com",
		Fingerprint: exampledata.ExampleFingerprint2,
		IsAdmin:     true,
	}

	chat := Person{
		Email:       "chat@example.com",
		Fingerprint: exampledata.ExampleFingerprint3,
		IsAdmin:     false,
	}

	chatAdmin := Person{
		Email:       "chat@example.com",
		Fingerprint: exampledata.ExampleFingerprint3,
		IsAdmin:     true,
	}

	mark := Person{
		Email:       "mark@example.com",
		Fingerprint: exampledata.ExampleFingerprint4,
		IsAdmin:     false,
	}

	team := Team{
		UUID:   uuid.Must(uuid.NewV4()),
		Name:   "Test team",
		People: []Person{tina, chat},
	}

	t.Run("a team member can be removed", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{tina, chat, mark}

		assert.NoError(t, ValidateUpdate(&team, &updatedTeam, &tina))
	})

	t.Run("a team member can be removed", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{tina}

		assert.NoError(t, ValidateUpdate(&team, &updatedTeam, &tina))
	})

	t.Run("a team member can be promoted to admin", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{tina, chatAdmin}

		assert.NoError(t, ValidateUpdate(&team, &updatedTeam, &tina))
	})

	t.Run("a team member can be demoted as admin", func(t *testing.T) {
		teamBefore := team
		teamBefore.People = []Person{tina, chatAdmin}

		teamAfter := team
		teamAfter.People = []Person{tina, chat}

		assert.NoError(t, ValidateUpdate(&teamBefore, &teamAfter, &tina))
	})

	t.Run("a team can be unchanged", func(t *testing.T) {
		assert.NoError(t, ValidateUpdate(&team, &team, &tina))
	})

	t.Run("error if I'm not an admin of the original team", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{tina, chat, mark}

		assert.Equal(t,
			fmt.Errorf("you're not a team admin"),
			ValidateUpdate(&team, &updatedTeam, &chat),
		)
	})

	t.Run("error if team UUID changes", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.UUID = uuid.Must(uuid.NewV4())

		assert.Equal(t,
			fmt.Errorf("team UUID cannot be changed"),
			ValidateUpdate(&team, &updatedTeam, &chat),
		)
	})

	t.Run("error if team name changes", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.Name = "Updated name"

		assert.Equal(t,
			fmt.Errorf("team name cannot currently be changed"),
			ValidateUpdate(&team, &updatedTeam, &chat),
		)
	})

	t.Run("error if removing self from team", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{chatAdmin}

		assert.Equal(t,
			fmt.Errorf("can't remove yourself from the team"),
			ValidateUpdate(&team, &updatedTeam, &tina),
		)
	})

	t.Run("error if demoting self as admin", func(t *testing.T) {
		teamBefore := team
		teamBefore.People = []Person{tina, chatAdmin}

		teamAfter := team
		teamAfter.People = []Person{tina, chat}

		assert.Equal(t,
			fmt.Errorf("can't demote yourself as team admin"),
			ValidateUpdate(&teamBefore, &teamAfter, &chat),
		)
	})

	t.Run("error if email appears twice (different fingerprint)", func(t *testing.T) {
		updatedTeam := team
		chatDifferentKey := chat
		chat.Fingerprint = exampledata.ExampleFingerprint4

		updatedTeam.People = []Person{tina, chat, chatDifferentKey}

		assert.Equal(t,
			fmt.Errorf("email listed more than once: chat@example.com"),
			ValidateUpdate(&team, &updatedTeam, &tina),
		)
	})

	t.Run("error if fingerprint appears twice (different emails)", func(t *testing.T) {
		updatedTeam := team

		chatDifferentEmail := chat
		chat.Email = "chat2@example.com"

		updatedTeam.People = []Person{tina, chat, chatDifferentEmail}

		assert.Equal(t,
			fmt.Errorf("fingerprint listed more than once: %s", chat.Fingerprint.String()),
			ValidateUpdate(&team, &updatedTeam, &chat),
		)
	})

	t.Run("error if no team members", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{}

		assert.Equal(t,
			fmt.Errorf("team has no members"),
			ValidateUpdate(&team, &updatedTeam, &chat),
		)
	})

	t.Run("error if no team admin", func(t *testing.T) {
		updatedTeam := team
		updatedTeam.People = []Person{chat}

		assert.Equal(t,
			fmt.Errorf("team has no administrators"),
			ValidateUpdate(&team, &updatedTeam, &chat),
		)
	})
}
