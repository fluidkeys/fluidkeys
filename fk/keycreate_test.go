package fk

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
)

type mockGetPublicKey struct {
	mockArmoredKey string
	mockError      error
}

func (m *mockGetPublicKey) GetPublicKey(email string) (string, error) {
	return m.mockArmoredKey, m.mockError
}

func TestVerifyEmailMatchesKeyInAPI(t *testing.T) {
	t.Run("with a valid armored key", func(t *testing.T) {
		mockGetter := mockGetPublicKey{exampledata.ExamplePublicKey2, nil}

		verified, err := verifyEmailMatchesKeyInAPI(
			"test2@example.com",
			exampledata.ExampleFingerprint2,
			&mockGetter,
		)

		assert.NoError(t, err)
		assertVerified(t, verified)
	})

	t.Run("with an invalid armored key", func(t *testing.T) {
		mockGetter := mockGetPublicKey{"foobar", nil}

		verified, err := verifyEmailMatchesKeyInAPI(
			"test2@example.com",
			exampledata.ExampleFingerprint2,
			&mockGetter,
		)
		assert.ErrorIsNotNil(t, err)
		assertNotVerified(t, verified)
	})

	t.Run("when the API returns an error", func(t *testing.T) {
		mockGetter := mockGetPublicKey{"", fmt.Errorf("Error")}

		verified, err := verifyEmailMatchesKeyInAPI(
			"test2@example.com",
			exampledata.ExampleFingerprint2,
			&mockGetter,
		)
		t.Run("swallows the error", func(t *testing.T) {
			assert.NoError(t, err)
		})
		assertNotVerified(t, verified)

	})

	t.Run("when the API returns a mismatching fingerprint", func(t *testing.T) {
		mockGetter := mockGetPublicKey{exampledata.ExamplePublicKey3, nil}

		verified, err := verifyEmailMatchesKeyInAPI(
			"test2@example.com",
			exampledata.ExampleFingerprint2,
			&mockGetter,
		)
		assert.ErrorIsNotNil(t, err)
		assert.Equal(
			t,
			fmt.Errorf("a key for test2@example.com is already verified\n     Please email security@fluidkeys.com and we can manually remove the old key\n"),
			err,
		)
		assertNotVerified(t, verified)
	})
}

func assertVerified(t *testing.T, verified bool) {
	t.Helper()
	if verified != true {
		t.Fatalf("expected tryToVerifyEmailAddress=true, got false")
	}
}

func assertNotVerified(t *testing.T, verified bool) {
	t.Helper()
	if verified != false {
		t.Fatalf("expected tryToVerifyEmailAddress=false, got true")
	}
}
