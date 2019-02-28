package scheduler

import (
	"fmt"
	"github.com/fluidkeys/fluidkeys/assert"
	"os/exec"
	"testing"
)

func TestEnable(t *testing.T) {
	t.Run("add to existing crontab", func(t *testing.T) {
		crontabBefore := "# existing crontab"

		mock := &mockCrontab{
			getResult: crontabBefore,
		}

		gotWasChanged, gotError := Enable(mock)
		assert.NoError(t, gotError)
		assert.Equal(t, true, gotWasChanged)
		assert.Equal(t, "# existing crontab"+CronLines, mock.setCapturedCrontab)
	})

	t.Run("do nothing if already in crontab", func(t *testing.T) {
		crontabBefore := "# existing crontab" + CronLines

		mock := &mockCrontab{
			getResult: crontabBefore,
		}

		gotWasChanged, gotError := Enable(mock)
		assert.NoError(t, gotError)
		assert.Equal(t, false, gotWasChanged)
		assert.Equal(t, false, mock.setWasCalled())
	})

	t.Run("pass up error from get crontab", func(t *testing.T) {
		mock := &mockCrontab{
			getError: fmt.Errorf("fake error from get"),
		}

		gotWasChanged, gotError := Enable(mock)
		assert.Equal(t, fmt.Errorf("error getting crontab: fake error from get"), gotError)
		assert.Equal(t, false, gotWasChanged)
		assert.Equal(t, false, mock.setWasCalled())
	})

	t.Run("pass up error from set crontab", func(t *testing.T) {
		mock := &mockCrontab{
			setError: fmt.Errorf("fake error from set"),
		}

		gotWasChanged, gotError := Enable(mock)
		assert.Equal(t, fmt.Errorf("fake error from set"), gotError)
		assert.Equal(t, false, gotWasChanged)
	})
}

func TestDisable(t *testing.T) {
	t.Run("remove if present in crontab", func(t *testing.T) {
		crontabBefore := "# existing crontab\n" + CronLines + "\n# more lines"

		mock := &mockCrontab{
			getResult: crontabBefore,
		}

		gotWasChanged, gotError := Disable(mock)
		assert.NoError(t, gotError)
		assert.Equal(t, true, gotWasChanged)
		assert.Equal(t, "# existing crontab\n\n# more lines", mock.setCapturedCrontab)
	})

	t.Run("do nothing if not already in crontab", func(t *testing.T) {
		crontabBefore := "# existing crontab\n# more lines"

		mock := &mockCrontab{
			getResult: crontabBefore,
		}

		gotWasChanged, gotError := Disable(mock)
		assert.NoError(t, gotError)
		assert.Equal(t, false, gotWasChanged)
		assert.Equal(t, false, mock.setWasCalled())
	})

	t.Run("pass up error from get crontab", func(t *testing.T) {
		mock := &mockCrontab{
			getError: fmt.Errorf("fake error from get"),
		}

		gotWasChanged, gotError := Disable(mock)
		assert.Equal(t, fmt.Errorf("error getting crontab: fake error from get"), gotError)
		assert.Equal(t, false, gotWasChanged)
		assert.Equal(t, false, mock.setWasCalled())
	})

	t.Run("pass up error from set crontab", func(t *testing.T) {
		mock := &mockCrontab{
			getResult: CronLines,
			setError:  fmt.Errorf("fake error from set"),
		}

		gotWasChanged, gotError := Disable(mock)
		assert.Equal(t, fmt.Errorf("fake error from set"), gotError)
		assert.Equal(t, false, gotWasChanged)
	})
}

func TestIsNoCrontabError(t *testing.T) {
	crontabMatchingOutput := "no crontab for foo"
	crontabNotMatchingOutput := "something went wrong"
	exitError := &exec.ExitError{}
	otherError := fmt.Errorf("other error")

	s := systemCrontab{}

	t.Run("returns true for exit error with matching crontab message", func(t *testing.T) {
		result := s.isNoCrontabError(
			crontabMatchingOutput,
			exitError,
		)
		assert.Equal(t, true, result)
	})

	t.Run("returns false for nil error", func(t *testing.T) {
		result := s.isNoCrontabError(
			crontabMatchingOutput,
			nil,
		)
		assert.Equal(t, false, result)
	})

	t.Run("returns false for other error with matching crontab message", func(t *testing.T) {
		result := s.isNoCrontabError(
			crontabMatchingOutput,
			otherError,
		)
		assert.Equal(t, false, result)
	})

	t.Run("returns false for exit error with some other crontab output", func(t *testing.T) {
		result := s.isNoCrontabError(
			crontabNotMatchingOutput,
			exitError,
		)
		assert.Equal(t, false, result)

	})
}

type mockCrontab struct {
	getResult string
	getError  error
	setError  error

	// setCapturedCrontab is set to newCrontab if set(newCrontab) is called, otherwise it will
	// be an empty string
	setCapturedCrontab string
}

func (m *mockCrontab) get() (string, error) {
	return m.getResult, m.getError
}

func (m *mockCrontab) set(newCrontab string) error {
	m.setCapturedCrontab = newCrontab

	return m.setError
}

func (m *mockCrontab) setWasCalled() bool {
	return m.setCapturedCrontab != ""
}
