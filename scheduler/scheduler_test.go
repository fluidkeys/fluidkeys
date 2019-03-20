package scheduler

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
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
		assert.Equal(t, "# existing crontab\n\n"+CronLines, mock.setCapturedCrontab)
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
		// we end up with an extra newline than we started with, but it's very difficult to
		// avoid that.
		assert.Equal(t, "# existing crontab\n\n\n# more lines\n", mock.setCapturedCrontab)
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

func TestAddCrontabLinesWithoutRepeating(t *testing.T) {
	t.Run("adds crontab lines", func(t *testing.T) {
		testCrontab := "# foo\n"
		got := addCrontabLinesWithoutRepeating(testCrontab)

		expected := "# foo\n\n" + // should leave an extra newline before the comment
			"# Fluidkeys added the following line to keep you and your team's keys updated\n" +
			"# automatically with `fk sync`\n" +
			"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
			"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"
		assert.Equal(t, expected, got)
	})

	t.Run("when crontab started off empty", func(t *testing.T) {
		testCrontab := ""
		got := addCrontabLinesWithoutRepeating(testCrontab)

		expected := "# Fluidkeys added the following line to keep you and your team's keys updated\n" +
			"# automatically with `fk sync`\n" +
			"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
			"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"

		assert.Equal(t, expected, got)
	})

	t.Run("when previous crontab had no trailing newline", func(t *testing.T) {
		testCrontab := "# foo"
		got := addCrontabLinesWithoutRepeating(testCrontab)

		expected := "# foo\n\n" + // ensure there's 2 newlines
			"# Fluidkeys added the following line to keep you and your team's keys updated\n" +
			"# automatically with `fk sync`\n" +
			"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
			"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"

		assert.Equal(t, expected, got)
	})

	t.Run("when crontab already contains the cron lines", func(t *testing.T) {
		testCrontab := "# foo\n" +
			"# Fluidkeys added the following line to keep you and your team's keys updated\n" +
			"# automatically with `fk sync`\n" +
			"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
			"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"
		got := addCrontabLinesWithoutRepeating(testCrontab)

		expected := "# foo\n\n" +
			"# Fluidkeys added the following line to keep you and your team's keys updated\n" +
			"# automatically with `fk sync`\n" +
			"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
			"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"

		assert.Equal(t, expected, got)
	})

	t.Run("when crontab contains the legacy cron lines ", func(t *testing.T) {
		testCrontab := "# foo\n" + legacyCronLines
		got := addCrontabLinesWithoutRepeating(testCrontab)

		expected := "# foo\n\n" +
			"# Fluidkeys added the following line to keep you and your team's keys updated\n" +
			"# automatically with `fk sync`\n" +
			"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
			"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"

		assert.Equal(t, expected, got)
	})
}

func TestRemoveCrontabLines(t *testing.T) {
	t.Run("removes crontab lines, leaving single trailing newline", func(t *testing.T) {
		testCrontab := "# foo\n\n" + CronLines
		got := removeCrontabLines(testCrontab)

		assert.Equal(t, "# foo\n", got)
	})

	t.Run("when fluidkeys cron lines don't have a final newline", func(t *testing.T) {
		testCrontab := strings.TrimRight("# foo\n\n"+CronLines, "\n")
		got := removeCrontabLines(testCrontab)

		assert.Equal(t, "# foo\n", got)
	})

	t.Run("when crontab only contains fluidkeys lines", func(t *testing.T) {
		testCrontab := CronLines
		got := removeCrontabLines(testCrontab)

		assert.Equal(t, "", got)
	})

	t.Run("removes legacy crontab lines", func(t *testing.T) {
		testCrontab := legacyCronLines
		got := removeCrontabLines(testCrontab)

		assert.Equal(t, "", got)
	})

	t.Run("removes current and legacy crontab lines", func(t *testing.T) {
		testCrontab := CronLines + legacyCronLines
		got := removeCrontabLines(testCrontab)

		assert.Equal(t, "", got)
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
