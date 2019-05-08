package scheduler

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
)

type cron struct{}

// Enable writes Fluidkeys' cron lines into crontab
func (c *cron) Enable() (crontabWasAdded bool, err error) {
	crontab := &systemCrontab{}
	return c.enable(crontab)
}

// Disable parses the crontab (output of `crontab -l`) and removes Fluidkeys'
// cron lines if present.
// If the remaining crontab is empty, the crontab is removed with `crontab -r`
func (c *cron) Disable() (cronLinesWereRemoved bool, err error) {
	crontab := &systemCrontab{}
	return c.disable(crontab)
}

func (c *cron) Name() string {
	return "cron"
}

func (c *cron) enable(crontab runCrontabInterface) (crontabWasAdded bool, err error) {
	currentCrontab, err := crontab.get()
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}

	if !hasFluidkeysCronLines(currentCrontab) {
		newCrontab := addCrontabLinesWithoutRepeating(currentCrontab)
		err = crontab.set(newCrontab)
		if err != nil {
			return false, ErrModifyingCrontab{origError: err}
		}
		return true, nil
	}

	return false, nil
}

func (c *cron) disable(crontab runCrontabInterface) (cronLinesWereRemoved bool, err error) {
	currentCrontab, err := crontab.get()
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}

	if hasFluidkeysCronLines(currentCrontab) {
		newCrontab := removeCrontabLines(currentCrontab)
		err = crontab.set(newCrontab)

		if err != nil {
			return false, ErrModifyingCrontab{origError: err}
		}
		return true, nil
	}
	return false, nil
}

func (c *cron) IsEnabled() (enabled bool, err error) {
	return c.isEnabled(&systemCrontab{})
}

func (c *cron) isEnabled(crontab runCrontabInterface) (enabled bool, err error) {
	currentCrontab, err := crontab.get()
	if err != nil {
		return false, fmt.Errorf("error getting crontab: %v", err)
	}
	return hasFluidkeysCronLines(currentCrontab), nil
}

func hasFluidkeysCronLines(crontab string) bool {
	return strings.Contains(crontab, strings.TrimSuffix(CronLines, "\n"))
}

type systemCrontab struct{}

func (s *systemCrontab) get() (string, error) {
	output, err := s.runCrontab("-l")

	if s.isNoCrontabError(output, err) {
		return "", nil
	}

	return output, err
}

func (s *systemCrontab) set(newCrontab string) error {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return fmt.Errorf("error opening temp file: %v", err)
	}

	if _, err := io.WriteString(f, newCrontab); err != nil {
		return fmt.Errorf("error writing to temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing temp file: %v", err)
	}

	if _, err := s.runCrontab(f.Name()); err != nil {
		return fmt.Errorf("error updating crontab: %v", err)
	}
	return nil
}

// isNoCrontabError returns true if and only if the error looks like a failure from `crontab -l`
// of the form "no crontab for foo"
func (s *systemCrontab) isNoCrontabError(cronOutput string, err error) bool {
	if err == nil {
		return false
	}

	return isExitError(err) && strings.Contains(cronOutput, "no crontab for")
}

func isExitError(err error) bool {
	if _, ok := err.(*exec.ExitError); ok {
		return true
	}
	return false
}

func (*systemCrontab) runCrontab(arguments ...string) (string, error) {
	log.Printf("Running `%s %s`", crontab, strings.Join(arguments, " "))
	cmd := exec.Command(crontab, arguments...)

	out, err := cmd.CombinedOutput()

	outString := string(out)

	if err != nil {
		return outString, err
	}
	return outString, nil
}

func addCrontabLinesWithoutRepeating(crontab string) string {
	removed := removeCrontabLines(crontab)

	if !strings.HasSuffix(removed, "\n") {
		// the crontab should always have a trailing newline
		removed += "\n"
	}

	if isEmpty(removed) {
		return CronLines
	}

	return removed + "\n" + CronLines
}

func removeCrontabLines(crontab string) string {
	linesWithoutFinalNewline := strings.TrimSuffix(CronLines, "\n")
	result := strings.Replace(crontab, linesWithoutFinalNewline, "", -1)

	legacyWithoutFinalNewline := strings.TrimSuffix(legacyCronLines, "\n")
	result = strings.Replace(result, legacyWithoutFinalNewline, "", -1)

	if isEmpty(result) {
		return ""
	}
	return strings.Trim(result, "\n") + "\n"
}

func isEmpty(crontab string) bool {
	return strings.Trim(crontab, "\n") == ""
}

const crontab string = "crontab"

// CronLines is the string Fluidkeys adds to a user's crontab to run itself
const CronLines string = "# Fluidkeys added the following line to keep you and your team's keys updated\n" +
	"# automatically with `fk sync`\n" +
	"# To configure this, edit your config file (see `ffk --help` for the location)\n" +
	"@hourly perl -e 'sleep int(rand(3600))' && /usr/local/bin/fk sync --cron-output\n"

const legacyCronLines string = "# Fluidkeys added the following line. To disable, edit your " +
	"Fluidkeys configuration file.\n" +
	"@hourly /usr/local/bin/fk key maintain automatic --cron-output\n"

// ErrModifyingCrontab is a custom error. It should be used to wrap any errors called during
// Enable or Disable to ensure the caller knows how to present the user with the steps they
// can take to manually recify the situation.
type ErrModifyingCrontab struct {
	origError error
}

func (e ErrModifyingCrontab) Error() string {
	if e.origError.Error() != "" {
		return e.origError.Error()
	}
	return "error modifying the crontab"
}
