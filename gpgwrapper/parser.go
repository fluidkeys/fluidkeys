package gpgwrapper

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func parseTimestamp(utcTimestamp string) (*time.Time, error) {
	seconds, err := strconv.ParseInt(utcTimestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Error parsing string as 64-bit int timestamp: '%s' err: %v", utcTimestamp, err)
	}
	resultTime := time.Unix(seconds, 0).UTC()
	return &resultTime, nil
}

// Return a human-friendly version of the fingerprint, which should be a 40
// character hex string. Accepts fingerprints with spaces, uppercase, lowercase
// but always returns the format:
// `AB01 AB01 AB01 AB01 AB01  AB01 AB01 AB01 AB01 AB01`

func parseFingerprint(fp string) (string, error) {
	expectedPattern := `^[A-Fa-f0-9 ]{40}$`
	if matched, err := regexp.MatchString(expectedPattern, fp); !matched || err != nil {
		return "", fmt.Errorf("fingerprint doesn't match pattern '%v', err=%v", expectedPattern, err)
	}

	withoutSpaces := strings.Replace(fp, " ", "", -1)
	f := strings.ToUpper(withoutSpaces)

	return fmt.Sprintf(
		"%s %s %s %s %s  %s %s %s %s %s",
		f[0:4], f[4:8], f[8:12], f[12:16], f[16:20],
		f[20:24], f[24:28], f[28:32], f[32:36], f[36:40]), nil
}
