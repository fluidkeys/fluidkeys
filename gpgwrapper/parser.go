package gpgwrapper

import (
	"fmt"
	"strconv"
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
