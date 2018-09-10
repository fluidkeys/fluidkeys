package gpgwrapper

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fluidkeys/fluidkeys/fingerprint"
)

// Parse the output of --with-colons --list-secret keys and return only valid
// keys (not revoked, not expired) as []SecretKeyListing
// For the format of the colon-delimited string, see:
// https://github.com/gpg/gnupg/blob/master/doc/DETAILS

func parseListSecretKeys(colonDelimitedString string) ([]SecretKeyListing, error) {
	parser := listSecretKeysParser{}

	for _, line := range strings.Split(colonDelimitedString, "\n") {
		parser.PushLine(strings.Split(line, ":"))
	}

	return parser.Keys(), nil
}

// listSecretKeysParser takes a line at a time from the colon-delimited output
// format of gpg --list-secret-keys.
// Because different parts of the key are on different lines (created,
// fingerprint, each uid), this object builds up a partial key as lines are
// pushed.
// When a line signifying a new key is pushed, or when end is called, the
// partial key is checked for validity and added to Keys.

type listSecretKeysParser struct {
	partialKey *SecretKeyListing
	keys       []SecretKeyListing
}

// Adds a line to the parser, which builds up its internal Keys field.
func (p *listSecretKeysParser) PushLine(cols []string) {

	typeOfRecord := cols[0]

	switch typeOfRecord {
	case "sec":
		p.handleSecretPrimaryKeyLine(cols)
		return

	case "fpr":
		p.handleFingerprintLine(cols)
		return

	case "uid":
		p.handleUidLine(cols)
		return
	}
}

// Keys() returns the list of keys that have been accumulated so far.
// It should be called when all lines have been pushed with `PushLine`, else
// keys may be missing, or, worse, they may have missing UIDs.
func (p *listSecretKeysParser) Keys() []SecretKeyListing {
	p.end()
	return p.keys
}

// Informs the parser that there are no more lines to parse.
func (p *listSecretKeysParser) end() {
	p.addPartialKeyToList()
}

func (p *listSecretKeysParser) handleSecretPrimaryKeyLine(cols []string) {
	p.addPartialKeyToList()

	validity := cols[1]
	if validity == "r" || validity == "e" || validity == "n" {
		// Ignore this invalid primary key.
		// https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-2---validity
		return
	}

	createdTime, err := parseTimestamp(cols[5])

	if err != nil {
		// Primary keys should always have a valid created time. Ignore
		// this broken key.
		return
	}

	p.partialKey = &SecretKeyListing{
		Created: *createdTime,
	}

}

func (p *listSecretKeysParser) handleFingerprintLine(cols []string) {
	if p.partialKey == nil {
		// We don't have a current key so either we're ignoring it
		// (maybe it's marked as revoked), or this line has come out
		// of order. Either way we can't do anything.
		return
	}

	if p.partialKey.Fingerprint.IsSet() {
		// We've already got a fingerprint for this key, so this is
		// probably a fingerprint for a subkey, which we're not
		// interested in
		return
	}
	fingerprint, err := fingerprint.Parse(cols[9])
	if err != nil {
		return
	}

	p.partialKey.Fingerprint = fingerprint
}

func (p *listSecretKeysParser) handleUidLine(cols []string) {
	if p.partialKey == nil {
		// We don't have a current key so either we're ignoring it
		// (maybe it's marked as revoked), or this line has come out
		// of order. Either way we can't do anything.
		return
	}

	uid := unquoteColons(cols[9])

	p.partialKey.Uids = append(p.partialKey.Uids, uid)
}

// Append partialKey (if set) to Keys and set it to nil.
// When the parser encounters a line which means represents a primary key, it
// creates `partialKey` and subsequent lines are added onto that struct.
// When the next primary key line (or the end of the output) is encountered,
// we need to check that the temporary key is complete and put it on Keys.

func (p *listSecretKeysParser) addPartialKeyToList() {
	if p.partialKey != nil && p.partialKey.Fingerprint.IsSet() && len(p.partialKey.Uids) > 0 {
		p.keys = append(p.keys, *p.partialKey)
	}
	p.partialKey = nil
}

func parseTimestamp(utcTimestamp string) (*time.Time, error) {
	seconds, err := strconv.ParseInt(utcTimestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Error parsing string as 64-bit int timestamp: '%s' err: %v", utcTimestamp, err)
	}
	resultTime := time.Unix(seconds, 0).UTC()
	return &resultTime, nil
}

// unquoteColons undoes GnuPG's quoting which is used to prevent fields breaking
// the colon-delimited output. Colons are replaced with a literal `\x3a`. No
// other characters are affected.
//
func unquoteColons(uid string) string {
	return strings.Replace(uid, `\x3a`, ":", -1)
}
