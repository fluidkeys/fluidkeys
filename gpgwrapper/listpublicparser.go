// Copyright 2019 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package gpgwrapper

import (
	"strings"

	"github.com/fluidkeys/fluidkeys/fingerprint"
)

// parseListPublicKeys parses the output of --with-colons --list-keys and returns only valid keys
// (not revoked, not expired) as []KeyListing
// For the format of the colon-delimited string, see:
// https://github.com/gpg/gnupg/blob/master/doc/DETAILS
func parseListPublicKeys(colonDelimitedString string) ([]KeyListing, error) {
	parser := listPublicKeysParser{}

	for _, line := range strings.Split(colonDelimitedString, "\n") {
		parser.PushLine(strings.Split(line, ":"))
	}

	return parser.Keys(), nil
}

// listPublicKeysParser takes a line at a time from the colon-delimited output format of
// `gpg --list-keys`.
// Because different parts of the key are on different lines (created, fingerprint, each uid), this
// object builds up a partial key as lines are pushed.
// When a line signifying a new key is pushed, or when end is called, the partial key is checked for
// validity and added to Keys.
type listPublicKeysParser struct {
	partialKey *KeyListing
	keys       []KeyListing
}

// PushLine adds a line to the parser, which builds up its internal Keys field.
func (p *listPublicKeysParser) PushLine(cols []string) {

	typeOfRecord := cols[0]

	switch typeOfRecord {
	case "pub":
		p.handlePublicKeyLine(cols)
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
func (p *listPublicKeysParser) Keys() []KeyListing {
	p.end()
	return p.keys
}

// end() informs the parser that there are no more lines to parse.
func (p *listPublicKeysParser) end() {
	p.addPartialKeyToList()
}

func (p *listPublicKeysParser) handlePublicKeyLine(cols []string) {
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

	p.partialKey = &KeyListing{
		Created: *createdTime,
	}

}

func (p *listPublicKeysParser) handleFingerprintLine(cols []string) {
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

func (p *listPublicKeysParser) handleUidLine(cols []string) {
	if p.partialKey == nil {
		// We don't have a current key so either we're ignoring it
		// (maybe it's marked as revoked), or this line has come out
		// of order. Either way we can't do anything.
		return
	}

	uid := unquoteColons(cols[9])

	p.partialKey.Uids = append(p.partialKey.Uids, uid)
}

// addPartialKeyToList will append partialKey (if set) to Keys and set it to nil.
// When the parser encounters a line which means represents a primary key, it
// creates `partialKey` and subsequent lines are added onto that struct.
// When the next primary key line (or the end of the output) is encountered,
// we need to check that the temporary key is complete and put it on Keys.
func (p *listPublicKeysParser) addPartialKeyToList() {
	if p.partialKey != nil && p.partialKey.Fingerprint.IsSet() && len(p.partialKey.Uids) > 0 {
		p.keys = append(p.keys, *p.partialKey)
	}
	p.partialKey = nil
}
