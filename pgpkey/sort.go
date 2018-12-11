// Copyright 2018 Paul Furley and Ian Drysdale
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

package pgpkey

import (
	"fmt"
	"github.com/fluidkeys/crypto/openpgp"
	"strings"
)

// ByCreated implements sort.Interface for []PgpKey based on
// the PrimaryKey.CreationTime field.
type ByCreated []PgpKey

func (a ByCreated) Len() int      { return len(a) }
func (a ByCreated) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByCreated) Less(i, j int) bool {
	iTime := a[i].PrimaryKey.CreationTime
	jTime := a[j].PrimaryKey.CreationTime
	return iTime.Before(jTime)
}

// ByCreated implements sort.Interface for []openpgp.Subkey based on
// the PublicKey.CreationTime field.
type BySubkeyCreated []openpgp.Subkey

func (a BySubkeyCreated) Len() int      { return len(a) }
func (a BySubkeyCreated) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BySubkeyCreated) Less(i, j int) bool {
	iTime := a[i].Sig.CreationTime
	jTime := a[j].Sig.CreationTime
	return iTime.Before(jTime)
}

// identityLess can be used with sort.Slice to sort a []openpgp.Identity in the
// order:
// 1. whether it's a "primary user id"
// 2. by the oldest self signature.
// 3. by the email address (domain, then local part)
// 3. by the full user ID string
//
// > sort.Slice(identities, func(i, j int) { return identityLess(ids[i], ids[j]) }
func identityLess(i, j openpgp.Identity) bool {
	// e.g. bool(i < j): should i come before j?
	var iIsPrimary bool = i.SelfSignature.IsPrimaryId != nil && *i.SelfSignature.IsPrimaryId
	var jIsPrimary bool = j.SelfSignature.IsPrimaryId != nil && *j.SelfSignature.IsPrimaryId

	if iIsPrimary && !jIsPrimary {
		return true
	} else if !iIsPrimary && jIsPrimary {
		return false
	}

	iTime := i.SelfSignature.CreationTime
	jTime := j.SelfSignature.CreationTime

	if iTime.Before(jTime) {
		return true
	} else if iTime.After(jTime) {
		return false
	}

	iEmail, iOk := getEmail(&i, true)
	jEmail, jOk := getEmail(&j, true)

	if iOk && jOk {
		switch compareEmail(iEmail, jEmail) {
		case -1: // i < j
			return true

		case +1: // i > j
			return false
		}
	}
	return i.Name < j.Name
}

// compareEmail compares an email address by domain first, then local part.
// it follows the old cmp convention:
// if i < j: returns -1
// if i > j: returns +1
// if i == j: returns 0
func compareEmail(i, j string) int {
	iparts := strings.SplitN(strings.ToLower(i), "@", 2)
	jparts := strings.SplitN(strings.ToLower(j), "@", 2)

	iDomainThenLocal := fmt.Sprintf("%s|%s", iparts[1], iparts[0]) // e.g. example.com|paul
	jDomainThenLocal := fmt.Sprintf("%s|%s", jparts[1], jparts[0]) // e.g. example.com|paul

	return strings.Compare(iDomainThenLocal, jDomainThenLocal)
}
