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

package status

import (
	"fmt"
	"time"

	"github.com/fluidkeys/fluidkeys/openpgpdefs/compression"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/hash"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/symmetric"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// ModifyPrimaryKeyExpiry iterates over all user IDs. For each UID, it updates
// the expiry date on the *self signature*.
// It re-signs the self signature.
type ModifyPrimaryKeyExpiry struct {
	KeyAction

	ValidUntil           time.Time
	PreviouslyValidUntil *time.Time
}

func (a ModifyPrimaryKeyExpiry) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.UpdateExpiryForAllUserIds(a.ValidUntil, now)
}

func (a ModifyPrimaryKeyExpiry) String() string {
	if a.PreviouslyValidUntil == nil || a.PreviouslyValidUntil.After(a.ValidUntil) {
		return fmt.Sprintf("Shorten the primary key expiry to %s", a.ValidUntil.Format("2 Jan 06"))
	} else {
		return fmt.Sprintf("Extend the primary key expiry to %s", a.ValidUntil.Format("2 Jan 06"))
	}
}
func (a ModifyPrimaryKeyExpiry) SortOrder() int {
	return sortOrderPrimaryKey
}

// CreateNewEncryptionSubkey creates a new subkey with the given
// ValidUntil expiry time and a subkey binding signature.
type CreateNewEncryptionSubkey struct {
	KeyAction

	ValidUntil time.Time
}

func (a CreateNewEncryptionSubkey) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.CreateNewEncryptionSubkey(a.ValidUntil, now, nil)
}

func (a CreateNewEncryptionSubkey) String() string {
	return fmt.Sprintf("Create a new encryption subkey valid until %s", a.ValidUntil.Format("2 Jan 06"))
}

func (a CreateNewEncryptionSubkey) SortOrder() int {
	return sortOrderCreateSubkey
}

// ExpireSubkey updates and re-signs the self signature on the given subkey to
// now, in order that the subkey becomes effectively unusable (although it
// could be updated again to bring the subkey back to life, unlike it it were
// revoked)
type ExpireSubkey struct {
	KeyAction

	SubkeyId uint64
}

func (a ExpireSubkey) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.ExpireSubkey(a.SubkeyId, now)
}
func (a ExpireSubkey) String() string {
	return fmt.Sprintf("Expire the encryption subkey now (0x%X)", a.SubkeyId)
}
func (a ExpireSubkey) SortOrder() int {
	return sortOrderModifySubkey
}

// ModifySubkeyExpiry iterates over all user IDs. For each UID, it updates
// the expiry date on the *self signature*.
// It re-signs the self signature.
type ModifySubkeyExpiry struct {
	KeyAction

	validUntil time.Time
	subkeyId   uint64
}

func (a ModifySubkeyExpiry) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.UpdateSubkeyValidUntil(a.subkeyId, a.validUntil, now)
}

func (a ModifySubkeyExpiry) String() string {
	return fmt.Sprintf("Extend encryption subkey expiry to %s", a.validUntil.Format("2 Jan 06"))
}
func (a ModifySubkeyExpiry) SortOrder() int {
	return sortOrderModifySubkey
}

// SetPreferredSymmetricAlgorithms iterates over all user IDs, setting the preferred
// symmetric algorithm preferences from NewPreferences
// It re-signs the self signature on each user ID.
type SetPreferredSymmetricAlgorithms struct {
	KeyAction

	NewPreferences []symmetric.SymmetricAlgorithm
}

func (a SetPreferredSymmetricAlgorithms) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.SetPreferredSymmetricAlgorithms(a.NewPreferences, now)
}

func (a SetPreferredSymmetricAlgorithms) String() string {
	return fmt.Sprintf("Set cipher preferences to %s", joinCipherNames(a.NewPreferences))
}

func (a SetPreferredSymmetricAlgorithms) SortOrder() int {
	return sortOrderPreferencesSymmetric
}

// SetPreferredHashAlgorithms iterates over all user IDs, setting the preferred
// hash algorithm preferences from NewPreferences
// It re-signs the self signature on each user ID.
type SetPreferredHashAlgorithms struct {
	KeyAction

	NewPreferences []hash.HashAlgorithm
}

func (a SetPreferredHashAlgorithms) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.SetPreferredHashAlgorithms(a.NewPreferences, now)
}

func (a SetPreferredHashAlgorithms) String() string {
	return fmt.Sprintf("Set hash preferences to %s", joinHashNames(a.NewPreferences))
}

func (a SetPreferredHashAlgorithms) SortOrder() int {
	return sortOrderPreferencesHash
}

// SetPreferredCompressionAlgorithms iterates over all user IDs, setting the preferred
// compression algorithm preferences from NewPreferences.
// It re-signs the self signature on each user ID.
type SetPreferredCompressionAlgorithms struct {
	KeyAction

	NewPreferences []compression.CompressionAlgorithm
}

func (a SetPreferredCompressionAlgorithms) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.SetPreferredCompressionAlgorithms(a.NewPreferences, now)
}

func (a SetPreferredCompressionAlgorithms) String() string {
	return fmt.Sprintf("Set compression preferences to %s", joinCompressionNames(a.NewPreferences))
}

func (a SetPreferredCompressionAlgorithms) SortOrder() int {
	return sortOrderPreferencesCompression
}

// RefreshUserIdSelfSignatures iterates over user ids and re-signs the self
// signatures. This is useful if the old signature uses a weak hash.
type RefreshUserIdSelfSignatures struct {
	KeyAction
}

func (a RefreshUserIdSelfSignatures) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.RefreshUserIdSelfSignatures(now)
}

func (a RefreshUserIdSelfSignatures) String() string {
	return "Create new self signatures"
}
func (a RefreshUserIdSelfSignatures) SortOrder() int {
	return sortOrderRefreshSignature
}

// RefreshSubkeyBindingSignature re-signs the subkey binding signature for
// the given SubkeyId. This is useful if the old signature uses a weak hash.
type RefreshSubkeyBindingSignature struct {
	KeyAction
	SubkeyId uint64
}

func (a RefreshSubkeyBindingSignature) Enact(key *pgpkey.PgpKey, now time.Time, password *string) error {
	return key.RefreshSubkeyBindingSignature(a.SubkeyId, now)
}
func (a RefreshSubkeyBindingSignature) String() string {
	return fmt.Sprintf("Create new signature for subkey 0x%X", a.SubkeyId)
}

func (a RefreshSubkeyBindingSignature) SortOrder() int {
	return sortOrderRefreshSignature
}

const (
	sortOrderPrimaryKey = iota
	sortOrderPreferencesSymmetric
	sortOrderPreferencesHash
	sortOrderPreferencesCompression
	sortOrderCreateSubkey
	sortOrderModifySubkey
	sortOrderRefreshSignature
)

type KeyAction interface {
	String() string
	Enact(*pgpkey.PgpKey, time.Time, *string) error
	SortOrder() int
}
