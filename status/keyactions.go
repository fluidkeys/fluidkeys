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

func (a ModifyPrimaryKeyExpiry) Enact(key *pgpkey.PgpKey) error {
	return key.UpdateExpiryForAllUserIds(a.ValidUntil)
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

func (a CreateNewEncryptionSubkey) Enact(key *pgpkey.PgpKey) error {
	return key.CreateNewEncryptionSubkey(a.ValidUntil)
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

func (a ExpireSubkey) Enact(key *pgpkey.PgpKey) error {
	return key.ExpireSubkey(a.SubkeyId)
}
func (a ExpireSubkey) String() string {
	return fmt.Sprintf("Expire the encryption subkey now (0x%X)", a.SubkeyId)
}
func (a ExpireSubkey) SortOrder() int {
	return sortOrderModifySubkey
}

// SetPreferredSymmetricAlgorithms iterates over all user IDs, setting the preferred
// symmetric algorithm preferences from NewPreferences
// It re-signs the self signature on each user ID.
type SetPreferredSymmetricAlgorithms struct {
	KeyAction

	NewPreferences []symmetric.SymmetricAlgorithm
}

func (a SetPreferredSymmetricAlgorithms) Enact(key *pgpkey.PgpKey) error {
	return key.SetPreferredSymmetricAlgorithms(a.NewPreferences, time.Now())
}

func (a SetPreferredSymmetricAlgorithms) String() string {
	return fmt.Sprintf("Set preferred encryption algorithms to %s", joinCipherNames(a.NewPreferences))
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

func (a SetPreferredHashAlgorithms) Enact(key *pgpkey.PgpKey) error {
	return key.SetPreferredHashAlgorithms(a.NewPreferences, time.Now())
}

func (a SetPreferredHashAlgorithms) String() string {
	return fmt.Sprintf("Set preferred hash algorithms to %s", joinHashNames(a.NewPreferences))
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

func (a SetPreferredCompressionAlgorithms) Enact(key *pgpkey.PgpKey) error {
	return key.SetPreferredCompressionAlgorithms(a.NewPreferences, time.Now())
}

func (a SetPreferredCompressionAlgorithms) String() string {
	return fmt.Sprintf("Set preferred compression algorithms to %s", joinCompressionNames(a.NewPreferences))
}

func (a SetPreferredCompressionAlgorithms) SortOrder() int {
	return sortOrderPreferencesCompression
}

// RefreshUserIdSelfSignatures iterates over user ids and re-signs the self
// signatures. This is useful if the old signature uses a weak hash.
type RefreshUserIdSelfSignatures struct {
	KeyAction
}

func (a RefreshUserIdSelfSignatures) Enact(key *pgpkey.PgpKey) error {
	return key.RefreshUserIdSelfSignatures(time.Now())
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

func (a RefreshSubkeyBindingSignature) Enact(key *pgpkey.PgpKey) error {
	return key.RefreshSubkeyBindingSignature(a.SubkeyId, time.Now())
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
	Enact(*pgpkey.PgpKey) error
	SortOrder() int
}
