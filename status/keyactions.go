package status

import (
	"fmt"
	"time"

	"github.com/fluidkeys/fluidkeys/openpgpdefs/compression"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/hash"
	"github.com/fluidkeys/fluidkeys/openpgpdefs/symmetric"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

// ModifyPrimaryKeyExpiry means the self signature of the key will be refreshed
// with a future expiry date
type ModifyPrimaryKeyExpiry struct {
	KeyAction

	ValidUntil           time.Time
	PreviouslyValidUntil *time.Time
}

// ModifyPrimaryKeyExpiry creates a new self signature on each user ID with
// ValidUntil
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

// CreateNewEncryptionSubkey describes creating a new subkey with the given
// ValidUntil expiry time.
type CreateNewEncryptionSubkey struct {
	KeyAction

	ValidUntil time.Time
}

// Enact calls PgpKey.CreateNewEncryptionSubkey()
func (a CreateNewEncryptionSubkey) Enact(key *pgpkey.PgpKey) error {
	return key.CreateNewEncryptionSubkey(a.ValidUntil)
}

func (a CreateNewEncryptionSubkey) String() string {
	return fmt.Sprintf("Create a new encryption subkey valid until %s", a.ValidUntil.Format("2 Jan 06"))
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

// SetPreferredSymmetricAlgorithms iterates over all user IDs, setting the preferred
// symmetric algorithm preferences from NewPreferences
// It re-signs the self signature on each user ID.
type SetPreferredSymmetricAlgorithms struct {
	KeyAction

	NewPreferences []symmetric.SymmetricAlgorithm
}

func (a SetPreferredSymmetricAlgorithms) Enact(key *pgpkey.PgpKey) error {
	return fmt.Errorf("not implemented")
}

func (a SetPreferredSymmetricAlgorithms) String() string {
	return fmt.Sprintf("Set preferred encryption algorithms to %s", joinCipherNames(a.NewPreferences))
}

// SetPreferredHashAlgorithms iterates over all user IDs, setting the preferred
// hash algorithm preferences from NewPreferences
// It re-signs the self signature on each user ID.
type SetPreferredHashAlgorithms struct {
	KeyAction

	NewPreferences []hash.HashAlgorithm
}

func (a SetPreferredHashAlgorithms) Enact(key *pgpkey.PgpKey) error {
	return fmt.Errorf("not implemented")
}

func (a SetPreferredHashAlgorithms) String() string {
	return fmt.Sprintf("Set preferred hash algorithms to %s", joinHashNames(a.NewPreferences))
}

// SetPreferredCompressionAlgorithms iterates over all user IDs, setting the preferred
// compression algorithm preferences from NewPreferences.
// It re-signs the self signature on each user ID.
type SetPreferredCompressionAlgorithms struct {
	KeyAction

	NewPreferences []compression.CompressionAlgorithm
}

func (a SetPreferredCompressionAlgorithms) Enact(key *pgpkey.PgpKey) error {
	return fmt.Errorf("not implemented")
}

func (a SetPreferredCompressionAlgorithms) String() string {
	return fmt.Sprintf("Set preferred compression algorithms to %s", joinCompressionNames(a.NewPreferences))
}

type RefreshUserIdSelfSignatures struct {
	KeyAction
}

func (a RefreshUserIdSelfSignatures) Enact(key *pgpkey.PgpKey) error {
	return fmt.Errorf("not implemented")
}
func (a RefreshUserIdSelfSignatures) String() string {
	return "Create new self signatures"
}

type RefreshSubkeyBindingSignature struct {
	KeyAction
	SubkeyId uint64
}

func (a RefreshSubkeyBindingSignature) Enact(key *pgpkey.PgpKey) error {
	return fmt.Errorf("not implemented")
}
func (a RefreshSubkeyBindingSignature) String() string {
	return fmt.Sprintf("Create new signature for subkey 0x%X", a.SubkeyId)
}

type KeyAction interface {
	String() string
	Enact(*pgpkey.PgpKey) error
}
