package status

import (
	"fmt"
	"time"

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

// RevokeSubkey indicates that the given SubkeyId will be revoked
type RevokeSubkey struct {
	KeyAction

	SubkeyId uint64
}

// Enact calls PgpKey.RevokeSubkey, passing in SubkeyId
func (a RevokeSubkey) Enact(key *pgpkey.PgpKey) error {
	return key.RevokeSubkey(a.SubkeyId)
}
func (a RevokeSubkey) String() string {
	return fmt.Sprintf("Expire the encryption subkey now (0x%X)", a.SubkeyId)
}

type KeyAction interface {
	String() string
	Enact(*pgpkey.PgpKey) error
}
