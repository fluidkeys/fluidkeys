package apiclient

import (
	fp "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

// Event contains data to be uploaded and stored in the API
type Event struct {
	Name string

	// Fingerprint is the key that this event relates to, if any.
	Fingerprint *fp.Fingerprint

	// TeamUUID is the team that this event relates to, if any.
	TeamUUID *uuid.UUID

	// Error is the error associated with this event, or nil if no error.
	Error error
}
