package pgpkey

import (
	"github.com/fluidkeys/crypto/openpgp"
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
