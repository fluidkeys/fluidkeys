package gpgwrapper

import (
	"github.com/fluidkeys/fluidkeys/fingerprint"
)

type ExportPrivateKeyInterface interface {
	ExportPrivateKey(fingerprint.Fingerprint, string) (string, error)
}

type ImportArmoredKeyInterface interface {
	ImportArmoredKey(string) (string, error)
}
