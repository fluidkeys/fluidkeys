package v1structs

// GetPublicKeyResponse is the JSON structure returned by the get public key
// API endpoint. See:
// https://github.com/fluidkeys/api/blob/master/README.md#get-a-public-key
type GetPublicKeyResponse struct {
	// ArmoredPublicKey is the ASCII-armored OpenPGP public key.
	ArmoredPublicKey string `json:"armoredPublicKey"`
}

// SendSecretRequest is the JSON structure used for requests to the send secret
// API endpoint. See:
// https://github.com/fluidkeys/api/blob/master/README.md#send-a-secret-to-a-public-key
type SendSecretRequest struct {
	RecipientFingerprint   string `json:"recipientFingerprint"`
	ArmoredEncryptedSecret string `json:"armoredEncryptedSecret"`
}

// ListSecretsResponse is the JSON structure returned by the list secrets
// API endpoint. See:
// https://github.com/fluidkeys/api/blob/master/README.md#list-your-secrets
type ListSecretsResponse struct {
	Secrets []Secret `json:"secrets"`
}

// Secret is the JSON structure containing the metadata and content for an
// encrypted secret returned by the list secrets API endpoint.
type Secret struct {
	// EncryptedMetadata is an ASCII-armored encrypted PGP message which
	// decrypts to a `SecretMetadata` JSON structure.
	EncryptedMetadata string `json:"encryptedMetadata"`

	// EncryptedContent is an ASCII-armored encrypted PGP message
	// containing the actual content of the secret.
	EncryptedContent string `json:"encryptedContent"`
}

// SecretMetadata contains non-content information about an encrypted secret.
type SecretMetadata struct {
	// SecretUUID uniquely identifies the secret to the API
	SecretUUID string `json:"secretUuid"`
}

// ErrorResponse is the JSON structure returned when the API encounters an
// error.
type ErrorResponse struct {
	// Detail is a human-readable string describing the error.
	Detail string `json:"detail"`
}
