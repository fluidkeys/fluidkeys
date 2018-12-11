package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fluidkeys/crypto/openpgp/clearsign"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"

	"github.com/fluidkeys/fluidkeys/fingerprint"

	"github.com/fluidkeys/api/v1structs"
)

const (
	defaultBaseURL = "https://api.fluidkeys.com/v1/"
	userAgent      = "fluidkeys"
)

// A Client manages communication with the Fluidkeys Server API.
type Client struct {
	client    *http.Client // HTTP client used to communicate with the API.
	BaseURL   *url.URL     // Base URL for API requests
	UserAgent string       // User agent used when communicating with the  API.
}

// NewClient returns a new Fluidkeys Server API client.
func NewClient(fluidkeysVersion string) *Client {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		client:    http.DefaultClient,
		BaseURL:   baseURL,
		UserAgent: userAgent + "-" + fluidkeysVersion,
	}
}

// GetPublicKey attempts to get a single armorded public key.
func (c *Client) GetPublicKey(email string) (string, error) {
	path := fmt.Sprintf("email/%s/key", url.QueryEscape(email))
	request, err := c.newRequest("GET", path, nil)
	if err != nil {
		return "", err
	}
	decodedJSON := new(v1structs.GetPublicKeyResponse)
	response, err := c.do(request, &decodedJSON)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", makeErrorForAPIResponse(response)
	}
	return decodedJSON.ArmoredPublicKey, nil
}

// CreateSecret creates a secret for the given recipient
func (c *Client) CreateSecret(recipientFingerprint fingerprint.Fingerprint, armoredEncryptedSecret string) error {
	sendSecretRequest := v1structs.SendSecretRequest{
		RecipientFingerprint:   recipientFingerprint.Uri(),
		ArmoredEncryptedSecret: armoredEncryptedSecret,
	}
	request, err := c.newRequest("POST", "secrets", sendSecretRequest)
	if err != nil {
		return err
	}

	response, err := c.do(request, nil)
	if err != nil {
		return fmt.Errorf("Failed to call API: %s", err)
	}
	if response.StatusCode != http.StatusCreated {
		return makeErrorForAPIResponse(response)
	}
	return nil
}

// ListSecrets for a particular fingerprint.
func (c *Client) ListSecrets(fingerprint fingerprint.Fingerprint) ([]v1structs.Secret, error) {
	request, err := c.newRequest("GET", "secrets", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("authorization", authorization(fingerprint))
	decodedJSON := new(v1structs.ListSecretsResponse)
	response, err := c.do(request, &decodedJSON)
	if err != nil {
		return nil, err
	}
	switch response.StatusCode {
	case http.StatusOK:
		return decodedJSON.Secrets, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("Couldn't sign in to API")
	default:
		return nil, makeErrorForAPIResponse(response)
	}
}

// DeleteSecret deletes a secret
func (c *Client) DeleteSecret(fingerprint fingerprint.Fingerprint, uuid string) error {
	path := fmt.Sprintf("secrets/%s", uuid)
	request, err := c.newRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	request.Header.Add("authorization", authorization(fingerprint))
	response, err := c.do(request, nil)
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusAccepted:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("Couldn't sign in to API")
	default:
		return makeErrorForAPIResponse(response)
	}
}

// UpsertPublicKey creates or updates a public key in the Fluidkeys Directory.
// It requires privateKey to ensure that only the owner of the public key can
// upload it.
func (c *Client) UpsertPublicKey(armoredPublicKey string, privateKey *pgpkey.PgpKey) error {
	armoredSignedJSON, err := makeUpsertPublicKeySignedData(armoredPublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("Failed to create ArmoredSignedJSON: %s", err)
	}
	upsertPublicKeyRequest := v1structs.UpsertPublicKeyRequest{
		ArmoredPublicKey:  armoredPublicKey,
		ArmoredSignedJSON: armoredSignedJSON,
	}
	request, err := c.newRequest("POST", "keys", upsertPublicKeyRequest)
	if err != nil {
		return fmt.Errorf("Failed to upload key: %s", err)
	}
	decodedUpsertResponse := new(v1structs.UpsertPublicKeyResponse)
	response, err := c.do(request, &decodedUpsertResponse)
	if err != nil {
		return fmt.Errorf("Failed to call API: %s", err)
	}
	if response.StatusCode != http.StatusOK {
		return makeErrorForAPIResponse(response)
	}
	return nil
}

func makeUpsertPublicKeySignedData(armoredPublicKey string, privateKey *pgpkey.PgpKey) (armoredSignedJSON string, err error) {
	publicKeyHash := fmt.Sprintf("%X", sha256.Sum256([]byte(armoredPublicKey)))

	singleTimeUUID, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("Couldn't generate UUID: %s", err)
	}

	publicKeyData := v1structs.UpsertPublicKeySignedData{
		Timestamp:       time.Now(),
		SingleUseUUID:   singleTimeUUID.String(),
		PublicKeySHA256: publicKeyHash,
	}

	jsonBytes, err := json.Marshal(publicKeyData)
	if err != nil {
		return "", fmt.Errorf("Couldn't marshal JSON: %s", err)
	}

	armoredSignedJSON, err = signText(jsonBytes, privateKey)
	if err != nil {
		return "", fmt.Errorf("Couldn't marshal JSON: %s", err)
	}

	return armoredSignedJSON, nil
}

func signText(bytesToSign []byte, key *pgpkey.PgpKey) (armoredSigned string, err error) {
	armorOutBuffer := bytes.NewBuffer(nil)
	privKey := key.Entity.PrivateKey

	armorWriteCloser, err := clearsign.Encode(armorOutBuffer, privKey, nil)
	if err != nil {
		return "", err
	}

	_, err = armorWriteCloser.Write(bytesToSign)
	if err != nil {
		return "", err
	}

	armorWriteCloser.Close()
	return armorOutBuffer.String(), nil
}

func makeErrorForAPIResponse(response *http.Response) error {
	apiErrorResponseDetail := decodeErrorResponse(response)
	if apiErrorResponseDetail != "" {
		return fmt.Errorf("Got API error: %d %s", response.StatusCode, apiErrorResponseDetail)
	}
	return fmt.Errorf("Got API error: %d", response.StatusCode)
}

func decodeErrorResponse(response *http.Response) string {
	if response.Body == nil {
		return ""
	}
	errorResponse := v1structs.ErrorResponse{}
	if err := json.NewDecoder(response.Body).Decode(&errorResponse); err != nil {
		return ""
	}
	return errorResponse.Detail
}

// newRequest creates an API request. relativePath is resolved relative to the
// BaseURL of the client.
// If specified, the value pointed to by requestData is JSON encoded and
// included as the request body.
func (c *Client) newRequest(method, relativePath string, requestData interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	url, err := c.BaseURL.Parse(relativePath)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if requestData != nil {
		buf = new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		err := enc.Encode(requestData)
		if err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequest(method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	if requestData != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		request.Header.Set("User-Agent", c.UserAgent)
	}
	return request, nil
}

// do sends an API request and decodes the JSON response, storing it in the
// value pointed to by responseData. If an API error occurs, it returns error.
func (c *Client) do(req *http.Request, responseData interface{}) (response *http.Response, err error) {
	response, err = c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if responseData != nil && response.Header.Get("Content-Type") == "application/json" && response.Body != nil {
		err = json.NewDecoder(response.Body).Decode(responseData)
	}

	return response, err
}

func authorization(fpr fingerprint.Fingerprint) string {
	return "tmpfingerprint: " + fmt.Sprintf("OPENPGP4FPR:%s", fpr.Hex())
}
