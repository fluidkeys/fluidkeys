package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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
func NewClient() *Client {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		client:    http.DefaultClient,
		BaseURL:   baseURL,
		UserAgent: userAgent,
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
func (c *Client) do(req *http.Request, responseData interface{}) (*http.Response, error) {
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if responseData != nil {
		err = json.NewDecoder(response.Body).Decode(responseData)
	}

	return response, err
}
