package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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

// NewClient returns a new Fluidkeys Server API client. If a nil httpClient is
// provided, http.DefaultClient will be used.
func NewClient() *Client {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		client:    http.DefaultClient,
		BaseURL:   baseURL,
		UserAgent: userAgent,
	}
}

// GetPublicKey attempts to get a single armorded public key.
func (c *Client) GetPublicKey(email string) (string, *http.Response, error) {
	url := fmt.Sprintf("email/%s/key", url.QueryEscape(email))
	request, err := c.newRequest("GET", url, nil)
	if err != nil {
		return "", nil, err
	}
	decodedJSON := new(v1structs.GetPublicKeyResponse)
	response, err := c.do(request, &decodedJSON)
	if err != nil {
		return "", response, err
	}
	return decodedJSON.ArmoredPublicKey, response, nil
}

// CreateSecret creates a secret for the given recipient
func (c *Client) CreateSecret(recipientFingerprint string, armoredEncryptedSecret string) (*http.Response, error) {
	sendSecretRequest := v1structs.SendSecretRequest{
		RecipientFingerprint:   recipientFingerprint,
		ArmoredEncryptedSecret: armoredEncryptedSecret,
	}
	url := fmt.Sprintf("secrets")
	request, err := c.newRequest("POST", url, sendSecretRequest)
	if err != nil {
		return nil, err
	}

	response, err := c.do(request, nil)
	if err != nil {
		return response, err
	}

	return response, nil
}

// newRequest creates an API request. A relative URL can be provided in urlStr,
// in which case it is resolved relative to the BaseURL of the Client.
// Relative URLs should always be specified without a preceding slash.
// If specified, the value pointed to by body is JSON encoded and included as
// the request body.
func (c *Client) newRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	url, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequest(method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		request.Header.Set("User-Agent", c.UserAgent)
	}
	return request, nil
}

// do sends an API request and decodes the JSON response, storing it in the
// value pointed to by v. If an API error occurs, it returns error.
func (c *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if v != nil {
		err = json.NewDecoder(response.Body).Decode(v)
	}

	return response, err
}
