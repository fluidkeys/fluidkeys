package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/fingerprint"

	"github.com/fluidkeys/api/v1structs"
)

// String is a helper routine that allocates a new string value
// to store v and returns a pointer to it.
func String(v string) *string { return &v }

func TestGetPublicKey(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/email/jane@example.com/key", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, `{"armoredPublicKey": "---- BEGIN PGP PUBLIC KEY..."}`)
	})

	armoredPublicKey, err := client.GetPublicKey("jane@example.com")

	assert.ErrorIsNil(t, err)

	want := "---- BEGIN PGP PUBLIC KEY..."
	if armoredPublicKey != want {
		t.Errorf("GetPublicKey(\"jane@example.com\") returned %+v, want %+v", armoredPublicKey, want)
	}
}

func TestCreateSecret(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	input := &v1structs.SendSecretRequest{
		RecipientFingerprint:   "OPENPGP4FPR:ABABABABABABABABABABABABABABABABABABABAB",
		ArmoredEncryptedSecret: "---- BEGIN PGP MESSAGE...",
	}

	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		v := new(v1structs.SendSecretRequest)
		json.NewDecoder(r.Body).Decode(v)
		testMethod(t, r, "POST")
		if !reflect.DeepEqual(v, input) {
			t.Errorf("Request body = %+v, want %+v", v, input)
		}

		w.WriteHeader(201)
	})

	fingerprint, err := fingerprint.Parse("ABAB ABAB ABAB ABAB ABAB  ABAB ABAB ABAB ABAB ABAB")
	if err != nil {
		t.Fatalf("Couldn't parse fingerprint: %s\n", err)
	}

	err = client.CreateSecret(
		fingerprint,
		"---- BEGIN PGP MESSAGE...",
	)
	assert.ErrorIsNil(t, err)
}

func TestDecodeErrorResponse(t *testing.T) {
	t.Run("a response body of nil", func(t *testing.T) {
		httpResponse := http.Response{Body: nil}
		assert.Equal(t, "", decodeErrorResponse(&httpResponse))
	})
	t.Run("a response body of invalid JSON", func(t *testing.T) {
		bodyString := "foo"
		httpResponse := http.Response{
			Body: ioutil.NopCloser(strings.NewReader(bodyString)),
		}
		assert.Equal(t, "", decodeErrorResponse(&httpResponse))
	})
	t.Run("Valid JSON but missing 'detail'", func(t *testing.T) {
		bodyString := `{"foo":"bar"}`
		httpResponse := http.Response{
			Body: ioutil.NopCloser(strings.NewReader(bodyString)),
		}
		assert.Equal(t, "", decodeErrorResponse(&httpResponse))
	})
	t.Run("Valid JSON but missing 'detail'", func(t *testing.T) {
		bodyString := `{"detail":"missing record"}`
		httpResponse := http.Response{
			Body: ioutil.NopCloser(strings.NewReader(bodyString)),
		}
		assert.Equal(t, "missing record", decodeErrorResponse(&httpResponse))
	})
}

// setup sets up a test HTTP server along with a fluidkeysServer.Client that is
// configured to talk to that test server. Tests should register handlers on
// mux which provide mock responses for the API method being tested.
func setup() (client *Client, mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	// client is the Fluidkeys Server client being tested and is
	// configured to use test server.
	client = NewClient("vtest")
	url, _ := url.Parse(server.URL + "/")
	client.BaseURL = url

	return client, mux, server.URL, server.Close
}

func testMethod(t *testing.T, r *http.Request, want string) {
	if got := r.Method; got != want {
		t.Errorf("Request method: %v, want %v", got, want)
	}
}
