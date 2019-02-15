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

	"github.com/fluidkeys/fluidkeys/exampledata"

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

	t.Run("with valid JSON response", func(t *testing.T) {
		mux.HandleFunc("/email/jane@example.com/key", func(w http.ResponseWriter, r *http.Request) {
			testMethod(t, r, "GET")
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"armoredPublicKey": "---- BEGIN PGP PUBLIC KEY..."}`)
		})

		armoredPublicKey, err := client.GetPublicKey("jane@example.com")

		assert.ErrorIsNil(t, err)

		want := "---- BEGIN PGP PUBLIC KEY..."
		if armoredPublicKey != want {
			t.Errorf("GetPublicKey(\"jane@example.com\") returned %+v, want %+v", armoredPublicKey, want)
		}
	})

	t.Run("with empty response", func(t *testing.T) {
		mux.HandleFunc("/email/joe@example.com/key", func(w http.ResponseWriter, r *http.Request) {
			testMethod(t, r, "GET")
		})

		armoredPublicKey, err := client.GetPublicKey("joe@example.com")

		assert.ErrorIsNil(t, err)

		want := ""
		if armoredPublicKey != want {
			t.Errorf("GetPublicKey(\"joe@example.com\") returned %+v, want %+v", armoredPublicKey, want)
		}
	})

	t.Run("with a server error", func(t *testing.T) {
		mux.HandleFunc("/email/abby@example.com/key", func(w http.ResponseWriter, r *http.Request) {
			testMethod(t, r, "GET")
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"detail": "Key not found"}`)
		})

		_, err := client.GetPublicKey("abby@example.com")

		assert.ErrorIsNotNil(t, err)
	})
}

func TestGetPublicKeyByFingerprint(t *testing.T) {
	t.Run("responds with a good armored pgp key with matching fingerprint", func(t *testing.T) {
		client, mux, _, teardown := setup()
		defer teardown()

		mockResponseHandler := func(w http.ResponseWriter, r *http.Request) {
			assertClientSentVerb(t, "GET", r.Method)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, exampledata.ExamplePublicKey4)
		}
		mux.HandleFunc(
			"/key/"+exampledata.ExampleFingerprint4.Hex()+".asc",
			mockResponseHandler,
		)

		key, err := client.GetPublicKeyByFingerprint(exampledata.ExampleFingerprint4)

		assert.ErrorIsNil(t, err)
		assert.Equal(t, exampledata.ExampleFingerprint4, key.Fingerprint())
	})

	t.Run("responds with an armored pgp key with the wrong fingerprint", func(t *testing.T) {
		client, mux, _, teardown := setup()
		defer teardown()

		mockResponseHandler := func(w http.ResponseWriter, r *http.Request) {
			assertClientSentVerb(t, "GET", r.Method)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, exampledata.ExamplePublicKey3)
		}
		mux.HandleFunc(
			"/key/"+exampledata.ExampleFingerprint4.Hex()+".asc",
			mockResponseHandler,
		)

		_, err := client.GetPublicKeyByFingerprint(exampledata.ExampleFingerprint4)

		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, fmt.Errorf("requested key BB3C 44BF 188D 56E6 35F4  A092 F73D 2F05 "+
			"33D7 F9D6 but got back 7C18 DE4D E478 1356 8B24  3AC8 719B D63E F03B DC20"), err)
	})

	t.Run("empty response body", func(t *testing.T) {
		client, mux, _, teardown := setup()
		defer teardown()

		mockResponseHandler := func(w http.ResponseWriter, r *http.Request) {
			assertClientSentVerb(t, "GET", r.Method)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "")
		}
		mux.HandleFunc(
			"/key/"+exampledata.ExampleFingerprint4.Hex()+".asc",
			mockResponseHandler,
		)

		_, err := client.GetPublicKeyByFingerprint(exampledata.ExampleFingerprint4)

		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, fmt.Errorf("got http 200, but with empty body"), err)
	})

	t.Run("404 gives a specific error", func(t *testing.T) {
		client, mux, _, teardown := setup()
		defer teardown()

		mockResponseHandler := func(w http.ResponseWriter, r *http.Request) {
			assertClientSentVerb(t, "GET", r.Method)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "")
		}
		mux.HandleFunc(
			"/key/"+exampledata.ExampleFingerprint4.Hex()+".asc",
			mockResponseHandler,
		)

		_, err := client.GetPublicKeyByFingerprint(exampledata.ExampleFingerprint4)

		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, ErrPublicKeyNotFound, err)
	})

	t.Run("responds with http 500 (unexpected http code)", func(t *testing.T) {
		client, mux, _, teardown := setup()
		defer teardown()

		mockResponseHandler := func(w http.ResponseWriter, r *http.Request) {
			assertClientSentVerb(t, "GET", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "")
		}
		mux.HandleFunc(
			"/key/"+exampledata.ExampleFingerprint4.Hex()+".asc",
			mockResponseHandler,
		)

		_, err := client.GetPublicKeyByFingerprint(exampledata.ExampleFingerprint4)

		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, fmt.Errorf("API error: 500"), err)
	})

	t.Run("responds with junk", func(t *testing.T) {
		client, mux, _, teardown := setup()
		defer teardown()

		mockResponseHandler := func(w http.ResponseWriter, r *http.Request) {
			assertClientSentVerb(t, "GET", r.Method)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "junk body")
		}
		mux.HandleFunc(
			"/key/"+exampledata.ExampleFingerprint4.Hex()+".asc",
			mockResponseHandler,
		)

		_, err := client.GetPublicKeyByFingerprint(exampledata.ExampleFingerprint4)

		assert.ErrorIsNotNil(t, err)
		assert.Equal(t, fmt.Errorf("failed to load armored key: error reading armored key ring: "+
			"openpgp: invalid argument: no armored data found"), err)
	})
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
