package testhelpers

import (
	"io/ioutil"
	"testing"
)

// Maketemp creates and returns a temporary directory
func Maketemp(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "fluidkeys-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}
