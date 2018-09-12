package keytableprinter

import (
	"fmt"
	"testing"

	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
)

func TestMakeTable(t *testing.T) {
	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	if err != nil {
		t.Fatalf("Failed to load example test data: %v", err)
	}

	keys := []pgpkey.PgpKey{*pgpKey}

	want := fmt.Sprintf("%s\n",
		colour.LightBlue("Email address                       Created      Next rotation"),
	)
	want += fmt.Sprintf("──────────────────────────────────  ───────────  ─────────────\n")
	want += fmt.Sprintf("another@example.com                 10 Sep 2018\n")
	want += fmt.Sprintf("test3@example.com\n")
	want += fmt.Sprintf("unbracketedemail@example.com\n")
	want += fmt.Sprintf("──────────────────────────────────  ───────────  ─────────────\n")

	got := makeTable(keys)

	if got != want {
		t.Fatalf("Expected:\n---\n%v\n---\nGot:\n---\n%v\n---", want, got)
	}
}

func TestColumnWidths(t *testing.T) {
	pgpKey, err := pgpkey.LoadFromArmoredPublicKey(exampledata.ExamplePublicKey3)
	if err != nil {
		t.Fatalf("Failed to load example test data: %v", err)
	}

	keys := []pgpkey.PgpKey{*pgpKey}

	want := [3]int{34, 11, 13}
	got := columnWidths(keys)

	if !assertEqualColumnWidths(t, want, got) {
		t.Fatalf("Expected %v, got %v", want, got)
	}
}

func TestHorizontalUnderlines(t *testing.T) {
	columns := [3]int{4, 2, 5}

	got := makeHorizontalUnderlines(columns)
	want := "────  ──  ─────"

	if got != want {
		t.Fatalf("Expected '%v', got '%v'", want, got)
	}
}

func assertEqualColumnWidths(t *testing.T, a, b [3]int) bool {
	t.Helper()
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
