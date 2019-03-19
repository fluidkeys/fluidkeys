package team

import (
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
)

// parse parses the team roster's TOML data, returning a Team or an error
func parse(r io.Reader) (*Team, error) {
	var parsedTeam Team
	metadata, err := toml.DecodeReader(r, &parsedTeam)

	if err != nil {
		return nil, fmt.Errorf("error in toml.DecodeReader: %v", err)
	}

	if len(metadata.Undecoded()) > 0 {
		// found config variables that we don't know how to match to
		// the Team structure
		return nil, fmt.Errorf("encountered unrecognised config keys: %v", metadata.Undecoded())
	}

	return &parsedTeam, nil
}
