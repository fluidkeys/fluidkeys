package team

import (
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
)

// Parse parses the team roster's TOML data, returning a Team or an error
func Parse(r io.Reader) (*Team, error) {
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

func (t *Team) serialize(w io.Writer) error {
	err := t.Validate()
	if err != nil {
		return fmt.Errorf("invalid team: %v", err)
	}
	if _, err := io.WriteString(w, defaultRosterFile); err != nil {
		return err
	}
	encoder := toml.NewEncoder(w)
	return encoder.Encode(t)
}

const defaultRosterFile = `# Fluidkeys team roster
`
