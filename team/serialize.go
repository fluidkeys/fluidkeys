package team

import (
	"bytes"
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
)

// serialize returns the team as a toml formatted string. You should validate the team
// prior to this function.
func (t Team) serialize() (roster string, err error) {
	err = t.Validate()
	if err != nil {
		return "", fmt.Errorf("invalid team: %v", err)
	}

	buffer := bytes.NewBuffer(nil)
	if _, err := io.WriteString(buffer, defaultRosterFile); err != nil {
		return "", fmt.Errorf("failed to write default header: %v", err)
	}
	encoder := toml.NewEncoder(buffer)
	if err := encoder.Encode(t); err != nil {
		return "", fmt.Errorf("failed to encode: %v", err)
	}
	return buffer.String(), nil
}

const defaultRosterFile = `# Fluidkeys team roster
`
