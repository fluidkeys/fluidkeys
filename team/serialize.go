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
	if _, err := io.WriteString(buffer, defaultRosterFile(t.Name)); err != nil {
		return "", fmt.Errorf("failed to write default header: %v", err)
	}
	encoder := toml.NewEncoder(buffer)
	if err := encoder.Encode(t); err != nil {
		return "", fmt.Errorf("failed to encode: %v", err)
	}
	return buffer.String(), nil
}

func defaultRosterFile(teamName string) string {
	return `# ` + teamName + ` team roster. Everyone in the team has a copy of this file.
#
# It is used to look up which key to use for an email address and fetch keys
# automatically.
`
}
