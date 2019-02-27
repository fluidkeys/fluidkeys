package team

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Roster returns the team as a toml formatted string. You should validate the team
// prior to this function.
func (t Team) Roster() (roster string, err error) {
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

func (t Team) subDirectory() string {
	slug := slugify(t.Name)

	if slug == "" {
		return t.UUID.String()
	}

	return slug + "-" + t.UUID.String()
}

func slugify(input string) string {
	slug := strings.TrimSpace(input)
	slug = strings.ToLower(slug)

	var subs = map[rune]string{
		'&': "and",
		'@': "a",
	}
	var buffer bytes.Buffer
	for _, char := range slug {
		if subChar, ok := subs[char]; ok {
			_, err := buffer.WriteString(subChar)
			if err != nil {
				log.Panic(err)
			}
		} else {
			_, err := buffer.WriteRune(char)
			if err != nil {
				log.Panic(err)
			}
		}
	}
	slug = buffer.String()

	slug = regexp.MustCompile("[^a-z0-9-_]").ReplaceAllString(slug, "-")
	slug = regexp.MustCompile("-+").ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-_")

	return slug
}

const defaultRosterFile = `# Fluidkeys team roster
`
