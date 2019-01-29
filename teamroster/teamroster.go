package teamroster

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
)

// Load scans the fluidkeys/teams directory for subdirectories, enters them and tries to load
// roster.toml
// Returns a slice of Team
func Load(fluidkeysDirectory string) ([]Team, error) {
	teamRosters, err := findTeamRosters(filepath.Join(fluidkeysDirectory, "teams"))
	if err != nil {
		return nil, err
	}

	teams := []Team{}
	for _, teamRoster := range teamRosters {
		log.Printf("loading team roster %s\n", teamRoster)
		team, err := loadTeamRoster(teamRoster)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %v", teamRoster, err)
		}
		teams = append(teams, *team)
	}
	return teams, nil
}

func findTeamRosters(directory string) ([]string, error) {
	teamSubdirs, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	teamRosters := []string{}

	for _, teamSubDir := range teamSubdirs {
		if !teamSubDir.IsDir() {
			continue
		}

		teamRoster := filepath.Join(directory, teamSubDir.Name(), "roster.toml")
		// TODO: also look for teamRoster.asc and validate the signature

		if fileExists(teamRoster) {
			teamRosters = append(teamRosters, teamRoster)
		} else {
			log.Printf("missing %s", teamRoster)
		}
	}
	return teamRosters, nil
}

func loadTeamRoster(filename string) (*Team, error) {
	reader, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", filename, err)
	}

	team, err := parse(reader)
	if err != nil {
		return nil, err
	}

	return team, nil
}

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

func fileExists(filename string) bool {
	if fileinfo, err := os.Stat(filename); err == nil {
		// path/to/whatever exists
		return !fileinfo.IsDir()
	}
	return false
}

type Team struct {
	UUID   uuid.UUID         `toml:uuid`
	Name   string            `toml:name`
	People map[string]Person `toml:people`
}

func (t *Team) Fingerprints() []fingerprint.Fingerprint {
	fps := []fingerprint.Fingerprint{}

	for _, person := range t.People {

		if person.Fingerprint != nil {
			fps = append(fps, *person.Fingerprint)
		}
	}
	return fps
}

type Person struct {
	Fingerprint *fingerprint.Fingerprint
}
