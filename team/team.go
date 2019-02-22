package team

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/gofrs/uuid"
	"github.com/natefinch/atomic"
)

// LoadTeams scans the fluidkeys/teams directory for subdirectories, enters them and tries to load
// roster.toml
// Returns a slice of Team
func LoadTeams(fluidkeysDirectory string) ([]Team, error) {
	teamRosters, err := findTeamRosters(getTeamDirectory(fluidkeysDirectory))
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

// Save validates the given team then tries to create a toml team roster in a subdirectory of the
// given directory.
func Save(team Team, fluidkeysDirectory string) error {
	err := team.Validate()
	if err != nil {
		return fmt.Errorf("invalid team: %v", err)
	}
	rosterDirectory := filepath.Join(
		getTeamDirectory(fluidkeysDirectory), // ~/.config/fluidkeys/teams
		team.subDirectory(),                  // fluidkeys-inc-4367436743
	)
	if _, err := os.Stat(rosterDirectory); !os.IsNotExist(err) {
		return fmt.Errorf("path already exists at %s", rosterDirectory)
	}
	if err = os.MkdirAll(rosterDirectory, 0700); err != nil {
		return fmt.Errorf("failed to make directory %s", rosterDirectory)
	}

	roster := bytes.NewBuffer(nil)
	if err := team.serialize(roster); err != nil {
		return fmt.Errorf("failed to serialize team roster: %v", err)
	}

	rosterFilename := filepath.Join(rosterDirectory, "roster.toml")
	if err = atomic.WriteFile(rosterFilename, roster); err != nil {
		return fmt.Errorf("failed write team roster: %v", err)
	}

	return nil
}

// Validate asserts that the team roster has no email addresses or fingerprints that are
// listed more than once.
func (t *Team) Validate() error {
	if t.UUID == uuid.Nil {
		return fmt.Errorf("invalid roster: invalid UUID")
	}

	emailsSeen := map[string]bool{} // look for multiple email addresses
	for _, person := range t.People {
		if _, alreadySeen := emailsSeen[person.Email]; alreadySeen {
			return fmt.Errorf("email listed more than once: %s", person.Email)
		}
		emailsSeen[person.Email] = true
	}

	fingerprintsSeen := map[fingerprint.Fingerprint]bool{}
	for _, person := range t.People {
		if _, alreadySeen := fingerprintsSeen[person.Fingerprint]; alreadySeen {
			return fmt.Errorf("fingerprint listed more than once: %s", person.Fingerprint)
		}
		fingerprintsSeen[person.Fingerprint] = true
	}
	return nil
}

// GetPersonForFingerprint takes a fingerprint and returns the person in the team with the
// matching fingperint.
func (t *Team) GetPersonForFingerprint(fpr fingerprint.Fingerprint) (*Person, error) {
	for _, person := range t.People {
		if person.Fingerprint == fpr {
			return &person, nil
		}
	}

	return nil, fmt.Errorf("person not found")
}

func getTeamDirectory(fluidkeysDirectory string) string {
	return filepath.Join(fluidkeysDirectory, "teams")
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

	team, err := Parse(reader)
	if err != nil {
		return nil, err
	}

	err = team.Validate()
	if err != nil {
		return nil, fmt.Errorf("error validating team: %v", err)
	}

	return team, nil
}

func fileExists(filename string) bool {
	if fileinfo, err := os.Stat(filename); err == nil {
		// path/to/whatever exists
		return !fileinfo.IsDir()
	}
	return false
}

// Team represents a group of people in Fluidkeys
type Team struct {
	UUID   uuid.UUID `toml:"uuid"`
	Name   string    `toml:"name"`
	People []Person  `toml:"person"`
}

// Fingerprints returns the key fingerprints for all people in the team
func (t *Team) Fingerprints() []fingerprint.Fingerprint {
	fps := []fingerprint.Fingerprint{}

	for _, person := range t.People {
		fps = append(fps, person.Fingerprint)
	}
	return fps
}

// Person represents a human team member
type Person struct {
	Email       string                  `toml:"email"`
	Fingerprint fingerprint.Fingerprint `toml:"fingerprint"`
}
