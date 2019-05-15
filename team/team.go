package team

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fluidkeys/crypto/openpgp"
	fpr "github.com/fluidkeys/fluidkeys/fingerprint"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/gofrs/uuid"
)

// LoadTeams scans the fluidkeys/teams directory for subdirectories, enters them and tries to load
// roster.toml
// Returns a slice of Team
func LoadTeams(fluidkeysDirectory string) ([]Team, error) {
	teamsDirectory, err := getTeamDirectory(fluidkeysDirectory)
	if err != nil {
		return nil, fmt.Errorf("couldn't get teams directory: %v", err)
	}

	teamSubdirs, err := findTeamSubdirectories(teamsDirectory)
	if err != nil {
		return nil, err
	}

	teams := []Team{}
	for _, subdir := range teamSubdirs {
		log.Printf("loading team roster from %s\n", subdir)
		roster, err := ioutil.ReadFile(filepath.Join(subdir, rosterFilename))
		if err != nil {
			return nil, fmt.Errorf("failed to read roster from %s: %v", subdir, err)
		}

		signature, err := ioutil.ReadFile(filepath.Join(subdir, signatureFilename))
		if err != nil {
			return nil, fmt.Errorf("failed to read signature from %s: %v", subdir, err)
		}

		team, err := Load(string(roster), string(signature))
		if err != nil {
			return nil, fmt.Errorf("failed to load team from %s: %v", subdir, err)
		}
		teams = append(teams, *team)
	}
	return teams, nil
}

// Load loads a team from the given roster and signature
func Load(roster string, signature string) (*Team, error) {
	team, err := parse(strings.NewReader(roster))
	if err != nil {
		return nil, err
	}

	err = team.Validate()
	if err != nil {
		return nil, fmt.Errorf("error validating team: %v", err)
	}

	team.roster = roster
	team.signature = signature
	return team, nil
}

// Directory returns the team subdirectory
func Directory(t Team, fluidkeysDirectory string) (directory string, err error) {
	teamDirectory, err := getTeamDirectory(fluidkeysDirectory)
	if err != nil {
		return "", err
	}
	return filepath.Join(
		teamDirectory,    // ~/.config/fluidkeys/teams
		t.subDirectory(), // fluidkeys-inc-4367436743
	), nil
}

// Admins returns the People who have IsAdmin set to true
func (t Team) Admins() (admins []Person) {
	for _, p := range t.People {
		if t.IsAdmin(p.Fingerprint) {
			admins = append(admins, p)
		}
	}
	return admins
}

// VerifyRoster cryptographically checks the signature against the roster, using the given
// signing keys
func VerifyRoster(roster string, signature string, adminKeys []*pgpkey.PgpKey) error {
	if signature == "" {
		return fmt.Errorf("empty signature")
	}
	var keyring openpgp.EntityList

	for i := range adminKeys {
		key := adminKeys[i]
		keyring = append(keyring, &key.Entity)
	}

	if _, err := openpgp.CheckArmoredDetachedSignature(
		keyring,
		strings.NewReader(roster),
		strings.NewReader(signature),
	); err != nil {
		return err
	}
	return nil
}

// PreviewRoster returns an (unsigned) roster based on the current state of the Team.
// Use this to preview the effect of any changes to the team, e.g. AddTeam, before actually
// updating and signing the roster.
func (t Team) PreviewRoster() (roster string, err error) {
	return t.serialize()
}

// UpdateRoster updates and signs the roster based on the state of the team. Subsequent calls to
// Roster() will return the new roster and signature.
func (t *Team) UpdateRoster(signingKey *pgpkey.PgpKey) error {
	if err := t.Validate(); err != nil {
		return fmt.Errorf("invalid team: %v", err)
	}

	if !t.IsAdmin(signingKey.Fingerprint()) {
		return fmt.Errorf("can't sign with key %s that's not an admin of the team",
			signingKey.Fingerprint())
	}

	roster, err := t.serialize()
	if err != nil {
		return err
	}

	signature, err := signingKey.MakeArmoredDetachedSignature([]byte(roster))
	if err != nil {
		return fmt.Errorf("failed to sign team roster: %v", err)
	}

	t.roster = roster
	t.signature = signature

	return nil
}

// Roster returns the TOML file representing the team roster, and the ASCII armored detached
// signature of that file.
func (t Team) Roster() (roster string, signature string) {
	if t.roster == "" || t.signature == "" {
		log.Panic("Roster called but roster & signature haven't been set")
	}
	return t.roster, t.signature
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

	fingerprintsSeen := map[fpr.Fingerprint]bool{}
	for _, person := range t.People {
		if _, alreadySeen := fingerprintsSeen[person.Fingerprint]; alreadySeen {
			return fmt.Errorf("fingerprint listed more than once: %s", person.Fingerprint)
		}
		fingerprintsSeen[person.Fingerprint] = true
	}

	if len(t.People) == 0 {
		return fmt.Errorf("team has no members")
	}

	if len(t.Admins()) == 0 {
		return fmt.Errorf("team has no administrators")
	}
	return nil
}

// IsAdmin takes a given fingerprint and returns whether they are an administor of the team
func (t Team) IsAdmin(fingerprint fpr.Fingerprint) bool {
	for _, person := range t.People {
		if person.IsAdmin && person.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// Contains returns whether the given fingerprint is a member of the team
func (t Team) Contains(fingerprint fpr.Fingerprint) bool {
	for _, person := range t.People {
		if person.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// GetPersonForFingerprint takes a fingerprint and returns the person in the team with the
// matching fingperint.
func (t *Team) GetPersonForFingerprint(fingerprint fpr.Fingerprint) (*Person, error) {
	for _, person := range t.People {
		if person.Fingerprint == fingerprint {
			return &person, nil
		}
	}

	return nil, fmt.Errorf("person not found")
}

// GetUpsertPersonWarnings checks if the given request to join a team causes any other team member to
// be overwritten, returning an error if so.
func (t *Team) GetUpsertPersonWarnings(newPerson Person) (existingPerson *Person, err error) {
	for _, existingPerson := range t.People {
		if existingPerson == newPerson {
			return &existingPerson, ErrPersonWouldNotBeChanged
		}

		fingerprintsEqual := existingPerson.Fingerprint == newPerson.Fingerprint
		emailsEqual := existingPerson.emailMatches(newPerson)
		isAdminsEqual := existingPerson.IsAdmin == newPerson.IsAdmin

		// 1. same email, different fingerprint
		// 2. same fingerprint, different email
		// 3. promoted to admin
		// 4. demoted from admin

		if !fingerprintsEqual && emailsEqual && isAdminsEqual {
			return &existingPerson, ErrKeyWouldBeUpdated
		}

		if !emailsEqual && fingerprintsEqual && isAdminsEqual {
			return &existingPerson, ErrEmailWouldBeUpdated
		}

		if !isAdminsEqual && emailsEqual && fingerprintsEqual {
			isPromotion := !existingPerson.IsAdmin && newPerson.IsAdmin

			if isPromotion {
				return &existingPerson, ErrPersonWouldBePromotedToAdmin
			}
			return &existingPerson, ErrPersonWouldBeDemotedAsAdmin
		}

	}
	return nil, nil
}

// UpsertPerson adds a Person to the team and removes anyone else that matches either the email or
// fingerprint.
func (t *Team) UpsertPerson(newPerson Person) {
	newPeople := []Person{}

	addedNewPerson := false

	for _, existingPerson := range t.People {
		if existingPerson.conflicts(newPerson) {
			newPeople = append(newPeople, newPerson)
			addedNewPerson = true
		} else {
			newPeople = append(newPeople, existingPerson)
		}
	}

	if !addedNewPerson {
		newPeople = append(newPeople, newPerson)
	}

	t.People = newPeople
}

func getTeamDirectory(fluidkeysDirectory string) (directory string, err error) {
	teamsDirectory := filepath.Join(fluidkeysDirectory, "teams")
	err = os.MkdirAll(teamsDirectory, 0700)
	if err != nil {
		return "", err
	}
	return teamsDirectory, nil
}

func findTeamSubdirectories(directory string) (teamSubdirs []string, err error) {
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		teamSubdir := filepath.Join(directory, f.Name())

		rosterPath := filepath.Join(teamSubdir, rosterFilename)
		signaturePath := filepath.Join(teamSubdir, signatureFilename)

		if fileExists(rosterPath) && fileExists(signaturePath) {
			teamSubdirs = append(teamSubdirs, teamSubdir)
		} else {
			log.Printf("ignoring %s (missing one of %s or %s)",
				teamSubdir, rosterFilename, signatureFilename)
		}
	}
	return teamSubdirs, nil
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

func fileExists(filename string) bool {
	if fileinfo, err := os.Stat(filename); err == nil {
		// path/to/whatever exists
		return !fileinfo.IsDir()
	}
	return false
}

// Team represents a group of people in Fluidkeys
type Team struct {
	UUID    uuid.UUID `toml:"uuid"`
	Version uint      `toml:"version"`
	Name    string    `toml:"name"`
	People  []Person  `toml:"person"`

	roster    string
	signature string
}

// Fingerprints returns the key fingerprints for all people in the team
func (t *Team) Fingerprints() []fpr.Fingerprint {
	fingerprints := []fpr.Fingerprint{}

	for _, person := range t.People {
		fingerprints = append(fingerprints, person.Fingerprint)
	}
	return fingerprints
}

// Person represents a human team member
type Person struct {
	Email       string          `toml:"email"`
	Fingerprint fpr.Fingerprint `toml:"fingerprint"`
	IsAdmin     bool            `toml:"is_admin"`
}

func (p Person) conflicts(other Person) bool {
	return p.emailMatches(other) || p.Fingerprint == other.Fingerprint
}

func (p Person) emailMatches(other Person) bool {
	// TODO: make this less naive
	return strings.ToLower(p.Email) == strings.ToLower(other.Email)
}

// RequestToJoinTeam represents a request to join a team
type RequestToJoinTeam struct {
	UUID        uuid.UUID
	TeamUUID    uuid.UUID
	TeamName    string
	Email       string
	Fingerprint fpr.Fingerprint
	// RequestAt is the moment at which the local client made the request
	RequestedAt time.Time
}

var (
	// ErrPersonWouldNotBeChanged means the person being upserted already exists in the team and would
	// be unchanged
	ErrPersonWouldNotBeChanged = fmt.Errorf("person already exists in roster")

	// ErrEmailWouldBeUpdated means there's already a key with a matching fingerprint, but a
	// different email address. Upserting this new person would change the email address.
	ErrEmailWouldBeUpdated = fmt.Errorf(
		"existing team member's email would be updated",
	)

	// ErrKeyWouldBeUpdated means there's already a person with the same email address but a
	// different key fingerprint, so their key will be updated.
	ErrKeyWouldBeUpdated = fmt.Errorf(
		"existing team member's key would be updated",
	)

	// ErrPersonWouldBeDemotedAsAdmin means the person is currently in the team as an admin.
	// Upserting this new person would demote them from being an admin.
	ErrPersonWouldBeDemotedAsAdmin = fmt.Errorf(
		"existing team member would be demoted as team admin",
	)

	// ErrPersonWouldBePromotedToAdmin means the person is currently in the team, but is not an
	// admin. Upserting this new person would promote them to admin.
	ErrPersonWouldBePromotedToAdmin = fmt.Errorf(
		"existing team member would be promoted to team admin",
	)
)
