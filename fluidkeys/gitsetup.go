package main

import (
	"context"
	"fmt"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/emailutils"
	"github.com/fluidkeys/fluidkeys/gitwrapper"
	"github.com/fluidkeys/fluidkeys/humanize"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"log"
	"strconv"
	"strings"
)

func gitSetup() exitCode {
	out.Print("\n")
	out.Print("Fluidkeys will configure git, GnuPG and Github to sign and verify commits\n" +
		"and tags.\n\n")

	out.Print("You'll see " + colour.Success("☑ Verified") + " on Github and you'll be able " +
		"to check signatures\n")
	out.Print("locally using " + colour.CommandLineCode("git --verify") + ".\n\n")

	email, err := getGitEmail()
	if err != nil {
		out.Print("git is not configured with. Configure git and try again:\n\n")
		out.Print("    " + colour.CommandLineCode("git config --global user.email <email>") + "\n\n")
		return 1
	}

	pgpKey := getFluidkeysKeyForEmail(email)

	out.Print(" ▸   Git is configured to commit as " + colour.Info(email) + "\n")

	if pgpKey != nil {
		out.Print(" ▸   Fluidkeys has a PGP key for " + email + "\n")
	} else {
		out.Print(" ▸   Fluidkeys doesn't yet have a PGP key for " + email + "\n")

		gpgHasKey := checkForGpgKeyWithEmail(email)
		if gpgHasKey {
			printFailed("gpg already has a key for " + email + " but it's not " +
				"connected to Fluidkeys.")
			out.Print("\n")
			out.Print("Please connect it first by runnning:\n\n")
			out.Print("    " + colour.CommandLineCode("fk key from-gpg") + "\n\n")
			out.Print("Then run this command again:\n\n")
			out.Print("    " + colour.CommandLineCode("fk git setup") + "\n\n")
			return 1
		} else {
			log.Print("gpg doesn't have a key matching the email address. will create.")
		}
	}

	out.Print("\n")
	out.Print("Fluidkeys will:\n\n")

	if pgpKey == nil {
		out.Print("     [ ] Create a PGP key for " + email + "\n")
		out.Print("     [ ] Store the new key in gpg (so git can sign commits using gpg)\n")
	}

	out.Print("     [ ] Configure git for signing:\n")
	out.Print("\n")
	out.Print("         user.signingkey        => " + fingerprintOrPlaceholder(pgpKey) + "\n")
	out.Print("         commit.gpgsign         => true\n")
	out.Print("         tag.forceSignAnnotated => true\n")
	out.Print("         log.showSignature      => true\n")
	out.Print("         gpg.program            => " + gpg.Path() + "\n")
	out.Print("\n")
	out.Print("     [ ] Ask you to create a Github personal access token\n")
	out.Print("     [ ] Check " + email + " is listed in your Github account\n")
	out.Print("     [ ] Upload the public key to Github\n")
	out.Print("     [ ] Check if your organisations have Fluidkeys for Teams\n")
	out.Print("     [ ] Fetch public keys for everyone in your organisation\n")

	prompter := interactiveYesNoPrompter{}
	out.Print("\n")
	if prompter.promptYesNo("Configure git, gpg & Github for "+
		colour.Info(email), "Y", nil) == false {

		out.Print("To use a different email, configure git by running:\n")
		out.Print("    " + colour.CommandLineCode("git config --global user.email <email>") + "\n\n")
		return 1
	}

	if pgpKey == nil {
		printHeader("Creating PGP key")
		var exitCode exitCode
		exitCode, pgpKey = keyCreate(email)
		if exitCode != 0 {
			return exitCode
		}
	}

	printHeader("Configuring git")
	err = configureGit(email, pgpKey)
	if err != nil {
		log.Panic(err.Error())
	}

	promptForInput("Configured git. Press enter to continue. ")

	printHeader("Configuring Github")
	token, err := getGithubPersonalAccessToken()
	if err != nil {
		log.Panic(err.Error())
	}

	emailOk, err := configureGithub(email, pgpKey, token)
	if err != nil {
		log.Panic(err.Error())
	} else if emailOk == false {
		return 1
	}

	promptForInput("Configured Github. Press enter to continue. ")

	printHeader("Checking Github organisations for Fluidkeys for Teams")
	err = printGithubOrganisations(token)
	if err != nil {
		log.Panic(err.Error())
	}

	printHeader("Fetching public keys for other team members")
	err = fetchPublicKeys(email, pgpKey)
	if err != nil {
		log.Panic(err.Error())
	}

	promptForInput("Finished fetching keys. Press enter to continue. ")

	printHeader("Setup complete")
	printGitCongratulations()
	return 0
}

// fingerprintOrPlaceholder returns either the hex formatted string (for use with git
// commit.signingkey) or placeholder text '<fingerprint of the new key>'
func fingerprintOrPlaceholder(key *pgpkey.PgpKey) string {
	if key == nil {
		return "<fingerprint of the new key>"
	} else {
		return key.Fingerprint().Hex()
	}
}

func getFluidkeysKeyForEmail(email string) *pgpkey.PgpKey {
	keys, err := loadPgpKeys()
	if err != nil {
		log.Panicf("error loading keys: %v", err)
	}

	for _, key := range keys {
		for _, keyEmail := range key.Emails(true) {
			if email == keyEmail {
				log.Printf("found key in Fluidkeys for email '%s'", email)
				return &key
			}
		}
	}
	log.Printf("didn't find key in Fluidkeys for email '%s'", email)
	return nil
}

func configureGit(email string, key *pgpkey.PgpKey) error {
	git, err := gitwrapper.Load()
	if err != nil {
		return err
	}

	out.Print("🛠️ Configuring git:\n\n")

	err = git.SetConfig("user.signingkey", key.Fingerprint().Hex())
	if err != nil {
		return err
	}
	printSuccessfulAction("Sign using key " + key.Fingerprint().Hex())

	err = git.SetConfig("commit.gpgsign", "true")
	if err != nil {
		return err
	}
	printSuccessfulAction("Always sign commits")

	err = git.SetConfig("tag.forceSignAnnotated", "true")
	if err != nil {
		return err
	}
	printSuccessfulAction("Always sign annotated tags")

	err = git.SetConfig("log.showSignature", "true")
	if err != nil {
		return err
	}
	printSuccessfulAction("Show signatures in git log")

	err = git.SetConfig("gpg.program", gpg.Path())
	if err != nil {
		return err
	}
	printSuccessfulAction("Use GnuPG at " + gpg.Path())
	out.Print("\n")
	return nil
}

func getGithubPersonalAccessToken() (string, error) {
	token := Config.GithubPersonalAccessToken()

	for {
		if token == "" {
			token = promptForAccessToken()
		}

		if testGithubToken(token) {
			printSuccess("Github token appears to be working")

			err := Config.SetGithubPersonalAccessToken(token)
			if err != nil {
				log.Print("Failed to save (working) Github token back to config")
			}

			return token, nil
		} else {
			printFailed("Github token didn't return an authenticated user")
			token = ""
		}
	}
}

func testGithubToken(token string) bool {
	client, err := makeGithubClient(token)
	if err != nil {
		log.Panic(err)
	}

	user, response, err := client.Users.Get(context.Background(), "")
	if err != nil {
		if response != nil && response.StatusCode == 401 {
			log.Printf("tested github token, treating error as 'bad token': %v", err)
			return false
		}
		log.Panic(fmt.Errorf("github token didn't return an authenticated user: %v", err))
	}

	log.Print("github token worked, got user '%s'", user.GetName())
	return true
}

func makeGithubClient(token string) (*github.Client, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	return github.NewClient(tc), nil
}

func promptForAccessToken() string {
	out.Print("To configure Github, you need to create a personal access token.\n")
	out.Print("\n")
	out.Print("Open this URL in your browser:\n\n")
	out.Print("    " + colour.Info("https://github.com/settings/tokens/new") + "\n")
	out.Print("\n")
	out.Print("Enter this Token description:\n")
	out.Print("\n")
	out.Print("    \"" + colour.Info("Fluidkeys (www.fluidkeys.com) `fk git setup`") + "\"\n\n")

	out.Print("Select these scropes to give Fluidkeys access:\n\n")
	out.Print("    ☑ " + colour.Info("read:org") + "      \"Read org and team membership\"\n")
	out.Print("                    To list your organisations and check for Fluidkeys for Teams.\n")
	out.Print("\n")
	out.Print("    ☑ " + colour.Info("user:email") + "    \"Access user email addresses (read-only)\"\n")
	out.Print("                    To confirm that paul@example.com is listed in your Github account\n")
	out.Print("\n")
	out.Print("    ☑ " + colour.Info("admin:gpg_key") + " \"Full control of user gpg keys\"\n")
	out.Print("                    To upload your public key now and after key rotation\n")
	out.Print("\n")
	out.Print("Click " + colour.Success("Generate token") + ", copy the token and paste " +
		"it here:\n\n")

	return promptForInput("[token] : ")
}

func configureGithub(email string, key *pgpkey.PgpKey, token string) (emailOk bool, err error) {
	out.Print("\n")
	out.Print("🛠️ Configuring Github:\n\n")

	client, err := makeGithubClient(token)
	if err != nil {
		return false, err
	}

	user, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return false, fmt.Errorf("github error getting user: %v", err)
	}

	userEmails, _, err := client.Users.ListEmails(context.Background(), nil)
	if err != nil {
		return false, fmt.Errorf("error getting email for user: %v", err)
	}

	for _, githubEmail := range userEmails {
		if email == *githubEmail.Email {
			if *githubEmail.Verified {
				printSuccessfulAction(
					"Confirmed " + email + " is listed in Github account " +
						user.GetLogin())
				emailOk = true
			} else {
				printFailedAction(email + " is unverified in Github account " +
					user.GetLogin())
				return false, nil
			}
		}
	}

	if !emailOk {
		printFailedAction(email + " is not listed in Github account " + user.GetLogin())
		return false, nil
	}

	err = deleteAndAddPublicKey(client, key)
	if err != nil {
		return false, err
	}

	return true, nil
}

func deleteAndAddPublicKey(client *github.Client, key *pgpkey.PgpKey) error {
	armoredKey, err := key.Armor()
	if err != nil {
		return err
	}

	allKeys, _, err := client.Users.ListGPGKeys(context.Background(), "", nil)
	if err != nil {
		return fmt.Errorf("error getting keys from Github: %v", err)
	}

	for _, githubKey := range allKeys {
		//githubKeyIdDecoded, err := hex.DecodeString(*githubKey.KeyID)
		githubKeyIdDecoded, err := strconv.ParseUint(*githubKey.KeyID, 16, 64)
		if err != nil {
			log.Panic(err)
		}

		if githubKeyIdDecoded == key.PrimaryKey.KeyId {
			internalKeyId := *githubKey.ID
			log.Printf("found matching pgp key with github ID %v", internalKeyId)

			_, _, err = client.Users.GetGPGKey(context.Background(), internalKeyId)
			if err != nil {
				return fmt.Errorf("error getting key in Github: %v", err)
			}

			_, err = client.Users.DeleteGPGKey(context.Background(), internalKeyId)
			if err != nil {
				return fmt.Errorf("error deleting key in Github: %v", err)
			} else {
				log.Printf("deleted key %X (github id %v) from Github",
					key.PrimaryKey.KeyId, internalKeyId)
			}

		}
	}

	_, _, err = client.Users.CreateGPGKey(context.Background(), armoredKey)
	if err != nil {
		return fmt.Errorf("error creating key in Github: %v", err)
	}
	printSuccessfulAction("Uploaded public key to Github account")
	out.Print("\n")
	return nil
}

func printGithubOrganisations(token string) error {
	client, err := makeGithubClient(token)
	if err != nil {
		return err
	}

	out.Print("Fluidkeys for Teams ensures you always have up-to-date keys for everyone " +
		"in your\norganisation, allowing you to verify their signatures.\n\n")

	orgs, _, err := client.Organizations.List(context.Background(), "", nil)
	for _, org := range orgs {

		fullOrg, _, err := client.Organizations.Get(context.Background(), *org.Login)
		if err != nil {
			return err
		}

		users, _, err := client.Organizations.ListMembers(context.Background(), *org.Login, nil)
		if err != nil {
			return err
		}

		out.Print(" ▸   " + orgName(fullOrg) + " (" +
			humanize.Pluralize(len(users), "person", "people") + ")\n")
		out.Print(colour.Warning(
			"     not subscribed: keys must be updated and synced manually\n"))
	}

	out.Print("\n")
	return nil
}

func orgName(org *github.Organization) string {
	if org.GetName() != "" {
		return org.GetName()
	}
	return org.GetLogin()
}

func fetchPublicKeys(email string, key *pgpkey.PgpKey) error {
	printWarning("Skipped: no organisations with Fluidkeys for Teams\n")
	return nil
}

func printGitCongratulations() {
	out.Print("🎉 Congratulations! You're ready to sign your git commits and tags!\n\n")
	out.Print(" >  " + colour.CommandLineCode("git commit") + "\n")
	out.Print("    create a signed commit\n")
	out.Print("\n")
	out.Print(" >  " + colour.CommandLineCode("git tag --sign -m \"v1.0\"") + "\n")
	out.Print("    create a signed, annotated tag\n")
	out.Print("\n")
	out.Print(" >  " + colour.CommandLineCode("git tag --verify \"v1.0\"") + "\n")
	out.Print("    verify the signature of an annotated tag\n")
	out.Print("\n")
	out.Print(" >  " + colour.CommandLineCode("git log --show-signature") + "\n")
	out.Print("    show commits and check signatures\n")

	out.Print("\n")
	printWarning("No public keys downloaded.")
	out.Print("     Fluidkeys for Teams can automate downloading, verifying and updating\n" +
		"     public keys for you:\n")
	out.Print("     " + colour.Info("https://www.fluidkeys.com/fluidkeys-for-teams") + "\n")
	out.Print("\n")
}

func checkForGpgKeyWithEmail(email string) bool {
	gpgEmails, err := getGpgEmails()
	if err != nil {
		log.Panic("error getting emails from gpg: %v", err)
	}

	for _, gpgEmail := range gpgEmails {
		if email == gpgEmail {
			log.Printf("found key in gpg for email '%s'", email)
			return true
		}
	}
	log.Printf("didn't find key in gpg for email '%s'", email)
	return false
}

func findPossibleEmails() []string {
	emails := []string{}

	gitEmail, err := getGitEmail()
	if err != nil {
		log.Printf("failed to get email from git: %v", err)
	} else {
		emails = append(emails, gitEmail)
	}

	gpgEmails, err := getGpgEmails()
	if err != nil {
		log.Printf("failed to get emails from GnuPG: %v", err)
	} else {
		emails = append(emails, gpgEmails...)
	}
	return filterEmails(emails)
}

func getGitEmail() (string, error) {
	git, err := gitwrapper.Load()
	if err != nil {
		return "", err
	}
	email, err := git.GetConfig("user.email")
	if err != nil {
		return "", err
	}

	if !emailutils.RoughlyValidateEmail(email) {
		return "", fmt.Errorf("got invalid email `%s` from git config", email)
	}
	return email, nil
}

func getGpgEmails() ([]string, error) {
	secretKeys, err := gpg.ListSecretKeys()
	if err != nil {
		return nil, err
	}

	emails := []string{}
	for _, k := range secretKeys {
		for _, userid := range k.Uids {
			emails = append(emails, parseEmailFromUserId(userid))
		}
	}
	return emails, nil
}

// de-duplicate and remove invalid email addresses
func filterEmails(emails []string) []string {
	goodEmails := []string{}
	emailsSeen := make(map[string]bool)

	for _, email := range emails {
		if _, alreadySeen := emailsSeen[email]; alreadySeen {
			continue
		}
		if !emailutils.RoughlyValidateEmail(email) {
			continue
		}
		goodEmails = append(goodEmails, email)
	}
	return goodEmails
}

func parseEmailFromUserId(userId string) string {
	_, _, email := parseUserId(userId)

	if emailutils.RoughlyValidateEmail(email) {
		return email

	} else if email == "" && emailutils.RoughlyValidateEmail(userId) {
		return userId
	}
	return ""
}

// parseUserId extracts the name, comment and email from a user id string that
// is formatted as "Full Name (Comment) <email@example.com>".
func parseUserId(id string) (name, comment, email string) {
	var n, c, e struct {
		start, end int
	}
	var state int

	for offset, rune := range id {
		switch state {
		case 0:
			// Entering name
			n.start = offset
			state = 1
			fallthrough
		case 1:
			// In name
			if rune == '(' {
				state = 2
				n.end = offset
			} else if rune == '<' {
				state = 5
				n.end = offset
			}
		case 2:
			// Entering comment
			c.start = offset
			state = 3
			fallthrough
		case 3:
			// In comment
			if rune == ')' {
				state = 4
				c.end = offset
			}
		case 4:
			// Between comment and email
			if rune == '<' {
				state = 5
			}
		case 5:
			// Entering email
			e.start = offset
			state = 6
			fallthrough
		case 6:
			// In email
			if rune == '>' {
				state = 7
				e.end = offset
			}
		default:
			// After email
		}
	}
	switch state {
	case 1:
		// ended in the name
		n.end = len(id)
	case 3:
		// ended in comment
		c.end = len(id)
	case 6:
		// ended in email
		e.end = len(id)
	}

	name = strings.TrimSpace(id[n.start:n.end])
	comment = strings.TrimSpace(id[c.start:c.end])
	email = strings.TrimSpace(id[e.start:e.end])
	return
}
