package scheduler

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
)

type launchd struct{}

// Enable creates the launchd script and then loads it using launchctl
func (ld *launchd) Enable() (launchdWasLoaded bool, err error) {
	launchctl := &systemLaunchctl{}
	launchdFilename, err := ld.getFilename()
	if err != nil {
		return false, err
	}

	return ld.enable(launchctl, &fileFunctionsPassthrough{}, launchdFilename)
}

// Disable deletes the .plist file, then removes the launchd script
func (ld *launchd) Disable() (launchdWasRemoved bool, err error) {
	launchctl := &systemLaunchctl{}
	launchdFilename, err := ld.getFilename()
	if err != nil {
		return false, err
	}

	return ld.disable(launchctl, &fileFunctionsPassthrough{}, launchdFilename, launchdLabel)
}

func (ld *launchd) Name() string {
	return "launchd"
}

func (ld *launchd) enable(
	launchctl runLaunchctlInterface,
	fileFunctions fileFunctionsInterface,
	launchdAgentFilename string) (
	launchdFileWasCreated bool, err error) {

	if exists, err := fileExists(fileFunctions, launchdAgentFilename); err != nil || !exists {
		log.Printf("creating launchd plist file %s", launchdAgentFilename)
		// file does not exist (or couldn't tell), try writing out default launchd agent file
		if err = fileFunctions.IoutilWriteFile(
			launchdAgentFilename, []byte(LaunchdFileContents), 0600); err != nil {
			log.Printf("failed to create file %s: %v", launchdAgentFilename, err)
			return false,
				fmt.Errorf("%s didn't exist and failed to create it: %v", launchdAgentFilename, err)
		}
		launchdFileWasCreated = true
	}

	_, err = launchctl.load(launchdAgentFilename)
	if err != nil {
		log.Printf("failed to call launchctl load: %v", err)
		return false, err
	}

	return launchdFileWasCreated, nil
}

func fileExists(fileFunctions fileFunctionsInterface, filename string) (exists bool, err error) {
	_, err = fileFunctions.OsStat(filename)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (ld *launchd) disable(
	launchctl runLaunchctlInterface,
	fileFunctions fileFunctionsInterface,
	launchdAgentFilename string,
	launchdLabel string,
) (
	launchdFileWasRemoved bool, err error) {

	if exists, err := fileExists(fileFunctions, launchdAgentFilename); err != nil || exists {
		if err := fileFunctions.OsRemove(launchdAgentFilename); err != nil {
			return false, fmt.Errorf("failed to remove %s: %v", launchdAgentFilename, err)
		}
		launchdFileWasRemoved = true
	}

	// Note: if we call this function from launchd the following line will execture, but
	// then terminate immediately (as it's been unloaded). This means that no further code will run.
	_, err = launchctl.remove(launchdLabel)
	if err != nil {
		log.Printf("failed to call launchctl remove (but plist file is gone): %v\n", err)
		// we didn't manage to remove the job from launchd, but since the file is deleted it will
		// stop after the next reboot, so consider this a success.
	}

	return launchdFileWasRemoved, nil
}

func (ld *launchd) getFilename() (string, error) {
	homeDirectory, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	return path.Join(homeDirectory, "Library", "LaunchAgents", launchdFile), nil
}

type systemLaunchctl struct{}

func (s *systemLaunchctl) load(agentFilename string) (output string, err error) {
	return s.runLaunchctl("load", agentFilename)
}

func (s *systemLaunchctl) remove(agentFilename string) (output string, err error) {
	return s.runLaunchctl("remove", launchdLabel)
}

func (s *systemLaunchctl) runLaunchctl(verb string, filename string) (string, error) {
	log.Printf("Running `%s %s %s`", launchctl, verb, filename)
	cmd := exec.Command(launchctl, verb, filename)

	out, err := cmd.CombinedOutput()

	outString := string(out)
	if err != nil {
		log.Printf("launchd failed (output follows) %v\n%s", err, outString)
		return outString, err
	}
	// If launchd can't find a file, it returns a string similiar to
	//    directory/nonexistant.plist: No such file or directory
	// but exits with code 0 and no error.
	if strings.Contains(outString, "No such file or directory") {
		return outString, errCouldntFindLaunchdFile
	}
	return outString, nil
}

const (
	// LaunchdFileContents is the agent file for running fk sync every 60 minutes
	LaunchdFileContents = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>` + launchdLabel + `</string>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/local/bin/fk</string>
            <string>sync</string>
            <string>--cron-output</string>
        </array>
        <key>StartInterval</key>
        <integer>3600</integer>
    </dict>
</plist>
`
	launchctl    = "launchctl"
	launchdLabel = "com.fluidkeys.fk.sync"
	launchdFile  = "com.fluidkeys.fk.sync.plist"
)

var (
	errCouldntFindLaunchdFile = errors.New("couldn't find launchd file")
)
