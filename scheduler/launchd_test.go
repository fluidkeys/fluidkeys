package scheduler

import (
	"os"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
)

var ld = launchd{}

func TestLaunchdEnable(t *testing.T) {
	t.Run("runs `launchctl load` if agent file is present", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          nil,
			IoutilWriteFileReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdEnabled, err := ld.enable(mockLaunchctl, &mockFileHelper, "fake.plist")
		assert.NoError(t, err)

		assert.Equal(t, true, launchdEnabled)
		assert.Equal(t, true, mockLaunchctl.loadCalled)
	})

	t.Run("creates agent file if it's missing", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist,
			IoutilWriteFileReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdEnabled, err := ld.enable(mockLaunchctl, &mockFileHelper, "fake.plist")
		assert.NoError(t, err)

		assert.Equal(t, LaunchdFileContents, string(mockFileHelper.IoutilWriteFileGotData))
		assert.Equal(t, os.FileMode(0600), mockFileHelper.IoutilWriteFileGotMode)

		t.Run("then runs `launchctl load`", func(t *testing.T) {
			assert.Equal(t, true, launchdEnabled)
			assert.Equal(t, true, mockLaunchctl.loadCalled)
		})
	})

	t.Run("errors if file is missing and couldn't be created due to permission error",
		func(t *testing.T) {
			mockFileHelper := mockFileFunctions{
				OsStatReturnError:          os.ErrNotExist,
				IoutilWriteFileReturnError: os.ErrPermission,
			}
			mockLaunchctl := &mockLaunchctl{}

			launchdEnabled, err := ld.enable(mockLaunchctl, &mockFileHelper, "fake.plist")
			assert.GotError(t, err)
			assert.Equal(t,
				"fake.plist didn't exist and failed to create it: permission denied",
				err.Error(),
			)

			assert.Equal(t, false, launchdEnabled)
			assert.Equal(t, false, mockLaunchctl.loadCalled)
		})
}

func TestLaunchdDisable(t *testing.T) {
	t.Run("unload and deletes successfully if file is removed", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsRemoveReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.NoError(t, err)

		assert.Equal(t, true, launchdDisabled)
		assert.Equal(t, "fake", mockLaunchctl.removeCalledFor)
	})

	t.Run("error if file couldn't be removed", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsRemoveReturnError: os.ErrPermission,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.GotError(t, err)
		assert.Equal(t,
			"failed to remove fake.plist: permission denied",
			err.Error(),
		)

		assert.Equal(t, false, launchdDisabled)
		assert.Equal(t, false, mockLaunchctl.removeCalled)
	})
}

type mockFileFunctions struct {
	// provides fake versions of os.Stat etc.
	// implements fileFunctionsInterface
	OsRemoveReturnError        error
	OsRemoveCalledWithFilename string
	OsStatReturnError          error
	IoutilWriteFileReturnError error

	// IoutilWriteFileGotData stores whatever data was was writeen to WriteFile()
	IoutilWriteFileGotData []byte
	IoutilWriteFileGotMode os.FileMode
}

func (m *mockFileFunctions) OsRemove(filename string) error {
	m.OsRemoveCalledWithFilename = filename
	return m.OsRemoveReturnError
}

func (m *mockFileFunctions) OsStat(filename string) (os.FileInfo, error) {
	return nil, m.OsStatReturnError
}

func (m *mockFileFunctions) IoutilWriteFile(filename string, data []byte, mode os.FileMode) (int error) {
	m.IoutilWriteFileGotData = data
	m.IoutilWriteFileGotMode = mode

	return m.IoutilWriteFileReturnError
}

type mockLaunchctl struct {
	loadResult   string
	loadError    error
	removeResult string
	removeError  error

	loadCalled      bool
	removeCalled    bool
	removeCalledFor string
}

func (m *mockLaunchctl) load(filename string) (string, error) {
	m.loadCalled = true
	return m.loadResult, m.loadError
}

func (m *mockLaunchctl) remove(label string) (string, error) {
	m.removeCalled = true
	m.removeCalledFor = label
	return m.removeResult, m.removeError
}
