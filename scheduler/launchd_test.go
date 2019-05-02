package scheduler

import (
	"fmt"
	"os"
	"testing"

	"github.com/fluidkeys/fluidkeys/assert"
)

var ld = launchd{}

func TestLaunchdEnable(t *testing.T) {
	t.Run("no existing plist file, file is created and launchtl load is called", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          os.ErrNotExist, // simulate that file is missing
			IoutilWriteFileReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdWasEnabled, err := ld.enable(mockLaunchctl, &mockFileHelper, "fake.plist")
		assert.NoError(t, err)

		t.Run("file should have been written out", func(t *testing.T) {
			assert.Equal(t, LaunchdFileContents, string(mockFileHelper.IoutilWriteFileGotData))
			assert.Equal(t, os.FileMode(0600), mockFileHelper.IoutilWriteFileGotMode)
		})

		t.Run("launchtl load should have been called", func(t *testing.T) {
			assert.Equal(t, true, mockLaunchctl.loadCalled)
		})

		t.Run("return value launchdWasEnabled should be true", func(t *testing.T) {
			assert.Equal(t, true, launchdWasEnabled)
		})
	})

	t.Run("existing plist file, file is untouched and launchtl load is called", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:          nil, // simulate that file exists (no ErrNotExist)
			IoutilWriteFileReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdWasEnabled, err := ld.enable(mockLaunchctl, &mockFileHelper, "fake.plist")
		assert.NoError(t, err)

		t.Run("file should not been written out", func(t *testing.T) {
			assert.Equal(t, "", string(mockFileHelper.IoutilWriteFileGotData))
		})

		t.Run("launchtl load should have been called", func(t *testing.T) {
			assert.Equal(t, true, mockLaunchctl.loadCalled)
		})

		t.Run("return value launchdWasEnabled should be false", func(t *testing.T) {
			assert.Equal(t, false, launchdWasEnabled)
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

	t.Run("plist file exists, file should be deleted and launchctl remove called", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:   nil, // simulate that file exists (no ErrNotExist)
			OsRemoveReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdWasDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.NoError(t, err)

		t.Run("file was deleted", func(t *testing.T) {
			assert.Equal(t, "fake.plist", mockFileHelper.OsRemoveCalledWithFilename)
		})

		t.Run("launchctl remove was called", func(t *testing.T) {
			assert.Equal(t, true, mockLaunchctl.removeCalled)
			assert.Equal(t, "fake", mockLaunchctl.removeCalledForLabel)
		})

		t.Run("return value launchdWasDisabled is true", func(t *testing.T) {
			assert.Equal(t, true, launchdWasDisabled)
		})
	})

	t.Run("plist file doesn't exist, file should be untouched and launchctl remove called", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:   os.ErrNotExist, // simulate that file is missing
			OsRemoveReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdWasDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.NoError(t, err)

		t.Run("file was untouched", func(t *testing.T) {
			assert.Equal(t, "", mockFileHelper.OsRemoveCalledWithFilename)
		})

		t.Run("launchctl remove was called", func(t *testing.T) {
			assert.Equal(t, true, mockLaunchctl.removeCalled)
			assert.Equal(t, "fake", mockLaunchctl.removeCalledForLabel)
		})

		t.Run("return value launchdWasDisabled is false", func(t *testing.T) {
			assert.Equal(t, false, launchdWasDisabled)
		})
	})

	t.Run("plist file was removed, but launchctl remove failed, doesn't error", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:   nil, // simulate that file exists (no ErrNotExist)
			OsRemoveReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{
			removeError: fmt.Errorf("launchctl failed"),
		}

		launchdWasDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.NoError(t, err)

		t.Run("return value launchdWasDisabled is true", func(t *testing.T) {
			assert.Equal(t, true, launchdWasDisabled)
		})
	})

	t.Run("plist file was missing, but launchctl remove failed, doesn't error", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsStatReturnError:   os.ErrNotExist, // simulate that file is missing
			OsRemoveReturnError: nil,
		}
		mockLaunchctl := &mockLaunchctl{
			removeError: fmt.Errorf("launchctl failed"),
		}

		launchdWasDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.NoError(t, err)

		t.Run("return value launchdWasDisabled is false", func(t *testing.T) {
			assert.Equal(t, false, launchdWasDisabled)
		})
	})

	t.Run("error if file couldn't be removed", func(t *testing.T) {
		mockFileHelper := mockFileFunctions{
			OsRemoveReturnError: os.ErrPermission,
		}
		mockLaunchctl := &mockLaunchctl{}

		launchdWasDisabled, err := ld.disable(mockLaunchctl, &mockFileHelper, "fake.plist", "fake")
		assert.GotError(t, err)
		assert.Equal(t,
			"failed to remove fake.plist: permission denied",
			err.Error(),
		)

		assert.Equal(t, false, launchdWasDisabled)
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

	loadCalled           bool
	removeCalled         bool
	removeCalledForLabel string
}

func (m *mockLaunchctl) load(filename string) (string, error) {
	m.loadCalled = true
	return m.loadResult, m.loadError
}

func (m *mockLaunchctl) remove(label string) (string, error) {
	m.removeCalled = true
	m.removeCalledForLabel = label
	return m.removeResult, m.removeError
}
