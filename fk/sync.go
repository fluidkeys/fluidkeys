// Copyright 2019 Paul Furley and Ian Drysdale
//
// This file is part of Fluidkeys Client which makes it simple to use OpenPGP.
//
// Fluidkeys Client is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Fluidkeys Client is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Fluidkeys Client.  If not, see <https://www.gnu.org/licenses/>.

package fk

import (
	"fmt"
	"log"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/colour"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/ui"
)

func syncSubcommand(args docopt.Opts) exitCode {
	return sync()
}

func sync() (code exitCode) {
	out.Print(ui.FormatInfo(
		"fk sync always runs in automatic (unattended) mode",
		[]string{
			"Because it's designed to run from cron. That means it won't ask for passwords, ",
			"and will fail if these can't be fetched from your " + Keyring.Name(),
		}))

	out.Print("\n")
	out.Print("-> " + colour.Cmd("fk key maintain automatic") + "\n")

	h := heartbeatData{}

	if h.keyMaintainExitCode = keyMaintain(false, true); h.keyMaintainExitCode != 0 {
		code = h.keyMaintainExitCode
	}

	out.Print("\n")
	out.Print("-> " + colour.Cmd("fk team fetch") + "\n\n")
	if h.teamFetchExitCode = teamFetch(true); h.teamFetchExitCode != 0 {
		code = h.teamFetchExitCode
	}

	sendHeartbeatNoMoreThanDaily(&h)
	return code
}

func sendHeartbeatNoMoreThanDaily(h *heartbeatData) {
	twentyFourHours := time.Duration(24) * time.Hour
	now := time.Now()

	if stale, err := db.IsOlderThan("send", "heartbeat", twentyFourHours, now); err != nil {
		log.Printf("failed to check time of last heartbeat: %v", err)
		return // don't risk sending it every time.
	} else if !stale {
		return
	}

	fmt.Printf("sending heartbeat packet:\n%#v\n", h)

	// TODO: actually send it

	err := db.RecordLast("send", "heartbeat", now)
	if err != nil {
		panic(fmt.Errorf("failed to record sending heartbeat: %v", err))
	}
}

type heartbeatData struct {
	keyMaintainExitCode exitCode
	teamFetchExitCode   exitCode
}
