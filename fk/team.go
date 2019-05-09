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
	"log"

	"github.com/docopt/docopt-go"
	"github.com/fluidkeys/fluidkeys/out"
	"github.com/fluidkeys/fluidkeys/ui"
	"github.com/gofrs/uuid"
)

func teamSubcommand(args docopt.Opts) exitCode {
	switch getSubcommand(args, []string{
		"authorize", "create", "apply", "fetch", "edit",
	}) {

	case "apply":
		id, err := args.String("<uuid>")
		if err != nil {
			log.Panic(err)
		}

		teamUUID, err := uuid.FromString(id)
		if err != nil {
			out.Print(ui.FormatFailure("Invalid UUID", nil, err))
			return 1
		}

		return teamApply(teamUUID)

	case "fetch":
		return teamFetch(false)

	case "create":
		return teamCreate()

	case "authorize":
		return teamAuthorize()

	case "edit":
		return teamEdit()
	}
	log.Panicf("secretSubcommand got unexpected arguments: %v", args)
	panic(nil)
}
