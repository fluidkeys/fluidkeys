// Copyright 2018 Paul Furley and Ian Drysdale
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

package status

// ByActionType implements sort.Interface for []KeyAction based on
// the SortOrder field.
type ByActionType []KeyAction

func (a ByActionType) Len() int           { return len(a) }
func (a ByActionType) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByActionType) Less(i, j int) bool { return a[i].SortOrder() < a[j].SortOrder() }
