// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"fmt"
)


// hpb protocol version control
const (
	ProtocolV111    uint = 100 // match up protocol versions and messages versions
	SubProtocolV111 uint = 100 // Light Hpb Sub-protocol versions
)

/*
!!!every change of version should sub VersionID one number!!!
 */
const VersionID  uint64 = 0x0002
const (
	VersionMajor = 1        // Major version component of the current release
	VersionHardv = 0        // Hardware version component of the current release
	VersionMinor = 4        // Minor version component of the current release
	VersionPatch = 2        // Patch version component of the current release
	VersionMeta  = "stable" // Version metadata to append to the version string
)


// Version holds the textual version string.
var Version = func() string {
	v := fmt.Sprintf("%d.%d.%d.%d", VersionMajor, VersionHardv,VersionMinor, VersionPatch)
	if VersionMeta != "" {
		v += "-" + VersionMeta
	}
	return v
}()

func VersionWithCommit(gitCommit string) string {
	vsn := Version
	if len(gitCommit) >= 8 {
		vsn += "-" + gitCommit[:8]
	}
	return vsn
}
