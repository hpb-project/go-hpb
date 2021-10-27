// Copyright 2018 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2014 The go-ethereum Authors.
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
	ProtocolV111 uint = 100 // match up protocol versions and messages versions
)

/*
!!!every change of version should sub VersionID one number!!!
*/
const DAOVersion uint64 = 0x0005  // use a version to seperate network. 2021/5/5
const DAOVersion2 uint64 = 0x0007 // use a version to seperate network. 2021/10/21

const VersionID uint64 = 0x0006 // not used.

const HandShakeVersion uint64 = DAOVersion2 // current handshake proto version.

const HandShakeNoHIDVersion uint64 = 0x0006 // prepare for handshake not check hid.

const (
	VersionMajor = 1        // Major version component of the current release
	VersionHardv = 0        // Hardware version component of the current release
	VersionMinor = 8        // Minor version component of the current release
	VersionPatch = 1        // Patch version component of the current release
	VersionMeta  = "stable" // Version metadata to append to the version string
)

// Version holds the textual version string.
var Version = func() string {
	v := fmt.Sprintf("%d.%d.%d.%d", VersionMajor, VersionHardv, VersionMinor, VersionPatch)
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
