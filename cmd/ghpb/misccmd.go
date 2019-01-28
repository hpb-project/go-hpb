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

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"


	"gopkg.in/urfave/cli.v1"
	"github.com/hpb-project/go-hpb/cmd/utils"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/network/p2p"
)

var (
	versionCommand = cli.Command{
		Action:    utils.MigrateFlags(version),
		Name:      "version",
		Usage:     "Print version numbers",
		ArgsUsage: " ",
		Category:  "MISCELLANEOUS COMMANDS",
		Description: `
The output of this command is supposed to be machine-readable.
`,
	}
	licenseCommand = cli.Command{
		Action:    utils.MigrateFlags(license),
		Name:      "license",
		Usage:     "Display license information",
		ArgsUsage: " ",
		Category:  "MISCELLANEOUS COMMANDS",
	}
)

func version(ctx *cli.Context) error {

	boehandle := boe.BoeGetInstance()
	err := boehandle.Init()
	var boeversion = ""

	if err != nil {
		boeversion = "Have no boe"
	} else {
		version, e := boehandle.GetVersion()
		if e != nil {
			boeversion = "Get failed"
		} else {
			boeversion = version.VersionString()
		}
	}

	fmt.Println(strings.Title(clientIdentifier))
	fmt.Println("Version:", config.Version)
	if gitCommit != "" {
		fmt.Println("Git Commit:", gitCommit)
	}

	fmt.Println("BOE Firmware:", boeversion)
	fmt.Println("Architecture:", runtime.GOARCH)
	fmt.Println("Protocol Versions:", p2p.ProtocolVersions)
	fmt.Println("Network Id:", config.DefaultConfig.NetworkId)
	fmt.Println("Go Version:", runtime.Version())
	fmt.Println("Operating System:", runtime.GOOS)
	fmt.Printf("GOPATH=%s\n", os.Getenv("GOPATH"))
	fmt.Printf("GOROOT=%s\n", runtime.GOROOT())
	return nil
}

func license(_ *cli.Context) error {
	fmt.Println(`Geth is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Geth is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ghpb. If not, see <http://www.gnu.org/licenses/>.
`)
	return nil
}
