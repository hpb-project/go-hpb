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
	"os"
	"os/signal"
	"strings"

	"github.com/hpb-project/go-hpb/cmd/utils"
	"github.com/hpb-project/go-hpb/common/console"
	"github.com/hpb-project/go-hpb/network/rpc"
	"gopkg.in/urfave/cli.v1"
	"github.com/hpb-project/go-hpb/config"
)

var (
	consoleFlags = []cli.Flag{utils.JSpathFlag, utils.ExecFlag, utils.PreloadJSFlag}

	consoleCommand = cli.Command{
		Action:   utils.MigrateFlags(localConsole),
		Name:     "console",
		Usage:    "Start an interactive JavaScript environment",
		Flags:    append(append(append(nodeFlags, rpcFlags...), consoleFlags...)),
		Category: "CONSOLE COMMANDS",
		Description: `
The Geth console is an interactive shell for the JavaScript runtime environment
which exposes a node admin interface as well as the Ðapp JavaScript API.`,
	}

	attachCommand = cli.Command{
		Action:    utils.MigrateFlags(remoteConsole),
		Name:      "attach",
		Usage:     "Start an interactive JavaScript environment (connect to node)",
		ArgsUsage: "[endpoint]",
		Flags:     append(consoleFlags, utils.DataDirFlag),
		Category:  "CONSOLE COMMANDS",
		Description: `
The Geth console is an interactive shell for the JavaScript runtime environment
which exposes a node admin interface as well as the Ðapp JavaScript API.
This command allows to open a console on a running ghpb node.`,
	}

	javascriptCommand = cli.Command{
		Action:    utils.MigrateFlags(ephemeralConsole),
		Name:      "js",
		Usage:     "Execute the specified JavaScript files",
		ArgsUsage: "<jsfile> [jsfile...]",
		Flags:     append(nodeFlags, consoleFlags...),
		Category:  "CONSOLE COMMANDS",
		Description: `
The JavaScript VM exposes a node admin interface as well as the Ðapp`,
	}
)

// localConsole starts a new ghpb node, attaching a JavaScript console to it at the
// same time.
func localConsole(ctx *cli.Context) error {
	// Create and start the node based on the CLI flags
	cfg := MakeConfigNode(ctx)
	node, err := createNode(cfg)
	if err != nil {
		utils.Fatalf("Failed to create node")
		return err
	}
	startNode(ctx, node, cfg)
	defer node.Stop()

	// Attach to the newly started node and start the JavaScript console
	client, err := node.Attach(rpc.RpcMgrInst().IpcHandle())
	if err != nil {
		utils.Fatalf("Failed to attach to the inproc ghpb: %v", err)
	}
	configvar := console.Config{
		DataDir: utils.MakeDataDir(ctx),
		DocRoot: ctx.GlobalString(utils.JSpathFlag.Name),
		Client:  client,
		Preload: utils.MakeConsolePreloads(ctx),
	}

	consolevar, err := console.New(configvar)
	if err != nil {
		utils.Fatalf("Failed to start the JavaScript console: %v", err)
	}
	defer consolevar.Stop(false)

	// If only a short execution was requested, evaluate and return
	if script := ctx.GlobalString(utils.ExecFlag.Name); script != "" {
		consolevar.Evaluate(script)
		return nil
	}
	// Otherwise print the welcome screen and enter interactive mode
	consolevar.Welcome()
	consolevar.Interactive()

	return nil
}

// remoteConsole will connect to a remote ghpb instance, attaching a JavaScript
// console to it.
func remoteConsole(ctx *cli.Context) error {
	// Attach to a remotely running ghpb instance and start the JavaScript console
	client, err := dialRPC(ctx.Args().First())
	if err != nil {
		utils.Fatalf("Unable to attach to remote ghpb: %v", err)
	}
	configvar := console.Config{
		DataDir: utils.MakeDataDir(ctx),
		DocRoot: ctx.GlobalString(utils.JSpathFlag.Name),
		Client:  client,
		Preload: utils.MakeConsolePreloads(ctx),
	}

	consolevar, err := console.New(configvar)
	if err != nil {
		utils.Fatalf("Failed to start the JavaScript console: %v", err)
	}
	defer consolevar.Stop(false)

	if script := ctx.GlobalString(utils.ExecFlag.Name); script != "" {
		consolevar.Evaluate(script)
		return nil
	}

	// Otherwise print the welcome screen and enter interactive mode
	consolevar.Welcome()
	consolevar.Interactive()

	return nil
}

// dialRPC returns a RPC client which connects to the given endpoint.
// The check for empty endpoint implements the defaulting logic
// for "ghpb attach" and "ghpb monitor" with no argument.
func dialRPC(endpoint string) (*rpc.Client, error) {
	if endpoint == "" {
		endpoint = config.DefaultIPCEndpoint(clientIdentifier)
	} else if strings.HasPrefix(endpoint, "rpc:") || strings.HasPrefix(endpoint, "ipc:") {
		// Backwards compatibility with ghpb < 1.5 which required
		// these prefixes.
		endpoint = endpoint[4:]
	}
	return rpc.Dial(endpoint)
}

// ephemeralConsole starts a new ghpb node, attaches an ephemeral JavaScript
// console to it, executes each of the files specified as arguments and tears
// everything down.
func ephemeralConsole(ctx *cli.Context) error {
	// Create and start the node based on the CLI flags
	cfg := MakeConfigNode(ctx)
	node, err := createNode(cfg)
	if err != nil {
		utils.Fatalf("Failed to create node")
		return err
	}
	startNode(ctx, node, cfg)
	defer node.Stop()

	// Attach to the newly started node and start the JavaScript console
	client, err := node.Attach(rpc.RpcMgrInst().IpcHandle())
	if err != nil {
		utils.Fatalf("Failed to attach to the inproc ghpb: %v", err)
	}
	configvar := console.Config{
		DataDir: utils.MakeDataDir(ctx),
		DocRoot: ctx.GlobalString(utils.JSpathFlag.Name),
		Client:  client,
		Preload: utils.MakeConsolePreloads(ctx),
	}

	consolevar, err := console.New(configvar)
	if err != nil {
		utils.Fatalf("Failed to start the JavaScript console: %v", err)
	}
	defer consolevar.Stop(false)

	// Evaluate each of the specified JavaScript files
	for _, file := range ctx.Args() {
		if err = consolevar.Execute(file); err != nil {
			utils.Fatalf("Failed to execute %s: %v", file, err)
		}
	}
	// Wait for pending callbacks, but stop for Ctrl-C.
	abort := make(chan os.Signal, 1)
	signal.Notify(abort, os.Interrupt)

	go func() {
		<-abort
		os.Exit(0)
	}()
	consolevar.Stop(true)

	return nil
}
