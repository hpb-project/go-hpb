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
// along with the go-hpb. If not, see <http://wwp.gnu.org/licenses/>.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"github.com/hpb-project/go-hpb/common/log"
)

// makeWizard creates and returns a new prometh prometh.
func makeCadPrometh(network string) *prometh {
	return &prometh{
		network: network,
		conf:  config{},
		in:       bufio.NewReader(os.Stdin),
	}
}

// run displays some useful infos to the user, starting on the journey of
// setting up a new or managing an existing HPB private network.
func (p *prometh) run() {
	fmt.Println("+-----------------------------------------------------------+")
	fmt.Println("| Welcome to prometh cadfile, your HPB private network manager |")
	fmt.Println("|                                                           |")
	fmt.Println("| This tool lets you create a new HPB network down to  |")
	fmt.Println("| the genesis block, bootnodes, miners and ethstats servers |")
	fmt.Println("| without the hassle that it would normally entail.         |")
	fmt.Println("|                                                           |")
	fmt.Println("| Prometh uses SSH to dial in to remote servers, and builds |")
	fmt.Println("| its network components out of Docker containers using the |")
	fmt.Println("| docker-compose toolset.                                   |")
	fmt.Println("+-----------------------------------------------------------+")
	fmt.Println()

	// Make sure we have a good network name to work with	fmt.Println()
	if p.network == "" {
		fmt.Println("Please specify a network name to administer (no spaces, please)")
		for {
			p.network = p.readString()
			if !strings.Contains(p.network, " ") {
				fmt.Printf("Sweet, you can set this via --network=%s next time!\n\n", p.network)
				break
			}
			log.Error("I also like to live dangerously, still no spaces")
		}
	}
	log.Info("Administering HPB network", "name", p.network)

	p.conf.path = filepath.Join(os.Getenv("HOME"), ".prometh", p.network)

	for{
		fmt.Println()
		fmt.Println("What would you like to do? (default = stats)")
		fmt.Println(" 1. Configure new genesis")
		fmt.Println(" 2. Manage existing genesis")

		choice := p.read()
		switch {
		case choice == "" || choice == "1":
			p.makeGenesis()
		case choice == "2":
			if len(p.conf.genesis) == 0 {
				log.Error("There is no genesis to manage")
			} else {
				p.manageGenesis()
			}
		default:
			log.Error("That's not something I can do")
		}
	}
}
