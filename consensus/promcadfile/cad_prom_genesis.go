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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
)


type CadWinner struct {
    NetworkId     string 
	Address       common.Address
	VoteIndex     uint64 
}


// 基于用户的输入产生genesis
func (p *prometh) makeGenesis() {
	
	fmt.Println()
	fmt.Println("Welcome to HPB consensus engine file maker")
    fmt.Println("Please input the networkid one by one")
    
	var networkids []string
    var cNodes []CadWinner
	for {
		if networkid := p.read(); networkid != "" {
			networkids = append(networkids, networkid)
			continue
		}
		if len(networkids) > 0 {
			break
		}
	}

	fmt.Println()
	fmt.Println("Please input the corresponding address, the same order with above networkid")
	for i := 0; i < len(networkids); i++{
		if address := p.readAddress(); address != nil {
			cNodes = append(cNodes,CadWinner{NetworkId: networkids[i], Address: *address,VoteIndex:uint64(0)})
			continue
		}
	}
	p.conf.genesis = cNodes
}


// manageGenesis permits the modification of chain configuration parameters in
// a genesis config and the export of the entire genesis spec.
func (p *prometh) manageGenesis() {
	// Figure out whether to modify or export the genesis
	fmt.Println()
	fmt.Println(" 1. Export genesis configuration")

	choice := p.read()
	switch {
	case choice == "1":
		fmt.Println()
		fmt.Printf("Which file to save the genesis into? (default = %s.json)\n", p.network)

		//out, _ := json.Marshal(p.conf.genesis)
		
		out, _ := json.MarshalIndent(p.conf.genesis, "", "  ")

		fmt.Printf("%s", out)

		if err := ioutil.WriteFile(p.readDefaultString(fmt.Sprintf("%s.json", p.network)), out, 0644); err != nil {
			log.Error("Failed to save genesis file", "err", err)
		}
		log.Info("Exported existing genesis block")

	default:
		log.Error("That's not something I can do")
	}
}


