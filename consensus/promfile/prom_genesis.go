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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"time"
	//"encoding/hex"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
)


// 基于用户的输入产生genesis
func (p *prometh) makeGenesis() {
	
	genesis := &bc.Genesis{
		//VoteIndex:  uint64(0),
		Timestamp:  uint64(time.Now().Unix()),
		GasLimit:   config.GenesisGasLimit.Uint64(),
		Difficulty: big.NewInt(1048576),
		Alloc:      make(bc.GenesisAlloc),
		Config: &config.ChainConfig{
		},
	}
	// Figure out which consensus engine to choose
	fmt.Println()
	fmt.Println("Welcome to HPB consensus engine file maker")

	//choice := p.read()

	genesis.Difficulty = big.NewInt(1)
	genesis.Config.Prometheus = &config.PrometheusConfig{
		Period: 15,
		Epoch:  30000,
	}
	fmt.Println()
	fmt.Println("How many seconds should blocks take? (default = 15)")
	genesis.Config.Prometheus.Period = uint64(p.readDefaultInt(15))

	fmt.Println()
	fmt.Println("How many blocks should voting epoch be ? (default = 30000)")
	genesis.Config.Prometheus.Epoch = uint64(p.readDefaultInt(30000))

	// We also need the initial list of signers
	fmt.Println()
	fmt.Println("Which accounts are allowed to seal? (initialise miner addresses)")

	var signers []common.Address

	for {
		if address := p.readAddress(); address != nil {
			signers = append(signers, *address)
			//genesis.CandAddress = *address
			continue
		}
		if len(signers) > 0 {
			break
		}
	}

	// Sort the signers and embed into the extra-data section
	for i := 0; i < len(signers); i++ {
		for j := i + 1; j < len(signers); j++ {
			if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
				signers[i], signers[j] = signers[j], signers[i]
			}
		}
	}

	//genesis.ExtraData = make([]byte, 32+len(signers)*common.AddressLength+65)
	genesis.ExtraData = make([]byte, 32+len(signers)*common.AddressLength+65)
	for i, signer := range signers {
		copy(genesis.ExtraData[32+i*common.AddressLength:], signer[:])
	}
   
	fmt.Println()
	fmt.Println("Which accounts should be pre-funded? (advisable at least one)")
	for {
		// Read the address of the account to fund
		if address := p.readAddress(); address != nil {
			genesis.Alloc[*address] = bc.GenesisAccount{
				Balance: new(big.Int).Lsh(big.NewInt(1), 3), // 2^256 / 128 (allow many pre-funds without balance overflows)
			}
			continue
		}
		break
	}
	
	
	fmt.Println()
	fmt.Println("Please input the initialization hardware random")
	
	genesis.HardwareRandom = make([]byte, 32)
	if hardwareRandom := p.readAddress(); hardwareRandom != nil {
		copy(genesis.HardwareRandom[0:], hardwareRandom[:])
	}
	
	fmt.Println()
	fmt.Println("Specify your chain/network ID if you want an explicit one (default = random)")
	genesis.Config.ChainId = new(big.Int).SetUint64(uint64(p.readDefaultInt(rand.Intn(65536))))

	fmt.Println()
	fmt.Println("Anything fun to embed into the genesis block? (max 32 bytes)")

	extra := p.read()
	if len(extra) > 32 {
		extra = extra[:32]
	}
	genesis.ExtraData = append([]byte(extra), genesis.ExtraData[len(extra):]...)

	p.conf.genesis = genesis
}

func (p *prometh) manageGenesis() {
	// Figure out whether to modify or export the genesis
	fmt.Println()
	fmt.Println(" 1. Export genesis configuration")

	choice := p.read()
	switch {
	case choice == "1":
		fmt.Println()
		fmt.Printf("Which file to save the genesis into? (default = %s.json)\n", p.network)
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