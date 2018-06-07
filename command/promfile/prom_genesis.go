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
	"hash/fnv"
	//"encoding/hex"


	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/core"
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/common/constant"
)


// 基于用户的输入产生genesis
func (p *prometh) makeGenesis() {
	// Construct a default genesis block
	genesis := &core.Genesis{
		Timestamp:  uint64(time.Now().Unix()),
		GasLimit:   params.GenesisGasLimit.Uint64(),
		Difficulty: big.NewInt(1048576),
		Alloc:      make(core.GenesisAlloc),
		Config: &params.ChainConfig{
		},
	}
	// Figure out which consensus engine to choose
	fmt.Println()
	fmt.Println("Welcome to HPB consensus engine file maker")

	//choice := p.read()

	genesis.Difficulty = big.NewInt(1)
	genesis.Config.Prometheus = &params.PrometheusConfig{
		Period: 15,
		Epoch:  30000,
		Random: "0",
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
			continue
		}
		if len(signers) > 0 {
			break
		}
	}

	/*
	if address := p.readAddress(); address != nil {
		signers = append(signers, *address)
	}
	*/


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
	fmt.Println("please input random number")
	//var signersHash []common.AddressHash

	//randStr := p.read();

	var randStrs []string

	for {
		if randStr := p.read(); randStr != "" {
			randStrs = append(randStrs, randStr)
			continue
		}
		if len(randStrs) > 0 {
			break
		}
	}

	genesis.Config.Prometheus.Random = randStrs[0]

	address_hashes := make([]common.AddressHash, (len(signers)/common.AddressLength)*common.AddressHashLength)

	for i, signer := range signers {
		fmt.Println("randStrs: %s", randStrs[len(signers)-i-1],"signer:",signer.Hex())
		address_hashes = append(address_hashes, common.BytesToAddressHash(p.fnv_hash([]byte(signer.Str() + randStrs[len(signers)-i-1]))))
	}

	genesis.ExtraHash = make([]byte, 32 + len(address_hashes) * common.AddressHashLength + 65)

	for i, address_hash := range address_hashes {
		copy(genesis.ExtraHash[32+ i*common.AddressHashLength:], address_hash[:])
	}
	fmt.Println()
	fmt.Println("Which accounts should be pre-funded? (advisable at least one)")
	for {
		// Read the address of the account to fund
		if address := p.readAddress(); address != nil {
			genesis.Alloc[*address] = core.GenesisAccount{
				Balance: new(big.Int).Lsh(big.NewInt(1), 256-7), // 2^256 / 128 (allow many pre-funds without balance overflows)
			}
			continue
		}
		break
	}

	// Add a batch of precompile balances to avoid them getting deleted
	//for i := int64(0); i < 256; i++ {
	//	genesis.Alloc[common.BigToAddress(big.NewInt(i))] = core.GenesisAccount{Balance: big.NewInt(1)}
	//}
	fmt.Println()

	// Query the user for some custom extras
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

	// All done, store the genesis and flush to disk

	p.conf.genesis = genesis
}


// Fowler–Noll–Vo is a non-cryptographic hash function created by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo.
//The basis of the FNV hash algorithm was taken from an idea sent as reviewer comments to the
//IEEE POSIX P1003.2 committee by Glenn Fowler and Phong Vo in 1991. In a subsequent ballot round,
//Landon Curt Noll improved on their algorithm. In an email message to Landon,
//they named it the Fowler/Noll/Vo or FNV hash.
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
func (p *prometh) fnv_hash(data ...[]byte) []byte {
	d := fnv.New32()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
	//return hex.EncodeToString(d.Sum(nil))
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
		// Save whatever genesis configuration we currently have
		fmt.Println()
		fmt.Printf("Which file to save the genesis into? (default = %s.json)\n", p.network)

		//fmt.Printf("%s", p.conf.genesis)

		out, _ := json.MarshalIndent(p.conf.genesis, "", "  ")

		//fmt.Printf("%s", out)

		if err := ioutil.WriteFile(p.readDefaultString(fmt.Sprintf("%s.json", p.network)), out, 0644); err != nil {
			log.Error("Failed to save genesis file", "err", err)
		}
		log.Info("Exported existing genesis block")

	default:
		log.Error("That's not something I can do")
	}
}