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

package snapshots

import (
	//"bytes"
	//"sort"
	//"fmt"
	"encoding/json"
	"math/big"

	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	//"github.com/hpb-project/ghpb/common/constant"
	//"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	//"strconv"
	//"errors"
)


type CadNodeSnap struct {
	Number       uint64                     `json:"number"`      
	Hash         common.Hash                `json:"hash"`         
	CanAddresses []common.Address           `json:"cadaddresses"` 
	VotePercents map[common.Address]float64 `json:"VotePercents"` 
}


type CadWinner struct {
	NetworkId string         `json:"networkid"` // winner id
	Address   common.Address `json:"address"`   // winner address
	VoteIndex uint64         `json:"voteIndex"` // winner index
}

func NewCadNodeSnap(number uint64, hash common.Hash, addresses []common.Address) *CadNodeSnap {
	cadNodeSnap := &CadNodeSnap{
		Number:       number,
		Hash:         hash,
		CanAddresses: addresses,
	}
	return cadNodeSnap
}

func NewCadNodeSnapvote(number uint64, hash common.Hash, addresses []common.Address, VotePercents map[common.Address]float64) *CadNodeSnap {
	cadNodeSnap := &CadNodeSnap{
		Number:       number,
		Hash:         hash,
		CanAddresses: addresses,
		VotePercents: VotePercents,
	}
	return cadNodeSnap
}

// Get snap in community by elections,
func CalcuCadNodeSnap(db hpbdb.Database, number uint64, hash common.Hash, headers []*types.Header, chain consensus.ChainReader) (*CadNodeSnap, error) {
	addresses := []common.Address{}

	addressesmap := make(map[common.Address]string)

	// check all the headers
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 /* || headers[i+1].Hash() != headers[i].ParentHash */ {
			return nil, consensus.ErrInvalidVotingChain
		}
	}

	for _, header := range headers {
		addressesmap[header.ComdAddress] = "ok"
	}
	bigaddrtemp, _ := new(big.Int).SetString("0000000000000000000000000000000000000000", 16)
	addresstemp := common.BigToAddress(bigaddrtemp)

	var Cadvotepercents map[common.Address]float64
	Cadvotepercents = make(map[common.Address]float64)

	var votes float64 = 0
	for _, header := range headers {
		if header.CandAddress == addresstemp {
			continue
		}
		votes = votes + 1
		
		if old, ok := Cadvotepercents[header.CandAddress]; ok {
			Cadvotepercents[header.CandAddress] = old + 1
		} else {
			Cadvotepercents[header.CandAddress] = 1
		}
	}

	for k, _ := range addressesmap {
		if k != addresstemp {
			addresses = append(addresses, k)
		}
	}
	cadNodeSnapvote := NewCadNodeSnapvote(number, hash, addresses, Cadvotepercents)
	return cadNodeSnapvote, nil
}

// load the node snapshot
func LoadCadNodeSnap(db hpbdb.Database, hash common.Hash) (*CadNodeSnap, error) {
	blob, err := db.Get(append([]byte("codnodesnap-"), hash[:]...))
	if err != nil {
		log.Debug("Log Read Failed1:", "err:", err)
		return nil, err
	}
	cadNodeSnap := new(CadNodeSnap)
	if err := json.Unmarshal(blob, cadNodeSnap); err != nil {
		log.Debug("Log Read Failed2:", "err", err)
		return nil, err
	}
	return cadNodeSnap, nil
}

// store inserts the snapshot into the database.
func (c *CadNodeSnap) StoreCadNodeSnap(db hpbdb.Database, hash common.Hash) error {
	blob, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("codnodesnap-"), hash[:]...), blob)
}
