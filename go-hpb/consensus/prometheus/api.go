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

package prometheus

import (
	//"fmt"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/core/types"
	"github.com/hpb-project/go-hpb/rpc"
	//	"github.com/hpb-project/go-hpb/core"
	//"math"
	"math/rand"

)


type API struct {
	chain  consensus.ChainReader
	prometheus *Prometheus
}

func (api *API) GetHistorysnap(number *rpc.BlockNumber) (*Historysnap, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

func (api *API) GetHistorysnapAtHash(hash common.Hash) (*Historysnap, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.AddressHash, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

func (api *API) GetSignersAtHash(hash common.Hash) ([]common.AddressHash, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

func (api *API) Proposals() map[common.AddressHash]bool {
	api.prometheus.lock.RLock()
	defer api.prometheus.lock.RUnlock()

	proposals := make(map[common.AddressHash]bool)
	for addressHash, auth := range api.prometheus.proposals {
		proposals[addressHash] = auth
	}
	return proposals
}

func (api *API) Propose(address common.Address, auth bool) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()
   
    //rand :=  pre_random().String()
    
    //addressHash.Str()
    //fmt.Printf("Hex: %s ", addressHash.Hex())
    //fmt.Printf("sha3: %s ", rand)
    //fmt.Printf("Hex + sha3: %s ", addressHash.Hex() + rand)
    //fmt.Printf("sha3: %s ", api.prometheus.Keccak512([]byte(rand)))
    
   // phash :=  api.prometheus.fnv_hash([]byte(addressHash.Hex() + rand))
   // fmt.Printf("fnv: %s", phash)
    
    //设置随机数
    //api.prometheus.randomStr = rand
    //设置随机后的Hash
    //api.prometheus.signerHash = common.BytesToAddressHash(phash)
    // 将Hash 推入到proposalsHash中
    //[]byte
    //api.prometheus.proposalsHash[common.BytesToAddressHash(phash)] = auth
    
    random := api.prometheus.config.Random
    
    confRand := string(random[rand.Intn(len(random))])
    
    //addressHash :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + api.prometheus.config.Random)))
    addressHash :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + confRand)))

    /*
	number := api.chain.CurrentHeader().Number.Uint64()
	
	if(number > api.prometheus.config.Epoch){
		voteNum := uint64(math.Floor(float64(number/(api.prometheus.config.Epoch))))*(api.prometheus.config.Epoch)
		stored := core.GetCanonicalHash(api.prometheus.db, voteNum)
		fmt.Printf("wwwwwwwww %d + eeeeeeeeeeeeeeeeee %s",number,stored.Hex())
		addressHash =  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + stored.Hex())))
	}
	fmt.Printf("wwwwwwwww %d + @@@@@@@@@@@@@@@@@@@@@@ %s",number,addressHash)
    */
	api.prometheus.proposals[addressHash] = auth
}

// 改变作废的方式
func (api *API) Discard(address common.Address) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()

    addressHash :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + api.prometheus.config.Random)))
	delete(api.prometheus.proposals, addressHash)
}
