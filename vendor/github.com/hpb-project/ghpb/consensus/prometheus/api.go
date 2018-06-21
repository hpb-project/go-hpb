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
	"fmt"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/network/rpc"
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

func (api *API) GetPrivateRandom() (string) {	
	//rand := api.chain.GetRandom()
	//if(rand ==""){
		//rand = getUniqueRandom()
	//}
	
	return  getUniqueRandom(api.chain)
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

func (api *API) Propose(address common.Address, confRand string, auth bool) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()
   
    addressHash :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + confRand)))
	
	fmt.Printf("addressHash%s",addressHash.String())

	api.prometheus.proposals[addressHash] = auth
}

// 改变作废的方式
func (api *API) Discard(address common.Address,  confRand string) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()
    addressHash :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + confRand)))
	delete(api.prometheus.proposals, addressHash)
}
