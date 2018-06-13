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
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/ghpb/consensus/snapshots"
)

type API struct {
	chain  consensus.ChainReader
	prometheus *Prometheus
}

// 获取最新的的快照
func (api *API) GetHistorysnap(number *rpc.BlockNumber) (*snapshots.HpbNodeSnap, error) {
	var header *types.Header
	header = api.GetLatestBlockHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	return api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

func (api *API) GetHistorysnapAtHash(hash common.Hash) (*snapshots.HpbNodeSnap, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	return api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

func (api *API) GetHpbNodes(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	// 获取到最新的header
	
	var header *types.Header
	header = api.GetLatestBlockHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	snap, err := api.prometheus.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.GetSigners(), nil
}

//跟根据区块号，获取最新的区块头
func (api *API) GetLatestBlockHeader(number *rpc.BlockNumber) (header *types.Header){
	//var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	return header
}

// 获取候选节点信息
func (api *API) GetCandidateNodes(number *rpc.BlockNumber) ([]common.Address, error) {
	//获取候选节点
	return nil, nil
}

// 获取候选社区选举节点信息
func (api *API) GetCommunityNodes(number *rpc.BlockNumber) ([]common.Address, error) {
	//获取社区选举结果
	return nil, nil
}

func (api *API) GetPrivateRandom() (string) {	
	//rand := api.chain.GetRandom()
	//if(rand ==""){
		//rand = getUniqueRandom()
	//}
	return  getUniqueRandom(api.chain)
}

func (api *API) Proposals() map[common.Address]bool {
	api.prometheus.lock.RLock()
	defer api.prometheus.lock.RUnlock()

	proposals := make(map[common.Address]bool)
	for address, auth := range api.prometheus.proposals {
		proposals[address] = auth
	}
	return proposals
}

func (api *API) Propose(address common.Address, confRand string, auth bool) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()
    //address :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + confRand)))
	//fmt.Printf("address%s",address.String())
	api.prometheus.proposals[address] = auth
}

// 改变作废的方式
func (api *API) Discard(address common.Address,  confRand string) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()
    //address :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(address.Str() + confRand)))
	delete(api.prometheus.proposals, address)
}
