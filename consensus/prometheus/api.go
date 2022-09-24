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

package prometheus

import (
	"errors"
	"math/big"

	bc "github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	"github.com/hpb-project/go-hpb/consensus/voting"
	"github.com/hpb-project/go-hpb/network/rpc"
)

type API struct {
	chain      consensus.ChainReader
	prometheus *Prometheus
}

func (api *API) GetHpbNodeSnap(number *rpc.BlockNumber) (*snapshots.HpbNodeSnap, error) {
	var header *types.Header
	header = api.GetLatestBlockHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	return voting.GetHpbNodeSnap(api.prometheus.db, api.prometheus.recents, api.prometheus.signatures, api.prometheus.config, api.chain, header.Number.Uint64(), header.Hash(), nil)
}

func (api *API) GetCandidateNodeSnap(number *rpc.BlockNumber) (*snapshots.CadNodeSnap, error) {
	var header *types.Header
	header = api.GetLatestBlockHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	return voting.GetCadNodeSnap(api.prometheus.db, api.prometheus.recents, api.chain, header.Number.Uint64(), header.ParentHash)
}

func (api *API) GetHpbNodes(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)

	var header *types.Header
	header = api.GetLatestBlockHeader(number)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	snap, err := voting.GetHpbNodeSnap(api.prometheus.db, api.prometheus.recents, api.prometheus.signatures, api.prometheus.config, api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.GetHpbNodes(), nil
}

func (api *API) GetElectedMiner(number *rpc.BlockNumber) (common.Address, error) {
	var bigblock = new(big.Int)
	if number == nil || *number == rpc.LatestBlockNumber {
		bigblock = api.chain.CurrentHeader().Number
	} else {
		bigblock = new(big.Int).SetInt64(number.Int64())
	}
	miner := bc.GetBlockElectedMiner(api.prometheus.db, bigblock)
	return miner, nil
}

func (api *API) GetCandidateNodes(number *rpc.BlockNumber) (snapshots.CadNodeSnap, error) {
	var header *types.Header
	header = api.GetLatestBlockHeader(number)
	if header == nil {
		return snapshots.CadNodeSnap{}, consensus.ErrUnknownBlock
	}
	cadNodeSnap, _ := voting.GetCadNodeSnap(api.prometheus.db, api.prometheus.recents, api.chain, header.Number.Uint64(), header.ParentHash)
	return *cadNodeSnap, nil
}

func (api *API) GetHpbNodeSnapAtHash(hash common.Hash) (*snapshots.HpbNodeSnap, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, consensus.ErrUnknownBlock
	}
	return voting.GetHpbNodeSnap(api.prometheus.db, api.prometheus.recents, api.prometheus.signatures, api.prometheus.config, api.chain, header.Number.Uint64(), header.Hash(), nil)
}

func (api *API) GetLatestBlockHeader(number *rpc.BlockNumber) (header *types.Header) {
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	return header
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
	api.prometheus.proposals[address] = auth
}

func (api *API) Discard(address common.Address, confRand string) {
	api.prometheus.lock.Lock()
	defer api.prometheus.lock.Unlock()
	delete(api.prometheus.proposals, address)
}

func (api *API) GetAllHpbNodes(blocknum *rpc.BlockNumber) ([]common.Address, error) {
	blockchain := api.chain
	var header *types.Header
	if blocknum == nil || *blocknum == rpc.LatestBlockNumber {
		header = blockchain.CurrentHeader()
	} else {
		header = blockchain.GetHeaderByNumber(uint64(blocknum.Int64()))
	}
	if header == nil {
		return nil, errors.New("get header error")
	}
	state, err := blockchain.StateAt(header.Root)
	if err != nil {
		return nil, errors.New("get state error")
	}
	if header.Number.Uint64() > consensus.StageNumberElection {
		return voting.GetAllBoeNodes_Election(blockchain, header, state)
	}

	return api.GetHpbNodes(blocknum)
}

func (api *API) GetAllVoters(boeaddr common.Address, blocknum *rpc.BlockNumber) ([]common.Address, []*big.Int, error) {
	blockchain := api.chain
	var header *types.Header
	if blocknum == nil || *blocknum == rpc.LatestBlockNumber {
		header = blockchain.CurrentHeader()
	} else {
		header = blockchain.GetHeaderByNumber(uint64(blocknum.Int64()))
	}
	if header == nil {
		return nil, nil, errors.New("get header error")
	}
	state, err := blockchain.StateAt(header.Root)
	if err != nil {
		return nil, nil, errors.New("get state error")
	}
	if header.Number.Uint64() > consensus.StageNumberElection {
		return voting.GetAllVorter_Election(blockchain, header, state, boeaddr)
	}

	return voting.GetOlderVorter(blockchain, header, state, boeaddr)
}
