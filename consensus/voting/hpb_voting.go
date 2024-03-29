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

package voting

import (
	"errors"
	"math"
	"math/big"
	"strings"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/account/abi"
	"github.com/hpb-project/go-hpb/blockchain/state"
	hpbdb "github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	"github.com/hpb-project/go-hpb/vmcore"
	"github.com/hpb-project/go-hpb/vmcore/vm"
)

func GetHpbNodeSnap(db hpbdb.Database, recents *lru.ARCCache, signatures *lru.ARCCache, config *config.PrometheusConfig, chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*snapshots.HpbNodeSnap, error) {

	if number == 0 {
		if snapg, err := GenGenesisSnap(db, recents, signatures, config, chain); err == nil {
			return snapg, err
		}
	}

	// no voting in the first ten blocks
	if number < consensus.HpbNodeCheckpointInterval {
		genesis := chain.GetHeaderByNumber(0)
		hash := genesis.Hash()

		if snapcd, err := GetDataFromCacheAndDb(db, recents, signatures, config, hash); err == nil {
			log.Debug("HPB_VOTING： Loaded voting Hpb Node Snap form cache and db", "number", number, "hash", hash)
			return snapcd, err
		} else {
			if snapg, err := GenGenesisSnap(db, recents, signatures, config, chain); err == nil {
				log.Debug("HPB_VOTING： Loaded voting Hpb Node Snap form genesis snap", "number", number, "hash", hash)
				return snapg, err
			}
		}
	}

	// after 10 blocks, retrieve the newest three rounds
	latestCheckPointNumber := uint64(math.Floor(float64(number/consensus.HpbNodeCheckpointInterval))) * consensus.HpbNodeCheckpointInterval

	header := chain.GetHeaderByNumber(uint64(latestCheckPointNumber))
	latestCheckPointHash := header.Hash()

	if number%consensus.HpbNodeCheckpointInterval != 0 {
		if snapcd, err := GetDataFromCacheAndDb(db, recents, signatures, config, latestCheckPointHash); err == nil {
			log.Debug("HPB_VOTING： Loaded voting Hpb Node Snap form cache and db", "number", number, "latestCheckPointNumber", latestCheckPointNumber)
			return snapcd, err
		} else {
			if snapa, err := snapshots.CalculateHpbSnap(uint64(1), signatures, config, number, latestCheckPointNumber, latestCheckPointHash, chain); err == nil {
				if err := StoreDataToCacheAndDb(recents, db, snapa, latestCheckPointHash); err != nil {
					return nil, err
				}
				return snapa, err
			} else {
				return nil, err
			}
		}
	} else {
		if snapa, err := snapshots.CalculateHpbSnap(uint64(1), signatures, config, number, latestCheckPointNumber, latestCheckPointHash, chain); err == nil {

			if err := StoreDataToCacheAndDb(recents, db, snapa, latestCheckPointHash); err != nil {
				return nil, err
			}
			return snapa, err
		} else {
			return nil, err
		}
	}
}

func GenGenesisSnap(db hpbdb.Database, recents *lru.ARCCache, signatures *lru.ARCCache, config *config.PrometheusConfig, chain consensus.ChainReader) (*snapshots.HpbNodeSnap, error) {

	genesis := chain.GetHeaderByNumber(0)
	extra, err := types.BytesToExtraDetail(genesis.Extra)
	if err != nil {
		log.Error("GenGenesisSnap", "bytesToExtraDetail failed, error", err)
		return nil, err
	}
	signers := extra.GetNodes()
	snap := snapshots.NewHistorysnap(config, signatures, 0, 0, genesis.Hash(), signers)

	if err := StoreDataToCacheAndDb(recents, db, snap, genesis.Hash()); err != nil {
		return nil, err
	}
	log.Trace("Stored genesis voting getHpbNodeSnap to disk")
	return snap, nil
}

func GetDataFromCacheAndDb(db hpbdb.Database, recents *lru.ARCCache, signatures *lru.ARCCache, config *config.PrometheusConfig, hash common.Hash) (*snapshots.HpbNodeSnap, error) {

	if s, ok := recents.Get(hash); ok {
		snapcache := s.(*snapshots.HpbNodeSnap)
		return snapcache, nil
	} else {
		if snapdb, err := snapshots.LoadHistorysnap(config, signatures, db, hash); err == nil {
			return snapdb, nil
		} else {
			return nil, err
		}
	}
}

func StoreDataToCacheAndDb(recents *lru.ARCCache, db hpbdb.Database, snap *snapshots.HpbNodeSnap, latestCheckPointHash common.Hash) error {

	recents.Add(latestCheckPointHash, snap)

	err := snap.Store(latestCheckPointHash, db)
	if err != nil {
		log.Trace("StoreDataToCacheAndDb hpb fail", "err", err)
	}

	return err
}

func GetAllBoeNodes_Election(chain consensus.ChainReader, header *types.Header, state *state.StateDB) ([]common.Address, error) {
	fechaddr := common.HexToAddress(consensus.NodeAddress)

	vmenv := vm.NewEVMForGeneration(&config.GetHpbConfigInstance().BlockChain, header, header.Coinbase, state,
		func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() }, 1000)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.NewgetAllBoeNodesABI))

	//get bootnode info "addr,cid,hid"
	packres, _ := fechABI.Pack(consensus.NewgetAllBoeNodes)
	result, err := vmenv.InnerCall(vmcore.AccountRef(header.Coinbase), fechaddr, packres)
	if err != nil {
		return nil, err
	} else {
		if result == nil || len(result) == 0 {
			return nil, errors.New("return bootnode info result is nil or length is 0")
		}
	}
	var out struct {
		Coinbases []common.Address
	}
	err = fechABI.UnpackIntoInterface(&out, consensus.NewgetAllBoeNodes, result)

	if err != nil {
		return nil, errors.New("GetAllBoeNodes_Election Unpack error")
	}
	return out.Coinbases, nil
}

func GetAllVorter_Election(chain consensus.ChainReader, header *types.Header, state *state.StateDB, boeaddr common.Address) ([]common.Address, []uint64, error) {

	fechaddr := common.HexToAddress(consensus.VoteAddress)
	vmenv := vm.NewEVMForGeneration(&config.GetHpbConfigInstance().BlockChain, header, header.Coinbase, state,
		func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() }, 1000)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.NewfetchVoteInfoForCandidateABI))

	packres, _ := fechABI.Pack(consensus.NewfetchVoteInfoForCandidate, boeaddr)
	result, err := vmenv.InnerCall(vmcore.AccountRef(header.Coinbase), fechaddr, packres)
	if err != nil {
		return nil, nil, err
	} else {
		if result == nil || len(result) == 0 {
			return nil, nil, errors.New("return bootnode info result is nil or length is 0")
		}
	}
	var out struct {
		Coinbases []common.Address
		nums      []uint64
	}

	if len(result) > 64 {
		base := 64
		index := 1
		length := (len(result)/32 - 2) / 2 // coinbase length
		for index < length {
			out.Coinbases = append(out.Coinbases, common.BytesToAddress(result[base+index*32:base+index*32+32]))
			index = index + 1
		}
		index = index + 1
		for index < 2*length {
			num := new(big.Int).SetBytes(result[base+index*32 : base+index*32+32])
			out.nums = append(out.nums, num.Uint64())
			index = index + 1
		}
	}
	return out.Coinbases, out.nums, nil
}
