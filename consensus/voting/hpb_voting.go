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

package voting

import (
	"math"
	//"strconv"
	//"errors"
	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
)

func GetHpbNodeSnap(db hpbdb.Database, recents *lru.ARCCache, signatures *lru.ARCCache, config *config.PrometheusConfig, chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*snapshots.HpbNodeSnap, error) {

	//var (
	//	headers []*types.Header
	//snap    *snapshots.HpbNodeSnap
	//)
	//number = consensus.SetNumber(number)

	// 首次要创建
	if number == 0 {
		if snapg, err := GenGenesisSnap(db, recents, signatures, config, chain); err == nil {
			return snapg, err
		}
	}

	//前十轮不会进行投票，前10轮采用区块0时候的数据
	//先获取缓存，如果缓存中没有则获取数据库，为了提升速度
	//if(true){
	if number < consensus.HpbNodeCheckpointInterval {
		genesis := chain.GetHeaderByNumber(0)
		hash := genesis.Hash()
		// 从缓存中获取
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

	// 开始考虑10轮之后的情况，往前回溯3轮，以保证一致性。
	// 开始计算最后一次的确认区块
	latestCheckPointNumber := uint64(math.Floor(float64(number/consensus.HpbNodeCheckpointInterval))) * consensus.HpbNodeCheckpointInterval
	//log.Error("Current latestCheckPointNumber in hpb voting:",strconv.FormatUint(latestCheckPointNumber, 10))

	header := chain.GetHeaderByNumber(uint64(latestCheckPointNumber))
	latestCheckPointHash := header.Hash()

	if number%consensus.HpbNodeCheckpointInterval != 0 {
		if snapcd, err := GetDataFromCacheAndDb(db, recents, signatures, config, latestCheckPointHash); err == nil {
			//log.Info("##########################HPB_VOTING： Loaded voting Hpb Node Snap form cache and db", "number", number, "latestCheckPointNumber", latestCheckPointNumber)
			return snapcd, err
		} else {
			if snapa, err := snapshots.CalculateHpbSnap(uint64(1), signatures, config, number, latestCheckPointNumber, latestCheckPointHash, chain); err == nil {
				//log.Info("@@@@@@@@@@@@@@@@@@@@@@@@HPB_VOTING： CalculateHpbSnap", "number", number, "latestCheckPointNumber", latestCheckPointNumber)
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
			//log.Info("@@@@@@@@@@@@@@@@@@@@@@@@HPB_VOTING： CalculateHpbSnap", "number", number, "latestCheckPointNumber", latestCheckPointNumber)
			//新轮次计算完高性能节点立即更新节点类型
			//prometheus.SetNetNodeType(snapa)
			if err := StoreDataToCacheAndDb(recents, db, snapa, latestCheckPointHash); err != nil {
				return nil, err
			}
			return snapa, err
		} else {
			return nil, err
		}
	}
}

//生成初始化的区块
func GenGenesisSnap(db hpbdb.Database, recents *lru.ARCCache, signatures *lru.ARCCache, config *config.PrometheusConfig, chain consensus.ChainReader) (*snapshots.HpbNodeSnap, error) {

	genesis := chain.GetHeaderByNumber(0)
	signers := make([]common.Address, (len(genesis.Extra)-consensus.ExtraVanity-consensus.ExtraSeal)/common.AddressLength)
	for i := 0; i < len(signers); i++ {
		//log.Info("miner initialization", "i:",i)
		copy(signers[i][:], genesis.Extra[consensus.ExtraVanity+i*common.AddressLength:consensus.ExtraVanity+(i+1)*common.AddressLength])
	}
	snap := snapshots.NewHistorysnap(config, signatures, 0, 0, genesis.Hash(), signers)
	// 存入缓存和数据库中
	if err := StoreDataToCacheAndDb(recents, db, snap, genesis.Hash()); err != nil {
		return nil, err
	}
	log.Trace("Stored genesis voting getHpbNodeSnap to disk")
	return snap, nil
}

// 从数据库和缓存中获取数据
func GetDataFromCacheAndDb(db hpbdb.Database, recents *lru.ARCCache, signatures *lru.ARCCache, config *config.PrometheusConfig, hash common.Hash) (*snapshots.HpbNodeSnap, error) {

	if s, ok := recents.Get(hash); ok {
		snapcache := s.(*snapshots.HpbNodeSnap)
		return snapcache, nil
	} else {
		// 从数据库中获取
		if snapdb, err := snapshots.LoadHistorysnap(config, signatures, db, hash); err == nil {
			//log.Trace("Prometheus： Loaded voting getHpbNodeSnap form disk", "number", number, "hash", hash)
			return snapdb, nil
		} else {
			return nil, err
		}
	}
	return nil, nil
}

//将数据存入到缓存和数据库中
func StoreDataToCacheAndDb(recents *lru.ARCCache, db hpbdb.Database, snap *snapshots.HpbNodeSnap, latestCheckPointHash common.Hash) error {
	// 存入到缓存中
	recents.Add(latestCheckPointHash, snap)
	// 存入数据库
	err := snap.Store(latestCheckPointHash, db)
	if err != nil {
		log.Trace("StoreDataToCacheAndDb hpb fail", "err", err)
	}

	return err
}
