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

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	//"github.com/hpb-project/go-hpb/network/p2p"
	//"github.com/hpb-project/go-hpb/network/p2p/discover"
	"bytes"
	"errors"
)

// 获取候选选举的快照
func GetCadNodeSnap(db hpbdb.Database, recents *lru.ARCCache, chain consensus.ChainReader, number uint64, hash common.Hash) (*snapshots.CadNodeSnap, error) {

	hpbAddressMap := make(map[common.Address]string)

	if snap, err := GetHpbNodeSnap(db, recents, nil, nil, chain, number, hash, nil); err == nil {
		// 去重
		for _, signer := range snap.GetHpbNodes() {
			hpbAddressMap[signer] = "ok"
		}
	} else {
		return nil, err
	}

	// reward on Cad nodes
	var Cadvotepercents map[common.Address]float64
	Cadvotepercents = make(map[common.Address]float64)

	//addresses := []common.Address{}
	if csnap, err := GetAllCadNodeSnap(db, recents, chain, number, hash); err == nil {
		if csnap != nil {
			for caddress, votepercent := range csnap.VotePercents {
				if hpbAddressMap[caddress] != "ok" {
					Cadvotepercents[caddress] = votepercent
				}
			}
		}
	} else {
		return nil, err
	}

	addresses := []common.Address{}
	if csnap, err := GetAllCadNodeSnap(db, recents, chain, number, hash); err == nil {
		if csnap != nil {
			for _, caddress := range csnap.CanAddresses {
				if hpbAddressMap[caddress] != "ok" {
					addresses = append(addresses, caddress)
				}
			}
		}
	} else {
		return nil, err
	}
	// 排序
	for i := 0; i < len(addresses); i++ {
		for j := i + 1; j < len(addresses); j++ {
			if bytes.Compare(addresses[i][:], addresses[j][:]) > 0 {
				addresses[i], addresses[j] = addresses[j], addresses[i]
			}
		}
	}
	cadNodeSnap := snapshots.NewCadNodeSnapvote(number, hash, addresses, Cadvotepercents)

	return cadNodeSnap, nil
}

// 获取候选选举的快照
func GetAllCadNodeSnap(db hpbdb.Database, recents *lru.ARCCache, chain consensus.ChainReader, number uint64, hash common.Hash) (*snapshots.CadNodeSnap, error) {
	//业务逻辑
	var (
		headers []*types.Header
	)

	//if number > consensus.StageNumberIII {
	//	consensus.CadNodeCheckpointInterval = 400
	//}

	gobacknum := 200
	if number > consensus.StageNumberIII {
		if number <= consensus.CadNodeCheckpointInterval+200 {
			return nil, nil
		}
		gobacknum = gobacknum + 200
	} else {
		// 开始直接返回nil
		if number <= consensus.CadNodeCheckpointInterval {
			return nil, nil
		}
	}

	//不在投票点开始获取数据库中的内容
	latestCheckPointNumber := uint64(math.Floor(float64(number/consensus.CadNodeCheckpointInterval))) * consensus.CadNodeCheckpointInterval
	header := chain.GetHeaderByNumber(uint64(latestCheckPointNumber))
	latestCadCheckPointHash := header.Hash()

	if number%consensus.CadNodeCheckpointInterval != 0 {
		if snapcd, err := GetCandDataFromCacheAndDb(db, recents, latestCadCheckPointHash); err == nil {
			return snapcd, err
		} else {
			// 开始获取之前的所有header
			for i := latestCheckPointNumber - uint64(gobacknum); i < latestCheckPointNumber-100; i++ {
				count := 0
			GetAllCadNodeSnaploop:
				header := chain.GetHeaderByNumber(uint64(i))
				if header != nil {
					headers = append(headers, header)
				} else {
					if count > 20 {
						//log.Debug("loop 20 times, return err")
						return nil, errors.New("GetAllCadNodeSnap get headers loop 20 times, return err")
					}
					log.Debug("----------number%consensus.CadNodeCheckpointInterval != 0----------before CalcuCadNodeSnap get header err----------------------", "number", i)
					count = count + 1
					goto GetAllCadNodeSnaploop
				}
			}

			if snapa, err := snapshots.CalcuCadNodeSnap(db, number, latestCadCheckPointHash, headers, chain); err == nil {
				log.Debug("HPB_CAD： Loaded voting Cad Node Snap form cache and db", "number", number, "latestCheckPointNumber", latestCheckPointNumber)
				if err := StoreCanDataToCacheAndDb(recents, db, snapa, latestCadCheckPointHash); err != nil {
					return nil, err
				}
				return snapa, err
			} else {
				return nil, err
			}
		}
	} else {
		// 开始获取之前的所有header
		for i := latestCheckPointNumber - uint64(gobacknum); i < latestCheckPointNumber-100; i++ {
			header := chain.GetHeaderByNumber(uint64(i))
			if header != nil {
				headers = append(headers, header)
			}
		}

		if snapa, err := snapshots.CalcuCadNodeSnap(db, number, latestCadCheckPointHash, headers, chain); err == nil {
			log.Debug("HPB_CAD： Loaded voting cad Node Snap form cache and db", "number", number, "latestCheckPointNumber", latestCheckPointNumber)
			if err := StoreCanDataToCacheAndDb(recents, db, snapa, latestCadCheckPointHash); err != nil {
				return nil, err
			}
			return snapa, err
		} else {
			return nil, err
		}
	}
}

// 从数据库和缓存中获取数据
func GetCandDataFromCacheAndDb(db hpbdb.Database, recents *lru.ARCCache, hash common.Hash) (*snapshots.CadNodeSnap, error) {
	key := append(hash[:], common.Hex2Bytes("cand")...)
	if s, ok := recents.Get(common.Bytes2Hex(key)); ok {
		cadNodeSnap := s.(*snapshots.CadNodeSnap)
		return cadNodeSnap, nil
	}
	if snapdb, err := snapshots.LoadCadNodeSnap(db, hash); err == nil {
		//log.Trace("Prometheus： Loaded voting getHpbNodeSnap form disk", "number", number, "hash", hash)
		return snapdb, nil
	} else {
		return nil, err
	}
	return nil, nil
}

//将数据存入到缓存和数据库中
func StoreCanDataToCacheAndDb(recents *lru.ARCCache, db hpbdb.Database, snap *snapshots.CadNodeSnap, latestCheckPointHash common.Hash) error {
	// 存入到缓存中
	key := append(latestCheckPointHash[:], common.Hex2Bytes("cand")...)
	recents.Add(common.Bytes2Hex(key), snap)
	// 存入数据库
	err := snap.StoreCadNodeSnap(db, latestCheckPointHash)
	if err != nil {
		log.Info("--------------cadidate StoreCanDataToCacheAndDb error--------------------------", "err", err)
	}

	return err
}
