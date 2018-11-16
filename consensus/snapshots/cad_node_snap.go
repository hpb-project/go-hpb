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

//定义结构体
type CadNodeSnap struct {
	Number       uint64                     `json:"number"`       // 生成快照的时间点
	Hash         common.Hash                `json:"hash"`         // 生成快照的Block hash
	CanAddresses []common.Address           `json:"cadaddresses"` // 当前的授权用户
	VotePercents map[common.Address]float64 `json:"VotePercents"` //候选节点获得的投票的百分比
}

//定义结构体
type CadWinner struct {
	NetworkId string         `json:"networkid"` // 获胜者的网络ID
	Address   common.Address `json:"address"`   // 获胜者的地址
	VoteIndex uint64         `json:"voteIndex"` // 获胜者的指标总和
}

// 创建对象
func NewCadNodeSnap(number uint64, hash common.Hash, addresses []common.Address) *CadNodeSnap {
	cadNodeSnap := &CadNodeSnap{
		Number:       number,
		Hash:         hash,
		CanAddresses: addresses,
	}
	return cadNodeSnap
}

// 创建对象
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

	// 检查所有的头部，检查连续性
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 /* || headers[i+1].Hash() != headers[i].ParentHash */ {
			return nil, consensus.ErrInvalidVotingChain
		}
	}

	for _, header := range headers {
		addressesmap[header.ComdAddress] = "ok"
		//log.Info("new headers", "headers", header.Number)
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
		//获取区块中的每个候选节点收到的投票数量，包括了高性能节点
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

//加载快照，直接去数据库中读取
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
