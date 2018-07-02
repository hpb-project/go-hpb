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
	//"math/big"
	
	"github.com/hpb-project/ghpb/common"
	//"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/storage"
	//"github.com/hpb-project/ghpb/common/constant"
	//"github.com/hashicorp/golang-lru"
	//"github.com/hpb-project/ghpb/common/log"
	//"github.com/hpb-project/ghpb/consensus"

	//"strconv"
	//"errors"
)



//定义结构体
type CadNodeSnap struct {
	Number  uint64                      `json:"number"`  // 生成快照的时间点
	Hash    common.Hash                 `json:"hash"`    // 生成快照的Block hash
	CadWinners  []CadWinner `json:"winners"`   // 当前的授权用户
}

//定义结构体
type CadWinner struct {
	NetworkId     string `json:"networkid"`             // 获胜者的网络ID
	Address       common.Address `json:"address"`               // 获胜者的地址
	VoteIndex     uint64 `json:"voteIndex"`             // 获胜者的指标总和
}

// 创建对象
func NewCadNodeSnap(number uint64, hash common.Hash,CadWinners  []CadWinner) CadNodeSnap {
	cadNodeSnap := CadNodeSnap{
		Number:   number,
		Hash:     hash,
		CadWinners: CadWinners,
	}
	return cadNodeSnap
}

//加载快照，直接去数据库中读取
func LoadCadNodeSnap(db hpbdb.Database, hash common.Hash) (*CadNodeSnap, error) {
	blob, err := db.Get(append([]byte("cadnodesnap-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	cadNodeSnap := new(CadNodeSnap)
	if err := json.Unmarshal(blob, cadNodeSnap); err != nil {
		return nil, err
	}
	return cadNodeSnap, nil
}

// store inserts the snapshot into the database.
func (s *CadNodeSnap) Store(db hpbdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("codnodesnap-"), s.Hash[:]...), blob)
}
