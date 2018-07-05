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
	"bytes"
	"sort"
	"fmt"
	"encoding/json"
	"math/big"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hashicorp/golang-lru"
	//"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"

	"strconv"
	//"errors"
	"math/rand"
	"github.com/hpb-project/go-hpb/common/log"
)

type Tally struct {
	CandAddress    common.Address  `json:"candAddress"`     // 通过投票的个数
	VoteNumbers    *big.Int  `json:"voteNumbers"`     // 通过投票的个数
	VoteIndexs     *big.Int   `json:"voteIndexs"`     // 通过投票的个数
	VotePercent    *big.Int  `json:"votePercent"`     // 通过投票的个数
}

type HpbNodeSnap struct {
	config   *config.PrometheusConfig 
	sigcache *lru.ARCCache       
	Number  uint64                      `json:"number"`  // 生成快照的时间点
	Hash    common.Hash                 `json:"hash"`    // 生成快照的Block hash
	Signers map[common.Address]struct{} `json:"signers"` // 当前的授权用户
	Recents map[uint64]common.Address   `json:"recents"` // 最近签名者 spam
	Tally   map[common.Address]Tally    `json:"tally"`   // 目前的计票情况
}

// 为创世块使用
func NewHistorysnap(config *config.PrometheusConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signersHash []common.Address) *HpbNodeSnap {
	snap := &HpbNodeSnap{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
		Tally:    make(map[common.Address]Tally),
	}
	for _, signerHash := range signersHash {
		snap.Signers[signerHash] = struct{}{}
	}
	return snap
}

//加载快照，直接去数据库中读取
func LoadHistorysnap(config *config.PrometheusConfig, sigcache *lru.ARCCache, db hpbdb.Database, hash common.Hash) (*HpbNodeSnap, error) {
	blob, err := db.Get(append([]byte("prometheus-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(HpbNodeSnap)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache
	return snap, nil
}

// store inserts the snapshot into the database.
func (s *HpbNodeSnap) Store(db hpbdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("prometheus-"), s.Hash[:]...), blob)
}


// 判断投票的有效性
func (s *HpbNodeSnap) ValidVote(address common.Address) bool {
	_, signer := s.Signers[address]
	return !signer
}


// 投票池中添加
func (s *HpbNodeSnap) cast(candAddress common.Address, voteIndexs *big.Int) bool {
	//if !s.ValidVote(address) {
	//	return false
	//}
	if old, ok := s.Tally[candAddress]; ok {
		log.Info("Add new candAddress", "VoteNumbers", old.VoteNumbers, "VoteIndexs", old.VoteIndexs, "VoteNumbers", old.VoteNumbers)
        old.VoteNumbers.Add(old.VoteNumbers, big.NewInt(1))
        old.VoteIndexs.Add(old.VoteIndexs, voteIndexs)
        old.VotePercent.Div(old.VoteIndexs, old.VoteNumbers)
        old.CandAddress = candAddress
	} else {
		log.Info("First add new candAddress", "VoteNumbers", old.VoteNumbers, "VoteIndexs", old.VoteIndexs, "VoteNumbers", old.VoteNumbers)
		s.Tally[candAddress] = Tally{
			VoteNumbers: big.NewInt(1),
			VoteIndexs: voteIndexs,
			VotePercent: voteIndexs,
			CandAddress: candAddress,
		}
	}
	return true
}

// 判断当前的次序
func (s *HpbNodeSnap) CalculateCurrentMiner(number uint64, signer common.Address) bool {
	
	// 实际开发中，从硬件中获取
	rand := rand.Uint64()
	
	signers, offset := s.GetHpbNodes(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return (rand % uint64(len(signers))) == uint64(offset)
}

// 判断当前的次序
func (s *HpbNodeSnap) GetHardwareRandom(number uint64) string {
	// 实际开发中，从硬件中获取
	rand := rand.Uint64()
	str := strconv.FormatUint(rand, 10)
	return str
}

// 判断当前的次序
func (s *HpbNodeSnap) GetOffset(number uint64, signer common.Address) uint64 {
	signers, offset := s.GetHpbNodes(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return uint64(offset)
}

// 已经授权的signers, 无需进行排序
func (s *HpbNodeSnap) GetHpbNodes() []common.Address {
	signers := make([]common.Address, 0, len(s.Signers))
	for signer := range s.Signers {
		signers = append(signers, signer)
	}
	
	for i := 0; i < len(signers); i++ {
		for j := i + 1; j < len(signers); j++ {
			if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
				signers[i], signers[j] = signers[j], signers[i]
			}
		}
	}
	return signers
}

func  CalculateHpbSnap(signatures *lru.ARCCache,config *config.PrometheusConfig, headers []*types.Header,chain consensus.ChainReader) (*HpbNodeSnap, error) {
	// Allow passing in no headers for cleaner code
	
	// 如果头部为空，直接返回
	if len(headers) == 0 {
		return nil, nil
	}

	// 检查所有的头部，检查连续性
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, consensus.ErrInvalidVotingChain
		}
	}
	
	signers := make([]common.Address,4)
	
	snap := NewHistorysnap(config, signatures, 0, headers[len(headers)-1].Hash(), signers)
	
	snap.Tally = make(map[common.Address]Tally)
	
	//开始投票
	for _, header := range headers {
		snap.cast(header.CandAddress, header.VoteIndex);
	}
	
	var keys []float64
	indexTally := make(map[float64]Tally,len(snap.Tally))
	
	for _, v := range snap.Tally{
		indexTally[float64(v.VotePercent.Uint64())] = v;
		keys = append(keys,float64(v.VotePercent.Uint64()))
	}
	
	sort.Float64s(keys) //对结果今昔那个排序
	
	fmt.Println("Sorted Test: ", sort.Float64sAreSorted(keys))
	
	//设置config长度
	for i := 0; i < 4; i++ {
		fmt.Printf("#####%.f\n", keys[len(keys)-i-1])
		if cands, ok := indexTally[keys[len(keys)-i-1]]; ok {
			snap.Signers[cands.CandAddress] = struct{}{}
		}
	}

	//等待完善
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	return snap, nil
}

