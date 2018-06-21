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
	"bytes"
	//"sort"
	//"fmt"
	"encoding/json"
	
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/storage"
	"github.com/hpb-project/ghpb/common/constant"
	"github.com/hashicorp/golang-lru"
	//"github.com/hpb-project/ghpb/common/log"
	 
	"github.com/hpb-project/ghpb/consensus"

	//"strconv"

)

//type *params.PrometheusConfig struct {
//	Period uint64 `json:"period"` // 打包区块间隔期
//	Epoch  uint64 `json:"epoch"`  // 充值投票点时间
//}

type Vote struct {
	Signer    common.AddressHash `json:"signerHash"`    // 可以投票的Signer
	Block     uint64         `json:"block"`     // 开始计票的区块
	AddressHash   common.AddressHash `json:"address"`   // 操作的账户
	Authorize bool           `json:"authorize"` // 投票的建议
}

type Tally struct {
	Authorize bool `json:"authorize"` // 投票的想法，加入还是剔除
	Votes     int  `json:"votes"`     // 通过投票的个数
}

type Historysnap struct {
	config   *params.PrometheusConfig 
	sigcache *lru.ARCCache       
	
	Number  uint64                      `json:"number"`  // 生成快照的时间点
	Hash    common.Hash                 `json:"hash"`    // 生成快照的Block hash
	Signers map[common.AddressHash]struct{} `json:"signers"` // 当前的授权用户
	//SignersHash map[common.AddressHash]struct{} `json:"signersHash"` // 当前的授权用户
	Recents map[uint64]common.AddressHash   `json:"recents"` // 最近签名者 spam
	Votes   []*Vote                     `json:"votes"`   // 最近的投票
	Tally   map[common.AddressHash]Tally    `json:"tally"`   // 目前的计票情况
}

// 为创世块使用
func newHistorysnap(config *params.PrometheusConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signersHash []common.AddressHash) *Historysnap {
	snap := &Historysnap{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Signers:  make(map[common.AddressHash]struct{}),
		//SignersHash:  make(map[common.AddressHash]struct{}),
		Recents:  make(map[uint64]common.AddressHash),
		Tally:    make(map[common.AddressHash]Tally),
	}
	
	for _, signerHash := range signersHash {
		snap.Signers[signerHash] = struct{}{}
	}
	
	//for _, signerhash := range signersHash {
	//	snap.SignersHash[signerhash] = struct{}{}
	//}
	
	return snap
}

func loadHistorysnap(config *params.PrometheusConfig, sigcache *lru.ARCCache, db hpbdb.Database, hash common.Hash) (*Historysnap, error) {
	blob, err := db.Get(append([]byte("prometheus-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Historysnap)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Historysnap) store(db hpbdb.Database) error {
	blob, err := json.Marshal(s)
	
	//log.Error("cuo wu le a", "err", err)


	if err != nil {
		return err
	}
	return db.Put(append([]byte("prometheus-"), s.Hash[:]...), blob)
}

// 深度拷贝
func (s *Historysnap) copy() *Historysnap {
	cpy := &Historysnap{
		config:   s.config,
		sigcache: s.sigcache,
		
		Number:   s.Number,
		Hash:     s.Hash,
		Signers:  make(map[common.AddressHash]struct{}),
		//SignersHash:  make(map[common.AddressHash]struct{}),
		Recents:  make(map[uint64]common.AddressHash),
		Votes:    make([]*Vote, len(s.Votes)),
		Tally:    make(map[common.AddressHash]Tally),
	}
	for signerHash := range s.Signers {
		cpy.Signers[signerHash] = struct{}{}
	}
	
	//for signerHash := range s.SignersHash {
	//	cpy.SignersHash[signerHash] = struct{}{}
	//}
	
	for block, signerHash := range s.Recents {
		cpy.Recents[block] = signerHash
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	copy(cpy.Votes, s.Votes)

	return cpy
}

// 判断投票的有效性
func (s *Historysnap) validVote(address common.AddressHash, authorize bool) bool {
	_, signerHash := s.Signers[address]
	//如果已经在，应该删除，如果不在申请添加才合法
	return (signerHash && !authorize) || (!signerHash && authorize)
}

/*
// 判断投票的有效性
func (s *Historysnap) validVoteHash(addressHash common.AddressHash, authorizeHash bool) bool {
	_, signerHash := s.SignersHash[addressHash]
	//如果已经在，应该删除，如果不在申请添加才合法
	return (signerHash && !authorizeHash) || (!signerHash && authorizeHash)
}
*/
// 投票池中添加
func (s *Historysnap) cast(address common.AddressHash, authorize bool) bool {

	if !s.validVote(address, authorize) {
		return false
	}
	
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// 从投票池中删除
func (s *Historysnap) uncast(address common.AddressHash, authorize bool) bool {

	tally, ok := s.Tally[address]
	if !ok {
		return false
	}

	if tally.Authorize != authorize {
		return false
	}

	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}



// 判断当前的次序
func (s *Historysnap) inturn(number uint64, signerHash common.AddressHash) bool {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signerHash {
		offset++
	}
	return (number % uint64(len(signers))) == uint64(offset)
}


// 判断当前的次序
func (s *Historysnap) getOffset(number uint64, signerHash common.AddressHash) uint64 {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signerHash {
		offset++
	}
	return uint64(offset)
}

// 已经授权的signers, 无需进行排序
func (s *Historysnap) signers() []common.AddressHash {
	signers := make([]common.AddressHash, 0, len(s.Signers))
	for signerHash := range s.Signers {
		signers = append(signers, signerHash)
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


// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Historysnap) apply(headers []*types.Header,chain consensus.ChainReader) (*Historysnap, error) {
	// Allow passing in no headers for cleaner code
	
	// 如果头部为空，直接返回
	if len(headers) == 0 {
		return s, nil
	}

	// 检查所有的头部，检查连续性
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	// 回溯到上一个阶段，在下一轮的第一个进行投票
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	
	// 创建一个新的快照
	snap := s.copy()

    //迭代头文件
	for _, header := range headers {
		// Remove any votes on checkpoint blocks
		// 初始化
		number := header.Number.Uint64()
		
		//到了投票点会进行重置
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.AddressHash]Tally)
		}
		// Delete the oldest signerHash from the recent list to allow it signing again
		// 删除Recents中已经保存的，允许从新签名，删除老的
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// 获取当前header是由谁打包的，从签名中还原
		signer, err := ecrecover(header, s.sigcache)

		//log.Info("current head", "Random",header.Random,"number",number)

		signerHash :=  common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(signer.Str() + header.Random)))
		
		if err != nil {
			return nil, err
		}
		
		// signerHash 是否在Signers中，如果不在则返回错误
		if _, ok := snap.Signers[signerHash]; !ok {
			return nil, errUnauthorized
		}
		
		// signerHash 是否在 recent中，说明已经签过名
		// 防止连续放入
		/*
		for _, recent := range snap.Recents {
			if recent == signerHash {
				return nil, errUnauthorized
			}
		}
		*/
		// 根据块号放入
		snap.Recents[number] = signerHash

		// Header authorized, discard any previous votes from the signerHash
		// 确认删除，删除之前的投票,删除signer之前的投票
		for i, vote := range snap.Votes {
			// 签名人已经在Signer，而且已经对当前的区块签了名字
			
			if vote.Signer == signerHash && vote.AddressHash == header.CoinbaseHash {
				// Uncast the vote from the cached tally
				// 从票池进行处理
				snap.uncast(vote.AddressHash, vote.Authorize)

				// Uncast the vote from the chronological list
				// 删除投票
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
				break // only one vote allowed
			}
		}
		// 开始新的投票
		var authorize bool
		switch {
		case bytes.Equal(header.Nonce[:], nonceAuthVote):
			authorize = true
		case bytes.Equal(header.Nonce[:], nonceDropVote):
			authorize = false
		default:
			return nil, errInvalidVote
		}
		
		//将投票结果进行放入到计票池子中
		if snap.cast(header.CoinbaseHash, authorize) {
			snap.Votes = append(snap.Votes, &Vote{
				Signer:    signerHash,
				Block:     number,
				AddressHash:   header.CoinbaseHash,
				Authorize: authorize,
			})
		}

		// 如果投票通过，则更新 signers
		if tally := snap.Tally[header.CoinbaseHash]; tally.Votes > len(snap.Signers)/2 {
			// 如果投票被批准，则放入
			if tally.Authorize {
				snap.Signers[header.CoinbaseHash] = struct{}{}
			} else {
				delete(snap.Signers, header.CoinbaseHash)
				// Signer list shrunk, delete any leftover recent caches
				// Signer 移动，删除左边的最新caches
				if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
					delete(snap.Recents, number-limit)
				}
				// Discard any previous votes the deauthorized signerHash cast
				// 删除
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Signer == header.CoinbaseHash {
						// Uncast the vote from the cached tally
						snap.uncast(snap.Votes[i].AddressHash, snap.Votes[i].Authorize)

						// Uncast the vote from the chronological list
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			// 删除之前的投票
			for i := 0; i < len(snap.Votes); i++ {
				if snap.Votes[i].AddressHash == header.CoinbaseHash {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.CoinbaseHash)
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

