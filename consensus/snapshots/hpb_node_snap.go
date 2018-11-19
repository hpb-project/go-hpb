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
	"encoding/json"
	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/config"
	"math/big"
	//"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	"strconv"
	//"errors"
	"errors"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/log"
	"math"
	"math/rand"
)

type Tally struct {
	CandAddress common.Address `json:"candAddress"` // 通过投票的个数
	VoteNumbers *big.Int       `json:"voteNumbers"` // 通过投票的个数
	VoteIndexs  *big.Int       `json:"voteIndexs"`  // 通过投票的个数
	VotePercent *big.Int       `json:"votePercent"` // 通过投票的个数
}

type HpbNodeSnap struct {
	config   *config.PrometheusConfig
	sigcache *lru.ARCCache
	//Number  uint64                      `json:"number"`  // 生成快照的时间点
	CheckPointNum  uint64                      `json:"checkPointNum"`  // 最近的检查点
	CheckPointHash common.Hash                 `json:"checkPointHash"` // 生成快照的Block hash
	Signers        map[common.Address]struct{} `json:"signers"`        // 当前的授权用户
	Recents        map[uint64]common.Address   `json:"recents"`        // 最近签名者 spam
	Tally          map[common.Address]Tally    `json:"tally"`          // 目前的计票情况
}

// 为创世块使用
func NewHistorysnap(config *config.PrometheusConfig, sigcache *lru.ARCCache, number uint64, checkPointNum uint64, checkPointHash common.Hash, signersHash []common.Address) *HpbNodeSnap {
	snap := &HpbNodeSnap{
		config:   config,
		sigcache: sigcache,
		//Number:   number,
		CheckPointNum:  checkPointNum,
		CheckPointHash: checkPointHash,
		Signers:        make(map[common.Address]struct{}),
		Recents:        make(map[uint64]common.Address),
		Tally:          make(map[common.Address]Tally),
	}
	if number == 0 {
		for _, signerHash := range signersHash {
			snap.Signers[signerHash] = struct{}{}
		}
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
func (s *HpbNodeSnap) Store(hash common.Hash, db hpbdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("prometheus-"), hash[:]...), blob)
}

// 判断投票的有效性
func (s *HpbNodeSnap) ValidVote(address common.Address) bool {
	_, signer := s.Signers[address]
	return !signer
}

/*
// 投票池中添加
func (s *HpbNodeSnap) cast(candAddress common.Address, voteIndexs *big.Int) bool {
	//if !s.ValidVote(address) {
	//	return false
	//}

	//fmt.Println("length Test: ", len(s.Tally))

	if old, ok := s.Tally[candAddress]; ok {
		s.Tally[candAddress] = Tally{
	        VoteNumbers: old.VoteNumbers.Add(old.VoteNumbers, big.NewInt(1)),
	        VoteIndexs:  old.VoteIndexs.Add(old.VoteIndexs, voteIndexs),
	        VotePercent: old.VotePercent.Div(old.VoteIndexs, old.VoteNumbers),
	        CandAddress: candAddress,
		}
	} else {
		s.Tally[candAddress] = Tally{
			VoteNumbers: big.NewInt(1),
			VoteIndexs: voteIndexs,
			VotePercent: voteIndexs,
			CandAddress: candAddress,
		}
		//log.Info("new candAddress", "VoteNumbers", 1, "VoteIndexs", voteIndexs, "VotePercent", voteIndexs)
	}
	return true
}
*/

func (s *HpbNodeSnap) CalculateCurrentMinerorigin(number uint64, signer common.Address) bool {

	// 实际开发中，从硬件中获取
	//rand := rand.Uint64()

	signers, offset := s.GetHpbNodes(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return (number % uint64(len(signers))) == uint64(offset)
}

// 判断当前的次序
func (s *HpbNodeSnap) GetHardwareRandom(number uint64) string {
	// 实际开发中，从硬件中获取
	//TODO：硬件随机数调用,暂时不使用
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

func (s *HpbNodeSnap) GetOffsethw(number uint64, signer common.Address, headers []*types.Header) (uint64, uint64, map[common.Address]uint64) {
	signers, offset := s.GetHpbNodes(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}

	//从一部分区块头中确定签过名的高性能节点结合
	var headersignaddr = make(map[common.Address]uint64)
	for _, header := range headers {
		if _, ok := headersignaddr[header.Coinbase]; ok {
			headersignaddr[header.Coinbase] = headersignaddr[header.Coinbase] + 1
		} else {
			headersignaddr[header.Coinbase] = 1
		}
	}

	return uint64(offset), uint64(len(signers) - len(headersignaddr)), headersignaddr
}

// 已经授权的signers, 无需进行排序
func (s *HpbNodeSnap) GetHpbNodes() []common.Address {
	if len(s.Signers) == 0 {
		log.Error(" GetHpbNodes() HpbNodeSnap`s Signers is nil", "HpbNodeSnap.Signers", s.Signers)
		return nil
	}
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

func CalculateHpbSnap(index uint64, signatures *lru.ARCCache, config *config.PrometheusConfig, number uint64, latestCheckPointNum uint64, latestCheckPointHash common.Hash, chain consensus.ChainReader) (*HpbNodeSnap, error) {
	// Allow passing in no headers for cleaner code

	var headers []*types.Header

	// 开始获取之前的所有header
	var from = latestCheckPointNum - index*consensus.HpbNodeCheckpointInterval
	if from == 0 {
		from = from + 1
	}
	for i := from; i < latestCheckPointNum-100; i++ {
		loopcount := 0
	GETCOUNT:
		header := chain.GetHeaderByNumber(uint64(i))
		if header != nil {
			headers = append(headers, header)
		} else {
			if loopcount > 20 {
				return nil, errors.New("get hpb snap but missing header")
			}
			loopcount += 1
			goto GETCOUNT
			//log.Error("get hpb snap but missing header", "number", i)
		}
	}

	// 如果头部为空，直接返回
	if len(headers) == 0 {
		return nil, errors.New("Calculate Hpb Snap headers is 0 ")
	}

	// 检查所有的头部，检查连续性
	for i := 0; i < len(headers)-1; i++ {
		log.Debug("CalculateHpbSnap get headers", "header hash", headers[i].Hash(), "header number", headers[i].Number)
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 /*|| headers[i+1].Hash() != headers[i].ParentHash */ {
			return nil, consensus.ErrInvalidVotingChain
		}
	}

	for _, v := range headers {
		log.Debug("-------------CalculateHpbSnap--------------", "number", v.Number, "candaddress", common.Bytes2Hex(v.CandAddress[:]), "voteindex", v.VoteIndex)
	}

	//signers := make([]common.Address, 0, consensus.HpbNodenumber)
	snap := NewHistorysnap(config, signatures, number, latestCheckPointNum, latestCheckPointHash, nil)
	snap.Tally = make(map[common.Address]Tally)

	for _, header := range headers {

		VoteNumberstemp := big.NewInt(0)
		VoteIndexstemp := big.NewInt(0)
		VotePercenttemp := big.NewInt(0)
		//票的数量与性能之间的关系，获取票的数量表示在线时间长度，所以应该选择在线时间长性能又好的节点。
		if old, ok := snap.Tally[header.CandAddress]; ok {
			VoteNumberstemp.Add(old.VoteNumbers, big.NewInt(1))
			VoteIndexstemp.Add(old.VoteIndexs, header.VoteIndex)
			VotePercenttemp.Div(VoteIndexstemp, VoteNumberstemp)
			snap.Tally[header.CandAddress] = Tally{
				VoteNumbers: VoteNumberstemp,
				VoteIndexs:  VoteIndexstemp,
				VotePercent: VotePercenttemp,
				CandAddress: header.CandAddress,
			}
		} else {
			snap.Tally[header.CandAddress] = Tally{
				VoteNumbers: big.NewInt(1),
				VoteIndexs:  header.VoteIndex,
				VotePercent: header.VoteIndex,
				CandAddress: header.CandAddress,
			}
		}
	}

	var tallytemp []Tally
	for _, v := range snap.Tally {
		tallytemp = append(tallytemp, v)
	}

	for i := 0; i < len(snap.Tally); i++ {
		for j := 0; j < len(snap.Tally)-i-1; j++ {
			if bytes.Compare(tallytemp[j].CandAddress[:], tallytemp[j+1].CandAddress[:]) > 0 {
				tallytemp[j], tallytemp[j+1] = tallytemp[j+1], tallytemp[j]
			}
		}
	}

	for i := 0; i < len(snap.Tally); i++ {
		for j := 0; j < len(snap.Tally)-i-1; j++ {
			var switchcondition bool
			if number >= consensus.StageNumberIII {
				switchcondition = tallytemp[j].VotePercent.Cmp(tallytemp[j+1].VotePercent) < 0
			} else {
				switchcondition = tallytemp[j].VotePercent.Cmp(tallytemp[j+1].VotePercent) > 0
			}
			if switchcondition {
				tallytemp[j], tallytemp[j+1] = tallytemp[j+1], tallytemp[j]
			} else if (tallytemp[j].VotePercent.Cmp(tallytemp[j+1].VotePercent) == 0) && (bytes.Compare(tallytemp[j].CandAddress[:], tallytemp[j+1].CandAddress[:]) > 0) {
				tallytemp[j], tallytemp[j+1] = tallytemp[j+1], tallytemp[j]
			}
		}
	}

	finaltally := make([]common.Address, 0, len(tallytemp))
	for _, v := range tallytemp {
		finaltally = append(finaltally, v.CandAddress)
	}

	var hpnodeNO int
	if len(finaltally) >= consensus.HpbNodenumber {
		hpnodeNO = consensus.HpbNodenumber
		goto END

	} else {
		if index == consensus.Hpcalclookbackround+1 { //look back round is consensus.Hpcalclookbackround
			hpnodeNO = len(finaltally)
			goto END
		}

		index = index + 1
		if index < uint64(math.Floor(float64(number/consensus.HpbNodeCheckpointInterval))) { // 往前回溯
			//log.Error("-------- go back for last snap------------", "index", index)
			header := chain.GetHeaderByNumber(uint64(latestCheckPointNum - consensus.HpbNodeCheckpointInterval))
			latestCheckPointHash := header.Hash()
			snaptemp, err := CalculateHpbSnap(index, signatures, config, number-consensus.HpbNodeCheckpointInterval, latestCheckPointNum-consensus.HpbNodeCheckpointInterval, latestCheckPointHash, chain)
			if err != nil {
				log.Debug("recursive call CalculateHpbSnap fail", "err", err)
				hpnodeNO = len(finaltally)
				goto END
			}
			//get last snap hp nodes, set in map
			hpsmaptemp := make(map[common.Address]struct{})
			lastsnap := snaptemp.GetHpbNodes()
			for _, v := range lastsnap {
				hpsmaptemp[v] = struct{}{}
			}
			//delete tallytemp.CandAddress in the map
			for _, v := range finaltally {
				if _, ok := hpsmaptemp[v]; ok {
					delete(hpsmaptemp, v)
				}
			}

			if 0 == len(hpsmaptemp) {
				hpnodeNO = len(finaltally)
				goto END
			}
			//order the hpsmaptemp by put it into []common.address
			delhpsmap := make([]common.Address, len(hpsmaptemp))
			for key, _ := range hpsmaptemp {
				delhpsmap = append(delhpsmap, key)
			}

			//sort by addr
			if 1 < len(delhpsmap) {
				for i := 0; i < len(delhpsmap); i++ {
					for j := 0; j < len(delhpsmap)-i-1; j++ {
						if bytes.Compare(delhpsmap[j][:], delhpsmap[j+1][:]) > 0 {
							delhpsmap[j], delhpsmap[j+1] = delhpsmap[j+1], delhpsmap[j]
						}
					}
				}
			}

			//calc how many last snap hps needing to add the latest snap
			if len(finaltally)+len(delhpsmap) > consensus.HpbNodenumber {
				for i := 0; i < consensus.HpbNodenumber-len(finaltally); i++ {
					finaltally = append(finaltally, delhpsmap[i])
				}
			} else {
				for i := 0; i < len(delhpsmap); i++ {
					finaltally = append(finaltally, delhpsmap[i])
				}
			}

		}
		hpnodeNO = len(finaltally)
	}

END:
	for i := len(finaltally) - 1; i > len(finaltally)-hpnodeNO-1; i-- {
		snap.Signers[finaltally[i]] = struct{}{}
	}

	zeroaddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	if _, ok := snap.Signers[zeroaddr]; ok {
		delete(snap.Signers, zeroaddr)
	}

	return snap, nil
}

func GenRand(input []byte) (error, []byte) {

	if len(input) == 0 || input == nil {
		return errors.New("bad param"), nil
	}

	output := crypto.Keccak256(input)

	return nil, output
}
