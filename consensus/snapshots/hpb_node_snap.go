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
	"github.com/hpb-project/go-hpb/common/log"
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

// 判断当前的次序
func (s *HpbNodeSnap) CalculateCurrentMiner(number uint64, signer common.Address, chain consensus.ChainReader, header *types.Header) (bool, error) {

	// 实际开发中，从硬件中获取
	//rand := rand.Uint64()
	//TODO：硬件随机数相关，直接使用的低16字节对应的uint64对uint64(len(snap.Signers)取余确定,每次都从区块头中获取轮次内的signer集合，然后作排除操作后，在进行确定offset
	var currentIndex uint64
	signers := s.GetHpbNodes() //hpb节点，是排序过的
	var hpbsignersmap = make(map[common.Address]int)
	for offset, signeradrr := range signers {
		hpbsignersmap[signeradrr] = offset //offset为signer对应的offset
	}

	randBigInt := new(big.Int)
	if len(header.HardwareRandom) == 0 {
		log.Error("---------------CalculateCurrentMiner header.HardwareRandom----------", "len(header.HardwareRandom)", "0")
	}
	randBigInt.SetBytes(header.HardwareRandom)

	var partheadersstart uint64
	//如果number为1，则直接对原来的singers集合进行取余操作获取offset，这里根绝signers的数组下标作为对应signer的offset，
	if number%uint64(len(signers)) == 1 {
		if offset, ok := hpbsignersmap[signer]; ok && uint64(offset) == randBigInt.Uint64()%uint64(len(hpbsignersmap)) {
			return true, nil
		} else {
			return false, nil
		}
	} else { //如果不为1，则作如下处理
		partheadersstart = number - (number-1)%uint64(len(signers))
		//log.Error("before GetOffsethw partheadersstart","partheadersstart",partheadersstart, "len(s.Signers)", len(s.Signers))
	}

	var partheaders = make([]*types.Header, (number-1)%uint64(len(signers)))
	//offset := s.GetOffset(number, signer) //当前的位置

	var gethbynumcount int = 0
	//获取部分区块头，为了获取这些区块头中都那些signer进行了签名操作
	for i := partheadersstart; i < number; i++ {
	loop:
		partheaders[i-partheadersstart] = chain.GetHeaderByNumber(i)
		gethbynumcount = gethbynumcount + 1
		if partheaders[i-partheadersstart] == nil || &partheaders[i-partheadersstart].Coinbase == nil {
			log.Error("before GetOffsethw---------------chain.GetHeaderByNumber(i) &partheaders[i-partheadersstart].Coinbase == nil", "number", number)
			if gethbynumcount > 20 {
				return false, errors.New("cannot get header by chain.GetHeaderByNumber")
			}
			goto loop
		}
	}
	//log.Error("before GetOffsethw number","number",number, "len partheaders", len(partheaders))
	//mappartheaders,是这些区块头中signer的map，包含了对应signer签署区块的个数，暂时没什么用
	_, _, mappartheaders := s.GetOffsethw(number, signer, partheaders)

	for recentsignaddr, _ := range mappartheaders {
		if _, ok := mappartheaders[recentsignaddr]; ok { //因为mappartheaders这个map的alue是int，所以只有通过这种办法才能确定这个key是否真正存在
			delete(hpbsignersmap, recentsignaddr) //存在就在之前保存的高性能节点的map中删除这个key，剩下的就是在这一轮次还没有签过名的高性能节点map
		} //hpbsignersmap 是高性能节点的差集
	}
	currentIndex = randBigInt.Uint64() % uint64(len(hpbsignersmap)) //挖矿的机器位置

	_, ok := hpbsignersmap[signer] //在未签名的高性能map中查找对应的signer是否存在
	//差集合放入数组，然后进行排序，
	hpbsignerarray := make([]common.Address, 0, len(hpbsignersmap))
	for addr, _ := range hpbsignersmap {
		hpbsignerarray = append(hpbsignerarray, addr)
	}
	for i := 0; i < len(hpbsignerarray); i++ {
		for j := 0; j < len(hpbsignerarray)-i-1; j++ {
			if bytes.Compare(hpbsignerarray[j][:], hpbsignerarray[j+1][:]) > 0 {
				hpbsignerarray[j], hpbsignerarray[j+1] = hpbsignerarray[j+1], hpbsignerarray[j]
			}
		}
	}

	//确定offset
	var unsigneroffset = 0
	for i := 0; i < len(hpbsignerarray); i++ {
		if hpbsignerarray[i] == signer {
			unsigneroffset = i
			break
		}
	}
	if ok && currentIndex == uint64(unsigneroffset) { //如果在区块头中未出现过，在未签名集合中，并且offset匹配则为真
		return true, nil
	} else {
		return false, nil
	}
	//return (number % uint64(len(signers))) == uint64(offset)
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
	log.Info("FUHY----------GetOffsethw number------------", "number", number)
	for _, header := range headers {
		log.Info("FUHY----------GetOffsethw header.Coinbase------------", "header.Coinbase", header.Coinbase)
		log.Info("FUHY----------GetOffsethw header.Number------------", "header.Number", header.Number)
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
		log.Error("FUHY GetHpbNodes() HpbNodeSnap`s Signers is nil", "HpbNodeSnap.Signers", s.Signers)
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

func CalculateHpbSnap(signatures *lru.ARCCache, config *config.PrometheusConfig, number uint64, latestCheckPointNum uint64, latestCheckPointHash common.Hash, headers []*types.Header, chain consensus.ChainReader) (*HpbNodeSnap, error) {
	// Allow passing in no headers for cleaner code

	// 如果头部为空，直接返回
	if len(headers) == 0 {
		log.Error("FUHY Calculate Hpb Snap headers is 0")
		return nil, errors.New("Calculate Hpb Snap headers is 0 ")
	}

	// 检查所有的头部，检查连续性
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, consensus.ErrInvalidVotingChain
		}
	}

	signers := make([]common.Address, 3)

	snap := NewHistorysnap(config, signatures, number, latestCheckPointNum, latestCheckPointHash, signers)

	snap.Tally = make(map[common.Address]Tally)

	//开始投票
	//fmt.Println(" ****************************************headers length ++++********************************* ", len(headers))

	//for _, header := range headers {
	//	snap.cast(header.CandAddress, header.VoteIndex);
	//}

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
		//log.Info("FUHY---------before---------tallytemp--------------------", "tallytemp[i].CandAddress", v.CandAddress.Hex(),"VotePercent.Int64()", v.VotePercent)
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
			if tallytemp[j].VotePercent.Cmp(tallytemp[j+1].VotePercent) > 0 {
				tallytemp[j], tallytemp[j+1] = tallytemp[j+1], tallytemp[j]
			} else if (tallytemp[j].VotePercent.Cmp(tallytemp[j+1].VotePercent) == 0) && (bytes.Compare(tallytemp[j].CandAddress[:], tallytemp[j+1].CandAddress[:]) > 0) {
				tallytemp[j], tallytemp[j+1] = tallytemp[j+1], tallytemp[j]
			}
		}
	}

	var hpnodeNO int
	if len(tallytemp) >= 3 {
		hpnodeNO = 3
	} else {
		hpnodeNO = len(tallytemp)
	}
	for i := len(tallytemp) - 1; i > len(tallytemp)-hpnodeNO-1; i-- {
		snap.Signers[tallytemp[i].CandAddress] = struct{}{}
		//log.Info("FUHY------------------CalculateHpbSnap--------------------", "tallytemp[i].CandAddress", tallytemp[i].CandAddress.Hex())
	}

	//for i:=0; i<len(tallytemp); i++  {
	//	log.Info("FUHY--------after----------tallytemp--------------------", "tallytemp[i].CandAddress", tallytemp[i].CandAddress.Hex(), "tallytemp[i].VotePercent", tallytemp[i].VotePercent)
	//}

	//等待完善
	//snap.Number += uint64(len(headers))
	//snap.Hash = latestCheckPointHash
	return snap, nil
}
