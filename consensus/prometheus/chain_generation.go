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
	"math/big"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/consensus"

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	"github.com/hpb-project/go-hpb/consensus/voting"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/node/db"
	//"strconv"
	"errors"
	"github.com/hpb-project/go-hpb/account/abi"
	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/hvm/evm"
	"math"
	"math/rand"
	"strings"
)

const (
	checkpointInterval    = 1024                   // 投票间隔
	inmemoryHistorysnaps  = 128                    // 内存中的快照个数
	inmemorySignatures    = 4096                   // 内存中的签名个数
	wiggleTime            = 500 * time.Millisecond // 延时单位
	comCheckpointInterval = 2                      // 社区投票间隔
	cadCheckpointInterval = 2                      // 社区投票间隔
)

// Prometheus protocol constants.
var (
	epochLength   = uint64(30000)            // 充值投票的时的间隔，默认 30000个
	blockPeriod   = uint64(15)               // 两个区块之间的默认时间 15 秒
	uncleHash     = types.CalcUncleHash(nil) //
	diffInTurn    = big.NewInt(2)            // 当轮到的时候难度值设置 2
	diffNoTurn    = big.NewInt(1)            // 当非轮到的时候难度设置 1
	reentryMux    sync.Mutex
	insPrometheus *Prometheus
)

// Prometheus 的主体结构
type Prometheus struct {
	config *config.PrometheusConfig // Consensus 共识配置
	db     hpbdb.Database           // 数据库

	recents    *lru.ARCCache // 最近的签名
	signatures *lru.ARCCache // 签名后的缓存

	proposals map[common.Address]bool // 当前的proposals

	signer    common.Address // 签名的 Key
	randomStr string         // 产生的随机数
	signFn    SignerFn       // 回调函数
	lock      sync.RWMutex   // Protects the signerHash fields
	hboe      *boe.BoeHandle //boe handle for using boe
}

// 新创建,在backend中调用
func New(config *config.PrometheusConfig, db hpbdb.Database) *Prometheus {

	conf := *config

	//设置默认参数
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	// 分配内存
	recents, _ := lru.NewARC(inmemoryHistorysnaps)
	signatures, _ := lru.NewARC(inmemorySignatures)

	return &Prometheus{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
		hboe:       boe.BoeGetInstance(),
	}
}

// InstanceBlockChain returns the singleton of BlockChain.
func InstancePrometheus() *Prometheus {
	if nil == insPrometheus {
		reentryMux.Lock()
		if nil == insPrometheus {
			insPrometheus = New(&config.GetHpbConfigInstance().Prometheus, db.GetHpbDbInstance())
		}
		reentryMux.Unlock()
	}
	return insPrometheus
}

// 回掉函数
type SignerFn func(accounts.Account, []byte) ([]byte, error)

// 实现引擎的Prepare函数
func (c *Prometheus) PrepareBlockHeader(chain consensus.ChainReader, header *types.Header, state *state.StateDB) error {

	//获取Coinbase
	//header.Coinbase = common.Address{}
	//获取Nonce
	header.Nonce = types.BlockNonce{}
	//获得块号
	number := header.Number.Uint64()

	// get hpb node snap
	snap, err := voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// get andidate node snap
	//csnap, cerr :=  voting.GetCadNodeSnap(c.db,chain, number, header.ParentHash)
	//if cerr != nil {
	//	return err
	//}
	SetNetNodeType(snap)

	c.lock.RLock()
	//bigaddr, _ := new(big.Int).SetString("0000000000000000000000000000000000000000", 16)
	//address := common.BigToAddress(bigaddr)

	// Get the best peer from the network
	if cadWinner, err := voting.GetCadNodeFromNetwork(state); err == nil {

		//log.Info("len(cadWinner)-------------", "len(cadWinner)", len(cadWinner))

		if cadWinner == nil || len(cadWinner) != 2 {
			//if no peers, add itself Coinbase to CandAddress and ComdAddress, or when candidate nodes is less len(hpbsnap.signers), the zero address will become the hpb node
			header.CandAddress = header.Coinbase
			header.ComdAddress = header.Coinbase
			header.VoteIndex = new(big.Int).SetUint64(0)
		} else {
			header.CandAddress = cadWinner[0].Address // 设置地址
			header.VoteIndex = new(big.Int).SetUint64(cadWinner[0].VoteIndex)
			copy(header.Nonce[:], consensus.NonceAuthVote)
			header.ComdAddress = cadWinner[1].Address // 设置地址
		}
	} else {
		return err
	}

	//log.Info("header.CandAddress-------------","CandAddress", header.CandAddress.Hex())
	//log.Info("header.ComdAddress-------------","ComdAddress", header.ComdAddress.Hex())

	c.lock.RUnlock()

	//TODO:在区块头中设置boehwrand,通过获取父节点header的HardwareRandom通过调用boe的GetNextHash获取当前区块的rand
	parentnum := number - 1
	parentheader := chain.GetHeaderByNumber(parentnum)
	if parentheader == nil {
		return errors.New("-----PrepareBlockHeader parentheader------ is nil")
	}
	if len(parentheader.HardwareRandom) == 0 {
		return errors.New("---------- PrepareBlockHeader parentheader.HardwareRandom----------------- is nil")
	}

	if config.GetHpbConfigInstance().Node.TestMode == 1 {
		//panic("boe broke, please contact with hpb")
		log.Info("TestMode, using the gensis.json hardwarerandom")
		header.HardwareRandom = make([]byte, len(parentheader.HardwareRandom))
		copy(header.HardwareRandom, parentheader.HardwareRandom)
		header.HardwareRandom[len(header.HardwareRandom)-1] = header.HardwareRandom[len(header.HardwareRandom)-1] + 1
	} else {
		if c.hboe.HWCheck() {
			if parentheader.HardwareRandom == nil || len(parentheader.HardwareRandom) != 32 {
				log.Error("parentheader.HardwareRandom is nil or length is not 32")
			}
			if boehwrand, err := c.hboe.GetNextHash(parentheader.HardwareRandom); err != nil {
				return err
			} else {
				if len(boehwrand) != 0 {
					header.HardwareRandom = make([]byte, len(boehwrand))
					copy(header.HardwareRandom, boehwrand)
				} else {
					return errors.New("c.hboe.GetNextHash success but output random length is 0")
				}
			}
		} else {
			log.Info("no boe device, using the gensis.json hardwarerandom")
			header.HardwareRandom = make([]byte, len(parentheader.HardwareRandom))
			copy(header.HardwareRandom, parentheader.HardwareRandom)
			header.HardwareRandom[len(header.HardwareRandom)-1] = header.HardwareRandom[len(header.HardwareRandom)-1] + 1
			//panic("boe broke, please contact with hpb")
		}
	}

	//确定当前轮次的难度值，如果当前轮次
	//根据快照中的情况
	header.Difficulty = diffNoTurn
	if snap.CalculateCurrentMinerorigin(new(big.Int).SetBytes(header.HardwareRandom).Uint64(), c.signer) {
		header.Difficulty = diffInTurn
	}
	//header.Difficulty = diffNoTurn
	//if diffbool, _, err := snap.CalculateCurrentMiner(header.Number.Uint64(), c.signer, chain, header); diffbool && err == nil {
	//	//log.Error("----prepare header------------test for waiting 8 minutes-------------", "primeminer", m, "number", header.Number)
	//	header.Difficulty = diffInTurn
	//} else if err != nil {
	//	log.Error("CalculateCurrentMiner fail", "error", err)
	//	return err
	//}

	// 检查头部的组成情况
	if len(header.Extra) < consensus.ExtraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, consensus.ExtraVanity-len(header.Extra))...)
	}

	header.Extra = header.Extra[:consensus.ExtraVanity]

	//在投票周期的时候，放入全部的Address
	if number%consensus.HpbNodeCheckpointInterval == 0 {
		for _, signer := range snap.GetHpbNodes() {
			header.Extra = append(header.Extra, signer[:]...)
		}
	}

	header.Extra = append(header.Extra, make([]byte, consensus.ExtraSeal)...)
	header.MixDigest = common.Hash{}

	//获取父亲的节点
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))

	//设置时间点，如果函数太小则，设置为当前的时间
	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}

	return nil
}

//生成区块
func (c *Prometheus) GenBlockWithSig(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()

	log.Info("HPB Prometheus Seal is starting")

	number := header.Number.Uint64()

	if number == 0 {
		return nil, consensus.ErrUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if c.config.Period == 0 && len(block.Transactions()) == 0 {
		return nil, consensus.ErrWaitTransactions
	}

	c.lock.RLock()
	signer, signFn := c.signer, c.signFn

	log.Info("GenBlockWithSig-------------+++++ signer's address", "signer", signer.Hex(), "number", number)

	c.lock.RUnlock()

	snap, err := voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, nil)

	// 已经投票结束
	//if (number%consensus.HpbNodeCheckpointInterval == 0) && (number != 1) {
	// 轮转
	SetNetNodeType(snap)
	//log.Info("SetNetNodeType ***********************")
	//}

	if err != nil {
		return nil, err
	}

	if _, authorized := snap.Signers[signer]; !authorized {
		return nil, consensus.ErrUnauthorized
	}

	//log.Info("Proposed the hardware random number in current round:" + header.HardwareRandom)

	// If we're amongst the recent signers, wait for the next block
	// 如果最近已经签名，则需要等待时序
	/*
		for seen, recent := range snap.Recents {
			if recent == signerHash {
				// 签名者在recents缓存中，等待被移除
				if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
					log.Info("Prometheus： Signed recently, must wait for others")
					<-stop
					return nil, nil
				}
			}
		}*/

	// 轮到我们的签名
	delay := time.Unix(header.Time.Int64(), 0).Sub(time.Now())
	if delay < 0 {
		delay = 0
		header.Time = big.NewInt(time.Now().Unix())
	}
	// 比较难度值，确定是否为适合的时间
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		//	// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		//	//log.Info("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
		//
		//	midIndex := uint64(len(snap.Signers) / 2)                //中间位置，一般的个数为奇数个
		//	currentIndex := number % uint64(len(snap.Signers))       //挖矿的机器位置
		//	offset := snap.GetOffset(header.Number.Uint64(), signer) //当前的位置
		//
		//	//在一定范围内延迟8分,当前的currentIndex往前的没有超过
		//	if currentIndex <= midIndex {
		//		if offset < currentIndex+midIndex/2 {
		//			wiggle = time.Duration(1000) * wiggleTime
		//			delay += wiggle
		//		} else {
		//			//log.Info("Out-of-turn signing requested", "delay", common.PrettyDuration(delay))
		//			delay += time.Duration(offset-currentIndex-midIndex) * wiggleTime
		//		}
		//	} else {
		//		if offset < currentIndex-midIndex/2 {
		//			wiggle = time.Duration(1000) * wiggleTime
		//			delay += wiggle
		//		} else {
		//			delay += time.Duration(offset-currentIndex-midIndex) * wiggleTime
		//		}
		//	}

		//fix delay calc
		//var primemineraddr common.Address
		//if _, tempmineraddr, err := snap.CalculateCurrentMiner(header.Number.Uint64(), c.signer, chain, header); err == nil {
		//	primemineraddr = tempmineraddr
		//} else {
		//	return nil, err
		//}
		//zeroaddr := common.HexToAddress("0000000000000000000000000000000000000000")
		//if zeroaddr.Big().Cmp(primemineraddr.Big()) == 0 {
		//	return nil, errors.New("primemineraddr is nil")
		//}
		//currentminer := snap.GetOffset(0, primemineraddr)
		currentminer := new(big.Int).SetBytes(header.HardwareRandom).Uint64() % uint64(len(snap.Signers)) //miner position
		//log.Error("-----genblocksig---------test for waiting 8 minutes--------------", "primemineraddr", primemineraddr, "primeoffset", currentminer, "number", number)
		myoffset := snap.GetOffset(header.Number.Uint64(), signer)
		distance := int(math.Abs(float64(int64(myoffset) - int64(currentminer))))
		if distance > len(snap.Signers)/2 {
			distance = len(snap.Signers) - distance
		}
		if distance > len(snap.Signers)/consensus.StepLength { //if signers length is smaller than 3,  it means myoffset smaller than currentminer have high priority
			delay += time.Duration(len(snap.Signers)-distance+10+rand.Intn(5)) * wiggleTime
		} else {
			wiggle = time.Duration(1000+rand.Intn(len(snap.Signers))) * wiggleTime
			delay += wiggle
		}
	}

	log.Info("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay), "number", number)

	select {
	case <-stop:
		return nil, nil
	case <-time.After(delay):
	}

	// 地址赋值
	header.Coinbase = signer

	// 签名交易，signFn为回掉函数
	sighash, err := signFn(accounts.Account{Address: signer}, consensus.SigHash(header).Bytes())
	if err != nil {
		return nil, err
	}

	//将签名后的结果返给到Extra中
	copy(header.Extra[len(header.Extra)-consensus.ExtraSeal:], sighash)

	return block.WithSeal(header), nil
}

// 设置网络节点类型
func SetNetNodeType(snapa *snapshots.HpbNodeSnap) error {
	addresses := snapa.GetHpbNodes()

	if p2p.PeerMgrInst().GetLocalType() == discover.PreNode || p2p.PeerMgrInst().GetLocalType() == discover.HpNode {
		newlocaltyp := discover.PreNode
		if flag := FindHpbNode(p2p.PeerMgrInst().DefaultAddr(), addresses); flag {
			newlocaltyp = discover.HpNode
		}
		if p2p.PeerMgrInst().GetLocalType() != newlocaltyp {
			p2p.PeerMgrInst().SetLocalType(newlocaltyp)
		}
	}

	peers := p2p.PeerMgrInst().PeersAll()
	for _, peer := range peers {
		switch peer.RemoteType() {
		case discover.PreNode:
			if flag := FindHpbNode(peer.Address(), addresses); flag {
				log.Info("PreNode ---------------------> HpNode", "addesss", peer.Address().Hex())
				peer.SetRemoteType(discover.HpNode)
			}
		case discover.HpNode:
			if flag := FindHpbNode(peer.Address(), addresses); !flag {
				log.Info("HpNode ---------------------> PreNode", "addesss", peer.Address().Hex())
				peer.SetRemoteType(discover.PreNode)
			}
		case discover.SynNode:
			if flag := FindHpbNode(peer.Address(), addresses); flag {
				log.Info("SynNode ---------------------> HpNode", "addesss", peer.Address().Hex())
				peer.SetRemoteType(discover.HpNode)
			}
			//peer.SetRemoteType(discover.SynNode)
		default:
			break
		}
	}
	return nil
}

func FindHpbNode(address common.Address, addresses []common.Address) bool {
	for _, addresstemp := range addresses {
		if addresstemp == address {
			return true
		}
	}
	return false
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Prometheus) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}

// 从当前的签名中，返回追溯到签名者
func (c *Prometheus) Author(header *types.Header) (common.Address, error) {
	return consensus.Ecrecover(header, c.signatures)
}

func (c *Prometheus) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {

	//log.Info("Finalize-------------+++++ signer's address", "signer", header.Coinbase.Hex())
	err := c.CalculateRewards(chain, state, header, uncles) //系统奖励
	if err != nil {
		log.Error("CalculateRewards return error", "err", err)
	}
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)
	// 返回最终的区块
	return types.NewBlock(header, txs, nil, receipts), nil
}

// 计算奖励
func (c *Prometheus) CalculateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header, uncles []*types.Header) error {
	// Select the correct block reward based on chain progression
	//hobBlockReward := big.NewInt(300000000)
	//canBlockReward := big.NewInt(100000000)

	var bigIntblocksoneyear = new(big.Int)
	secondsoneyesr := big.NewFloat(60 * 60 * 24 * 365)                         //seconds in one year
	secondsoneyesr.Quo(secondsoneyesr, big.NewFloat(float64(c.config.Period))) //blocks mined by miners in one year
	secondsoneyesr.Int(bigIntblocksoneyear)                                    //from big.Float to big.Int

	bigrewards := big.NewFloat(float64(100000000 * 0.03)) //hpb coins additional issue one year
	bigrewards.Mul(bigrewards, big.NewFloat(float64(consensus.Nodenumfirst)))
	bigrewards.Quo(bigrewards, big.NewFloat(float64(consensus.Nodenumfirst)))

	bigIntblocksoneyearfloat := new(big.Float)
	bigIntblocksoneyearfloat.SetInt(bigIntblocksoneyear)      //from big.Int to big.Float
	A := bigrewards.Quo(bigrewards, bigIntblocksoneyearfloat) //calc reward mining one block

	//mul 2/3
	A.Mul(A, big.NewFloat(2))
	A.Quo(A, big.NewFloat(3))

	//new two vars using below codes
	var bigA23 = new(big.Float)                       //2/3 one block reward
	var bigA13 = new(big.Float)                       //1/3 one block reward
	bigA23.Set(A)                                     //为了cad奖励的时候使用
	bigA13.Set(A)                                     //为了cad奖励的时候使用
	bighobBlockReward := A.Mul(A, big.NewFloat(0.35)) //reward hpb coin for hpb nodes

	ether2weis := big.NewInt(10)
	ether2weis.Exp(ether2weis, big.NewInt(18), nil) //one hpb coin to weis

	ether2weisfloat := new(big.Float)
	ether2weisfloat.SetInt(ether2weis)
	bighobBlockRewardwei := bighobBlockReward.Mul(bighobBlockReward, ether2weisfloat) //reward weis for hpb nodes

	number := header.Number.Uint64()
	if number == 0 {
		return consensus.ErrUnknownBlock
	}

	var hpsnap *snapshots.HpbNodeSnap
	var err error
	if number < consensus.StageNumberII {
		finalhpbrewards := new(big.Int)
		bighobBlockRewardwei.Int(finalhpbrewards) //from big.Float to big.Int
		state.AddBalance(header.Coinbase, finalhpbrewards)
	} else {
		if hpsnap, err = voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, nil); err == nil {
			bighobBlockRewardwei.Quo(bighobBlockRewardwei, big.NewFloat(float64(len(hpsnap.Signers))))
			finalhpbrewards := new(big.Int)
			bighobBlockRewardwei.Int(finalhpbrewards) //from big.Float to big.Int
			for _, v := range hpsnap.GetHpbNodes() {
				state.AddBalance(v, finalhpbrewards)
			}
		} else {
			return err
		}
	}

	if csnap, err := voting.GetCadNodeSnap(c.db, c.recents, chain, number, header.ParentHash); err == nil {
		if csnap != nil && len(csnap.CanAddresses) != 0 {
			bigA23.Mul(bigA23, big.NewFloat(0.65))
			canBlockReward := bigA23.Quo(bigA23, big.NewFloat(float64(len(csnap.VotePercents)))) //calc average reward coin part about cadidate nodes

			bigcadRewardwei := new(big.Float)
			bigcadRewardwei.SetInt(ether2weis)
			bigcadRewardwei.Mul(bigcadRewardwei, canBlockReward) //calc average reward weis part about candidate nodes

			cadReward := new(big.Int)
			bigcadRewardwei.Int(cadReward) //from big.Float to big.Int

			for caddress, _ := range csnap.VotePercents {
				state.AddBalance(caddress, cadReward) //reward every cad node average
			}

			if number%consensus.HpbNodeCheckpointInterval == 0 && number >= consensus.StageNumberII {
				return c.rewardvotepercentcad(chain, header, state, bigA13, ether2weisfloat, csnap, hpsnap)
			}
		}
	} else {
		return err
	}
	return nil
}

// 返回的API
func (c *Prometheus) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "prometheus",
		Version:   "1.0",
		Service:   &API{chain: chain, prometheus: c},
		Public:    false,
	}}
}

func (c *Prometheus) rewardvotepercentcad(chain consensus.ChainReader, header *types.Header, state *state.StateDB, bigA13 *big.Float, ether2weisfloat *big.Float, csnap *snapshots.CadNodeSnap, hpsnap *snapshots.HpbNodeSnap) error {

	if csnap == nil || hpsnap == nil {
		return errors.New("input param snap is nil")
	}
	fechaddr := common.HexToAddress(consensus.Fechcontractaddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.signer,
		Coinbase:    c.signer,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		GasPrice:    new(big.Int).Set(big.NewInt(1000)),
	}
	cfg := evm.Config{}
	vmenv := evm.NewEVM(context, state, &config.GetHpbConfigInstance().BlockChain, cfg)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.FechHpbBallotAddrABI))

	//get contract addr
	packres, err := fechABI.Pack("getContractAddr")
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.signer), fechaddr, packres)
	if err != nil {
		log.Error("getContractAddr InnerCall fail", "err", err)
		return err
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			return errors.New("return resultaddr is nil or length is 0")
		}
	}

	packres, _ = fechABI.Pack("getFunStr")
	resultfun, err := vmenv.InnerCall(evm.AccountRef(c.signer), fechaddr, packres)
	if err != nil {
		log.Error("getFunStr InnerCall fail", "err", err)
		return err
	} else {
		if resultfun == nil || len(resultfun) < 74 {
			return errors.New("getFunStr InnerCall success but result length is short")
		}
	}

	//use read contract addr and funstr get vote result
	realaddr := common.BytesToAddress(resultaddr)
	funparamstr := new([8]byte)
	copy(funparamstr[:], resultfun[66:66+8])
	funparam := common.Hex2Bytes(string(funparamstr[:]))

	paramnum := big.NewInt(header.Number.Int64())
	bufparam := new(bytes.Buffer)
	bufparam.Write(funparam[:])
	pendingbc := new([32]byte)
	bufparam.Write(pendingbc[:32-len(paramnum.Bytes())])
	bufparam.Write(paramnum.Bytes())

	resultvote, err := vmenv.InnerCall(evm.AccountRef(c.signer), realaddr, bufparam.Bytes())
	vmenv.Cancel()
	if err != nil {
		log.Error("realaddr InnerCall fail", "err", err)
		return err
	}
	if resultvote == nil || len(resultvote) < 64+32+32+32+32 { //64 bytes + number1 + number2 + addrcounts + votes, at least have these bytes
		//log.Error("realaddr InnerCall success but result length is too short", "length", len(resultvote))
		return errors.New("realaddr InnerCall success but result length is too short")
	}
	resultvote = resultvote[64:]
	rewardsnum := consensus.CadNodeCheckpointInterval //test

	addrbigcount := new(big.Int).SetBytes(resultvote[64 : 64+32])
	if len(resultvote) < int(64+32+32+addrbigcount.Uint64()*32) {
		return errors.New("1 return data length is not enough")
	}
	votebigcount := new(big.Int).SetBytes(resultvote[64+32+addrbigcount.Uint64()*32 : 64+32+32+addrbigcount.Uint64()*32])
	if len(resultvote) < int(64+32+32+addrbigcount.Uint64()*32+votebigcount.Uint64()*32) {
		return errors.New("2 return data length is not enough")
	}
	//log.Error("addr and vote peer count", "addrbigcount", addrbigcount.String(), "votebigcount", votebigcount.String())
	if addrbigcount.Cmp(votebigcount) != 0 {
		return errors.New("vote contract return addrs and votes number donnot match")
	}
	if addrbigcount.Uint64() == 0 {
		return nil
	}
	//log.Error("addr and vote peer count", "count", addrbigcount)

	voteres := make(map[common.Address]big.Int)
	for i := 0; i < int(addrbigcount.Int64()); i++ {
		var tempaddr common.Address
		tempaddr.SetBytes(resultvote[64+32+i*32 : 64+32+i*32+32])
		var tempvote big.Int
		tempvote.SetBytes(resultvote[64+32+(i+1+int(addrbigcount.Int64()))*32 : 64+32+(i+1+int(addrbigcount.Int64()))*32+32])
		voteres[tempaddr] = tempvote
	}

	for addr, _ := range voteres {
		_, ok1 := csnap.VotePercents[addr]
		_, ok2 := hpsnap.Signers[addr]
		if !ok1 && !ok2 {
			delete(voteres, addr)
		}
	}

	//获取所有cad的总票数
	votecounts := new(big.Int)
	for _, votes := range voteres {
		votecounts.Add(votecounts, &votes)
	}
	votecountsfloat := new(big.Float)
	votecountsfloat.SetInt(votecounts)

	bigA13.Quo(bigA13, big.NewFloat(2))
	bigA13.Mul(bigA13, ether2weisfloat)
	bigA13.Mul(bigA13, big.NewFloat(float64(rewardsnum))) //mul interval number

	for addr, votes := range voteres {
		tempaddrvotefloat := new(big.Float)
		tempreward := new(big.Int)
		tempaddrvotefloat.SetInt(&votes)
		tempaddrvotefloat.Quo(tempaddrvotefloat, votecountsfloat)
		tempaddrvotefloat.Mul(tempaddrvotefloat, bigA13)
		tempaddrvotefloat.Int(tempreward)
		state.AddBalance(addr, tempreward) //reward every cad node by vote percent
	}

	return nil
}
