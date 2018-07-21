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
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/consensus/voting"
	"github.com/hpb-project/go-hpb/node/db"
)

const (
	checkpointInterval   = 1024 // 投票间隔
	inmemoryHistorysnaps = 128  // 内存中的快照个数
	inmemorySignatures   = 4096 // 内存中的签名个数
	wiggleTime = 500 * time.Millisecond // 延时单位
	comCheckpointInterval   = 2 // 社区投票间隔
	cadCheckpointInterval   = 2 // 社区投票间隔
)

// Prometheus protocol constants.
var (
	epochLength = uint64(30000) // 充值投票的时的间隔，默认 30000个
	blockPeriod = uint64(15)    // 两个区块之间的默认时间 15 秒
	uncleHash = types.CalcUncleHash(nil) //
	diffInTurn = big.NewInt(2) // 当轮到的时候难度值设置 2
	diffNoTurn = big.NewInt(1) // 当非轮到的时候难度设置 1
	reentryMux sync.Mutex
	insPrometheus *Prometheus
)

// Prometheus 的主体结构
type Prometheus struct {
	config *config.PrometheusConfig // Consensus 共识配置
	db     hpbdb.Database           // 数据库

	recents    *lru.ARCCache // 最近的签名
	signatures *lru.ARCCache // 签名后的缓存

	proposals map[common.Address]bool // 当前的proposals

	signer     common.Address     // 签名的 Key
	randomStr  string             // 产生的随机数
	signFn     SignerFn           // 回调函数
	lock       sync.RWMutex       // Protects the signerHash fields
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
	}
}

// InstanceBlockChain returns the singleton of BlockChain.
func InstancePrometheus() (*Prometheus) {
	if nil == insPrometheus {
		reentryMux.Lock()
		if  nil == insPrometheus {
			intanconf, err := config.GetHpbConfigInstance()
			
			proIns := New(&intanconf.Prometheus ,db.GetHpbDbInstance())
			
			///*consensus.engine.InstanceEngine()*/nil
			if err != nil {
				insPrometheus = nil
			}
			insPrometheus = proIns
		}
		reentryMux.Unlock()
	}
	return insPrometheus
}

// 回掉函数
type SignerFn func(accounts.Account, []byte) ([]byte, error)

// 实现引擎的Prepare函数
func (c *Prometheus) PrepareBlockHeader(chain consensus.ChainReader, header *types.Header) error {

	//获取Coinbase
	header.Coinbase = common.Address{}
	//获取Nonce
	header.Nonce = types.BlockNonce{}
	//获得块号
	number := header.Number.Uint64()

    // get hpb node snap
	snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config,chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	
	// get andidate node snap
	csnap, cerr :=  voting.GetCadNodeSnap(c.db,chain, number-1, header.ParentHash)
	if cerr != nil {
		return err
	}
	
	//在非投票点, 从网络中获取进行提案
	if (number%c.config.Epoch != 0) {
		c.lock.RLock()
		
		bigaddr, _ := new(big.Int).SetString("0000000000000000000000000000000000000000", 16)
		address := common.BigToAddress(bigaddr)
		
		if (csnap==nil || len(csnap.CadWinners) < 2){
		    header.CandAddress = address
		}else{
			// Get the best peer from the network
			if cadWinner,err := voting.GetBestCadNodeFromNetwork(snap,csnap); err == nil {
				if(cadWinner == nil){
					 header.CandAddress = address
				}else{
					header.CandAddress = cadWinner.Address // 设置地址
					header.VoteIndex = new(big.Int).SetUint64(cadWinner.VoteIndex)   // 设置最新的计算结果
					copy(header.Nonce[:], consensus.NonceAuthVote)
				}
			}else{
				return err
			}
		}
		c.lock.RUnlock()
	}

	//确定当前轮次的难度值，如果当前轮次
	//根据快照中的情况
	header.Difficulty = diffNoTurn
	if snap.CalculateCurrentMiner(header.Number.Uint64(), c.signer) {
		header.Difficulty = diffInTurn
	}
	
	// set hardware random
	header.HardwareRandom  = snap.GetHardwareRandom(header.Number.Uint64())
	
	// 检查头部的组成情况
	if len(header.Extra) < consensus.ExtraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, consensus.ExtraVanity-len(header.Extra))...)
	}

	header.Extra = header.Extra[:consensus.ExtraVanity]

    //在投票周期的时候，放入全部的Address
	if number%c.config.Epoch == 0 {
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

	log.Info("signer's address","signer", signer.Hex())

	c.lock.RUnlock()

	snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config, chain, number-1, header.ParentHash, nil)
	
	if err != nil {
		return nil, err
	}

	if _, authorized := snap.Signers[signer]; !authorized {
		return nil, consensus.ErrUnauthorized
	}

	log.Info("Proposed the hardware random number in current round:" + header.HardwareRandom)

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
	// 比较难度值，确定是否为适合的时间
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		//delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Info("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
		
		currentIndex := number % uint64(len(snap.Signers))	
		offset := snap.GetOffset(header.Number.Uint64(), signer)

       //在一定范围内延迟8分,当前的currentIndex往前的没有超过
       if(currentIndex <= uint64(len(snap.Signers)/2)){
	       if(offset - currentIndex <= uint64(len(snap.Signers)/2)){
				wiggle = time.Duration(1000) * wiggleTime
				//log.Info("$$$$$$$$$$$$$$$$$$$$$$$","less than half",common.PrettyDuration(wiggle))
				delay += wiggle;
			}else{
				delay += time.Duration(offset - currentIndex - uint64(len(snap.Signers)/2))* wiggle
			}
       }else{
       	    if(offset + uint64(len(snap.Signers)/2) <= currentIndex){
				wiggle = time.Duration(1000) * wiggleTime
				//log.Info("$$$$$$$$$$$$$$$$$$$$$$$","more than half",common.PrettyDuration(wiggle))
				delay += wiggle;
			}else{
				delay += time.Duration(offset - currentIndex - uint64(len(snap.Signers)/2))* wiggle
			}
       }
		log.Info("Out-of-turn signing requested ++++++++++++++++++++++++++++++++++", "delay", common.PrettyDuration(delay))
	}

	log.Info("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))

	select {
	case <-stop:
		return nil, nil
	case <-time.After(delay):
	}
	// 签名交易，signFn为回掉函数
	sighash, err := signFn(accounts.Account{Address: signer}, consensus.SigHash(header).Bytes())
	if err != nil {
		return nil, err
	}

	//将签名后的结果返给到Extra中
	copy(header.Extra[len(header.Extra)-consensus.ExtraSeal:], sighash)

	return block.WithSeal(header), nil
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
	
	c.CalculateRewards(chain, state, header, uncles) //系统奖励
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)
	// 返回最终的区块
	return types.NewBlock(header, txs, nil, receipts), nil
}

// 计算奖励
func (c *Prometheus) CalculateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header, uncles []*types.Header) (error) {
	// Select the correct block reward based on chain progression
	hobBlockReward := big.NewInt(5e+18)
	//canBlockReward := big.NewInt(5e+18)

	
	// 将来的接口，调整奖励，调整奖励与配置有关系
	//config *params.ChainConfig
	//if config(header.Number) {
	//	blockReward = ByzantiumBlockReward
	//}
	
	// Accumulate the rewards for the miner and any included uncles
	hpbReward := new(big.Int).Set(hobBlockReward)
	//canReward := new(big.Int).Set(canBlockReward)
	
	number := header.Number.Uint64()
	if number == 0 {
		return consensus.ErrUnknownBlock
	}
	
	// reward on hpb nodes
	if snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config, chain, number-1, header.ParentHash, nil); err == nil{
		// 奖励所有的高性能节点
		for _, signer := range snap.GetHpbNodes() {
			state.AddBalance(signer, hpbReward)
		}
	}else{
		return err
	}
	
	// reward on Cad nodes
	/*
	if csnap, err :=  voting.GetCadNodeSnap(c.db,chain, number-1, header.ParentHash);err == nil{
		
		for _, csigner := range csnap.CadWinners {
			state.AddBalance(csigner.Address, canReward)
		}
	}else{
		return err
	}
	*/
	/*
	r := new(big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, big8)
		state.AddBalance(uncle.Coinbase, r)
		r.Div(blockReward, big32)
		reward.Add(reward, r)
	}
	*/
	//state.AddBalance(header.Coinbase, reward)
	
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
