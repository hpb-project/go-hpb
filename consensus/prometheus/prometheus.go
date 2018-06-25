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
	"errors"
	//"fmt"
	"math/big"
	//"math/rand"
	"sync"
	"time"
	"math"
	"strconv"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	//"github.com/hpb-project/ghpb/common/hexutil"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core/state"
	"github.com/hpb-project/ghpb/core/types"

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/ghpb/common/constant"
	//"github.com/hpb-project/ghpb/common/crypto"
	//"github.com/hpb-project/ghpb/common/crypto/sha3"
	"github.com/hpb-project/ghpb/common/log"
	//"github.com/hpb-project/ghpb/common/rlp"
	"github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/ghpb/storage"
	
	"github.com/hpb-project/ghpb/consensus/snapshots"
	"github.com/hpb-project/ghpb/consensus/voting"
	
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
)

// Prometheus 的主体结构
type Prometheus struct {
	config *params.PrometheusConfig // Consensus 共识配置
	db     hpbdb.Database           // 数据库

	recents    *lru.ARCCache // 最近的签名
	signatures *lru.ARCCache // 签名后的缓存

	proposals map[common.Address]bool // 当前的proposals
	//proposalsHash map[common.AddressHash]bool // 当前 proposals hash

	signer     common.Address     // 签名的 Key
	//signerHash common.AddressHash // 地址的hash
	randomStr  string             // 产生的随机数
	signFn     SignerFn           // 回调函数
	lock       sync.RWMutex       // Protects the signerHash fields
}

// 新创建,在backend中调用
func New(config *params.PrometheusConfig, db hpbdb.Database) *Prometheus {

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

	snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config,chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	
	//在非投票点, 从网络中获取进行提案
	if number%c.config.Epoch != 0 {
		c.lock.RLock()
		// 从网络中获取一个
		if cadWinner,err := voting.GetBestCadNodeFromNetwork(c.db, chain, number-1, header.ParentHash); err == nil{
			caddress := common.HexToAddress(cadWinner.Address)
			//if snap.ValidVote(address, true) {
			header.CandAddress = caddress // 设置地址
			//header.VoteIndex = big.NewInt(int64(cadWinner.VoteIndex))   // 设置最新的计算结果
			header.VoteIndex = new(big.Int).SetUint64(cadWinner.VoteIndex)   // 设置最新的计算结果
			copy(header.Nonce[:], consensus.NonceAuthVote)
			//}
			log.Info("#########################################TESE", cadWinner.Address)
		}
	    if err != nil {
			return err
		}
		c.lock.RUnlock()
	}

	//确定当前轮次的难度值，如果当前轮次
	//根据快照中的情况
	header.Difficulty = diffNoTurn
	if snap.Inturn(header.Number.Uint64(), c.signer) {
		header.Difficulty = diffInTurn
	}
	
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

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, consensus.ErrUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if c.config.Period == 0 && len(block.Transactions()) == 0 {
		return nil, consensus.ErrWaitTransactions
	}
	// Don't hold the signerHash fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn

	//log.Info("Current seal random is" + header.Random)
	//signerHash := common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(signer.Str() + header.Random)))

	log.Info("signer's address","signer", signer.Hex())

	c.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config, chain, number-1, header.ParentHash, nil)
	//
	if err != nil {
		return nil, err
	}

	if _, authorized := snap.Signers[signer]; !authorized {
		return nil, consensus.ErrUnauthorized
	}

	//log.Info("Proposed the random number in current round:" + header.Random)

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
	// Sweet, the protocol permits us to sign the block, wait for our time
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
				log.Info("$$$$$$$$$$$$$$$$$$$$$$$","less than half",common.PrettyDuration(wiggle))
				delay += wiggle;
			}else{
				delay += time.Duration(offset - currentIndex - uint64(len(snap.Signers)/2))* wiggle
			}
       }else{
       	    if(offset + uint64(len(snap.Signers)/2) <= currentIndex){
				wiggle = time.Duration(1000) * wiggleTime
				log.Info("$$$$$$$$$$$$$$$$$$$$$$$","more than half",common.PrettyDuration(wiggle))
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

// 获取社区选举的快照
func (c *Prometheus) getComNodeSnap(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*snapshots.ComNodeSnap, error) {
	
	//业务逻辑
	var (
	 //comNodeSnap    *snapshots.ComNodeSnap
	 header  *types.Header
	 latestCheckPointHash common.Hash
	 //latestCheckPointNumber float64
	)
	
	// 进来的请求恰好在投票检查点，此时重新计票
	log.Error("current number:",strconv.FormatUint(number, 10))
	if number%comCheckpointInterval == 0 {
		if comNodeSnap, err0 := c.CalcuComNodeSnap(number, hash); err0 == nil {
			return comNodeSnap,nil
		}
	}
	
	//不在投票点开始获取数据库中的内容
	latestCheckPointNumber :=  uint64(math.Floor(float64(number/comCheckpointInterval)))*comCheckpointInterval
	log.Error("current latestCheckPointNumber:",strconv.FormatUint(latestCheckPointNumber, 10))

	header = chain.GetHeaderByNumber(uint64(latestCheckPointNumber))
	latestCheckPointHash = header.Hash()
	
	if comNodeSnap, err := snapshots.LoadComNodeSnap(c.db, latestCheckPointHash); err == nil {
		log.Info("Prometheus： Loaded voting comNodeSnap form disk", "number", number, "hash", hash)
		return comNodeSnap,nil
	} else { //数据库中没有正常的获取，再次去统计
		if comNodeSnap, err1 := c.CalcuComNodeSnap(number, hash); err1 == nil {
			return comNodeSnap,nil
		}
	}
	return nil,nil
}

// 从社区选举中的投票中去获取
func (c *Prometheus) CalcuComNodeSnap(number uint64, hash common.Hash) (*snapshots.ComNodeSnap, error) {

		//开始读取智能合约
		//
		str := strconv.FormatUint(number, 10)
		// 模拟从外部获取		
		type Winners []*snapshots.Winner
		w1 := &snapshots.Winner{"192.168.2.14",str}
		w2 := &snapshots.Winner{"192.168.2.12","17SPaMHq1EkWNVGZuxdoLbDZQ8P39LzKgm"}
		w3 := &snapshots.Winner{"192.168.2.33","1Ljzw8EodRSLmtxPrFsQP9Ew94htgJ3xze"}
		
		allWinners := Winners([]*snapshots.Winner{w1, w2, w3}) 
		
		comNodeSnap := snapshots.NewComNodeSnap(number,hash,allWinners)

        log.Info("get Com form outside************************************", comNodeSnap.Winners[0].NetworkId)
		
		// 存储到数据库中
		if err := comNodeSnap.Store(c.db); err != nil {
				log.Error("Stored Error")
				return nil, err
		}
		log.Trace("Stored genesis voting ComNodeSnap to disk")
		return comNodeSnap,nil
}

// 从当前的签名中，返回追溯到签名者
func (c *Prometheus) Author(header *types.Header) (common.Address, error) {
	return consensus.Ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Prometheus) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *Prometheus) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Prometheus) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return consensus.ErrUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % c.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return consensus.ErrInvalidCheckpointBeneficiary
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], consensus.NonceAuthVote) && !bytes.Equal(header.Nonce[:], consensus.NonceDropVote) {
		return consensus.ErrInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], consensus.NonceDropVote) {
		return consensus.ErrInvalidCheckpointVote
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < consensus.ExtraVanity {
		return consensus.ErrMissingVanity
	}
	if len(header.Extra) < consensus.ExtraVanity+ consensus.ExtraSeal {
		return consensus.ErrMissingSignature
	}
	// Ensure that the extra-data contains a signerHash list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - consensus.ExtraVanity - consensus.ExtraSeal
	if !checkpoint && signersBytes != 0 {
		return consensus.ErrExtraSigners
	}
	if checkpoint && signersBytes%common.AddressLength != 0 {
		log.Info("at checkpoint", "checkpoint",checkpoint)
		return consensus.ErrInvalidCheckpointSigners
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return consensus.ErrInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return consensus.ErrInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return consensus.ErrInvalidDifficulty
		}
	}

	// All basic checks passed, verify cascading fields
	return c.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *Prometheus) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time.Uint64()+c.config.Period > header.Time.Uint64() {
		return consensus.ErrInvalidTimestamp
	}
	// Retrieve the getHpbNodeSnap needed to verify this header and cache it
	snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config,chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the signerHash list
	if number%c.config.Epoch == 0 {
		//获取出当前快照的内容, snap.Signers 实际为hash
		log.Info("the block is at epoch checkpoint", "block number",number)
		signers := make([]byte, len(snap.Signers)*common.AddressLength)
		for i, signerHash := range snap.GetHpbNodes() {
			copy(signers[i*common.AddressLength:], signerHash[:])
		}
		extraSuffix := len(header.Extra) - consensus.ExtraSeal
		if !bytes.Equal(header.Extra[consensus.ExtraVanity:extraSuffix], signers) {
			return consensus.ErrInvalidCheckpointSigners
		}
	}
	// All basic checks passed, verify the seal and return
	return c.verifySeal(chain, header, parents)
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Prometheus) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *Prometheus) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return c.verifySeal(chain, header, nil)
}

// 验证封装的正确性，判断是否满足共识算法的需求
func (c *Prometheus) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported

	number := header.Number.Uint64()
	if number == 0 {
		return consensus.ErrUnknownBlock
	}
	// Retrieve the getHpbNodeSnap needed to verify this header and cache it
	snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config,chain, number-1, header.ParentHash, parents)

	if err != nil {
		return err
	}

	// Resolve the authorization key and check against signers
	signer, err := consensus.Ecrecover(header, c.signatures)

	//signerHash := common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(signer.Str() + header.Random)))
	
	//log.Info("current block head from remote nodes", "Number",number,"Random",header.Random,"Difficulty",header.Difficulty)

	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return consensus.ErrUnauthorized
	}

	/*
	for seen, recent := range snap.Recents {
		if recent == signerHash {
			// Signer is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(snap.Signers)/2 + 1); seen > number-limit {
				return errUnauthorized
			}
		}
	}
	*/
	// Ensure that the difficulty corresponds to the turn-ness of the signerHash
	inturn := snap.Inturn(header.Number.Uint64(), signer)
	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
		return consensus.ErrInvalidDifficulty
	}
	if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
		return consensus.ErrInvalidDifficulty
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (c *Prometheus) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signerHash voting.
func (c *Prometheus) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "prometheus",
		Version:   "1.0",
		Service:   &API{chain: chain, prometheus: c},
		Public:    false,
	}}
}
