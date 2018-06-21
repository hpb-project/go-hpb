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
	"math/rand"
	"sync"
	"time"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/common/hexutil"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core/state"
	"github.com/hpb-project/ghpb/core/types"

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/ghpb/common/constant"
	"github.com/hpb-project/ghpb/common/crypto"
	"github.com/hpb-project/ghpb/common/crypto/sha3"
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/common/rlp"
	"github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/ghpb/storage"
	
)

const (
	checkpointInterval   = 1024 // 投票间隔
	inmemoryHistorysnaps = 128  // 内存中的快照个数
	inmemorySignatures   = 4096 // 内存中的签名个数

	wiggleTime = 500 * time.Millisecond // 延时单位
)

// Prometheus protocol constants.
var (
	epochLength = uint64(30000) // 充值投票的时的间隔，默认 30000个
	blockPeriod = uint64(15)    // 两个区块之间的默认时间 15 秒

	extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signerHash vanity
	extraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signerHash seal

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signerHash
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signerHash.

	uncleHash = types.CalcUncleHash(nil) //

	diffInTurn = big.NewInt(2) // 当轮到的时候难度值设置 2
	diffNoTurn = big.NewInt(1) // 当非轮到的时候难度设置 1
)

// 回掉函数
type SignerFn func(accounts.Account, []byte) ([]byte, error)

// 对区块头部进行签名，最小65Byte
func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.CoinbaseHash,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65],
		header.MixDigest,
		header.Nonce,
	})
	hasher.Sum(hash[:0])
	return hash
}

// 实现引擎的Prepare函数
func (c *Prometheus) Prepare(chain consensus.ChainReader, header *types.Header) error {

	header.CoinbaseHash = common.AddressHash{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()

	log.Info("Prepare the parameters for mining")
	
	uniquerand := getUniqueRandom(chain)
    signerHash := common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(c.signer.Str() + uniquerand)))
	header.Random = uniquerand

	// Assemble the voting snapshot to check which votes make sense
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if number%c.config.Epoch != 0 {
		c.lock.RLock()
		// Gather all the proposals that make sense voting on
		addresses := make([]common.AddressHash, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			header.CoinbaseHash = addresses[rand.Intn(len(addresses))]
			if c.proposals[header.CoinbaseHash] {
				copy(header.Nonce[:], nonceAuthVote)
			} else {
				copy(header.Nonce[:], nonceDropVote)
			}
		}
		c.lock.RUnlock()
	}

	// Set the correct difficulty
	// 根据 addressHash 来判断是否
	header.Difficulty = diffNoTurn
	//if snap.inturn(header.Number.Uint64(), c.signerHash) {
	if snap.inturn(header.Number.Uint64(), signerHash) {
		header.Difficulty = diffInTurn
	}
	
	// Ensure the extra data has all it's components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}

	header.Extra = header.Extra[:extraVanity]

	if number%c.config.Epoch == 0 {
		//在投票周期的时候，放入全部的AddressHash
		for _, signerHash := range snap.signers() {
			header.Extra = append(header.Extra, signerHash[:]...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))
	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}
	return nil
}

// 获取快照
func (c *Prometheus) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Historysnap, error) {

	var (
		headers []*types.Header
		snap    *Historysnap
	)
	//CoinbaseHash
	for snap == nil {

		// 直接使用内存中的，recents存部分
		if s, ok := c.recents.Get(hash); ok {
			snap = s.(*Historysnap)
			break
		}

		// 如果是检查点的时候，保存周期和投票周日不一致
		if number%checkpointInterval == 0 {
			if s, err := loadHistorysnap(c.config, c.signatures, c.db, hash); err == nil {
				log.Trace("Prometheus： Loaded voting snapshot form disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		// 首次要创建
		if number == 0 {
			genesis := chain.GetHeaderByNumber(0)
			if err := c.VerifyHeader(chain, genesis, false); err != nil {
				return nil, err
			}

			signers := make([]common.AddressHash, (len(genesis.ExtraHash)-extraVanity-extraSeal)/common.AddressHashLength)

			for i := 0; i < len(signers); i++ {
				log.Info("miner initialization", "i:",i)
				copy(signers[i][:], genesis.ExtraHash[extraVanity+i*common.AddressHashLength:extraVanity+(i+1)*common.AddressHashLength])
			}

			snap = newHistorysnap(c.config, c.signatures, 0, genesis.Hash(), signers)

			if err := snap.store(c.db); err != nil {
				return nil, err
			}
			log.Trace("Stored genesis voting snapshot to disk")
			break
		}

		// 没有发现快照，开始收集Header 然后往回回溯
		var header *types.Header
		if len(parents) > 0 {
			// 如果有指定的父亲，直接用
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// 没有指定的父亲
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}

		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// 找到了之前的快照，然后进行处理
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}

	snap, err := snap.apply(headers,chain)
	if err != nil {
		return nil, err
	}

	// 存入到缓存中
	c.recents.Add(snap.Hash, snap)

	// 检查点的时候，保存硬盘
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// 获取当前的签名者
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {

	// 从缓存中获取
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// 从头文件中获取extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// 还原公钥
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// Prometheus 的主体结构
type Prometheus struct {
	config *params.PrometheusConfig // Consensus 共识配置
	db     hpbdb.Database           // 数据库

	recents    *lru.ARCCache // 最近的签名
	signatures *lru.ARCCache // 签名后的缓存

	proposals map[common.AddressHash]bool // 当前的proposals
	//proposalsHash map[common.AddressHash]bool // 当前 proposals hash

	signer     common.Address     // 签名的 Key
	signerHash common.AddressHash // 地址的hash
	randomStr  string             // 产生的随机数
	signFn     SignerFn           // 回调函数
	lock       sync.RWMutex       // Protects the signerHash fields
}

// 新创建
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
		proposals:  make(map[common.AddressHash]bool),
	}
}

// 从当前的签名中，返回追溯到签名者
func (c *Prometheus) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, c.signatures)
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
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % c.config.Epoch) == 0
	if checkpoint && header.CoinbaseHash != (common.AddressHash{}) {
		return errInvalidCheckpointBeneficiary
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidCheckpointVote
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// Ensure that the extra-data contains a signerHash list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && signersBytes != 0 {
		return errExtraSigners
	}
	if checkpoint && signersBytes%common.AddressHashLength != 0 {
		log.Info("at checkpoint", "checkpoint",checkpoint)
		return errInvalidCheckpointSigners
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
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
		return ErrInvalidTimestamp
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the signerHash list
	if number%c.config.Epoch == 0 {
		//获取出当前快照的内容, snap.Signers 实际为hash
		log.Info("the block is at epoch checkpoint", "block number",number)
		signers := make([]byte, len(snap.Signers)*common.AddressHashLength)
		for i, signerHash := range snap.signers() {
			copy(signers[i*common.AddressHashLength:], signerHash[:])
		}
		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], signers) {
			return errInvalidCheckpointSigners
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
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)

	if err != nil {
		return err
	}

	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, c.signatures)

	signerHash := common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(signer.Str() + header.Random)))
	
	log.Info("current block head from remote nodes", "Number",number,"Random",header.Random,"Difficulty",header.Difficulty)

	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signerHash]; !ok {
		return errUnauthorized
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
	inturn := snap.inturn(header.Number.Uint64(), signerHash)
	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
		return errInvalidDifficulty
	}
	if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
		return errInvalidDifficulty
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

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Prometheus) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Prometheus) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()

	log.Info("HPB Prometheus Seal is starting ")

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if c.config.Period == 0 && len(block.Transactions()) == 0 {
		return nil, errWaitTransactions
	}
	// Don't hold the signerHash fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn

	log.Info("Current seal random is" + header.Random)
	signerHash := common.BytesToAddressHash(common.Fnv_hash_to_byte([]byte(signer.Str() + header.Random)))

	log.Info("signer's address","signer", signer.Hex())

	c.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	//
	if err != nil {
		return nil, err
	}

	if _, authorized := snap.Signers[signerHash]; !authorized {
		return nil, errUnauthorized
	}

	log.Info("Proposed the random number in current round:" + header.Random)

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
		offset := snap.getOffset(header.Number.Uint64(), signerHash)

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
	sighash, err := signFn(accounts.Account{Address: signer}, sigHash(header).Bytes())
	if err != nil {
		return nil, err
	}

	//将签名后的结果返给到Extra中
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	return block.WithSeal(header), nil
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
