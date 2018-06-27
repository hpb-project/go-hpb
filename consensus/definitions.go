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

package consensus

import (
	"errors"
	
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/common/hexutil"
	"github.com/hpb-project/ghpb/core/types"

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/ghpb/common/crypto"
	"github.com/hpb-project/ghpb/common/crypto/sha3"
	"github.com/hpb-project/ghpb/common/rlp"

)


var (
	// ErrUnknownAncestor is returned when validating a block requires an ancestor
	// that is unknown.
	ErrUnknownAncestor = errors.New("unknown ancestor")

	// ErrFutureBlock is returned when a block's timestamp is in the future according
	// to the current node.
	ErrFutureBlock = errors.New("block in the future")

	// ErrInvalidNumber is returned if a block's number doesn't equal it's parent's
	// plus one.
	ErrInvalidNumber = errors.New("invalid block number")
	
	// extra-data 信息不完整
	 ErrMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// 缺少签名
	 ErrMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// 如果非检查点数据块在其外部数据字段中包含签名者数据，则返回errExtraSigners。
	 ErrExtraSigners = errors.New("non-checkpoint block contains extra signer list")
	
	// 没有经过授权的Signers
	 ErrInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// 错误的签名
	 ErrInvalidMixDigest = errors.New("non-zero mix digest")

	// 非法的叔叔hash
	 ErrInvalidUncleHash = errors.New("non empty uncle hash")

	// 错误的难度值，目前的难度值仅1和2
	 ErrInvalidDifficulty = errors.New("invalid difficulty")
	
	// 错误的时间戳，保持一定的间隔
	 ErrInvalidTimestamp = errors.New("invalid timestamp")

	// 不可靠的投票
	 ErrInvalidVotingChain = errors.New("invalid voting chain")

	// 未授权错误
	 ErrUnauthorized = errors.New("unauthorized")

    // 禁止使用0交易的区块
	 ErrWaitTransactions = errors.New("waiting for transactions")
	
	// 未知的区块
	 ErrUnknownBlock = errors.New("unknown block")

	// 检查点异常
	 ErrInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// 投票只有两种结果
	 ErrInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")
	// 非法的投票检查点
	 ErrInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")
)

var (
	NonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signerHash
	NonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signerHash.
	
	ExtraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signerHash vanity
	ExtraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signerHash seal
)


// 获取当前的签名者
func Ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {

	// 从缓存中获取
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// 从头文件中获取extra-data
	if len(header.Extra) < ExtraSeal {
		return common.Address{}, ErrMissingSignature
	}
	signature := header.Extra[len(header.Extra)-ExtraSeal:]

	// 还原公钥
	pubkey, err := crypto.Ecrecover(SigHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}


// 对区块头部进行签名，最小65Byte
func SigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		//header.CoinbaseHash,
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


  

