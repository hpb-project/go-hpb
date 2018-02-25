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
	"errors"
)

	// extra-data 信息不完整
	var errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// 缺少签名
	var errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// 如果非检查点数据块在其外部数据字段中包含签名者数据，则返回errExtraSigners。
	var errExtraSigners = errors.New("non-checkpoint block contains extra signer list")
	
	// 没有经过授权的Signers
	var errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// 错误的签名
	var errInvalidMixDigest = errors.New("non-zero mix digest")

	// 非法的叔叔hash
	var errInvalidUncleHash = errors.New("non empty uncle hash")

	// 错误的难度值，目前的难度值仅1和2
	var errInvalidDifficulty = errors.New("invalid difficulty")
	
	// 错误的时间戳，保持一定的间隔
	var ErrInvalidTimestamp = errors.New("invalid timestamp")

	// 不可靠的投票
	var errInvalidVotingChain = errors.New("invalid voting chain")

	// 未授权错误
	var errUnauthorized = errors.New("unauthorized")

    // 禁止使用0交易的区块
	var errWaitTransactions = errors.New("waiting for transactions")
	
	// 未知的区块
	var errUnknownBlock = errors.New("unknown block")

	// 检查点异常
	var errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// 投票只有两种结果
	var errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")
	// 非法的投票检查点
	var errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")
