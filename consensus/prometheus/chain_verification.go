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
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	"github.com/hpb-project/go-hpb/consensus/voting"
	"github.com/hpb-project/go-hpb/network/p2p"
	"math/big"
	"strings"
	"time"
)

// 验证头部，对外调用接口
func (c *Prometheus) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool, mode config.SyncMode) error {
	return c.verifyHeader(chain, header, nil, mode)
}

// 批量验证
func (c *Prometheus) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool, mode config.SyncMode) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i], mode)

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (c *Prometheus) SetNetTopology(chain consensus.ChainReader, headers []*types.Header) {
	//for i, header := range headers {
	//	if (i%consensus.HpbNodeCheckpointInterval == 0) && (i != 1) {
	//		c.SetNetTypeByOneHeader(chain, header, headers[:i])
	//	}
	//}
	c.SetNetTypeByOneHeader(chain, headers[len(headers)-1], nil)
}

func (c *Prometheus) SetNetTypeByOneHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) {
	number := header.Number.Uint64()
	// Retrieve the getHpbNodeSnap needed to verify this header and cache it
	snap, err := voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, parents)
	if err != nil || len(snap.Signers) == 0 {
		log.Warn("-------------------snap retrieve fail-------------------------")
		return
	}
	SetNetNodeType(snap)
}

// 批量验证，为了避免，支持批量传入
func (c *Prometheus) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header, mode config.SyncMode) error {
	if header.Number == nil {
		return consensus.ErrUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	//if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
	if header.Time.Cmp(new(big.Int).Add(big.NewInt(time.Now().Unix()), new(big.Int).SetUint64(c.config.Period))) > 0 {
		log.Error("errInvalidChain occur in (c *Prometheus) verifyHeader()", "header.Time", header.Time, "big.NewInt(time.Now().Unix())", big.NewInt(time.Now().Unix()))
		return consensus.ErrFutureBlock
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % consensus.HpbNodeCheckpointInterval) == 0
	//if checkpoint && header.Coinbase != (common.Address{}) {
	//	return consensus.ErrInvalidCheckpointBeneficiary
	//}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	//if !bytes.Equal(header.Nonce[:], consensus.NonceAuthVote) && !bytes.Equal(header.Nonce[:], consensus.NonceDropVote) {
	//	return consensus.ErrInvalidVote
	//}
	//if checkpoint && !bytes.Equal(header.Nonce[:], consensus.NonceDropVote) {
	//	return consensus.ErrInvalidCheckpointVote
	//}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < consensus.ExtraVanity {
		return consensus.ErrMissingVanity
	}
	if len(header.Extra) < consensus.ExtraVanity+consensus.ExtraSeal {
		return consensus.ErrMissingSignature
	}
	// Ensure that the extra-data contains a signerHash list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - consensus.ExtraVanity - consensus.ExtraSeal
	if !checkpoint && signersBytes != 0 {
		return consensus.ErrExtraSigners
	}
	//if checkpoint && signersBytes%common.AddressLength != 0 {
	//	log.Info("at checkpoint", "checkpoint",checkpoint)
	//	return consensus.ErrInvalidCheckpointSigners
	//}
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
	//Ensure that the block`s nonce that is peer`s bandwith do not beyond the BandwithLimit too much
	//check prehp node bandwith
	if !bytes.Equal(header.Nonce[:], consensus.NonceAuthVote) {
		if new(big.Int).SetInt64(int64(header.Nonce[6])).Int64() > consensus.BandwithLimit+10 {
			return consensus.ErrBandwith
		}
		if new(big.Int).SetInt64(int64(header.Nonce[7])).Int64() > consensus.BandwithLimit+10 {
			return consensus.ErrBandwith
		}
	}

	// All basic checks passed, verify cascading fields
	return c.verifyCascadingFields(chain, header, parents, mode)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *Prometheus) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header, mode config.SyncMode) error {
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
	/*
		snap, err := voting.GetHpbNodeSnap(c.db, c.recents,c.signatures,c.config,chain, number, header.ParentHash, parents)
		if err != nil {
			return err
		}
		// If the block is a checkpoint block, verify the signerHash list
		if number%consensus.HpbNodeCheckpointInterval == 0 {
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
	*/
	if number > consensus.StageNumberIII && mode == config.FullSync {

		lastheader := chain.GetHeader(header.ParentHash, number-1)
		state, _ := chain.StateAt(lastheader.Root)
		if cadWinner, _, err := c.GetSelectPrehp(state, chain, header, number, true); nil == err {
			if bytes.Compare(cadWinner[0].Address[:], header.CandAddress[:]) != 0 {
				return consensus.ErrInvalidCadaddr
			}
		} else {
			return err
		}
	}

	// All basic checks passed, verify the seal and return
	return c.verifySeal(chain, header, parents, mode)
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
//in the header satisfies the consensus protocol requirements.
func (c *Prometheus) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	//return c.verifySeal(chain, header, nil)
	return nil
}

// 验证封装的正确性，判断是否满足共识算法的需求
func (c *Prometheus) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header, mode config.SyncMode) error {
	// Verifying the genesis block is not supported

	number := header.Number.Uint64()
	if number == 0 {
		return consensus.ErrUnknownBlock
	}
	var parentheader *types.Header
	if len(parents) > 0 {
		parentheader = parents[len(parents)-1]
	} else {
		parentheader = chain.GetHeader(header.ParentHash, number-1)
	}

	// Resolve the authorization key and check against signers
	signer, err := consensus.Ecrecover(header, c.signatures)
	if err != nil {
		return err
	}

	var snap *snapshots.HpbNodeSnap
	if mode == config.FullSync {
		snap, err = voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, nil)
		if err != nil {
			log.Debug("verifySeal GetHpbNodeSnap fail", "err", err)
			return consensus.ErrInvalidblockbutnodrop
		}
		if _, ok := snap.Signers[signer]; !ok {
			for _, v := range snap.Signers {
				log.Trace("verify fail consensus.ErrUnauthorized", "snap.Signer", v)
			}
			return consensus.ErrUnauthorized
		}
	}

	// false &&
	if /*mode == config.FullSync && */ config.GetHpbConfigInstance().Network.RoleType != "synnode" && config.GetHpbConfigInstance().Network.RoleType != "bootnode" && number >= consensus.StageNumberII {
		// Retrieve the getHpbNodeSnap needed to verify this header and cache it

		if config.GetHpbConfigInstance().Node.TestMode != 1 {
			if !c.hboe.HWCheck() {
				return consensus.Errboehwcheck
			}
			//parentheader := chain.GetHeader(header.ParentHash, number-1)
			if parentheader == nil {
				log.Error("verifySeal GetHeaderByNumber", "fail", "header is nil")
				return consensus.ErrInvalidblockbutnodrop
			}
			if parentheader.HardwareRandom == nil || len(parentheader.HardwareRandom) == 0 {
				log.Error("verifySeal GetHeaderByNumber", "fail", "HardwareRandom is nil")
				return consensus.ErrInvalidblockbutnodrop
			}
			newrand, err := c.GetNextRand(parentheader.HardwareRandom, number)
			if err != nil {
				log.Error("verifySeal GetNextHash", "fail", err)
				return consensus.ErrInvalidblockbutnodrop
			}
			if bytes.Compare(newrand, header.HardwareRandom) != 0 {
				log.Error("verify fail consensus.Errrandcheck", "boe gen random", common.Bytes2Hex(newrand))
				return consensus.Errrandcheck
			}
		}

		if mode == config.FullSync {
			//Ensure that the difficulty corresponds to the turn-ness of the signerHash
			inturn := snap.CalculateCurrentMinerorigin(new(big.Int).SetBytes(header.HardwareRandom).Uint64(), signer)
			if inturn {
				if header.Difficulty.Cmp(diffInTurn) != 0 {
					return consensus.ErrInvalidDifficulty
				}
			} else { //inturn is false
				if header.Difficulty.Cmp(diffNoTurn) != 0 {
					return consensus.ErrInvalidDifficulty
				}
			}
		}

	}
	return nil
}

func (c *Prometheus) GetSelectPrehp(state *state.StateDB, chain consensus.ChainReader, header *types.Header, number uint64, verify bool) ([]*snapshots.CadWinner, []byte, error) {

	if state == nil {
		return nil, nil, errors.New("chain stateAt return nil")
	}
	err, bootnodeinfp := c.GetNodeinfoFromContract(chain, header, state)
	if nil != err || len(bootnodeinfp) == 0 || bootnodeinfp == nil {
		log.Debug("GetNodeinfoFromContract err", "value", err)
		//return err
	GETBOOTNODEINFO:
		bootnodeinfp = p2p.PeerMgrInst().GetHwInfo()
		if bootnodeinfp == nil || len(bootnodeinfp) == 0 {
			goto GETBOOTNODEINFO
		}
		err, bootnodeinfp = PreDealNodeInfo(bootnodeinfp)
		if nil != err {
			return nil, nil, err
		}
	} else {
		err, bootnodeinfp = PreDealNodeInfo(bootnodeinfp)
		if nil != err {
			return nil, nil, err
		}
		err = p2p.PeerMgrInst().SetHwInfo(bootnodeinfp)
		if nil != err {
			log.Debug("VerifySelectPrehp get node info from contract, p2p.PeerMgrInst().SetHwInfo set fail ", "err", err)
			return nil, nil, err
		}
	}
	//log.Error("------------test-------------","bootnodeinfp", bootnodeinfp)
	addrlist := make([]common.Address, 0, len(bootnodeinfp))
	for _, v := range bootnodeinfp {
		addrlist = append(addrlist, common.HexToAddress(strings.Replace(v.Adr, " ", "", -1)))
	}

	if len(addrlist) == 0 {
		return nil, nil, errors.New("forbid mining before successfully connect with bootnode")
	}

	if verify == true {
		comaddrinboot := false
		for _, v := range bootnodeinfp {
			addr := common.HexToAddress(v.Adr)
			if bytes.Compare(addr[:], header.ComdAddress[:]) == 0 {
				comaddrinboot = true
				break
			}
		}

		if !comaddrinboot {
			return nil, nil, errors.New("comaddress invalid")
		}
	}

	//get all votes
	err, _, voteres := c.GetVoteRes(chain, header, state)
	if nil != err {
		//return false, err
		log.Debug("GetVoteRes return err, please deploy contract!")
		voteres = make(map[common.Address]big.Int)
		for _, v := range addrlist {
			voteres[v] = *big.NewInt(0)
		}
	}
	//get votes ranking res
	voterank, errvote := c.GetRankingRes(voteres, addrlist)
	//get bandwith ranking res
	bandrank, errbandwith := c.GetBandwithRes(addrlist, chain, number-1)
	//get all balances
	allbalances, err := c.GetAllBalances(addrlist, state)
	if err != nil {
		return nil, nil, err
	}
	//get balance ranking res
	balancerank, errbalance := c.GetRankingRes(allbalances, addrlist)
	if errvote != nil || errbandwith != nil || errbalance != nil {
		return nil, nil, errors.New("get ranking fail")
	}
	rankingmap := make(map[common.Address]float64)
	for _, v := range addrlist {
		rankingmap[v] = float64(bandrank[v])*0.5 + float64(balancerank[v])*0.15 + float64(voterank[v])*0.35
		log.Trace("**********************+three item ranking info******************", "addr", v, "bandwith", bandrank[v], "balance", balancerank[v], "vote", voterank[v], "number", number)
	}

	random := crypto.Keccak256(header.Number.Bytes())
	// Get the best peer from the network
	if cadWinner, nonce, err := voting.GetCadNodeFromNetwork(random, rankingmap); err == nil {
		return cadWinner, nonce, nil
	} else {
		return nil, nil, err
	}
}
