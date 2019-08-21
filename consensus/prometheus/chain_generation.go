// Copyright 2018 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2014 The go-ethereum Authors.
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
	"math"
	"strings"

	"github.com/hpb-project/go-hpb/account/abi"
	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/hvm/evm"
)

// constant parameter definition
const (
	checkpointInterval    = 1024 // voting interval
	inmemoryHistorysnaps  = 128
	inmemorySignatures    = 4096
	wiggleTime            = 1000 * time.Millisecond
	comCheckpointInterval = 2
	cadCheckpointInterval = 2
)

// Prometheus protocol constants.
var (
	epochLength   = uint64(30000)
	blockPeriod   = uint64(15)               // default block interval is 15 seconds
	uncleHash     = types.CalcUncleHash(nil) //
	diffInTurn    = big.NewInt(2)            // the node is in turn, and its diffcult number is 2
	diffNoTurn    = big.NewInt(1)            // the node is not in turn, and its diffcult number is 1
	reentryMux    sync.Mutex
	insPrometheus *Prometheus
)

type Prometheus struct {
	config *config.PrometheusConfig // Consensus config
	db     hpbdb.Database           // Database

	recents    *lru.ARCCache // the recent signature
	signatures *lru.ARCCache // the last signature

	proposals map[common.Address]bool // current proposals (hpb nodes)

	signer    common.Address
	randomStr string
	signFn    SignerFn       // Callback function
	lock      sync.RWMutex   // Protects the signerHash fields
	hboe      *boe.BoeHandle //boe handle for using boe
}

func New(config *config.PrometheusConfig, db hpbdb.Database) *Prometheus {

	conf := *config

	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}

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

type SignerFn func(accounts.Account, []byte) ([]byte, error)

func (c *Prometheus) GetNextRand(lastrand []byte, number uint64) ([]byte, error) {
	if number < consensus.StageNumberV {
		return c.hboe.GetNextHash(lastrand)
	} else {
		return c.hboe.GetNextHash_v2(lastrand)
	}

}

// Prepare function for Block
func (c *Prometheus) PrepareBlockHeader(chain consensus.ChainReader, header *types.Header, state *state.StateDB) error {

	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()

	parentnum := number - 1
	parentheader := chain.GetHeaderByNumber(parentnum)
	if parentheader == nil {
		return errors.New("-----PrepareBlockHeader parentheader------ is nil")
	}
	if len(parentheader.HardwareRandom) == 0 {
		return errors.New("---------- PrepareBlockHeader parentheader.HardwareRandom----------------- is nil")
	}

	if config.GetHpbConfigInstance().Node.TestMode == 1 || config.GetHpbConfigInstance().Network.RoleType == "synnode" {
		log.Debug("TestMode, using the gensis.json hardwarerandom")
		header.HardwareRandom = make([]byte, len(parentheader.HardwareRandom))
		copy(header.HardwareRandom, crypto.Keccak256(parentheader.HardwareRandom))
	} else {
		if c.hboe.HWCheck() {
			if parentheader.HardwareRandom == nil || len(parentheader.HardwareRandom) != 32 {
				log.Debug("parentheader.HardwareRandom is nil or length is not 32")
			}
			if boehwrand, err := c.GetNextRand(parentheader.HardwareRandom, number); err != nil {
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
			return errors.New("boe check fail")
		}
	}

	snap, err := voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, nil)
	if err != nil {
		return err
	}
	SetNetNodeType(snap)

	if 0 == len(snap.Signers) {
		return errors.New("prepare header get hpbnodesnap success, but snap`s singers is 0")
	}
	header.Difficulty = diffNoTurn
	if snap.CalculateCurrentMinerorigin(new(big.Int).SetBytes(header.HardwareRandom).Uint64(), c.GetSinger()) {
		header.Difficulty = diffInTurn
	}

	if header.Difficulty == diffNoTurn {
		// check mine backup block.
		var chooseBackupMiner = 100
		if header.Number.Int64() > int64(chooseBackupMiner) {
			signersgenblks := make([]types.Header, 0, chooseBackupMiner)
			for i := uint64(0); i < uint64(chooseBackupMiner); i++ {
				oldHeader := chain.GetHeaderByNumber(number - i - 1)
				if oldHeader != nil {
					signersgenblks = append(signersgenblks, *oldHeader)
				}
			}
			if !snap.CalculateBackupMiner(header.Number.Uint64(), c.GetSinger(), signersgenblks) {
				return errors.New("Not in turn")
			}
		} else {
			return errors.New("Not in turn")
		}
	}

	c.lock.RLock()

	if cadWinner, nonce, err := c.GetSelectPrehp(state, chain, header, number, false); nil == err {

		if cadWinner == nil || len(cadWinner) != 2 {
			//if no peers, add itself Coinbase to CandAddress and ComdAddress, or when candidate nodes is less len(hpbsnap.signers), the zero address will become the hpb node
			header.CandAddress = header.Coinbase
			header.ComdAddress = header.Coinbase
			header.VoteIndex = new(big.Int).SetUint64(0)
		} else {
			header.CandAddress = cadWinner[0].Address
			header.VoteIndex = new(big.Int).SetUint64(cadWinner[0].VoteIndex)
			header.ComdAddress = cadWinner[1].Address
		}
		log.Trace(">>>>>>>>>>>>>header.CandAddress<<<<<<<<<<<<<<<<<", "addr", header.CandAddress, "number", number) //for test

		if nil == nonce {
			copy(header.Nonce[:], consensus.NonceDropVote)
		} else {
			if number > consensus.StageNumberIII {
				copy(header.Nonce[len(header.Nonce)-len(nonce):], nonce)
			} else {
				copy(header.Nonce[:], consensus.NonceDropVote)
			}
		}

	} else {
		c.lock.RUnlock()
		return err
	}
	c.lock.RUnlock()

	// check the header
	if len(header.Extra) < consensus.ExtraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, consensus.ExtraVanity-len(header.Extra))...)
	}

	header.Extra = header.Extra[:consensus.ExtraVanity]

	// get all the hpb node address
	if number%consensus.HpbNodeCheckpointInterval == 0 {
		for _, signer := range snap.GetHpbNodes() {
			header.Extra = append(header.Extra, signer[:]...)
		}
	}

	header.Extra = append(header.Extra, make([]byte, consensus.ExtraSeal)...)
	header.MixDigest = common.Hash{}

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

// generate blocks by giving the signature
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

	log.Debug("GenBlockWithSig signer's address", "signer", signer.Hex(), "number", number)

	c.lock.RUnlock()

	snap, err := voting.GetHpbNodeSnap(c.db, c.recents, c.signatures, c.config, chain, number, header.ParentHash, nil)

	SetNetNodeType(snap)

	if err != nil {
		return nil, err
	}

	if _, authorized := snap.Signers[signer]; !authorized {
		return nil, consensus.ErrUnauthorized
	}

	delay := time.Unix(header.Time.Int64(), 0).Sub(time.Now())
	if delay < 0 {
		delay = 0
		header.Time = big.NewInt(time.Now().Unix())
	}
	// set delay time for out-turn hpb nodes
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		//It's not our turn explicitly to sign, delay it a bit
		currentminer := new(big.Int).SetBytes(header.HardwareRandom).Uint64() % uint64(len(snap.Signers)) //miner position
		myoffset := snap.GetOffset(header.Number.Uint64(), signer)
		distance := int(math.Abs(float64(int64(myoffset) - int64(currentminer))))
		if distance > len(snap.Signers)/2 {
			distance = len(snap.Signers) - distance
		}
		delay = time.Second*time.Duration(c.config.Period*2) + time.Duration(distance)*wiggleTime
	}

	log.Debug("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay), "number", number)

	select {
	case <-stop:
		return nil, nil
	case <-time.After(delay):
	}

	header.Coinbase = signer

	// signing to get the signature
	sighash, err := signFn(accounts.Account{Address: signer}, consensus.SigHash(header).Bytes())
	if err != nil {
		return nil, err
	}

	// put the signature result to the Extra field
	copy(header.Extra[len(header.Extra)-consensus.ExtraSeal:], sighash)

	return block.WithSeal(header), nil
}

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
				peer.SetRemoteType(discover.HpNode)
			}
		case discover.HpNode:
			if flag := FindHpbNode(peer.Address(), addresses); !flag {
				peer.SetRemoteType(discover.PreNode)
			}
		case discover.SynNode:
			if flag := FindHpbNode(peer.Address(), addresses); flag {
				peer.SetRemoteType(discover.HpNode)
			}
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

// retrieve the signer from the signature
func (c *Prometheus) Author(header *types.Header) (common.Address, error) {
	return consensus.Ecrecover(header, c.signatures)
}

func (c *Prometheus) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	err := c.CalculateRewards(chain, state, header, uncles)
	if err != nil {
		log.Info("CalculateRewards return", "info", err)
		if config.GetHpbConfigInstance().Node.TestMode != 1 && consensus.IgnoreRetErr != true {
			return nil, err
		}
	}
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)
	return types.NewBlock(header, txs, nil, receipts), nil
}

func (c *Prometheus) CalculateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header, uncles []*types.Header) error {
	if header.Number.Uint64()%consensus.HpbNodeCheckpointInterval != 0 && header.Number.Uint64() > consensus.StageNumberIV {
		log.Debug("CalculateRewards number is not 200 mulitple, do not reward", "number", header.Number)
		return nil
	}
	// Select the correct block reward based on chain progression
	var bigIntblocksoneyear = new(big.Int)
	secondsoneyesr := big.NewFloat(60 * 60 * 24 * 365)                         //seconds in one year
	secondsoneyesr.Quo(secondsoneyesr, big.NewFloat(float64(c.config.Period))) //blocks mined by miners in one year

	secondsoneyesr.Int(bigIntblocksoneyear) //from big.Float to big.Int

	bigrewards := big.NewFloat(float64(100000000 * 0.03)) //hpb coins additional issue one year
	bigrewards.Mul(bigrewards, big.NewFloat(float64(consensus.Nodenumfirst)))
	bigrewards.Quo(bigrewards, big.NewFloat(float64(consensus.Nodenumfirst)))

	bigIntblocksoneyearfloat := new(big.Float)
	bigIntblocksoneyearfloat.SetInt(bigIntblocksoneyear)      //from big.Int to big.Float
	A := bigrewards.Quo(bigrewards, bigIntblocksoneyearfloat) //calc reward mining one block

	if header.Number.Uint64() >= consensus.StageNumberIII {
		seconds := big.NewInt(0)
		tempheader := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
		fromtime := tempheader.Time

		for l := 0; l < 200; l++ {
			tempheader = chain.GetHeader(tempheader.ParentHash, tempheader.Number.Uint64()-1)
		}

		seconds.Sub(fromtime, tempheader.Time)
		secondsfloat := big.NewFloat(0)
		secondsfloat.SetInt(seconds)
		if header.Number.Uint64() <= consensus.StageNumberIV {
			secondsfloat.Quo(secondsfloat, big.NewFloat(200))
		}

		A.Quo(A, big.NewFloat(float64(c.config.Period)))
		A.Mul(A, secondsfloat)
	}
	log.Trace("CalculateRewards calc reward mining one block", "hpb coin", A)

	//mul 2/3
	A.Mul(A, big.NewFloat(2))
	A.Quo(A, big.NewFloat(3))

	//new two vars using below codes
	var bigA23 = new(big.Float) //2/3 one block reward
	var bigA13 = new(big.Float) //1/3 one block reward
	bigA23.Set(A)
	bigA13.Set(A)
	if consensus.StageNumberVI < header.Number.Uint64() {
		bigA13.Quo(bigA13, big.NewFloat(200.0))
	}

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
				log.Trace(">>>>>>>>>reward hpnode in the snapshot<<<<<<<<<<<<", "addr", v, "reward value", finalhpbrewards)
			}
		} else {
			return err
		}
	}

	if csnap, err := voting.GetCadNodeSnap(c.db, c.recents, chain, number, header.ParentHash); err == nil {
		if csnap != nil {
			if number < consensus.StageNumberII {
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
			} else if len(csnap.CanAddresses) > 0 {
				bigA23.Mul(bigA23, big.NewFloat(0.65))
				canBlockReward := bigA23.Quo(bigA23, big.NewFloat(float64(len(csnap.CanAddresses)))) //calc average reward coin part about cadidate nodes

				bigcadRewardwei := new(big.Float)
				bigcadRewardwei.SetInt(ether2weis)
				bigcadRewardwei.Mul(bigcadRewardwei, canBlockReward) //calc average reward weis part about candidate nodes

				cadReward := new(big.Int)
				bigcadRewardwei.Int(cadReward) //from big.Float to big.Int

				for _, caddress := range csnap.CanAddresses {
					state.AddBalance(caddress, cadReward) //reward every cad node average
					log.Trace("<<<<<<<<<<<<<<<reward prenode in the snapshot>>>>>>>>>>", "addr", caddress, "reward value", cadReward)
				}
			}

			if number%consensus.HpbNodeCheckpointInterval == 0 && number <= consensus.NewContractVersion && number >= consensus.StageNumberII {
				var errreward error
				loopcount := 3
			GETCONTRACTLOOP:
				if errreward = c.rewardvotepercentcad(chain, header, state, bigA13, ether2weisfloat, csnap, hpsnap); errreward != nil {
					log.Info("rewardvotepercent get contract fail", "info", errreward)
					loopcount -= 1
					if 0 != loopcount {
						goto GETCONTRACTLOOP
					}
				}
				return errreward
			}
			if number%consensus.HpbNodeCheckpointInterval == 0 && number > consensus.NewContractVersion {
				var errreward error
				loopcount := 3
				for i := 0; i < loopcount; i++ {
					errreward = c.rewardvotepercentcadByNewContrac(chain, header, state, bigA13, ether2weisfloat, csnap, hpsnap)
					if errreward == nil {
						break
					}
				}
				return errreward
			}
		}
	} else {
		return err
	}
	return nil
}

// API for the terminal
func (c *Prometheus) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "prometheus",
		Version:   "1.0",
		Service:   &API{chain: chain, prometheus: c},
		Public:    false,
	}}
}

func (c *Prometheus) rewardvotepercentcad(chain consensus.ChainReader, header *types.Header, state *state.StateDB, bigA13 *big.Float, ether2weisfloat *big.Float, csnap *snapshots.CadNodeSnap, hpsnap *snapshots.HpbNodeSnap) error {

	if csnap == nil {
		return errors.New("input param csnap is nil")
	}
	if hpsnap == nil {
		return errors.New("input param hpsnap is nil")
	}
	fechaddr := common.HexToAddress(consensus.Fechcontractaddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.GetSinger(),
		Coinbase:    c.GetSinger(),
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
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("getContractAddr InnerCall fail", "err", err)
		return err
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			return errors.New("return resultaddr is nil or length is 0")
		}
	}

	packres, _ = fechABI.Pack("getFunStr")
	resultfun, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("getFunStr InnerCall fail", "err", err)
		return err
	} else {
		if resultfun == nil || len(resultfun) < 74 {
			return errors.New("getFunStr InnerCall success but result length is short")
		}
	}

	//use read contract addr and funstr get vote result
	var realaddr common.Address
	if (consensus.StageNumberVI < header.Number.Uint64()) && (header.Number.Uint64() < consensus.StageNumberVII) {
		realaddr = common.HexToAddress("0x2072f300c98539760be185b05b738f9e94d2e48a")
	} else {
		realaddr = common.BytesToAddress(resultaddr)
	}
	log.Debug("Get Real Address From Votes:", "realaddr", realaddr.String())

	funparamstr := new([8]byte)
	copy(funparamstr[:], resultfun[66:66+8])
	funparam := common.Hex2Bytes(string(funparamstr[:]))

	paramnum := big.NewInt(header.Number.Int64())
	bufparam := new(bytes.Buffer)
	bufparam.Write(funparam[:])
	pendingbc := new([32]byte)
	bufparam.Write(pendingbc[:32-len(paramnum.Bytes())])
	bufparam.Write(paramnum.Bytes())

	resultvote, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), realaddr, bufparam.Bytes())
	vmenv.Cancel()
	if err != nil {
		log.Error("realaddr InnerCall fail", "err", err)
		return err
	}
	if resultvote == nil || len(resultvote) < 64+32+32+32+32 { //64 bytes + number1 + number2 + addrcounts + votes, at least have these bytes
		log.Debug("realaddr InnerCall success but result length is too short", "length", len(resultvote))
		return errors.New("realaddr InnerCall success but result length is too short")
	}
	resultvote = resultvote[64:]
	rewardsnum := consensus.HpbNodeCheckpointInterval //test

	addrbigcount := new(big.Int).SetBytes(resultvote[64 : 64+32])
	if len(resultvote) < int(64+32+32+addrbigcount.Uint64()*32) {
		return errors.New("1 return data length is not enough")
	}
	votebigcount := new(big.Int).SetBytes(resultvote[64+32+addrbigcount.Uint64()*32 : 64+32+32+addrbigcount.Uint64()*32])
	if len(resultvote) < int(64+32+32+addrbigcount.Uint64()*32+votebigcount.Uint64()*32) {
		return errors.New("2 return data length is not enough")
	}
	log.Debug("addr and vote peer count", "addrbigcount", addrbigcount.String(), "votebigcount", votebigcount.String())
	if addrbigcount.Cmp(votebigcount) != 0 {
		return errors.New("vote contract return addrs and votes number donnot match")
	}
	if addrbigcount.Uint64() == 0 {
		return nil
	}
	log.Debug("addr and vote peer count", "count", addrbigcount)

	voteres := make(map[common.Address]big.Int)
	for i := 0; i < int(addrbigcount.Int64()); i++ {
		var tempaddr common.Address
		tempaddr.SetBytes(resultvote[64+32+i*32 : 64+32+i*32+32])
		var tempvote big.Int
		tempvote.SetBytes(resultvote[64+32+(i+1+int(addrbigcount.Int64()))*32 : 64+32+(i+1+int(addrbigcount.Int64()))*32+32])
		voteres[tempaddr] = tempvote
	}
	VotePercents := make(map[common.Address]int64)
	for _, v := range csnap.CanAddresses {
		VotePercents[v] = 1
	}

	for addr := range voteres {
		_, ok1 := VotePercents[addr]
		_, ok2 := hpsnap.Signers[addr]
		if !ok1 && !ok2 {
			delete(voteres, addr)
		}
	}

	// get all the voting result
	votecounts := new(big.Int)
	for _, votes := range voteres {
		votecounts.Add(votecounts, &votes)
	}

	if votecounts.Cmp(big.NewInt(0)) == 0 {
		return nil
	}
	votecountsfloat := new(big.Float)
	votecountsfloat.SetInt(votecounts)

	bigA13.Quo(bigA13, big.NewFloat(2))
	bigA13.Mul(bigA13, ether2weisfloat)
	bigA13.Mul(bigA13, big.NewFloat(float64(rewardsnum))) //mul interval number
	log.Info("Reward vote", "totalvote", votecountsfloat, "total reawrd", bigA13)
	for addr, votes := range voteres {
		tempaddrvotefloat := new(big.Float)
		tempreward := new(big.Int)
		tempaddrvotefloat.SetInt(&votes)
		tempaddrvotefloat.Quo(tempaddrvotefloat, votecountsfloat)
		log.Info("Reward percent", "votes", votes, "percent", tempaddrvotefloat)
		tempaddrvotefloat.Mul(tempaddrvotefloat, bigA13)
		tempaddrvotefloat.Int(tempreward)
		state.AddBalance(addr, tempreward) //reward every cad node by vote percent
		log.Trace("++++++++++reward node with the vote contract++++++++++++", "addr", addr, "reward float", tempaddrvotefloat, "reward value", tempreward)
	}

	return nil
}

func (c *Prometheus) GetVoteRes(chain consensus.ChainReader, header *types.Header, state *state.StateDB) (error, *big.Int, map[common.Address]big.Int) {

	fechaddr := common.HexToAddress(consensus.Fechcontractaddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.GetSinger(),
		Coinbase:    c.GetSinger(),
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
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("getContractAddr InnerCall fail", "err", err)
		return err, nil, nil
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			return errors.New("return resultaddr is nil or length is 0"), nil, nil
		}
	}

	packres, _ = fechABI.Pack("getFunStr")
	resultfun, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("getFunStr InnerCall fail", "err", err)
		return err, nil, nil
	} else {
		if resultfun == nil || len(resultfun) < 74 {
			return errors.New("getFunStr InnerCall success but result length is short"), nil, nil
		}
	}

	//use read contract addr and funstr get vote result
	var realaddr common.Address
	if (consensus.StageNumberVI < header.Number.Uint64()) && (header.Number.Uint64() < consensus.StageNumberVII) {
		realaddr = common.HexToAddress("0x2072f300c98539760be185b05b738f9e94d2e48a")
	} else {
		realaddr = common.BytesToAddress(resultaddr)
	}
	log.Debug("Get Real Address From VoteRes:", "realaddr", realaddr.String())

	funparamstr := new([8]byte)
	copy(funparamstr[:], resultfun[66:66+8])
	funparam := common.Hex2Bytes(string(funparamstr[:]))

	paramnum := big.NewInt(header.Number.Int64())
	bufparam := new(bytes.Buffer)
	bufparam.Write(funparam[:])
	pendingbc := new([32]byte)
	bufparam.Write(pendingbc[:32-len(paramnum.Bytes())])
	bufparam.Write(paramnum.Bytes())

	resultvote, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), realaddr, bufparam.Bytes())
	vmenv.Cancel()
	if err != nil {
		log.Error("realaddr InnerCall fail", "err", err)
		return err, nil, nil
	}
	if resultvote == nil || len(resultvote) < 64+32+32+32+32 { //64 bytes + number1 + number2 + addrcounts + votes, at least have these bytes
		return errors.New("realaddr InnerCall success but result length is too short"), nil, nil
	}
	resultvote = resultvote[64:]

	addrbigcount := new(big.Int).SetBytes(resultvote[64 : 64+32])
	if len(resultvote) < int(64+32+32+addrbigcount.Uint64()*32) {
		return errors.New("1 return data length is not enough"), nil, nil
	}
	votebigcount := new(big.Int).SetBytes(resultvote[64+32+addrbigcount.Uint64()*32 : 64+32+32+addrbigcount.Uint64()*32])
	if len(resultvote) < int(64+32+32+addrbigcount.Uint64()*32+votebigcount.Uint64()*32) {
		return errors.New("2 return data length is not enough"), nil, nil
	}
	if addrbigcount.Cmp(votebigcount) != 0 {
		return errors.New("vote contract return addrs and votes number donnot match"), nil, nil
	}
	if addrbigcount.Uint64() == 0 {
		return nil, nil, nil
	}

	voteres := make(map[common.Address]big.Int)
	for i := 0; i < int(addrbigcount.Int64()); i++ {
		var tempaddr common.Address
		tempaddr.SetBytes(resultvote[64+32+i*32 : 64+32+i*32+32])
		var tempvote big.Int
		tempvote.SetBytes(resultvote[64+32+(i+1+int(addrbigcount.Int64()))*32 : 64+32+(i+1+int(addrbigcount.Int64()))*32+32])
		voteres[tempaddr] = tempvote
	}

	//获取所有cad的总票数
	votecounts := new(big.Int)
	for _, votes := range voteres {
		votecounts.Add(votecounts, &votes)
	}

	if votecounts.Cmp(big.NewInt(0)) == 0 {
		return nil, nil, nil
	}
	log.Trace(">>>>>>>>>>>>>>get vote result<<<<<<<<<<<<<<<<<", "value", voteres)

	return nil, votecounts, voteres
}

//input number, return key is commonAddress, order is value
func (c *Prometheus) GetBandwithRes(addrlist []common.Address, chain consensus.ChainReader, number uint64) (map[common.Address]int, error) {

	if number < consensus.NumberBackBandwith {
		return nil, nil
	}

	var bCalcZero = true
	if number < consensus.StageNumberIV {
		bCalcZero = false
	}

	mapaddrbandwithres := make(map[common.Address]*BandWithStatics)
	for i := number - consensus.NumberBackBandwith; i < number-100; i++ {
		if nil == chain.GetHeaderByNumber(i) {
			log.Warn("GetBandwithRes GetHeaderByNumber fail", "nmuber", i)
			return nil, errors.New("GetBandwithRes GetHeaderByNumber fail")
		}
		//statistics prehp node bandwith
		tempaddr1 := chain.GetHeaderByNumber(i).CandAddress
		tempBandwith1 := chain.GetHeaderByNumber(i).Nonce[6]
		if 0xff != tempBandwith1 {
			if 0 != tempBandwith1 || bCalcZero {
				if v, ok := mapaddrbandwithres[tempaddr1]; !ok {
					mapaddrbandwithres[tempaddr1] = &BandWithStatics{uint64(tempBandwith1), 1}
				} else {
					v.AverageValue = (v.AverageValue*v.Num + uint64(tempBandwith1)) / (v.Num + 1)
					v.Num += 1
				}
			}
		}

		//statistics comaddress node bandwith
		tempaddr2 := chain.GetHeaderByNumber(i).ComdAddress
		tempBandwith2 := chain.GetHeaderByNumber(i).Nonce[7]
		if 0xff != tempBandwith2 {
			if 0 != tempBandwith2 || bCalcZero {
				if v, ok := mapaddrbandwithres[tempaddr2]; !ok {
					mapaddrbandwithres[tempaddr2] = &BandWithStatics{uint64(tempBandwith2), 1}
				} else {
					v.AverageValue = (v.AverageValue*v.Num + uint64(tempBandwith2)) / (v.Num + 1)
					v.Num += 1
				}
			}
		}
		log.Trace(">>>>>>>>>header     bandwith<<<<<<<<<<<<<<", "string CandAddress addr", common.Bytes2Hex(tempaddr1[:]), "bandwith", tempBandwith1, "string ComdAddress addr", common.Bytes2Hex(tempaddr2[:]), "bandwith", tempBandwith2)
	}

	for i := 0; i < len(addrlist); i++ {
		if _, ok := mapaddrbandwithres[addrlist[i]]; !ok {
			mapaddrbandwithres[addrlist[i]] = &BandWithStatics{0, 0}
		}
	}

	arrayaddrbandwith := make([]common.Address, 0, 151)
	for k, v := range mapaddrbandwithres {
		log.Trace(">>>>>>>>>bandwith<<<<<<<<<<<<<<", "string addr", common.Bytes2Hex(k[:]), "bandwithaverage", v.AverageValue)
		arrayaddrbandwith = append(arrayaddrbandwith, k)
	}

	arrayaddrlen := len(arrayaddrbandwith)
	for i := 0; i <= arrayaddrlen-1; i++ {
		for j := arrayaddrlen - 1; j >= i+1; j-- {
			if bytes.Compare(arrayaddrbandwith[j-1][:], arrayaddrbandwith[j][:]) < 0 {
				arrayaddrbandwith[j-1], arrayaddrbandwith[j] = arrayaddrbandwith[j], arrayaddrbandwith[j-1]
			}
		}
	}

	for i := 0; i <= arrayaddrlen-1; i++ {
		for j := arrayaddrlen - 1; j >= i+1; j-- {
			if mapaddrbandwithres[arrayaddrbandwith[j-1]].AverageValue < mapaddrbandwithres[arrayaddrbandwith[j]].AverageValue {
				arrayaddrbandwith[j-1], arrayaddrbandwith[j] = arrayaddrbandwith[j], arrayaddrbandwith[j-1]
			}
		}
	}

	mapintaddr := make(map[int][]common.Address)
	offset := 0
	tempaddrslice := make([]common.Address, 0, 151)
	tempaddrslice = append(tempaddrslice, arrayaddrbandwith[0])
	mapintaddr[0] = tempaddrslice

	//set map, key is int ,value is []addr
	for i := 1; i < len(arrayaddrbandwith); i++ {
		if mapv, ok := mapintaddr[offset]; ok {
			if mapaddrbandwithres[arrayaddrbandwith[i]].AverageValue == mapaddrbandwithres[arrayaddrbandwith[i-1]].AverageValue {
				mapv = append(mapv, arrayaddrbandwith[i])
				mapintaddr[offset] = mapv
			} else {
				offset++
				tempaddrslice := make([]common.Address, 0, 151)
				tempaddrslice = append(tempaddrslice, arrayaddrbandwith[i])
				mapintaddr[offset] = tempaddrslice
			}
		} else {
			tempaddrslice := make([]common.Address, 0, 151)
			tempaddrslice = append(tempaddrslice, arrayaddrbandwith[i])
			mapintaddr[offset] = tempaddrslice
		}
	}

	res := make(map[common.Address]int)
	for k, v := range mapintaddr {
		for _, addr := range v {
			res[addr] = k
		}
	}

	return res, nil
}

type BandWithStatics struct {
	AverageValue uint64
	Num          uint64
}

func (c *Prometheus) GetAllBalances(addrlist []common.Address, state *state.StateDB) (map[common.Address]big.Int, error) {

	if addrlist == nil || len(addrlist) == 0 || state == nil {
		return nil, consensus.ErrBadParam
	}

	mapBalance := make(map[common.Address]big.Int)
	arrayaddrwith := make([]common.Address, 0, len(addrlist))
	for _, v := range addrlist {
		arrayaddrwith = append(arrayaddrwith, v)
	}
	for _, v := range arrayaddrwith {
		mapBalance[v] = *state.GetBalance(v)
		log.Trace("GetBalanceRes ranking", "string addr", common.Bytes2Hex(v[:]), "state get", state.GetBalance(v))
	}
	return mapBalance, nil
}

/*
 *  GetAllBalancesByCoin
 *
 *  In:   addrlist  hpnode addresses from contract
		  coinlist  hpHolderCoin addresses from contract,Correspond addrlist by index
		  state     a pointer to stateDB
 *  Out:  mapBalance   hpnode address->hpHolderCoin address's balance
 *
 *  This function will get the balance of the coinaddress corresponding to the hpnode address.
 *  To separate Coinbase account and holdercoin address
*/
func (c *Prometheus) GetAllBalancesByCoin(addrlist []common.Address, coinlist []common.Address, state *state.StateDB) (map[common.Address]big.Int, error) {

	if addrlist == nil || len(addrlist) == 0 || state == nil || len(addrlist) != len(coinlist) {
		return nil, consensus.ErrBadParam
	}

	mapBalance := make(map[common.Address]big.Int)
	arrayaddrwith := make([]common.Address, 0, len(addrlist))
	for _, v := range addrlist {
		arrayaddrwith = append(arrayaddrwith, v)
	}
	for i, v := range arrayaddrwith {
		mapBalance[v] = *state.GetBalance(coinlist[i])
		log.Trace("GetBalanceRes ranking", "string addr", common.Bytes2Hex(v[:]), "state get", state.GetBalance(coinlist[i]))
	}
	return mapBalance, nil
}
func (c *Prometheus) GetRankingRes(voteres map[common.Address]big.Int, addrlist []common.Address) (map[common.Address]int, error) {

	if addrlist == nil || len(addrlist) == 0 {
		return nil, consensus.ErrBadParam
	}

	mapVotes := make(map[common.Address]*big.Int)
	arrayaddrwith := make([]common.Address, 0, len(addrlist))
	for _, v := range addrlist {
		arrayaddrwith = append(arrayaddrwith, v)
	}
	for _, v := range arrayaddrwith {
		if votes, ok := voteres[v]; ok {
			mapVotes[v] = &votes
		} else {
			mapVotes[v] = big.NewInt(0)
		}
		log.Trace("GetAllVoteRes ranking", "string addr", common.Bytes2Hex(v[:]), "votes", mapVotes[v])
	}

	arrayaddrlen := len(arrayaddrwith)
	for i := 0; i <= arrayaddrlen-1; i++ {
		for j := arrayaddrlen - 1; j >= i+1; j-- {
			if mapVotes[arrayaddrwith[j-1]].Cmp(mapVotes[arrayaddrwith[j]]) < 0 {
				arrayaddrwith[j-1], arrayaddrwith[j] = arrayaddrwith[j], arrayaddrwith[j-1]
			}
		}
	}

	mapintaddr := make(map[int][]common.Address)
	offset := 0
	tempaddrslice := make([]common.Address, 0, 151)
	tempaddrslice = append(tempaddrslice, arrayaddrwith[0])
	mapintaddr[0] = tempaddrslice

	//set map, key is int ,value is []addr
	for i := 1; i < len(arrayaddrwith); i++ {
		if mapv, ok := mapintaddr[offset]; ok {
			if mapVotes[arrayaddrwith[i]].Cmp(mapVotes[arrayaddrwith[i-1]]) == 0 {
				mapv = append(mapv, arrayaddrwith[i])
				mapintaddr[offset] = mapv
			} else {
				offset++
				tempaddrslice := make([]common.Address, 0, 151)
				tempaddrslice = append(tempaddrslice, arrayaddrwith[i])
				mapintaddr[offset] = tempaddrslice
			}
		} else {
			tempaddrslice := make([]common.Address, 0, 151)
			tempaddrslice = append(tempaddrslice, arrayaddrwith[i])
			mapintaddr[offset] = tempaddrslice
		}
	}

	res := make(map[common.Address]int)
	for k, v := range mapintaddr {
		for _, addr := range v {
			res[addr] = k
		}
	}

	return res, nil
}

func (c *Prometheus) GetSinger() common.Address {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.signer
}

func (c *Prometheus) GetNodeinfoFromContract(chain consensus.ChainReader, header *types.Header, state *state.StateDB) (error, []p2p.HwPair) {

	fechaddr := common.HexToAddress(consensus.BootnodeInfoContractAddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.GetSinger(),
		Coinbase:    c.GetSinger(),
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		GasPrice:    new(big.Int).Set(big.NewInt(1000)),
	}
	cfg := evm.Config{}
	vmenv := evm.NewEVM(context, state, &config.GetHpbConfigInstance().BlockChain, cfg)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.BootnodeInfoContractABI))

	//get bootnode info "addr,cid,hid"
	packres, err := fechABI.Pack(consensus.BootnodeInfoContractMethodName)
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("get bootnode info from InnerCall fail", "err", err)
		return err, nil
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			return errors.New("return bootnode info result is nil or length is 0"), nil
		}
	}

	var out struct {
		Coinbases []common.Address
		Cid1s     [][32]byte
		Cid2s     [][32]byte
		Hids      [][32]byte
	}

	err = fechABI.Unpack(&out, consensus.BootnodeInfoContractMethodName, resultaddr)

	n := len(out.Coinbases)
	if len(out.Coinbases) == 0 || n != len(out.Cid1s) || n != len(out.Hids) || n != len(out.Cid2s) {
		log.Error("return 4 parts do not match", "Coinbases", n, "Cid1s", len(out.Cid1s), "Cid2s", len(out.Cid2s), "Hids", len(out.Hids))
		return errors.New("contract return 4 parts length do not match"), nil
	}

	res := make([]p2p.HwPair, 0, 151)
	for i := 0; i < n; i++ {
		if bytes.Compare(out.Coinbases[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		if bytes.Compare(out.Cid1s[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		if bytes.Compare(out.Cid2s[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		if bytes.Compare(out.Hids[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		buff := new(bytes.Buffer)
		_, err1 := buff.Write(out.Cid1s[i][:])
		_, err2 := buff.Write(out.Cid2s[i][:])
		if err1 != nil || err2 != nil {
			log.Error("construct cid fail", "err1", err1, "err2", err2)
			return errors.New("construct cid fail"), nil
		}
		res = append(res, p2p.HwPair{Adr: "0x" + common.Bytes2Hex(out.Coinbases[i][:]), Cid: buff.Bytes(), Hid: out.Hids[i][:]})
	}

	return nil, res
}

func PreDealNodeInfo(pairs []p2p.HwPair) (error, []p2p.HwPair) {
	if nil == pairs {
		return consensus.Errnilparam, nil
	}
	res := make([]p2p.HwPair, 0, len(pairs))
	log.Trace("PrepareBlockHeader from p2p.PeerMgrInst().HwInfo() return", "value", pairs) //for test
	for i := 0; i < len(pairs); i++ {
		if len(pairs[i].Adr) != 0 {
			pairs[i].Adr = strings.Replace(pairs[i].Adr, " ", "", -1)
			res = append(res, pairs[i])
		}
	}
	if 0 == len(res) {
		return errors.New("input node info addr all zero"), nil
	}
	log.Trace(">>>>>>>>>>>>> PreDealNodeInfo <<<<<<<<<<<<<<<<", "res", res, "length", len(res))

	return nil, res
}

/*
 *  GetCoinAddressFromNewContract
 *
 *  This function will get all coinbase addresses and holdercoin addresses.
 *  coinbase address and holdercoin address correspond by index
 */
func (c *Prometheus) GetCoinAddressFromNewContract(chain consensus.ChainReader, header *types.Header, state *state.StateDB) (error, []common.Address, []common.Address) {

	fechaddr := common.HexToAddress(consensus.NewContractAddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.GetSinger(),
		Coinbase:    c.GetSinger(),
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		GasPrice:    new(big.Int).Set(big.NewInt(1000)),
	}
	cfg := evm.Config{}
	vmenv := evm.NewEVM(context, state, &config.GetHpbConfigInstance().BlockChain, cfg)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.NewContractABI))

	//get bootnode info "addr,cid,hid"
	packres, err := fechABI.Pack(consensus.NewContractMethod, big.NewInt(consensus.InvokeIndexThree))
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("GetCoinAddressFromNewContract fail", "err", err)
		return err, nil, nil
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			return errors.New("return resultaddr is nil or length is 0"), nil, nil
		}
	}
	log.Debug("Innercall", "resultaddr", common.ToHex(resultaddr))

	var realcontract struct {
		contractAddr common.Address
		methodId     []byte
	}
	realcontract.contractAddr = common.BytesToAddress(resultaddr[12:32])
	realcontract.methodId = []byte(resultaddr[32:36])
	log.Debug("contractAddr", "contractaddr", realcontract.contractAddr)
	log.Debug("contractAddr", "methodId", common.ToHex(realcontract.methodId))

	result, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), realcontract.contractAddr, realcontract.methodId)
	if err != nil {
		log.Error("getFunStr InnerCall fail", "err", err)
		return err, nil, nil
	} else {
		if result == nil || len(result) == 0 {
			return errors.New("return resultaddr is nil or length is 0"), nil, nil
		}
	}
	log.Debug("resultvote", "resultvote", common.ToHex(result))

	var out struct {
		Coinbases   []common.Address
		HolderAddrs []common.Address
	}
	fechABI, _ = abi.JSON(strings.NewReader(consensus.NewContractInterfaceABI))
	err = fechABI.Unpack(&out, consensus.NewfetchAllHolderAddrs, result)

	if len(out.Coinbases) == 0 || len(out.HolderAddrs) == 0 || len(out.Coinbases) != len(out.HolderAddrs) {
		log.Error("return 4 parts do not match", "len(Coinbases)", len(out.Coinbases))
		return errors.New("contract return 4 parts length do not match"), nil, nil
	}

	return nil, out.Coinbases, out.HolderAddrs
}

/*
 *  GetVoteResFromNewContract
 *
 *  This function will get voteresult by contract.
 */
func (c *Prometheus) GetVoteResFromNewContract(chain consensus.ChainReader, header *types.Header, state *state.StateDB) (error, map[common.Address]big.Int) {

	fechaddr := common.HexToAddress(consensus.NewContractAddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.GetSinger(),
		Coinbase:    c.GetSinger(),
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		GasPrice:    new(big.Int).Set(big.NewInt(1000)),
	}
	cfg := evm.Config{}
	vmenv := evm.NewEVM(context, state, &config.GetHpbConfigInstance().BlockChain, cfg)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.NewContractABI))

	//get contract addr
	packres, err := fechABI.Pack(consensus.NewContractMethod, big.NewInt(consensus.InvokeIndexTwo))
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("getContractAddr InnerCall fail", "err", err)
		return err, nil
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			return errors.New("return resultaddr is nil or length is 0"), nil
		}
	}
	log.Debug("Innercall", "resultaddr", common.ToHex(resultaddr))

	var realcontract struct {
		contractAddr common.Address
		methodId     []byte
	}
	realcontract.contractAddr = common.BytesToAddress(resultaddr[12:32])
	realcontract.methodId = []byte(resultaddr[32:36])

	resultvote, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), realcontract.contractAddr, realcontract.methodId)
	if err != nil {
		log.Error("getFunStr InnerCall fail", "err", err)
		return err, nil
	} else {
		if resultvote == nil || len(resultvote) == 0 {
			return errors.New("return resultaddr is nil or length is 0"), nil
		}
	}
	log.Trace("resultvote", "resultvote", common.ToHex(resultvote))
	var result struct {
		CandidateAddrs []common.Address
		Nums           []*big.Int
	}
	fechABI, _ = abi.JSON(strings.NewReader(consensus.NewContractInterfaceABI))
	err = fechABI.Unpack(&result, consensus.NewfetchAllVoteResult, resultvote)
	if len(result.CandidateAddrs) == 0 || len(result.Nums) == 0 || len(result.CandidateAddrs) != len(result.Nums) {
		log.Error("getVote err", "len(addrs)", len(result.CandidateAddrs), "len(nums)", len(result.Nums), "err", err)
		return nil, nil
	}
	voteres := make(map[common.Address]big.Int)
	for i := 0; i < len(result.CandidateAddrs); i++ {
		voteres[result.CandidateAddrs[i]] = *result.Nums[i]
	}

	log.Trace(">>>>>>>>>>>>>>get vote result<<<<<<<<<<<<<<<<<", "value", voteres)

	return nil, voteres
}

/*
 *  GetNodeinfoFromNewContract
 *
 *  This function will get all boenodes by contract.
 */
func (c *Prometheus) GetNodeinfoFromNewContract(chain consensus.ChainReader, header *types.Header, state *state.StateDB) (error, []p2p.HwPair) {

	fechaddr := common.HexToAddress(consensus.NewContractAddr)
	context := evm.Context{
		CanTransfer: evm.CanTransfer,
		Transfer:    evm.Transfer,
		GetHash:     func(u uint64) common.Hash { return chain.GetHeaderByNumber(u).Hash() },
		Origin:      c.GetSinger(),
		Coinbase:    c.GetSinger(),
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		GasPrice:    new(big.Int).Set(big.NewInt(1000)),
	}
	cfg := evm.Config{}
	vmenv := evm.NewEVM(context, state, &config.GetHpbConfigInstance().BlockChain, cfg)
	fechABI, _ := abi.JSON(strings.NewReader(consensus.NewContractABI))

	//get bootnode info "addr,cid,hid"
	packres, _ := fechABI.Pack(consensus.NewContractMethod, big.NewInt(consensus.InvokeIndexOne))
	log.Debug("GetNodeinfoFromNewContract", "packres", common.ToHex(packres))
	resultaddr, err := vmenv.InnerCall(evm.AccountRef(c.GetSinger()), fechaddr, packres)
	if err != nil {
		log.Error("GetNodeinfoFromNewContract bootnode info from InnerCall fail", "err", err)
		return err, nil
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			log.Error("GetNodeinfoFromNewContract bootnode info from InnerCall fail", "err", err)
			return errors.New("return bootnode info result is nil or length is 0"), nil
		}
	}
	log.Debug("InnerCALL", "resultaddr", common.ToHex(resultaddr))
	var realcontract struct {
		contractAddr common.Address
		methodId     []byte
	}

	realcontract.contractAddr = common.BytesToAddress(resultaddr[12:32])
	realcontract.methodId = []byte(resultaddr[32:36])

	if err != nil || realcontract.contractAddr == consensus.Zeroaddr {
		log.Error("GetNodeinfoFromNewContract getcontractaddr", "err", err)
		return err, nil
	}
	resultaddr, err = vmenv.InnerCall(evm.AccountRef(c.GetSinger()), realcontract.contractAddr, realcontract.methodId)
	if err != nil {
		log.Error("GetNodeinfoFromNewContract bootnode info from InnerCall fail", "err", err)
		return err, nil
	} else {
		if resultaddr == nil || len(resultaddr) == 0 {
			log.Error("GetNodeinfoFromNewContract bootnode info from InnerCall fail", "err", err)
			return errors.New("return bootnode info result is nil or length is 0"), nil
		}
	}
	log.Trace("HPBInnerCALL", "resultaddr", common.ToHex(resultaddr))

	var out struct {
		Coinbases []common.Address
		Cid1s     [][32]byte
		Cid2s     [][32]byte
		Hids      [][32]byte
	}
	fechABI, _ = abi.JSON(strings.NewReader(consensus.NewContractInterfaceABI))
	err = fechABI.Unpack(&out, consensus.NewgetAllHpbNodes, resultaddr)

	n := len(out.Coinbases)
	if len(out.Coinbases) == 0 || n != len(out.Cid1s) || n != len(out.Hids) || n != len(out.Cid2s) {
		log.Error("return 4 parts do not match", "Coinbases", n, "Cid1s", len(out.Cid1s), "Cid2s", len(out.Cid2s), "Hids", len(out.Hids))
		return errors.New("contract return 4 parts length do not match"), nil
	}

	res := make([]p2p.HwPair, 0, 151)
	for i := 0; i < n; i++ {
		if bytes.Compare(out.Coinbases[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		if bytes.Compare(out.Cid1s[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		if bytes.Compare(out.Cid2s[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		if bytes.Compare(out.Hids[i][:], common.Hex2Bytes("0000000000000000000000000000000000000000")) == 0 {
			continue
		}
		buff := new(bytes.Buffer)
		_, err1 := buff.Write(out.Cid1s[i][:])
		_, err2 := buff.Write(out.Cid2s[i][:])
		if err1 != nil || err2 != nil {
			log.Error("construct cid fail", "err1", err1, "err2", err2)
			return errors.New("construct cid fail"), nil
		}
		res = append(res, p2p.HwPair{Adr: "0x" + common.Bytes2Hex(out.Coinbases[i][:]), Cid: buff.Bytes(), Hid: out.Hids[i][:]})
	}

	return nil, res
}

func (c *Prometheus) rewardvotepercentcadByNewContrac(chain consensus.ChainReader, header *types.Header, state *state.StateDB, bigA13 *big.Float, ether2weisfloat *big.Float, csnap *snapshots.CadNodeSnap, hpsnap *snapshots.HpbNodeSnap) error {

	if csnap == nil {
		return errors.New("input param csnap is nil")
	}
	if hpsnap == nil {
		return errors.New("input param hpsnap is nil")
	}
	err, voteres := c.GetVoteResFromNewContract(chain, header, state)
	if err != nil {
		return err
	}
	VotePercents := make(map[common.Address]int64)
	for _, v := range csnap.CanAddresses {
		VotePercents[v] = 1
	}

	for addr := range voteres {
		_, ok1 := VotePercents[addr]
		_, ok2 := hpsnap.Signers[addr]
		if !ok1 && !ok2 {
			delete(voteres, addr)
		}
	}

	// get all the voting result
	votecounts := new(big.Int)
	for _, votes := range voteres {
		votecounts.Add(votecounts, &votes)
	}

	if votecounts.Cmp(big.NewInt(0)) == 0 {
		return nil
	}
	votecountsfloat := new(big.Float)
	votecountsfloat.SetInt(votecounts)

	bigA13.Quo(bigA13, big.NewFloat(2))
	bigA13.Mul(bigA13, ether2weisfloat)
	bigA13.Mul(bigA13, big.NewFloat(float64(consensus.HpbNodeCheckpointInterval))) //mul interval number
	log.Trace("Reward vote", "totalvote", votecountsfloat, "total reawrd", bigA13)
	for addr, votes := range voteres {
		tempaddrvotefloat := new(big.Float)
		tempreward := new(big.Int)
		tempaddrvotefloat.SetInt(&votes)
		tempaddrvotefloat.Quo(tempaddrvotefloat, votecountsfloat)
		log.Trace("Reward percent", "votes", votes, "percent", tempaddrvotefloat)
		tempaddrvotefloat.Mul(tempaddrvotefloat, bigA13)
		tempaddrvotefloat.Int(tempreward)
		state.AddBalance(addr, tempreward) //reward every cad node by vote percent
		log.Trace("++++++++++reward node with the vote contract++++++++++++", "addr", addr, "reward float", tempaddrvotefloat, "reward value", tempreward)
	}

	return nil
}
