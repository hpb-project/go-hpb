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

package consensus

import (
	"errors"

	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/hexutil"

	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/crypto/sha3"
	"github.com/hpb-project/go-hpb/common/rlp"
)

const HpbNodeCheckpointInterval = 200
const HpbNodeBacktrackingNumber = 100
const Nodenumfirst = 151
const StepLength = 4
const FechHpbBallotAddrABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"roundNum\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"contractAddr\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"deleteAdmin\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_contractAddr\",\"type\":\"address\"}],\"name\":\"setContractAddr\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_funStr\",\"type\":\"string\"}],\"name\":\"setFunStr\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"addAdmin\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"funStr\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getContractAddr\",\"outputs\":[{\"name\":\"_contractAddr\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getRoundNum\",\"outputs\":[{\"name\":\"_roundNum\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"adminMap\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_roundNum\",\"type\":\"uint256\"}],\"name\":\"setRoundNum\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getFunStr\",\"outputs\":[{\"name\":\"_funStr\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"_contractAddr\",\"type\":\"address\"}],\"name\":\"SetContractAddr\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"_funStr\",\"type\":\"string\"}],\"name\":\"SetFunStr\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"_roundNum\",\"type\":\"uint256\"}],\"name\":\"SetRoundNum\",\"type\":\"event\"}]"
const Fechcontractaddr = "0x43f75fc8c4fc623b8ddf0039ee76e9d4ca9ca7b3"

const BootnodeInfoContractABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"coinbases\",\"type\":\"address[]\"}],\"name\":\"deleteHpbNodeBatch\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"coinbase\",\"type\":\"address\"},{\"name\":\"cid1\",\"type\":\"bytes32\"},{\"name\":\"cid2\",\"type\":\"bytes32\"},{\"name\":\"hid\",\"type\":\"bytes32\"}],\"name\":\"updateHpbNode\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"currentStageNum\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"nodeStages\",\"outputs\":[{\"name\":\"blockNumber\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"coinbases\",\"type\":\"address[]\"},{\"name\":\"cid1s\",\"type\":\"bytes32[]\"},{\"name\":\"cid2s\",\"type\":\"bytes32[]\"},{\"name\":\"hids\",\"type\":\"bytes32[]\"}],\"name\":\"addHpbNodeBatch\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_stageNum\",\"type\":\"uint256\"}],\"name\":\"getAllHpbNodesByStageNum\",\"outputs\":[{\"name\":\"coinbases\",\"type\":\"address[]\"},{\"name\":\"cid1s\",\"type\":\"bytes32[]\"},{\"name\":\"cid2s\",\"type\":\"bytes32[]\"},{\"name\":\"hids\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"coinbases\",\"type\":\"address[]\"},{\"name\":\"cid1s\",\"type\":\"bytes32[]\"},{\"name\":\"cid2s\",\"type\":\"bytes32[]\"},{\"name\":\"hids\",\"type\":\"bytes32[]\"}],\"name\":\"updateHpbNodeBatch\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"stageNum\",\"type\":\"uint256\"}],\"name\":\"copyAllHpbNodesByStageNum\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"addStage\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"coinbase\",\"type\":\"address\"}],\"name\":\"deleteHpbNode\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getAllHpbNodes\",\"outputs\":[{\"name\":\"Coinbases\",\"type\":\"address[]\"},{\"name\":\"Cid1s\",\"type\":\"bytes32[]\"},{\"name\":\"Cid2s\",\"type\":\"bytes32[]\"},{\"name\":\"Hids\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"coinbase\",\"type\":\"address\"},{\"name\":\"cid1\",\"type\":\"bytes32\"},{\"name\":\"cid2\",\"type\":\"bytes32\"},{\"name\":\"hid\",\"type\":\"bytes32\"}],\"name\":\"addHpbNode\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"to\",\"type\":\"address\"}],\"name\":\"TransferOwnership\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"stageNum\",\"type\":\"uint256\"}],\"name\":\"ChangeStage\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"stageNum\",\"type\":\"uint256\"},{\"indexed\":true,\"name\":\"coinbase\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"cid1\",\"type\":\"bytes32\"},{\"indexed\":false,\"name\":\"cid2\",\"type\":\"bytes32\"},{\"indexed\":true,\"name\":\"hid\",\"type\":\"bytes32\"}],\"name\":\"AddHpbNode\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"stageNum\",\"type\":\"uint256\"},{\"indexed\":true,\"name\":\"coinbase\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"cid1\",\"type\":\"bytes32\"},{\"indexed\":false,\"name\":\"cid2\",\"type\":\"bytes32\"},{\"indexed\":true,\"name\":\"hid\",\"type\":\"bytes32\"}],\"name\":\"UpdateHpbNode\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"coinbase\",\"type\":\"address\"}],\"name\":\"DeleteHpbNode\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"stageNum\",\"type\":\"uint256\"}],\"name\":\"CopyAllHpbNodesByStageNum\",\"type\":\"event\"}]"
const BootnodeInfoContractAddr = "0x2251a2533556e7c6243a73f015eb96aa155c5791" //mainnet nodeinfo contract addr
const BootnodeInfoContractMethodName = "getAllHpbNodes"

const NewContractAddr = "0x5f1fbc00690f2cba74985126cae1b9e0bc09cdc8"
const NewContractABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"invokeIndex\",\"type\":\"uint256\"}],\"name\":\"getInvokeContract\",\"outputs\":[{\"name\":\"contractAddr\",\"type\":\"address\"},{\"name\":\"methodId\",\"type\":\"bytes4\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

const NewContractMethod = "getInvokeContract"
const NewfetchAllHolderAddrs = "fetchAllHolderAddrs"
const NewfetchAllVoteResult = "fetchAllVoteResult"
const NewgetAllHpbNodes = "getAllHpbNodes"

const NewContractInterfaceABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"fetchAllVoteResult\",\"outputs\":[{\"name\":\"candidateAddrs\",\"type\":\"address[]\"},{\"name\":\"nums\",\"type\":\"uint256[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"fetchAllHolderAddrs\",\"outputs\":[{\"name\":\"coinbases\",\"type\":\"address[]\"},{\"name\":\"_holderAddrs\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getAllHpbNodes\",\"outputs\":[{\"name\":\"coinbases\",\"type\":\"address[]\"},{\"name\":\"cid1s\",\"type\":\"bytes32[]\"},{\"name\":\"cid2s\",\"type\":\"bytes32[]\"},{\"name\":\"hids\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

const InvokeIndexOne = 1
const InvokeIndexTwo = 2
const InvokeIndexThree = 3

const Hpcalclookbackround = 3
const BandwithLimit = 200       //200M
const NumberBackBandwith = 1100 //bandwith statistic block num + 100
// Todo : lrj change to english.
var (
	HpbNodenumber = 31    //hpb nodes number
	NumberPrehp   = 20    //nodes num from 151 nodes select
	IgnoreRetErr  = false //ignore finalize return err

	StageNumberII  uint64 = 260000
	StageNumberIII uint64 = 1200000
	StageNumberIV  uint64 = 2560000
	StageNumberV   uint64 = 999999000000 // no use
	StageNumberVI  uint64 = 2561790
	StageNumberVII uint64 = 2896000

	NewContractVersion        uint64 = 3788000
	CadNodeCheckpointInterval uint64 = 200
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

	// extra-data
	ErrMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	ErrMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	ErrExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// invalid signer list on checkpoint block
	ErrInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	ErrInvalidMixDigest = errors.New("non-zero mix digest")

	ErrInvalidUncleHash = errors.New("non empty uncle hash")

	// invalid difficulty, only 1 or 2 allowed
	ErrInvalidDifficulty = errors.New("invalid difficulty")

	ErrInvalidTimestamp = errors.New("invalid timestamp")

	ErrInvalidVotingChain = errors.New("invalid voting chain")

	ErrUnauthorized = errors.New("unauthorized")

	ErrWaitTransactions = errors.New("waiting for transactions")

	ErrUnknownBlock = errors.New("unknown block")

	ErrInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	ErrInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")
	
	// vote nonce in checkpoint block non-zero
	ErrInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")
	// reject block but do not drop peer
	ErrInvalidblockbutnodrop = errors.New("reject block but do not drop peer")
	// boe hecheck err
	Errboehwcheck = errors.New("boe hwcheck err")
	// verify header random err
	Errrandcheck = errors.New("verify header random err")
	// bandwith err
	ErrBandwith = errors.New("verify header bandwith beyond the limit")
	// bad param
	ErrBadParam = errors.New("input bad param")
	// invalid cadaddress
	ErrInvalidCadaddr = errors.New("invalid cadaddress")
	Errnilparam       = errors.New("input param is nil")
	ErrNoLastBlock    = errors.New("No Last Block when verify during the fullsync")
)

var (
	NonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signerHash
	NonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signerHash.
	Zeroaddr      = common.HexToAddress("0x0000000000000000000000000000000000000000")

	ExtraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signerHash vanity
	ExtraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signerHash seal
)

// get current signer
func Ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {

	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	
	if len(header.Extra) < ExtraSeal {
		return common.Address{}, ErrMissingSignature
	}
	signature := header.Extra[len(header.Extra)-ExtraSeal:]

	// recover the public key
	pubkey, err := crypto.Ecrecover(SigHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

func SigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
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

func SetTestParam() {
	StageNumberII = 1
	StageNumberIII = 0
	StageNumberIV = 1
}
