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

package bc

import (
	"errors"
	"fmt"
	"github.com/hpb-project/go-hpb/account/abi"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/vmcore"
	"github.com/hpb-project/go-hpb/vmcore/vm"
	"math/big"
	"strings"

	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/math"
	"github.com/hpb-project/go-hpb/config"
)

var (
	Big0                         = big.NewInt(0)
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
	ErrInsufficientBalance       = errors.New("insufficient balance")

	gasDiscountContractAddr = common.HexToAddress("0x6c0c0bcc145672bd0Fd67dD771947F6420c4533d")
	gasABI                  = "[{\"constant\":true,\"inputs\":[{\"name\":\"dappaddr\",\"type\":\"address\"}],\"name\":\"getratebyaddr\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"},{\"name\":\"\",\"type\":\"uint256\"},{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"}]"
	gasFunname              = "getratebyaddr"
	gasCacheContractAddr    = common.HexToAddress("0x6c0c0bcc145672bd0Fd67dD771947F6420c4533d")
	gasCacheAddrs           = map[common.Address]bool{}
	gasCacheFunname         = "getaddrs"
	gasCacheFunABI          = "[{\"constant\":false,\"inputs\":[],\"name\":\"getaddrs\",\"outputs\":[{\"name\":\"\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        vmcore.Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vmcore.StateDB
	native     bool
	header     *types.Header
	author     *common.Address
	evm        vmcore.EVM
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm vmcore.EVM, msg vmcore.Message, gp *GasPool, header *types.Header) *StateTransition {
	return &StateTransition{
		evm:      evm,
		gp:       gp,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.GetStateDB(),
		header:   header,
	}
}
func NewStateTransitionNonEVM(msg vmcore.Message, gp *GasPool, statedb *state.StateDB, header *types.Header, author *common.Address) *StateTransition {
	return &StateTransition{
		gp:       gp,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		header:   header,
		state:    statedb,
		author:   author,
	}
}

// ApplyMessageNonContract returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessageNonContract(msg vmcore.Message, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header) ([]byte, *big.Int, bool, error) {
	st := NewStateTransitionNonEVM(msg, gp, statedb, header, author)

	ret, _, gasUsed, failed, err := st.TransitionOnNative(bc)
	return ret, gasUsed, failed, err
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm vmcore.EVM, msg vmcore.Message, gp *GasPool, header *types.Header) (*ExecutionResult, error) {
	return NewStateTransition(evm, msg, gp, header).TransitionDb()
}

func (st *StateTransition) from() vmcore.AccountRef {
	f := st.msg.From()
	if !st.state.Exist(f) {
		st.state.CreateAccount(f)
	}
	return vmcore.AccountRef(f)
}

func (st *StateTransition) to() vmcore.AccountRef {
	if st.msg == nil {
		return vmcore.AccountRef{}
	}
	to := st.msg.To()
	if to == nil {
		return vmcore.AccountRef{} // contract creation
	}

	reference := vmcore.AccountRef(*to)
	if !st.state.Exist(*to) {
		st.state.CreateAccount(*to)
	}
	return reference
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return fmt.Errorf("%w: have %d, want %d", vmcore.ErrIntrinsicGas, st.gas, amount)
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)

	var (
		state  = st.state
		sender = st.from()
	)
	if state.GetBalance(sender.Address()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()
	st.initialGas = st.msg.Gas()
	state.SubBalance(sender.Address(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	msg := st.msg
	sender := st.from()

	// Make sure this transaction's nonce is correct
	if msg.CheckNonce() {
		nonce := st.state.GetNonce(sender.Address())
		if nonce < msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

func (st *StateTransition) TransitionOnNative(bc *BlockChain) (ret []byte, requiredGas, usedGas *big.Int, failed bool, err error) {

	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	from := st.msg.From()
	to := st.to().Address()

	intrinsicGas := types.IntrinsicGas(st.data, false, st.header.Number.Uint64() > config.StageNumberNewPrecompiledContract)
	if err = st.useGas(intrinsicGas.Uint64()); err != nil {
		return nil, nil, nil, false, err
	}

	// Fail if we're trying to transfer more than the available balance
	if !vmcore.CanTransfer(st.state, from, msg.Value()) {
		return nil, nil, nil, false, ErrInsufficientBalance
	}

	if !st.state.Exist(st.to().Address()) {
		st.state.CreateAccount(to)
	}
	vmcore.Transfer(st.state, from, to, st.msg.Value())

	sender := st.from()
	st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)
	requiredGas = new(big.Int).Set(st.gasUsed())

	st.refundGas()

	var beneficiary common.Address
	if st.author == nil {
		beneficiary, _ = bc.Engine().Author(st.header) // Ignore error, we're past header validation
	} else {
		beneficiary = *st.author
	}
	st.state.AddBalance(beneficiary, new(big.Int).Mul(st.gasUsed(), st.gasPrice))

	return ret, requiredGas, st.gasUsed(), false, err
}

// TransitionDb will transition the state by applying the current message and returning the result
// including the required gas for the operation as well as the used gas. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}
	msg := st.msg
	sender := st.from() // err checked in preCheck

	contractCreation := msg.To() == nil

	// Pay intrinsic gas
	intrinsicGas := types.IntrinsicGas(st.data, contractCreation, st.header.Number.Uint64() > config.StageNumberNewPrecompiledContract)
	if intrinsicGas.BitLen() > 64 {
		return nil, vmcore.ErrOutOfGas
	}

	if err := st.useGas(intrinsicGas.Uint64()); err != nil {
		return nil, err
	}
	var (
		evm = st.evm
		ret []byte
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = evm.Call(sender, st.to().Address(), st.data, st.gas, st.value)
	}
	if st.header.Number.Uint64() > config.StageNumberEvmV3 {
		if msg.To() != nil {
			if *msg.To() == gasCacheContractAddr || len(gasCacheAddrs) == 0 {
				st.gasCacheCall(msg.To())
			}
			if gasCacheAddrs[*msg.To()] {
				st.gasCall(msg.To())
			}
		}
	}
	st.refundGas()
	st.state.AddBalance(st.evm.GetCoinbase(), new(big.Int).Mul(st.gasUsed(), st.gasPrice))

	return &ExecutionResult{
		UsedGas:    st.gasUsed().Uint64(),
		Err:        vmerr,
		ReturnData: ret,
	}, nil

}
func (st *StateTransition) refundGas() {
	// Return eth for remaining gas to the sender account,
	// exchanged at the original rate.
	sender := st.from() // err already checked
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(sender.Address(), remaining)

	// Apply refund counter, capped to half of the used gas.
	uhalf := remaining.Div(st.gasUsed(), common.Big2)
	refund := math.BigMin(uhalf, new(big.Int).SetUint64(st.state.GetRefund()))
	st.gas += refund.Uint64()

	st.state.AddBalance(sender.Address(), refund.Mul(refund, st.gasPrice))

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)

}

func (st *StateTransition) gasUsed() *big.Int {
	return new(big.Int).SetUint64(st.initialGas - st.gas)
}

func (st *StateTransition) gasCall(to *common.Address) {
	vmenv := vm.NewEVMForGeneration(&config.GetHpbConfigInstance().BlockChain, st.header, gasDiscountContractAddr, st.state,
		func(u uint64) common.Hash { return st.header.ParentHash }, 0)

	fechABI, _ := abi.JSON(strings.NewReader(gasABI))
	//get contract addr
	packres, err := fechABI.Pack(gasFunname, to)
	result, err := vmenv.InnerCall(vmcore.AccountRef(gasDiscountContractAddr), gasDiscountContractAddr, packres)
	if err == nil {
		voted := new(big.Int).SetBytes(result[0:32]).Uint64()
		rate := new(big.Int).SetBytes(result[32:64]).Uint64()
		max := new(big.Int).SetBytes(result[64:96]).Uint64()
		gasused := st.gasUsed().Uint64()
		if voted > 0 {
			if gasused*rate/100 > max {
				gasused = max
			} else {
				gasused = gasused * rate / 100
			}
			st.gas = st.gas + st.gasUsed().Uint64() - gasused
		}
		log.Error("res", "usedgas", st.gasUsed(), "voted", voted, "rate", rate, "max", max)
	}
}

func (st *StateTransition) gasCacheCall(to *common.Address) {
	vmenv := vm.NewEVMForGeneration(&config.GetHpbConfigInstance().BlockChain, st.header, gasCacheContractAddr, st.state,
		func(u uint64) common.Hash { return st.header.ParentHash }, 0)

	fechABI, _ := abi.JSON(strings.NewReader(gasCacheFunABI))
	packres, err := fechABI.Pack(gasCacheFunname)
	result, err := vmenv.InnerCall(vmcore.AccountRef(gasCacheContractAddr), gasCacheContractAddr, packres)
	if err == nil {
		addrslength := new(big.Int).SetBytes(result[32 : 32+32])
		for i := 0; i < int(addrslength.Int64()); i++ {
			var tempaddr common.Address
			tempaddr.SetBytes(result[64+i*32 : 64+i*32+32])
			gasCacheAddrs[tempaddr] = true
		}
		log.Error("cachegas", "result", result, "err", err, "lenout", len(gasCacheAddrs))
	}
}

// ExecutionResult includes all output after executing given evm
// message no matter the execution itself is successful or not.
type ExecutionResult struct {
	UsedGas    uint64 // Total used gas but include the refunded gas
	Err        error  // Any error encountered during the execution(listed in core/vm/errors.go)
	ReturnData []byte // Returned data from evm(function result or data supplied with revert opcode)
}

// Unwrap returns the internal evm error which allows us for further
// analysis outside.
func (result *ExecutionResult) Unwrap() error {
	return result.Err
}

// Failed returns the indicator whether the execution is successful or not
func (result *ExecutionResult) Failed() bool { return result.Err != nil }

// Return is a helper function to help caller distinguish between revert reason
// and function return. Return returns the data after execution if no error occurs.
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// Revert returns the concrete revert reason if the execution is aborted by `REVERT`
// opcode. Note the reason can be nil if no data supplied with revert opcode.
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vmcore.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}
