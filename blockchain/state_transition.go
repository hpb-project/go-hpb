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

package bc

import (
	"errors"
	"math/big"

	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/math"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/hvm"
	"github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/hvm/native"
)

var (
	Big0                         = big.NewInt(0)
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
	ErrInsufficientBalance       = errors.New("insufficient balance")
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
	gp         *hvm.GasPool
	msg        hvm.Message
	gas        uint64
	gasPrice   *big.Int
	initialGas *big.Int
	value      *big.Int
	data       []byte
	state      *state.StateDB
	native     bool
	header     *types.Header
	author     *common.Address
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(msg hvm.Message, gp *hvm.GasPool, db *state.StateDB, header *types.Header, author *common.Address) *StateTransition {
	nativeCall := msg.To() != nil && db.GetCodeSize(msg.From()) == 0
	return &StateTransition{
		gp:         gp,
		msg:        msg,
		gasPrice:   msg.GasPrice(),
		initialGas: new(big.Int),
		value:      msg.Value(),
		data:       msg.Data(),
		state:      db,
		native:     nativeCall,
		header:     header,
		author:     author,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(header *types.Header, db *state.StateDB, author *common.Address, msg hvm.Message, gp *hvm.GasPool) ([]byte, *big.Int, bool, error) {


	st := NewStateTransition(msg, gp, db, header, author)

	if err := st.preCheck(); err != nil {
		return nil, nil, false, err
	}


	////////////////////////
	contractCreation := msg.To() == nil
	// Pay intrinsic gas
	intrinsicGas := types.IntrinsicGas(st.data, contractCreation)
	if intrinsicGas.BitLen() > 64 {
		return nil, nil, false, evm.ErrOutOfGas
	}
	if err := st.useGas(intrinsicGas.Uint64()); err != nil {
		return nil, nil, false, err
	}

	if !st.native {
		ret, _, gasUsed, failed, err := st.TransitionOnNative()
		return ret, gasUsed, failed, err
	} else {
		// Apply the transaction to the current state (included in the env)
		ret, _, gasUsed, failed, err := st.TransitionOnEVM()
		return ret, gasUsed, failed, err
	}
}

func (st *StateTransition) from() evm.AccountRef {
	f := st.msg.From()
	if !st.state.Exist(f) {
		st.state.CreateAccount(f)
	}
	return evm.AccountRef(f)
}

func (st *StateTransition) to() evm.AccountRef {
	if st.msg == nil {
		return evm.AccountRef{}
	}
	to := st.msg.To()
	if to == nil {
		return evm.AccountRef{} // contract creation
	}

	reference := evm.AccountRef(*to)
	if !st.state.Exist(*to) {
		st.state.CreateAccount(*to)
	}
	return reference
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return evm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	mgas := st.msg.Gas()
	if mgas.BitLen() > 64 {
		return evm.ErrOutOfGas
	}

	mgval := new(big.Int).Mul(mgas, st.gasPrice)

	var (
		state  = st.state
		sender = st.from()
	)
	if state.GetBalance(sender.Address()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(mgas); err != nil {
		return err
	}
	st.gas += mgas.Uint64()

	st.initialGas.Set(mgas)
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

func (st *StateTransition) TransitionOnNative() (ret []byte, requiredGas, usedGas *big.Int, failed bool, err error) {
	msg := st.msg
	from := st.msg.From()
	to := st.to().Address()

	// Fail if we're trying to transfer more than the available balance
	if !native.CanTransfer(st.state, from, msg.Value()) {
		return nil, nil, nil, false, ErrInsufficientBalance
	}

	if !st.state.Exist(st.to().Address()) {
		st.state.CreateAccount(to)
	}
	native.Transfer(st.state, from, to, st.msg.Value())

	sender := st.from()
	st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)
	requiredGas = new(big.Int).Set(st.gasUsed())

	st.refundGas()

	var beneficiary common.Address
	if st.author == nil {
		beneficiary, _ = InstanceBlockChain().Engine().Author(st.header) // Ignore error, we're past header validation
	} else {
		beneficiary = *st.author
	}
	st.state.AddBalance(beneficiary, new(big.Int).Mul(st.gasUsed(), st.gasPrice))

	return ret, requiredGas, st.gasUsed(), false, err
}

// TransitionDb will transition the state by applying the current message and returning the result
// including the required gas for the operation as well as the used gas. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionOnEVM() (ret []byte, requiredGas, usedGas *big.Int, failed bool, err error) {
	// Create a new context to be used in the EVM environment
	context := hvm.NewEVMContext(st.msg, st.header, InstanceBlockChain(), st.author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	ethereum_vm := evm.NewEVM(context, st.state, config.MainnetChainConfig, evm.Config{})

	msg := st.msg
	sender := st.from() // err checked in preCheck

	contractCreation := msg.To() == nil

	var (
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = ethereum_vm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = ethereum_vm.Call(sender, st.to().Address(), st.data, st.gas, st.value)
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == evm.ErrInsufficientBalance {
			return nil, nil, nil, false, vmerr
		}
	}
	requiredGas = new(big.Int).Set(st.gasUsed())

	st.refundGas()
	st.state.AddBalance(ethereum_vm.Coinbase, new(big.Int).Mul(st.gasUsed(), st.gasPrice))

	return ret, requiredGas, st.gasUsed(), vmerr != nil, err
}

func (st *StateTransition) refundGas() {
	// Return eth for remaining gas to the sender account,
	// exchanged at the original rate.
	sender := st.from() // err already checked
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(sender.Address(), remaining)

	// Apply refund counter, capped to half of the used gas.
	uhalf := remaining.Div(st.gasUsed(), common.Big2)
	refund := math.BigMin(uhalf, st.state.GetRefund())
	st.gas += refund.Uint64()

	st.state.AddBalance(sender.Address(), refund.Mul(refund, st.gasPrice))

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(new(big.Int).SetUint64(st.gas))
}

func (st *StateTransition) gasUsed() *big.Int {
	return new(big.Int).Sub(st.initialGas, new(big.Int).SetUint64(st.gas))
}
