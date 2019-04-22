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

	//"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/constant"
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
	gp         *GasPool
	msg        hvm.Message
	gas        uint64
	gasPrice   *big.Int
	initialGas *big.Int
	value      *big.Int
	data       []byte
	state      evm.StateDB
	native     bool
	header     *types.Header
	author     *common.Address
	evm        *evm.EVM
}

// IntrinsicGas computes the 'intrinsic gas' for a message
// with the given data.
//
// TODO convert to uint64
func IntrinsicGas(data []byte, contractCreation bool) *big.Int {
	igas := new(big.Int)
	if contractCreation {
		igas.SetUint64(config.TxGasContractCreation)
	} else {
		igas.SetUint64(config.TxGas)
	}
	if len(data) > 0 {
		var nz int64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		m := big.NewInt(nz)
		m.Mul(m, new(big.Int).SetUint64(params.TxDataNonZeroGas))
		igas.Add(igas, m)
		m.SetInt64(int64(len(data)) - nz)
		m.Mul(m, new(big.Int).SetUint64(params.TxDataZeroGas))
		igas.Add(igas, m)
	}
	return igas
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *evm.EVM, msg hvm.Message, gp *GasPool) *StateTransition {
	//nativeCall := len(msg.Data()) == 0
	return &StateTransition{
		evm:        evm,
		gp:         gp,
		msg:        msg,
		gasPrice:   msg.GasPrice(),
		initialGas: new(big.Int),
		value:      msg.Value(),
		data:       msg.Data(),
		//native:     nativeCall,
		state: evm.StateDB,
	}
}
func NewStateTransitionNonEVM(msg hvm.Message, gp *GasPool, statedb *state.StateDB, header *types.Header, author *common.Address) *StateTransition {
	//nativeCall := len(msg.Data()) == 0
	return &StateTransition{
		//evm:        evm,
		gp:         gp,
		msg:        msg,
		gasPrice:   msg.GasPrice(),
		initialGas: new(big.Int),
		value:      msg.Value(),
		data:       msg.Data(),
		header:     header,
		//native:     nativeCall,
		state:  statedb,
		author: author,
	}
}

// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessageNonContract(msg hvm.Message, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header) ([]byte, *big.Int, bool, error) {
	st := NewStateTransitionNonEVM(msg, gp, statedb, header, author)

	ret, _, gasUsed, failed, err := st.TransitionOnNative(bc)
	return ret, gasUsed, failed, err
}

//  computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *evm.EVM, msg hvm.Message, gp *GasPool) ([]byte, *big.Int, bool, error) {
	st := NewStateTransition(evm, msg, gp)

	ret, _, gasUsed, failed, err := st.TransitionDb()
	return ret, gasUsed, failed, err
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

func (st *StateTransition) TransitionOnNative(bc *BlockChain) (ret []byte, requiredGas, usedGas *big.Int, failed bool, err error) {

	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	from := st.msg.From()
	to := st.to().Address()

	//intrinsicGas := new(big.Int).SetUint64(config.TxGas)
	intrinsicGas := IntrinsicGas(st.data, false)
	if err = st.useGas(intrinsicGas.Uint64()); err != nil {
		return nil, nil, nil, false, err
	}

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
func (st *StateTransition) TransitionDb() (ret []byte, requiredGas, usedGas *big.Int, failed bool, err error) {
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	sender := st.from() // err checked in preCheck

	contractCreation := msg.To() == nil

	// Pay intrinsic gas
	// TODO convert to uint64
	intrinsicGas := IntrinsicGas(st.data, contractCreation)
	if intrinsicGas.BitLen() > 64 {
		return nil, nil, nil, false, hvm.ErrOutOfGas
	}
	if err = st.useGas(intrinsicGas.Uint64()); err != nil {
		return nil, nil, nil, false, err
	}
	var (
		evm = st.evm
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
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == hvm.ErrInsufficientBalance {
			return nil, nil, nil, false, vmerr
		}
	}
	requiredGas = new(big.Int).Set(st.gasUsed())

	st.refundGas()
	st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(st.gasUsed(), st.gasPrice))

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
