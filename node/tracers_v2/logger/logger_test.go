// Copyright 2021 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2018 The go-ethereum Authors.
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

package logger

import (
	"math/big"
	"testing"

	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/common"
	params "github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/evm/vm"
)

type dummyContractRef struct {
	calledForEach bool
}

func (dummyContractRef) Address() common.Address     { return common.Address{} }
func (dummyContractRef) Value() *big.Int             { return new(big.Int) }
func (dummyContractRef) SetCode(common.Hash, []byte) {}
func (d *dummyContractRef) ForEachStorage(callback func(key, value common.Hash) bool) {
	d.calledForEach = true
}
func (d *dummyContractRef) SubBalance(amount *big.Int) {}
func (d *dummyContractRef) AddBalance(amount *big.Int) {}
func (d *dummyContractRef) SetBalance(*big.Int)        {}
func (d *dummyContractRef) SetNonce(uint64)            {}
func (d *dummyContractRef) Balance() *big.Int          { return new(big.Int) }

type dummyStatedb struct {
	state.StateDB
}

func (*dummyStatedb) GetRefund() uint64                                       { return 1337 }
func (*dummyStatedb) GetState(_ common.Address, _ common.Hash) common.Hash    { return common.Hash{} }
func (*dummyStatedb) SetState(_ common.Address, _ common.Hash, _ common.Hash) {}

func TestStoreCapture(t *testing.T) {
	var (
		logger   = NewStructLogger(nil)
		env      = vm.NewEVM(vm.BlockContext{}, vm.TxContext{}, &dummyStatedb{}, params.MainnetChainConfig, vm.Config{Debug: true, Tracer: logger})
		contract = vm.NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 100000)
	)
	contract.Code = []byte{byte(vm.PUSH1), 0x1, byte(vm.PUSH1), 0x0, byte(vm.SSTORE)}
	var index common.Hash
	logger.CaptureStart(env, common.Address{}, contract.Address(), false, nil, 0, nil)
	_, err := env.Interpreter().Run(contract, []byte{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(logger.storage[contract.Address()]) == 0 {
		t.Fatalf("expected exactly 1 changed value on address %x, got %d", contract.Address(),
			len(logger.storage[contract.Address()]))
	}
	exp := common.BigToHash(big.NewInt(1))
	if logger.storage[contract.Address()][index] != exp {
		t.Errorf("expected %x, got %x", exp, logger.storage[contract.Address()][index])
	}
}
