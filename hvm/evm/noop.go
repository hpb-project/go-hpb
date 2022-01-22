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

package evm

import (
	"github.com/hpb-project/go-hpb/vmcore"
	"math/big"

	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
)

func NoopCanTransfer(db vmcore.StateDB, from common.Address, balance *big.Int) bool {
	return true
}
func NoopTransfer(db vmcore.StateDB, from, to common.Address, amount *big.Int) {}

type NoopEVMCallContext struct{}

func (NoopEVMCallContext) Call(caller vmcore.ContractRef, addr common.Address, data []byte, gas, value *big.Int) ([]byte, error) {
	return nil, nil
}
func (NoopEVMCallContext) CallCode(caller vmcore.ContractRef, addr common.Address, data []byte, gas, value *big.Int) ([]byte, error) {
	return nil, nil
}
func (NoopEVMCallContext) Create(caller vmcore.ContractRef, data []byte, gas, value *big.Int) ([]byte, common.Address, error) {
	return nil, common.Address{}, nil
}
func (NoopEVMCallContext) DelegateCall(me vmcore.ContractRef, addr common.Address, data []byte, gas *big.Int) ([]byte, error) {
	return nil, nil
}

type NoopStateDB struct{}

func (NoopStateDB) CreateAccount(common.Address)                      {}
func (NoopStateDB) SubBalance(common.Address, *big.Int)               {}
func (NoopStateDB) AddBalance(common.Address, *big.Int)               {}
func (NoopStateDB) GetBalance(common.Address) *big.Int                { return nil }
func (NoopStateDB) GetNonce(common.Address) uint64                    { return 0 }
func (NoopStateDB) SetNonce(common.Address, uint64)                   {}
func (NoopStateDB) GetCodeHash(common.Address) common.Hash            { return common.Hash{} }
func (NoopStateDB) GetCode(common.Address) []byte                     { return nil }
func (NoopStateDB) SetCode(common.Address, []byte)                    {}
func (NoopStateDB) GetCodeSize(common.Address) int                    { return 0 }
func (NoopStateDB) AddRefund(uint64)                                  {}
func (NoopStateDB) GetRefund() uint64                                 { return 0 }
func (NoopStateDB) GetState(common.Address, common.Hash) common.Hash  { return common.Hash{} }
func (NoopStateDB) SetState(common.Address, common.Hash, common.Hash) {}
func (NoopStateDB) Suicide(common.Address) bool                       { return false }
func (NoopStateDB) HasSuicided(common.Address) bool                   { return false }
func (NoopStateDB) Exist(common.Address) bool                         { return false }
func (NoopStateDB) Empty(common.Address) bool                         { return false }
func (NoopStateDB) RevertToSnapshot(int)                              {}
func (NoopStateDB) Snapshot() int                                     { return 0 }
func (NoopStateDB) AddLog(*types.Log)                                 {}
func (NoopStateDB) AddPreimage(common.Hash, []byte)                   {}
func (NoopStateDB) ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error {
	return nil
}
