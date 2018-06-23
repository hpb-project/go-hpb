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

package node

import (
	"math/big"
	"github.com/hpb-project/go-hpb/blockchain"
)

// GasPool tracks the amount of gas available during
// execution of the transactions in a block.
// The zero value is a pool with zero gas available.
type GasPool big.Int

// AddGas makes gas available for execution.
func (gp *GasPool) AddGas(amount *big.Int) *GasPool {
	i := (*big.Int)(gp)
	i.Add(i, amount)
	return gp
}

// SubGas deducts the given amount from the pool if enough gas is
// available and returns an error otherwise.
func (gp *GasPool) SubGas(amount *big.Int) error {
	i := (*big.Int)(gp)
	if i.Cmp(amount) < 0 {
		return bc.ErrGasLimitReached
	}
	i.Sub(i, amount)
	return nil
}

func (gp *GasPool) String() string {
	return (*big.Int)(gp).String()
}
