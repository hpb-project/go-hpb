// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package election

import (
	"math/big"
	"testing"

	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/account/abi/bind/backends"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/account/abi/bind"
	"github.com/hpb-project/go-hpb/common"
)

var (
	key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	name   = "my name on ENS"
	hash   = crypto.Keccak256Hash([]byte("my content"))
	addr   = crypto.PubkeyToAddress(key.PublicKey)
)

func TestHPB_ElectionContract(t *testing.T) {
	contractBackend := backends.NewSimulatedBackend(bc.GenesisAlloc{addr: {Balance: big.NewInt(1000000000)}})
	transactOpts := bind.NewKeyedTransactor(key)
	// Workaround for bug estimating gas in the call to Register
	transactOpts.GasLimit = big.NewInt(1000000)

	addr, tx, ballot, err := DeployHpbballot(transactOpts, contractBackend, common.StringToHash("abc"), big.NewInt(1), big.NewInt(100), big.NewInt(1), big.NewInt(10), big.NewInt(1))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	t.Logf("address : %s \n", addr.String())
	t.Logf("tx DeployHpbballot : %s \n", tx)
	t.Logf("ballot : %s \n", ballot)

	contractBackend.Commit()

	ballot, _ = NewHpbballot(addr, contractBackend)
	start, _ := ballot.StartBlock(nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	t.Logf("tx StartBlock : %s \n", start)
}
