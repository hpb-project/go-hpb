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

package state

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"
	"testing"

	hpbdb "github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	checker "gopkg.in/check.v1"
)

type StateSuite struct {
	db    *hpbdb.MemDatabase
	state *StateDB
}

var _ = checker.Suite(&StateSuite{})

var toAddr = common.BytesToAddress

func (s *StateSuite) TestDump(c *checker.C) {
	// generate a few entries
	obj1 := s.state.GetOrNewStateObject(toAddr([]byte{0x01}))
	obj1.AddBalance(big.NewInt(22))
	obj2 := s.state.GetOrNewStateObject(toAddr([]byte{0x01, 0x02}))
	obj2.SetCode(crypto.Keccak256Hash([]byte{3, 3, 3, 3, 3, 3, 3}), []byte{3, 3, 3, 3, 3, 3, 3})
	obj3 := s.state.GetOrNewStateObject(toAddr([]byte{0x02}))
	obj3.SetBalance(big.NewInt(44))

	// write some of them to the trie
	s.state.updateStateObject(obj1)
	s.state.updateStateObject(obj2)
	s.state.CommitTo(s.db, false)

	// check that dump contains the state objects that are in trie
	got := string(s.state.Dump())
	want := `{
    "root": "71edff0130dd2385947095001c73d9e28d862fc286fca2b922ca6f6f3cddfdd2",
    "accounts": {
        "0000000000000000000000000000000000000001": {
            "balance": "22",
            "nonce": 0,
            "root": "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "code": "",
            "storage": {}
        },
        "0000000000000000000000000000000000000002": {
            "balance": "44",
            "nonce": 0,
            "root": "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "code": "",
            "storage": {}
        },
        "0000000000000000000000000000000000000102": {
            "balance": "0",
            "nonce": 0,
            "root": "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "87874902497a5bb968da31a2998d8f22e949d1ef6214bcdedd8bae24cca4b9e3",
            "code": "03030303030303",
            "storage": {}
        }
    }
}`
	if got != want {
		c.Errorf("dump mismatch:\ngot: %s\nwant: %s\n", got, want)
	}
}

func (s *StateSuite) SetUpTest(c *checker.C) {
	s.db, _ = hpbdb.NewMemDatabase()
	s.state, _ = New(common.Hash{}, NewDatabase(s.db))
}

func (s *StateSuite) TestNull(c *checker.C) {
	address := common.HexToAddress("0x823140710bf13990e4500136726d8b55")
	s.state.CreateAccount(address)
	//value := common.FromHex("0x823140710bf13990e4500136726d8b55")
	var value common.Hash
	s.state.SetState(address, common.Hash{}, value)
	s.state.CommitTo(s.db, false)
	value = s.state.GetState(address, common.Hash{})
	if !common.EmptyHash(value) {
		c.Errorf("expected empty hash. got %x", value)
	}
}

func (s *StateSuite) TestSnapshot(c *checker.C) {
	stateobjaddr := toAddr([]byte("aa"))
	var storageaddr common.Hash
	data1 := common.BytesToHash([]byte{42})
	data2 := common.BytesToHash([]byte{43})

	// set initial state object value
	s.state.SetState(stateobjaddr, storageaddr, data1)
	// get snapshot of current state
	snapshot := s.state.Snapshot()

	// set new state object value
	s.state.SetState(stateobjaddr, storageaddr, data2)
	// restore snapshot
	s.state.RevertToSnapshot(snapshot)

	// get state storage value
	res := s.state.GetState(stateobjaddr, storageaddr)

	c.Assert(data1, checker.DeepEquals, res)
}

func (s *StateSuite) TestSnapshotEmpty(c *checker.C) {
	s.state.RevertToSnapshot(s.state.Snapshot())
}

// use testing instead of checker because checker does not support
// printing/logging in tests (-check.vv does not work)
func TestSnapshot2(t *testing.T) {
	db, _ := hpbdb.NewMemDatabase()
	state, _ := New(common.Hash{}, NewDatabase(db))

	stateobjaddr0 := toAddr([]byte("so0"))
	stateobjaddr1 := toAddr([]byte("so1"))
	var storageaddr common.Hash

	data0 := common.BytesToHash([]byte{17})
	data1 := common.BytesToHash([]byte{18})

	state.SetState(stateobjaddr0, storageaddr, data0)
	state.SetState(stateobjaddr1, storageaddr, data1)

	// db, trie are already non-empty values
	so0 := state.getStateObject(stateobjaddr0)
	so0.SetBalance(big.NewInt(42))
	so0.SetNonce(43)
	so0.SetCode(crypto.Keccak256Hash([]byte{'c', 'a', 'f', 'e'}), []byte{'c', 'a', 'f', 'e'})
	so0.suicided = false
	so0.deleted = false
	state.setStateObject(so0)

	root, _ := state.CommitTo(db, false)
	state.Reset(root)

	// and one with deleted == true
	so1 := state.getStateObject(stateobjaddr1)
	so1.SetBalance(big.NewInt(52))
	so1.SetNonce(53)
	so1.SetCode(crypto.Keccak256Hash([]byte{'c', 'a', 'f', 'e', '2'}), []byte{'c', 'a', 'f', 'e', '2'})
	so1.suicided = true
	so1.deleted = true
	state.setStateObject(so1)

	so1 = state.getStateObject(stateobjaddr1)
	if so1 != nil {
		t.Fatalf("deleted object not nil when getting")
	}

	snapshot := state.Snapshot()
	state.RevertToSnapshot(snapshot)

	so0Restored := state.getStateObject(stateobjaddr0)
	// Update lazily-loaded values before comparing.
	so0Restored.GetState(state.db, storageaddr)
	so0Restored.Code(state.db)
	// non-deleted is equal (restored)
	compareStateObjects(so0Restored, so0, t)

	// deleted should be nil, both before and after restore of state copy
	so1Restored := state.getStateObject(stateobjaddr1)
	if so1Restored != nil {
		t.Fatalf("deleted object not nil after restoring snapshot: %+v", so1Restored)
	}
}

func compareStateObjects(so0, so1 *stateObject, t *testing.T) {
	if so0.Address() != so1.Address() {
		t.Fatalf("Address mismatch: have %v, want %v", so0.address, so1.address)
	}
	if so0.Balance().Cmp(so1.Balance()) != 0 {
		t.Fatalf("Balance mismatch: have %v, want %v", so0.Balance(), so1.Balance())
	}
	if so0.Nonce() != so1.Nonce() {
		t.Fatalf("Nonce mismatch: have %v, want %v", so0.Nonce(), so1.Nonce())
	}
	if so0.data.Root != so1.data.Root {
		t.Errorf("Root mismatch: have %x, want %x", so0.data.Root[:], so1.data.Root[:])
	}
	if !bytes.Equal(so0.CodeHash(), so1.CodeHash()) {
		t.Fatalf("CodeHash mismatch: have %v, want %v", so0.CodeHash(), so1.CodeHash())
	}
	if !bytes.Equal(so0.code, so1.code) {
		t.Fatalf("Code mismatch: have %v, want %v", so0.code, so1.code)
	}

	if len(so1.cachedStorage) != len(so0.cachedStorage) {
		t.Errorf("Storage size mismatch: have %d, want %d", len(so1.cachedStorage), len(so0.cachedStorage))
	}
	for k, v := range so1.cachedStorage {
		if so0.cachedStorage[k] != v {
			t.Errorf("Storage key %x mismatch: have %v, want %v", k, so0.cachedStorage[k], v)
		}
	}
	for k, v := range so0.cachedStorage {
		if so1.cachedStorage[k] != v {
			t.Errorf("Storage key %x mismatch: have %v, want none.", k, v)
		}
	}

	if so0.suicided != so1.suicided {
		t.Fatalf("suicided mismatch: have %v, want %v", so0.suicided, so1.suicided)
	}
	if so0.deleted != so1.deleted {
		t.Fatalf("Deleted mismatch: have %v, want %v", so0.deleted, so1.deleted)
	}
}

func TestCopy(t *testing.T) {
	db, _ := hpbdb.NewMemDatabase()
	// Create a random state test to copy and modify "independently"
	orig, _ := New(common.Hash{}, NewDatabase(db))

	for i := byte(0); i < 255; i++ {
		obj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		obj.AddBalance(big.NewInt(int64(i)))
		orig.updateStateObject(obj)
	}
	orig.Finalise(false)

	// Copy the state
	copy := orig.Copy()

	// Copy the copy state
	ccopy := copy.Copy()

	// modify all in memory
	for i := byte(0); i < 255; i++ {
		origObj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		copyObj := copy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		ccopyObj := ccopy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))

		origObj.AddBalance(big.NewInt(2 * int64(i)))
		copyObj.AddBalance(big.NewInt(3 * int64(i)))
		ccopyObj.AddBalance(big.NewInt(4 * int64(i)))

		orig.updateStateObject(origObj)
		copy.updateStateObject(copyObj)
		ccopy.updateStateObject(copyObj)
	}

	// Finalise the changes on all concurrently
	finalise := func(wg *sync.WaitGroup, db *StateDB) {
		defer wg.Done()
		db.Finalise(true)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go finalise(&wg, orig)
	go finalise(&wg, copy)
	go finalise(&wg, ccopy)
	wg.Wait()

	// Verify that the three states have been updated independently
	for i := byte(0); i < 255; i++ {
		origObj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		copyObj := copy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		ccopyObj := ccopy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))

		if want := big.NewInt(3 * int64(i)); origObj.Balance().Cmp(want) != 0 {
			t.Errorf("orig obj %d: balance mismatch: have %v, want %v", i, origObj.Balance(), want)
		}
		if want := big.NewInt(4 * int64(i)); copyObj.Balance().Cmp(want) != 0 {
			t.Errorf("copy obj %d: balance mismatch: have %v, want %v", i, copyObj.Balance(), want)
		}
		if want := big.NewInt(5 * int64(i)); ccopyObj.Balance().Cmp(want) != 0 {
			t.Errorf("copy obj %d: balance mismatch: have %v, want %v", i, ccopyObj.Balance(), want)
		}
	}
}

func TestCopy1(t *testing.T) {
	db, _ := hpbdb.NewMemDatabase()
	state, _ := New(common.Hash{}, NewDatabase(db))
	addr := common.HexToAddress("aaaa")
	state.SetNonce(addr, 290083)

	fmt.Println("---state->", state)

	state.Finalise(false)

	delete(state.stateObjects, addr)
	delete(state.stateObjectsDirty, addr)

	state1 := state.Copy()

	fmt.Println("---state->", state1)

	copy := state1.Copy()

	state1.SetNonce(addr, 290084)

	state1.Finalise(false)

	if got := copy.GetNonce(addr); got != 290083 {
		t.Fatalf("2nd copy fail, expected 290083, got %v", got)
	}
	fmt.Println("---copy->", copy)

}

func TestCopyOfCopy(t *testing.T) {
	db, _ := hpbdb.NewMemDatabase()
	state, _ := New(common.Hash{}, NewDatabase(db))
	addr := common.HexToAddress("aaaa")
	state.SetBalance(addr, big.NewInt(42))

	if got := state.Copy().GetBalance(addr).Uint64(); got != 42 {
		t.Fatalf("1st copy fail, expected 42, got %v", got)
	}
	if got := state.Copy().Copy().GetBalance(addr).Uint64(); got != 42 {
		t.Fatalf("2nd copy fail, expected 42, got %v", got)
	}
}

func TestCopyCommitCopy(t *testing.T) {
	db, _ := hpbdb.NewMemDatabase()

	state, _ := New(common.Hash{}, NewDatabase(db))

	// Create an account and check if the retrieved balance is correct
	addr := common.HexToAddress("0xaffeaffeaffeaffeaffeaffeaffeaffeaffeaffe")
	skey := common.HexToHash("aaa")
	sval := common.HexToHash("bbb")

	state.SetBalance(addr, big.NewInt(42)) // Change the account trie
	state.SetCode(addr, []byte("hello"))   // Change an external metadata
	state.SetState(addr, skey, sval)       // Change the storage trie

	if balance := state.GetBalance(addr); balance.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("initial balance mismatch: have %v, want %v", balance, 42)
	}
	if code := state.GetCode(addr); !bytes.Equal(code, []byte("hello")) {
		t.Fatalf("initial code mismatch: have %x, want %x", code, []byte("hello"))
	}
	if val := state.GetState(addr, skey); val != sval {
		t.Fatalf("initial non-committed storage slot mismatch: have %x, want %x", val, sval)
	}

	// Copy the non-committed state database and check pre/post commit balance
	copyOne := state.Copy()
	if balance := copyOne.GetBalance(addr); balance.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("first copy pre-commit balance mismatch: have %v, want %v", balance, 42)
	}
	if code := copyOne.GetCode(addr); !bytes.Equal(code, []byte("hello")) {
		t.Fatalf("first copy pre-commit code mismatch: have %x, want %x", code, []byte("hello"))
	}
	if val := copyOne.GetState(addr, skey); val != sval {
		t.Fatalf("first copy pre-commit non-committed storage slot mismatch: have %x, want %x", val, sval)
	}

	copyOne.CommitTo(db, false)
	if balance := copyOne.GetBalance(addr); balance.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("first copy post-commit balance mismatch: have %v, want %v", balance, 42)
	}
	if code := copyOne.GetCode(addr); !bytes.Equal(code, []byte("hello")) {
		t.Fatalf("first copy post-commit code mismatch: have %x, want %x", code, []byte("hello"))
	}
	if val := copyOne.GetState(addr, skey); val != sval {
		t.Fatalf("first copy post-commit non-committed storage slot mismatch: have %x, want %x", val, sval)
	}

	// Copy the copy and check the balance once more
	copyTwo := copyOne.Copy()
	if balance := copyTwo.GetBalance(addr); balance.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("second copy balance mismatch: have %v, want %v", balance, 42)
	}
	if code := copyTwo.GetCode(addr); !bytes.Equal(code, []byte("hello")) {
		t.Fatalf("second copy code mismatch: have %x, want %x", code, []byte("hello"))
	}
	if val := copyTwo.GetState(addr, skey); val != sval {
		t.Fatalf("second copy non-committed storage slot mismatch: have %x, want %x", val, sval)
	}
}
