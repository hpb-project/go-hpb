// Copyright 2015 The go-hpb Authors
// This file is part of the go-hpb library.
//
// The go-hpb library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb library. If not, see <http://www.gnu.org/licenses/>.

package bc

import (
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"testing"
)


func TestVoteResultStorage(t *testing.T) {
	db, _ := hpbdb.NewMemDatabase()

	vr := &types.VoteResult {
		Version  : 1 ,
	}

	vr.Winners = append(vr.Winners, common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"))
	vr.Winners = append(vr.Winners, common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"))

	// Write and verify the body in the database
	if err := WriteVoteResult(db, vr); err != nil {
		t.Fatalf("Failed to write vote into database: %v", err)
	}
	if entry := GetVoteResult(db); entry == nil {
		t.Fatalf("Stored vote not found")
	} else {
		t.Log( entry)
	}
	DeleteVoteResult(db)
	if entry := GetVoteResult(db); entry != nil {
		t.Fatalf("Deleted vote returned: %v", entry)
	}
}
