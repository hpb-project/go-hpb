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

package state

import (
	"bytes"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/common/trie"
)

// NewStateSync create a new state trie download scheduler.
func NewStateSync(root common.Hash, database trie.DatabaseReader) *trie.TrieSync {
	var syncer *trie.TrieSync
	callback := func(leaf []byte, parent common.Hash) error {
		var obj Account
		if err := rlp.Decode(bytes.NewReader(leaf), &obj); err != nil {
			return err
		}
		syncer.AddSubTrie(obj.Root, 64, parent, nil)
		syncer.AddRawEntry(common.BytesToHash(obj.CodeHash), 64, parent)
		return nil
	}
	syncer = trie.NewTrieSync(root, database, callback)
	return syncer
}
