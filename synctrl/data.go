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

package synctrl

import (
	"fmt"
	"io"
	"math/big"

	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/network/p2p"
)

// newBlockHashesData is the network packet for the block announcements.
type newBlockHashesData []struct {
	Hash   common.Hash // Hash of one particular block being announced
	Number uint64      // Number of one particular block being announced
}

// GetBlockHeadersData represents a block header query.
type getBlockHeadersData struct {
	Origin  hashOrNumber // Block from which to retrieve headers
	Amount  uint64       // Maximum number of headers to retrieve
	Skip    uint64       // Blocks to skip between consecutive headers
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
}

// hashOrNumber is a combined field for specifying an origin block.
type hashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

// EncodeRLP is a specialized encoder for hashOrNumber to encode only one of the
// two contained union fields.
func (hn *hashOrNumber) EncodeRLP(w io.Writer) error {
	if hn.Hash == (common.Hash{}) {
		return rlp.Encode(w, hn.Number)
	}
	if hn.Number != 0 {
		return fmt.Errorf("both origin hash (%x) and number (%d) provided", hn.Hash, hn.Number)
	}
	return rlp.Encode(w, hn.Hash)
}

// DecodeRLP is a specialized decoder for hashOrNumber to decode the contents
// into either a block hash or a block number.
func (hn *hashOrNumber) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	origin, err := s.Raw()
	if err == nil {
		switch {
		case size == 32:
			err = rlp.DecodeBytes(origin, &hn.Hash)
		case size <= 8:
			err = rlp.DecodeBytes(origin, &hn.Number)
		default:
			err = fmt.Errorf("invalid input size %d for origin", size)
		}
	}
	return err
}

// newBlockData is the network packet for the block propagation message.
type newBlockData struct {
	Block *types.Block
	TD    *big.Int
}

type hashBlock struct {
	Header    *types.Header
	Uncles    []*types.Header
	TxsHash   []common.Hash
	Td        *big.Int
	BlockHash common.Hash
}

type newBlockHashData struct {
	BlockH *hashBlock
	TD     *big.Int
}

// blockBody represents the data content of a single block.
type blockBody struct {
	Transactions []*types.Transaction // Transactions contained within a block
	Uncles       []*types.Header      // Uncles contained within a block
}

// blockBodiesData is the network packet for block content distribution.
type blockBodiesData []*blockBody

func sendNewBlock(peer *p2p.Peer, block *types.Block, td *big.Int) error {
	peer.KnownBlockAdd(block.Hash())
	return p2p.SendData(peer, p2p.NewBlockMsg, []interface{}{block, td})
}

func sendNewHashBlock(peer *p2p.Peer, block *types.Block, td *big.Int) error {
	log.Warn("######>>>>>> Send new hash block msg.", "peerid", peer.ID())
	txsHash := make([]common.Hash, 0, block.Transactions().Len())
	for _, tx := range block.Transactions() {
		txsHash = append(txsHash, tx.Hash())
	}
	hashBlock := &hashBlock{Header: block.Header(), Uncles: block.Uncles(), TxsHash: txsHash, Td: td, BlockHash: block.Hash()}

	peer.KnownBlockAdd(block.Hash())
	return p2p.SendData(peer, p2p.NewHashBlockMsg, []interface{}{hashBlock, td})
}

func sendNewBlockHashes(peer *p2p.Peer, hashes []common.Hash, numbers []uint64) error {
	for _, hash := range hashes {
		peer.KnownBlockAdd(hash)
	}
	request := make(newBlockHashesData, len(hashes))
	for i := 0; i < len(hashes); i++ {
		request[i].Hash = hashes[i]
		request[i].Number = numbers[i]
	}
	return p2p.SendData(peer, p2p.NewBlockHashesMsg, request)
}

func sendBlockHeaders(peer *p2p.Peer, headers []*types.Header) error {
	return p2p.SendData(peer, p2p.BlockHeadersMsg, headers)
}

// sendBlockBodiesRLP sends a batch of block contents to the remote peer from
// an already RLP encoded format.
func sendBlockBodiesRLP(peer *p2p.Peer, bodies []rlp.RawValue) error {
	return p2p.SendData(peer, p2p.BlockBodiesMsg, bodies)
}

// sendNodeData sends a batch of arbitrary internal data, corresponding to the
// hashes requested.
func sendNodeData(peer *p2p.Peer, data [][]byte) error {
	return p2p.SendData(peer, p2p.NodeDataMsg, data)
}

// sendReceiptsRLP sends a batch of transaction receipts, corresponding to the
// ones requested from an already RLP encoded format.
func sendReceiptsRLP(peer *p2p.Peer, receipts []rlp.RawValue) error {
	return p2p.SendData(peer, p2p.ReceiptsMsg, receipts)
}

// requestOneHeader is a wrapper around the header query functions to fetch a
// single header. It is used solely by the fetcher.
func requestOneHeader(peer *p2p.Peer, hash common.Hash) error {
	log.Debug("Fetching single header", "hash", hash)
	return p2p.SendData(peer, p2p.GetBlockHeadersMsg, &getBlockHeadersData{Origin: hashOrNumber{Hash: hash}, Amount: uint64(1), Skip: uint64(0), Reverse: false})
}

// requestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func requestBodies(peer *p2p.Peer, hashes []common.Hash) error {
	log.Debug("Fetching batch of block bodies", "count", len(hashes))
	return p2p.SendData(peer, p2p.GetBlockBodiesMsg, hashes)
}
