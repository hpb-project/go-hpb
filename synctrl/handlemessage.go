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
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/node/db"
	"github.com/hpb-project/go-hpb/txpool"
	"math/big"
	"sync/atomic"
	"time"
)

// HandleGetBlockHeadersMsg deal received GetBlockHeadersMsg
func HandleGetBlockHeadersMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the complex header query
	var query getBlockHeadersData
	if err := msg.Decode(&query); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
	}
	hashMode := query.Origin.Hash != (common.Hash{})

	// Gather headers until the fetch or network limits is reached
	var (
		bytes   common.StorageSize
		headers []*types.Header
		unknown bool
	)
	for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < MaxHeaderFetch {
		// Retrieve the next header satisfying the query
		var origin *types.Header
		if hashMode {
			origin = bc.InstanceBlockChain().GetHeaderByHash(query.Origin.Hash)
		} else {
			origin = bc.InstanceBlockChain().GetHeaderByNumber(query.Origin.Number)
		}
		if origin == nil {
			break
		}
		number := origin.Number.Uint64()
		headers = append(headers, origin)
		bytes += estHeaderRlpSize

		// Advance to the next header of the query
		switch {
		case query.Origin.Hash != (common.Hash{}) && query.Reverse:
			// Hash based traversal towards the genesis block
			for i := 0; i < int(query.Skip)+1; i++ {
				if header := bc.InstanceBlockChain().GetHeader(query.Origin.Hash, number); header != nil {
					query.Origin.Hash = header.ParentHash
					number--
				} else {
					unknown = true
					break
				}
			}
		case query.Origin.Hash != (common.Hash{}) && !query.Reverse:
			// Hash based traversal towards the leaf block
			var (
				current = origin.Number.Uint64()
				next    = current + query.Skip + 1
			)
			if next <= current {
				log.Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", p.ID())
				unknown = true
			} else {
				if header := bc.InstanceBlockChain().GetHeaderByNumber(next); header != nil {
					if bc.InstanceBlockChain().GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
						query.Origin.Hash = header.Hash()
					} else {
						unknown = true
					}
				} else {
					unknown = true
				}
			}
		case query.Reverse:
			// Number based traversal towards the genesis block
			if query.Origin.Number >= query.Skip+1 {
				query.Origin.Number -= (query.Skip + 1)
			} else {
				unknown = true
			}

		case !query.Reverse:
			// Number based traversal towards the leaf block
			query.Origin.Number += (query.Skip + 1)
		}
	}
	return sendBlockHeaders(p, headers)
}

// HandleBlockHeadersMsg deal received BlockHeadersMsg
func HandleBlockHeadersMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of headers arrived to one of our previous requests
	var headers []*types.Header
	if err := msg.Decode(&headers); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}

	// Filter out any explicitly requested headers, deliver the rest to the downloader
	filter := len(headers) == 1
	if filter {
		// Irrelevant of the fork checks, send the header to the fetcher just in case
		headers = InstanceSynCtrl().puller.FilterHeaders(p.GetID(), headers, time.Now())
	}
	if len(headers) > 0 || !filter {
		err := InstanceSynCtrl().syner.DeliverHeaders(p.GetID(), headers)
		if err != nil {
			log.Debug("Failed to deliver headers", "err", err)
		}
	}
	return nil
}

// HandleGetBlockBodiesMsg deal received GetBlockBodiesMsg
func HandleGetBlockBodiesMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather blocks until the fetch or network limits is reached
	var (
		hash   common.Hash
		bytes  int
		bodies []rlp.RawValue
	)
	for bytes < softResponseLimit && len(bodies) < MaxBlockFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested block body, stopping if enough was found
		if data := bc.InstanceBlockChain().GetBodyRLP(hash); len(data) != 0 {
			bodies = append(bodies, data)
			bytes += len(data)
		}
	}
	return sendBlockBodiesRLP(p, bodies)
}

// HandleBlockBodiesMsg deal received BlockBodiesMsg
func HandleBlockBodiesMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of block bodies arrived to one of our previous requests
	var request blockBodiesData
	if err := msg.Decode(&request); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver them all to the downloader for queuing
	trasactions := make([][]*types.Transaction, len(request))
	uncles := make([][]*types.Header, len(request))

	for i, body := range request {
		trasactions[i] = body.Transactions
		uncles[i] = body.Uncles
	}
	// Filter out any explicitly requested bodies, deliver the rest to the downloader
	filter := len(trasactions) > 0 || len(uncles) > 0
	if filter {
		trasactions, uncles = InstanceSynCtrl().puller.FilterBodies(p.GetID(), trasactions, uncles, time.Now())
	}
	if len(trasactions) > 0 || len(uncles) > 0 || !filter {
		err := InstanceSynCtrl().syner.DeliverBodies(p.GetID(), trasactions, uncles)
		if err != nil {
			log.Debug("Failed to deliver bodies", "err", err)
		}
	}
	return nil
}

// HandleGetNodeDataMsg deal received GetNodeDataMsg
func HandleGetNodeDataMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather state data until the fetch or network limits is reached
	var (
		hash  common.Hash
		bytes int
		data  [][]byte
	)
	for bytes < softResponseLimit && len(data) < MaxStateFetch {
		// Retrieve the hash of the next state entry
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested state entry, stopping if enough was found
		if entry, err := db.GetHpbDbInstance().Get(hash.Bytes()); err == nil {
			data = append(data, entry)
			bytes += len(entry)
		}
	}
	return sendNodeData(p, data)
}

// HandleNodeDataMsg deal received NodeDataMsg
func HandleNodeDataMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of node state data arrived to one of our previous requests
	var data [][]byte
	if err := msg.Decode(&data); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := InstanceSynCtrl().syner.DeliverNodeData(p.GetID(), data); err != nil {
		log.Debug("Failed to deliver node state data", "err", err)
	}
	return nil
}

// HandleGetReceiptsMsg deal received GetReceiptsMsg
func HandleGetReceiptsMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather state data until the fetch or network limits is reached
	var (
		hash     common.Hash
		bytes    int
		receipts []rlp.RawValue
	)
	for bytes < softResponseLimit && len(receipts) < MaxReceiptFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested block's receipts, skipping if unknown to us
		results := bc.GetBlockReceipts(db.GetHpbDbInstance(), hash, bc.GetBlockNumber(db.GetHpbDbInstance(), hash))
		if results == nil {
			if header := bc.InstanceBlockChain().GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
				continue
			}
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(results); err != nil {
			log.Error("Failed to encode receipt", "err", err)
		} else {
			receipts = append(receipts, encoded)
			bytes += len(encoded)
		}
	}
	return sendReceiptsRLP(p, receipts)
}

// HandleReceiptsMsg deal received ReceiptsMsg
func HandleReceiptsMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of receipts arrived to one of our previous requests
	var receipts [][]*types.Receipt
	if err := msg.Decode(&receipts); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := InstanceSynCtrl().syner.DeliverReceipts(p.GetID(), receipts); err != nil {
		log.Debug("Failed to deliver receipts", "err", err)
	}
	return nil
}

// HandleNewBlockHashesMsg deal received NewBlockHashesMsg
func HandleNewBlockHashesMsg(p *p2p.Peer, msg p2p.Msg) error {
	var announces newBlockHashesData
	if err := msg.Decode(&announces); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
	}
	// Mark the hashes as present at the remote node
	for _, block := range announces {
		p.KnownBlockAdd(block.Hash)
	}
	// Schedule all the unknown hashes for retrieval
	unknown := make(newBlockHashesData, 0, len(announces))
	for _, block := range announces {
		if !bc.InstanceBlockChain().HasBlock(block.Hash, block.Number) {
			unknown = append(unknown, block)
		}
	}
	for _, block := range unknown {
		InstanceSynCtrl().puller.Notify(p.GetID(), block.Hash, block.Number, time.Now(), requestOneHeader, requestBodies)
	}

	return nil
}

// HandleNewBlockMsg deal received NewBlockMsg
func HandleNewBlockMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Retrieve and decode the propagated block
	var request newBlockData
	if err := msg.Decode(&request); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
	}
	request.Block.ReceivedAt = msg.ReceivedAt
	request.Block.ReceivedFrom = p

	// Mark the peer as owning the block and schedule it for import
	p.KnownBlockAdd(request.Block.Hash())
	InstanceSynCtrl().puller.Enqueue(p.GetID(), request.Block)

	// Assuming the block is importable by the peer, but possibly not yet done so,
	// calculate the head hash and TD that the peer truly must have.
	var (
		trueHead = request.Block.ParentHash()
		trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
	)
	// Update the peers total difficulty if better than the previous
	if _, td := p.Head(); trueTD.Cmp(td) > 0 {
		p.SetHead(trueHead, trueTD)

		// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
		// a singe block (as the true TD is below the propagated block), however this
		// scenario should easily be covered by the fetcher.
		currentBlock := bc.InstanceBlockChain().CurrentBlock()
		if trueTD.Cmp(bc.InstanceBlockChain().GetTd(currentBlock.Hash(), currentBlock.NumberU64())) > 0 {
		}
	}
	return nil
}

// HandleNewBlockMsg deal received NewBlockMsg
func HandleNewHashBlockMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Retrieve and decode the propagated block
	var request newBlockHashData
	if err := msg.Decode(&request); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
	}
	txs := make([]*types.Transaction, 0, len(request.BlockH.TxsHash))
	for _, txhs := range request.BlockH.TxsHash {
		//get tx data from txpool
		tx := txpool.GetTxPool().GetTxByHash(txhs)
		txs = append(txs, tx)
	}
	newBlock := types.BuildBlock(request.BlockH.Header, txs, request.BlockH.Uncles, request.BlockH.Td)

	newBlock.ReceivedAt = msg.ReceivedAt
	newBlock.ReceivedFrom = p
	////////////////////////////////////////////////

	////////////////////////////////////////////////
	// Mark the peer as owning the block and schedule it for import
	p.KnownBlockAdd(newBlock.Hash())
	InstanceSynCtrl().puller.Enqueue(p.GetID(), newBlock)

	// Assuming the block is importable by the peer, but possibly not yet done so,
	// calculate the head hash and TD that the peer truly must have.
	var (
		trueHead = newBlock.ParentHash()
		trueTD   = new(big.Int).Sub(request.BlockH.Td, newBlock.Difficulty())
	)
	// Update the peers total difficulty if better than the previous
	if _, td := p.Head(); trueTD.Cmp(td) > 0 {
		p.SetHead(trueHead, trueTD)

		// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
		// a singe block (as the true TD is below the propagated block), however this
		// scenario should easily be covered by the fetcher.
		currentBlock := bc.InstanceBlockChain().CurrentBlock()
		if trueTD.Cmp(bc.InstanceBlockChain().GetTd(currentBlock.Hash(), currentBlock.NumberU64())) > 0 {
		}
	}
	return nil
}

// HandleTxMsg deal received TxMsg
func HandleTxMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	// Don't change this code if you don't understand it
	if atomic.LoadUint32(&InstanceSynCtrl().AcceptTxs) == 0 {
		return nil
	}
	// Transactions can be processed, parse all of them and deliver to the pool
	var txs []*types.Transaction
	if err := msg.Decode(&txs); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	for i, tx := range txs {
		// Validate and mark the remote transaction
		if tx == nil {
			return p2p.ErrResp(p2p.ErrDecode, "transaction %d is nil", i)
		}
		p.KnownTxsAdd(tx.Hash())
	}
	//batch TxsAsynSender
	if len(txs) > 1 {
		go txpool.GetTxPool().GoTxsAsynSender(txs)
		go txpool.GetTxPool().AddTxs(txs)
	}else {
		go txpool.GetTxPool().AddTxs(txs)
	}

	return nil
}
