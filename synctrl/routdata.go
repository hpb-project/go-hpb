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
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math"
	"math/big"
	"time"
)

// routingBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func routBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := p2p.PeerMgrInst().PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := bc.InstanceBlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), bc.InstanceBlockChain().GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			switch peer.LocalType() {
			case discover.PreNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlock(peer, block, td)
					break
				case discover.SynNode:
					sendNewBlock(peer, block, td)
					break
				default:
					break
				}
				break
			case discover.HpNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlock(peer, block, td)
					break
				case discover.HpNode:
					sendNewBlock(peer, block, td)
					break
				case discover.SynNode:
					//ONLY FOR TEST
					sendNewBlock(peer, block, td)
					break
				default:
					break
				}
				break
			default:
				break
			}
		}
		log.Trace("Propagated block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if bc.InstanceBlockChain().HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			switch peer.LocalType() {
			case discover.PreNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				case discover.SynNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				default:
					break
				}
				break
			case discover.HpNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				case discover.HpNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				case discover.SynNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				default:
					break
				}
				break
			default:
				break
			}
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}
/*
// routingTx will propagate a transaction to peers by type which are not known to
// already have the given transaction.
func routTx(hash common.Hash, tx *types.Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := p2p.PeerMgrInst().PeersWithoutTx(hash)
	for _, peer := range peers {
		switch peer.LocalType() {
		case discover.PreNode:
			switch peer.RemoteType() {
			case discover.PreNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			default:
				break
			}
			break
		case discover.HpNode:
			switch peer.RemoteType() {
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			default:
				break
			}
			break
		case discover.SynNode:
			switch peer.RemoteType() {
			case discover.PreNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			default:
				break
			}
			break
		default:
			break
		}
	}

	log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
}
*/


// routingTx will propagate a transaction to peers by type which are not known to
// already have the given transaction.
func routTx(hash common.Hash, tx *types.Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it

	if tx.IsForward() {
		routForwardTx(hash,tx)
	} else {
		tx.SetForward(true)
		routNativeTx(hash,tx)
	}
}

func routNativeTx(hash common.Hash, tx *types.Transaction) {
	peers := p2p.PeerMgrInst().PeersWithoutTx(hash)
	if len(peers) == 0 { return }

	switch p2p.PeerMgrInst().GetLocalType() {
	case discover.HpNode:
		for _, peer := range peers {
			switch peer.RemoteType() {
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			}
		}
		break
	case discover.PreNode:
		for _, peer := range peers {
			switch peer.RemoteType() {
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			}
		}

		toPreCount := 0
		for _, peer := range peers {
			switch peer.RemoteType() {
			case discover.PreNode:
				sendTransactions(peer, types.Transactions{tx})
				toPreCount += 1
				break
			}
			if toPreCount >= 1 {
				break
			}
		}

		break
	case discover.SynNode:
		for _, peer := range peers {
			switch peer.RemoteType() {
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			}
		}

		toPreCount := 0
		for _, peer := range peers {
			switch peer.RemoteType() {
			case discover.PreNode:
				sendTransactions(peer, types.Transactions{tx})
				toPreCount += 1
				break
			}

			if toPreCount >= 1 {
				break
			}
		}
		break
	}
	log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
}

func routForwardTx(hash common.Hash, tx *types.Transaction) {
	peers := p2p.PeerMgrInst().PeersWithoutTx(hash)
	if len(peers) == 0 { return }

	switch p2p.PeerMgrInst().GetLocalType() {
	case discover.HpNode:
		break
	case discover.PreNode:
		for _, peer := range peers {
			switch peer.RemoteType() {
			case discover.HpNode:
				sendTransactions(peer, types.Transactions{tx})
				break
			}
		}
		break
	case discover.SynNode:
		break
	}

	log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
}

func sendTransactions(peer *p2p.Peer, txs types.Transactions) error {
	for _, tx := range txs {
		peer.KnownTxsAdd(tx.Hash())
	}
	return p2p.SendData(peer, p2p.TxMsg, txs)
}
