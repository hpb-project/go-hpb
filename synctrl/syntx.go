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
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math/rand"
)

type txsync struct {
	p   *p2p.Peer
	txs []*types.Transaction
}

// syncTransactions starts sending all currently pending transactions to the given peer.
func (this *SynCtrl) syncTransactions(p *p2p.Peer) {
	var txs types.Transactions
	pending, _ := this.txpool.Pending()
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	if len(txs) == 0 {
		return
	}
	select {
	case this.txsyncCh <- &txsync{p, txs}:
	case <-this.quitSync:
	}
}

// txsyncLoop takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
func (this *SynCtrl) txsyncLoop() {
	var (
		pending = make(map[discover.NodeID]*txsync)
		sending = false               // whether a send is active
		pack    = new(txsync)         // the pack that is being sent
		done    = make(chan error, 1) // result of the send
	)

	// send starts a sending a pack of transactions from the sync.
	send := func(s *txsync) {
		// Fill pack with transactions up to the target size.
		size := common.StorageSize(0)
		pack.p = s.p
		pack.txs = pack.txs[:0]
		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
			pack.txs = append(pack.txs, s.txs[i])
			size += s.txs[i].Size()
		}
		// Remove the transactions that will be sent.
		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
		if len(s.txs) == 0 {
			delete(pending, s.p.ID())
		}
		// Send the pack in the background.
		log.Trace("Sending batch of transactions", "count", len(pack.txs), "bytes", size)
		sending = true
		go func() { done <- sendTransactions(pack.p, pack.txs) }()
	}

	// pick chooses the next pending sync.
	pick := func() *txsync {
		if len(pending) == 0 {
			return nil
		}
		n := rand.Intn(len(pending)) + 1
		for _, s := range pending {
			if n--; n == 0 {
				return s
			}
		}
		return nil
	}

	for {
		select {
		case s := <-this.txsyncCh:
			pending[s.p.ID()] = s
			if !sending {
				send(s)
			}
		case err := <-done:
			sending = false
			// Stop tracking peers that cause send failures.
			if err != nil {
				log.Debug("Transaction send failed", "err", err)
				delete(pending, pack.p.ID())
			}
			// Schedule the next send.
			if s := pick(); s != nil {
				send(s)
			}
		case <-this.quitSync:
			return
		}
	}
}

func (this *SynCtrl) txRoutingLoop() {

	//TODO new event system
	/*txPreReceiver := event.RegisterReceiver("tx_pool_tx_pre_receiver",
		func(payload interface{}) {
			switch msg := payload.(type) {
			case event.TxPreEvent:
				this.routingTx(msg.Message.Hash(), msg.Message)

				//t.Logf("TxPool get TxPreEvent %s", msg.Message.String())
				break
			}
		})
	event.Subscribe(txPreReceiver, event.TxPreTopic)*/


	for {
		select {
		case event := <-this.txCh:
			//log.Error("-----------receive txpre event--------")
			this.routingTx(event.Tx.Hash(), event.Tx)

		// Err() channel will be closed when unsubscribing.
		// todo by xjl
		//case <-this.   txSub.Err():
		//	return
		}
	}
}

// routingTx will propagate a transaction to peers by type which are not known to
// already have the given transaction.
func (this *SynCtrl) routingTx(hash common.Hash, tx *types.Transaction) {
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
		default:
			break
		}
	}

	log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
}

func sendTransactions(peer *p2p.Peer, txs types.Transactions) error {
	for _, tx := range txs {
		peer.KnownTxsAdd(tx.Hash())
	}
	return p2p.SendData(peer,p2p.TxMsg, txs)
}