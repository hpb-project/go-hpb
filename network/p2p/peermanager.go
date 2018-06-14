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

package p2p

import (
	"sync"
	"errors"
	"math/big"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/log"
)


var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

type PeerManager struct {
	lock   sync.RWMutex
	peers  map[string]*Peer
	closed bool

	server  *Server
	hpb     *Protocol
}

var pm   *PeerManager
var lock *sync.Mutex = &sync.Mutex {}

func PeerMgrInst() *PeerManager {
	if pm == nil {
		lock.Lock()
		defer lock.Unlock()
		pm =&PeerManager{
			peers:   make(map[string]*Peer),
		}
	}
	return pm
}

func (prm *PeerManager)Start() error {
	hpb ,err := NewProtos()
	if err != nil {
		log.Error("PeerManager hpb protocol build","error",err)
		return err
	}
	log.Info("Hpb protocol","Hpb",hpb.Protocols())

	prm.hpb = hpb

	prm.server = &Server{
		//Config:       config,
	}

	if err := prm.server.Start(); err != nil {
		log.Error("Hpb protocol","error",err)
		return err
	}

	return nil

}

func (prm *PeerManager)Stop(){

	prm.server.Stop()
	prm.server = nil

}

//接口定义
// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
func (prm *PeerManager) Register(p *Peer) error {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	if prm.closed {
		return errClosed
	}
	if _, ok := prm.peers[p.id]; ok {
		return errAlreadyRegistered
	}
	prm.peers[p.id] = p
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (prm *PeerManager) Unregister(id string) error {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	if _, ok := prm.peers[id]; !ok {
		return errNotRegistered
	}
	delete(prm.peers, id)
	return nil
}

// Peer retrieves the registered peer with the given id.
func (prm *PeerManager) Peer(id string) *Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	return prm.peers[id]
}

// Len returns if the current number of peers in the set.
func (prm *PeerManager) PeersCount() int {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	return len(prm.peers)
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (prm *PeerManager) PeersWithoutBlock(hash common.Hash) []*Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	list := make([]*Peer, 0, len(prm.peers))
	for _, p := range prm.peers {
		if !p.knownBlocks.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (prm *PeerManager) PeersWithoutTx(hash common.Hash) []*Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	list := make([]*Peer, 0, len(prm.peers))
	for _, p := range prm.peers {
		if !p.knownTxs.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (prm *PeerManager) BestPeer() *Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	var (
		bestPeer *Peer
		bestTd   *big.Int
	)
	for _, p := range prm.peers {
		if _, td := p.Head(); bestPeer == nil || td.Cmp(bestTd) > 0 {
			bestPeer, bestTd = p, td
		}
	}
	return bestPeer
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (prm *PeerManager) closePeers() {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	for _, p := range prm.peers {
		p.Disconnect(DiscQuitting)
	}
	prm.closed = true
}




