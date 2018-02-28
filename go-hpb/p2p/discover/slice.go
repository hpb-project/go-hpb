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

// slice.go implements the CommNode and PreCommNode keep-live Protocol.
package discover

import(
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/crypto"
	"github.com/hpb-project/go-hpb/log"
)

const (
	maxConcurrencyPingPongs = 16
	pingInerval             = 10 * time.Second
)

type Slice struct {
	mutex     sync.Mutex    // Mutex for members
	members   []*Node       // Members of the consensus
	actives   []*Node       // active member(keep live success)
	roleType  uint8         // Slice's nodes type
	keepSlots chan struct{} // limits total number of active bonding processes
	keepmu    sync.Mutex
	keeping   map[NodeID]*bondproc
	db        *nodeDB
	net       transport
	self      *Node

	refreshReq chan chan struct{}
	closeReq   chan struct{}
	closed     chan struct{}
}

func (sl *Slice) Self() *Node {
	return sl.self
}

func (sl *Slice) Close() {
	select {
	case <-sl.closed:
		// already closed.
	case sl.closeReq <- struct{}{}:
		<-sl.closed // wait for keepLiveLoop to end.
	}
}

// Returns only the nodes available
func (sl *Slice) Fetch() []*Node {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	var activeSlice []*Node
	for _, m := range sl.actives {
		activeSlice = append(activeSlice, m)
	}

	return activeSlice
}

func (sl *Slice) Delete(n *Node) {
	sl.db.deleteNode(n.ID)
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	var index = 0
	for _, m := range sl.members {
		if m.ID == n.ID {
			sl.members = append(sl.members[:index], sl.members[index+1:]...)
		}
		index++
	}
}

// If the pingPong test is successful, it will be added to the DB.
func (sl *Slice) Add(n *Node) {
	sl.mutex.Lock()
	sl.members = append(sl.members, n)
	sl.mutex.Unlock()
	// The new node starts ping-pong immediately.
	sl.refresh()
}

func (sl *Slice) SetFallbackNodes(nodes []*Node) error {
	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}
	}
	sl.mutex.Lock()
	var tmpNodes []*Node
	for _, n := range nodes {
		cpy := *n
		// Recompute cpy.sha because the node might not have been
		// created by NewNode or ParseNode.
		cpy.sha = crypto.Keccak256Hash(n.ID[:])
		tmpNodes = append(tmpNodes, &cpy)
	}
	sl.members = tmpNodes
	sl.mutex.Unlock()
	sl.refresh()
	return nil
}

func newSlice (ci commInfo, roleType uint8) (*Slice, error) {
	slice := &Slice{
		net:        ci.udpSt,
		keepSlots:  make(chan struct{}, maxConcurrencyPingPongs),
		keeping:    make(map[NodeID]*bondproc),
		db:         ci.lvlDb,
		roleType:   roleType,
		self:       NewNode(ci.ourId, ci.ourRole, ci.ourAddr.IP, uint16(ci.ourAddr.Port), uint16(ci.ourAddr.Port)),

		refreshReq: make(chan chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
	}

	for i := 0; i < cap(slice.keepSlots); i++ {
		slice.keepSlots <- struct{}{}
	}

	// TODO by xujl: 传入slice为空，则从orgnode拉取，如果再失败则从本地db加载
	go slice.pullSlice(roleType)
	slice.loadFromDB(ci.lvlDb, roleType)

	go slice.keepLiveLoop()

	return slice, nil
}

// Guaranteed keepLive function scheduling.
func (sl *Slice) keepLiveLoop()  {
	var (
		timer   = time.NewTicker(pingInerval)
		waiting []chan struct{} // accumulates waiting callers while keepLiveLoop runs
		done    chan struct{}   // where keepLiveLoop reports completion
	)
loop:
	for {
		select {
		case <-timer.C:
			if done == nil {
				done = make(chan struct{})
				go sl.keepAllLive(done)
			}
		case req := <-sl.refreshReq:
			waiting = append(waiting, req)
			if done == nil {
				done = make(chan struct{})
				go sl.keepAllLive(done)
			}
		case <-done:
			for _, ch := range waiting {
				close(ch)
			}
			waiting = nil
			done = nil
		case <-sl.closeReq:
			break loop
		}
	}

	if sl.net != nil {
		sl.net.close()
	}
	if done != nil {
		<-done
	}
	for _, ch := range waiting {
		close(ch)
	}
	sl.db.close()
	close(sl.closed)
}

func (sl *Slice) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	case sl.refreshReq <- done:
	case <-sl.closed:
		close(done)
	}
	return done
}

func (sl *Slice) keepAllLive(done chan struct{}) {
	defer close(done)

	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	rc := make(chan *Node, len(sl.members))
	for i := range sl.members {
		go func(node * Node) {
			nn, _ := sl.keepLive(false, node.ID, node.Role, node.addr(), uint16(node.TCP))
			rc <- nn
		} (sl.members[i])
	}

	var sucMem []*Node

	for range sl.members {
		if node := <-rc; node != nil {
			if node != nil {
				//only pingPong success node be retained
				sucMem = append(sucMem, node)
			}
		}
	}

	sl.actives = sucMem
	for _, n := range sl.actives {
		log.Info("keep-live", "active node", n)
	}
}

func (sl *Slice) keepLive(pinged bool, id NodeID, role uint8, addr *net.UDPAddr, tcpPort uint16) (*Node, error) {
	// This is unlikely to happen.
	if id == sl.self.ID {
		return nil, errors.New("is self")
	}

	var result error
	log.Trace("Starting keeping ping/pong", "id", id)

	sl.keepmu.Lock()
	w := sl.keeping[id]
	if w != nil {
		// Wait for an existing keeping process to complete.
		sl.keepmu.Unlock()
		<-w.done
	} else {
		// Register a new keeping process.
		w = &bondproc{done: make(chan struct{})}
		sl.keeping[id] = w
		sl.keepmu.Unlock()
		// Do the ping/pong. The result goes into w.
		sl.pingPong(w, pinged, id, role, addr, tcpPort)
		// Unregister the process after it's done.
		sl.keepmu.Lock()
		delete(sl.keeping, id)
		sl.keepmu.Unlock()
	}
	// Retrieve the keeping results
	result = w.err
	if result != nil {
		return nil, result
	}
	node := w.n
	if node != nil {
		sl.db.updateLastPong(id, nodeDBCommitteePong, time.Now())
	}
	return node, result
}

func (sl *Slice) pingPong(w *bondproc, pinged bool, id NodeID, role uint8, addr *net.UDPAddr, tcpPort uint16) {
	// keepSlots to limit network usage
	<-sl.keepSlots
	defer func() { sl.keepSlots <- struct{}{} }()

	// Ping the remote side and wait for a pong
	if w.err = sl.ping(id, role, addr); w.err != nil {
		close(w.done)
		return
	}
	if !pinged {
		sl.net.waitping(id, role, sl.roleType)
	}
	// keeping succeeded, update the node database.
	w.n = NewNode(id, role, addr.IP, uint16(addr.Port), tcpPort)
	sl.db.updateNode(w.n, nodeDBCommitteeRoot)
	close(w.done)
}

func (sl *Slice) ping(id NodeID, role uint8, addr *net.UDPAddr) error {
	sl.db.updateLastPing(id, nodeDBCommitteePing, time.Now())
	if err := sl.net.ping(id, role, sl.roleType, addr); err != nil {
		return err
	}
	sl.db.updateLastPong(id, nodeDBCommitteePong, time.Now())

	// TODO by xujl: Whether to reuse KAD DB timeout Mechanism
	sl.db.ensureExpirer(nodeDBCommitteeRoot, nodeDBCommitteePong)
	return nil
}

func (sl *Slice) loadFromDB(db *nodeDB, forRole uint8) {
	if db == nil {
		return
	}
}

func (sl *Slice) pullSlice(forRole uint8) {


}