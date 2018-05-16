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

// implements nodes keep-live Protocol.
package discover

import(
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hpb-project/ghpb/common/crypto"
	"github.com/hpb-project/ghpb/common/log"
)

const (
	maxConcurrencyPingPongs = 16
	pingInterval             = 10 * time.Second
)

type Crowd struct {
	mutex     sync.Mutex    // Mutex for members
	members   []*Node       // Members of the consensus
	actives   []*Node       // active member(keep live success)
	roleType  uint8         // Crowd's nodes type
	keepSlots chan struct{} // limits total number of active bonding processes
	keepMu    sync.Mutex
	keeping   map[NodeID]*bondproc
	net       transport
	self      *Node

	refreshReq chan chan struct{}
	closeReq   chan struct{}
	closed     chan struct{}
}

func (cr *Crowd) Self() *Node {
	return cr.self
}

func (cr *Crowd) Close() {
	select {
	case <-cr.closed:
		// already closed.
	case cr.closeReq <- struct{}{}:
		<-cr.closed // wait for keepLiveLoop to end.
	}
}

// Returns only the nodes available
func (cr *Crowd) Fetch() []*Node {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()
	var activeCrowd []*Node
	for _, m := range cr.actives {
		activeCrowd = append(activeCrowd, m)
	}
	return activeCrowd
}

func (cr *Crowd) Set(nds []*Node) {
	cr.mutex.Lock()
	cr.members = nds
	cr.mutex.Unlock()
	// The new node starts ping-pong immediately.
	cr.refresh()
}

func (cr *Crowd) Add(n *Node) {
	cr.mutex.Lock()
	cr.members = append(cr.members, n)
	cr.mutex.Unlock()
	// The new node starts ping-pong immediately.
	cr.refresh()
}

func (cr *Crowd) Clear() {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()
	cr.members = make([] *Node, 0)
}

func (cr *Crowd) Delete(n *Node) {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()
	var index = 0
	for _, m := range cr.members {
		if m.ID == n.ID {
			cr.members = append(cr.members[:index], cr.members[index+1:]...)
		}
		index++
	}
}

func (cr *Crowd) SetFallbackNodes(nodes []*Node) error {
	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}
	}
	cr.mutex.Lock()
	var tmpNodes []*Node
	for _, n := range nodes {
		cpy := *n
		// Recompute cpy.sha because the node might not have been
		// created by NewNode or ParseNode.
		cpy.sha = crypto.Keccak256Hash(n.ID[:])
		tmpNodes = append(tmpNodes, &cpy)
	}
	cr.members = tmpNodes
	cr.mutex.Unlock()
	cr.refresh()
	return nil
}

func newCrowd (ci commInfo, roleType uint8) (*Crowd, error) {
	Crowd := &Crowd{
		net:        ci.udpSt,
		keepSlots:  make(chan struct{}, maxConcurrencyPingPongs),
		keeping:    make(map[NodeID]*bondproc),
		roleType:   roleType,
		self:       NewNode(ci.ourId, ci.ourRole, ci.ourAddr.IP, uint16(ci.ourAddr.Port), uint16(ci.ourAddr.Port)),

		refreshReq: make(chan chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
	}

	for i := 0; i < cap(Crowd.keepSlots); i++ {
		Crowd.keepSlots <- struct{}{}
	}

	go Crowd.keepLiveLoop()

	return Crowd, nil
}

// Guaranteed keepLive function scheduling.
func (cr *Crowd) keepLiveLoop()  {
	var (
		timer   = time.NewTicker(pingInterval)
		waiting []chan struct{} // accumulates waiting callers while keepLiveLoop runs
		done    chan struct{}   // where keepLiveLoop reports completion
	)
loop:
	for {
		select {
		case <-timer.C:
			if done == nil {
				done = make(chan struct{})
				go cr.keepAllLive(done)
			}
		case req := <-cr.refreshReq:
			waiting = append(waiting, req)
			if done == nil {
				done = make(chan struct{})
				go cr.keepAllLive(done)
			}
		case <-done:
			for _, ch := range waiting {
				close(ch)
			}
			waiting = nil
			done = nil
		case <-cr.closeReq:
			break loop
		}
	}

	if cr.net != nil {
		cr.net.close()
	}
	if done != nil {
		<-done
	}
	for _, ch := range waiting {
		close(ch)
	}
	close(cr.closed)
}

func (cr *Crowd) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	case cr.refreshReq <- done:
	case <-cr.closed:
		close(done)
	}
	return done
}

func (cr *Crowd) keepAllLive(done chan struct{}) {
	defer close(done)

	cr.mutex.Lock()
	defer cr.mutex.Unlock()
    cr.members = nodesDuplicate(cr.members)
	rc := make(chan *Node, len(cr.members))
	for i := range cr.members {
		go func(node * Node) {
			nn, _ := cr.keepLive(false, node.ID, node.Role, node.addr(), uint16(node.TCP))
			rc <- nn
		} (cr.members[i])
	}

	var sucMem []*Node

	for range cr.members {
		if node := <-rc; node != nil {
			if node != nil {
				//only pingPong success node be retained
				sucMem = append(sucMem, node)
			}
		}
	}

	cr.actives = sucMem
	for _, n := range cr.actives {
		log.Debug("keep-live", "active node", n)
	}
}

func (cr *Crowd) keepLive(pinged bool, id NodeID, role uint8, addr *net.UDPAddr, tcpPort uint16) (*Node, error) {
	// This is unlikely to happen.
	if id == cr.self.ID {
		return nil, errors.New("is self")
	}

	var result error
	log.Trace("Starting keeping ping/pong", "id", id)

	cr.keepMu.Lock()
	w := cr.keeping[id]
	if w != nil {
		// Wait for an existing keeping process to complete.
		cr.keepMu.Unlock()
		<-w.done
	} else {
		// Register a new keeping process.
		w = &bondproc{done: make(chan struct{})}
		cr.keeping[id] = w
		cr.keepMu.Unlock()
		// Do the ping/pong. The result goes into w.
		cr.pingPong(w, pinged, id, role, addr, tcpPort)
		// Unregister the process after it's done.
		cr.keepMu.Lock()
		delete(cr.keeping, id)
		cr.keepMu.Unlock()
	}
	// Retrieve the keeping results
	result = w.err
	if result != nil {
		return nil, result
	}
	node := w.n
	return node, result
}

func (cr *Crowd) pingPong(w *bondproc, pinged bool, id NodeID, role uint8, addr *net.UDPAddr, tcpPort uint16) {
	// keepSlots to limit network usage
	<-cr.keepSlots
	defer func() { cr.keepSlots <- struct{}{} }()

	// Ping the remote side and wait for a pong
	if w.err = cr.ping(id, role, addr); w.err != nil {
		close(w.done)
		return
	}
	if !pinged {
		cr.net.waitping(id, crowdService, role, cr.roleType)
	}
	// keeping succeeded, update the node database.
	w.n = NewNode(id, role, addr.IP, uint16(addr.Port), tcpPort)
	close(w.done)
}

func (cr *Crowd) ping(id NodeID, role uint8, addr *net.UDPAddr) error {
	if err := cr.net.ping(id, crowdService, role, cr.roleType, addr); err != nil {
		return err
	}

	return nil
}