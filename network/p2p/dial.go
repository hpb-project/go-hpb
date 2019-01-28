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
	"container/heap"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/network/p2p/netutil"
)

const (
	dialHistoryExpiration = 30 * time.Second
)

var dialHistroyAddr []string = []string{}
var fronttime int64 = time.Now().Unix()
var mutex sync.Mutex

// NodeDialer is used to connect to nodes in the network, typically by using
// an underlying net.Dialer but also using net.Pipe in tests
type NodeDialer interface {
	Dial(*discover.Node) (net.Conn, error)
}

// TCPDialer implements the NodeDialer interface by using a net.Dialer to
// create TCP connections to nodes in the network
type TCPDialer struct {
	*net.Dialer
}

// Dial creates a TCP connection to the node
func (t TCPDialer) Dial(dest *discover.Node) (net.Conn, error) {
	addr := &net.TCPAddr{IP: dest.IP, Port: int(dest.TCP)}
	return t.Dialer.Dial("tcp", addr.String())
}

type dialstate struct {
	//maxDynDials int
	ntab        discoverTable
	netrestrict *netutil.Netlist

	dialing map[discover.NodeID]connFlag
	static  map[discover.NodeID]*dialTask
	hist    *dialHistory

	start     time.Time        // time when the dialer was first used
	bootnodes []*discover.Node // default dials when there are no peers
}

type discoverTable interface {
	Self() *discover.Node
	Close()
	FindNodes() []*discover.Node
	Bondall(nodes []*discover.Node) int

	//AddNode(node *discover.Node)
	RemoveNode(nid discover.NodeID)
	//HasNode(nid discover.NodeID) bool
}

// the dial history remembers recent dials.
type dialHistory []pastDial

// pastDial is an entry in the dial history.
type pastDial struct {
	id  discover.NodeID
	exp time.Time
}

type task interface {
	Do(*Server)
}

// A dialTask is generated for each node that is dialed. Its
// fields cannot be accessed while the task is running.
type dialTask struct {
	flags        connFlag
	dest         *discover.Node
	lastResolved time.Time
	resolveDelay time.Duration
}

// A waitExpireTask is generated if there are no other tasks
// to keep the loop in Server.run ticking.
type waitExpireTask struct {
	time.Duration
}

func newDialState(static []*discover.Node, bootnodes []*discover.Node, ntab discoverTable, netrestrict *netutil.Netlist) *dialstate {
	s := &dialstate{
		ntab:        ntab,
		netrestrict: netrestrict,
		static:      make(map[discover.NodeID]*dialTask),
		dialing:     make(map[discover.NodeID]connFlag),
		bootnodes:   make([]*discover.Node, len(bootnodes)),
		hist:        new(dialHistory),
	}

	copy(s.bootnodes, bootnodes)
	for _, n := range static {
		s.addStatic(n)
	}

	return s
}

func (s *dialstate) addStatic(n *discover.Node) {
	s.static[n.ID] = &dialTask{flags: staticDialedConn, dest: n}
}

func (s *dialstate) removeStatic(n *discover.Node) {
	delete(s.static, n.ID)
	// This removes a previous dial timestamp so that application
	// can force a server to reconnect with chosen peer immediately.
	s.hist.remove(n.ID)
}

func (s *dialstate) newTasks(nRunning int, peers map[discover.NodeID]*PeerBase, now time.Time) []task {
	if s.start == (time.Time{}) {
		s.start = now
	}

	var newtasks []task
	addDial := func(flag connFlag, n *discover.Node) bool {
		if err := s.checkDial(n, peers); err != nil {
			log.Trace("Skipping dial candidate", "id", n.ID, "addr", &net.TCPAddr{IP: n.IP, Port: int(n.TCP)}, "err", err)
			return false
		}
		s.dialing[n.ID] = flag
		newtasks = append(newtasks, &dialTask{flags: flag, dest: n})
		return true
	}

	// Expire the dial history on every invocation.
	s.hist.expire(now)

	// Create dials for static nodes if they are not connected.
	for id, t := range s.static {
		err := s.checkDial(t.dest, peers)
		switch err {
		case errNotWhitelisted, errSelf:
			log.Warn("Removing static dial candidate", "id", t.dest.ID, "addr", &net.TCPAddr{IP: t.dest.IP, Port: int(t.dest.TCP)}, "err", err)
			delete(s.static, t.dest.ID)
		case nil:
			s.dialing[id] = t.flags
			newtasks = append(newtasks, t)
		}
	}

	nodes := s.ntab.FindNodes()
	for _, n := range nodes {
		if addDial(dynDialedConn, n) {
			log.Trace("Add node to dial task.", "id", n.ID)
		}
	}

	if nRunning == 0 && len(newtasks) == 0 {
		t := &waitExpireTask{time.Second}
		newtasks = append(newtasks, t)
	}

	return newtasks
}

func (s *dialstate) checkDial(n *discover.Node, peers map[discover.NodeID]*PeerBase) error {
	_, dialing := s.dialing[n.ID]
	switch {
	case dialing:
		return errAlreadyDialing
	case peers[n.ID] != nil:
		return errAlreadyConnected
	case s.ntab != nil && n.ID == s.ntab.Self().ID:
		return errSelf
	case s.netrestrict != nil && !s.netrestrict.Contains(n.IP):
		return errNotWhitelisted
	case s.hist.contains(n.ID):
		return errRecentlyDialed
	}
	return nil
}

func (s *dialstate) taskDone(t task, now time.Time) {
	switch t := t.(type) {
	case *dialTask:
		s.hist.add(t.dest.ID, now.Add(dialHistoryExpiration))
		delete(s.dialing, t.dest.ID)
	}
}

func (t *dialTask) Do(srv *Server) {
	if t.dest.Incomplete() {
		return
	}
	if srv.delHist.contains(t.dest.ID) {
		log.Debug("Do task: recently delete node.")
		return
	}
	success := t.dial(srv, t.dest)
	log.Trace("One dial task done.", "result", success)

}

// dial performs the actual connection attempt.
func (t *dialTask) dial(srv *Server, dest *discover.Node) bool {
	addr := &net.TCPAddr{IP: dest.IP, Port: int(dest.TCP)}

	if len(dialHistroyAddr) > 30 || time.Now().Unix()-fronttime > int64(100) {
		fronttime = time.Now().Unix()
		mutex.Lock()
		dialHistroyAddr = []string{}
		mutex.Unlock()
	}
	for _, v := range dialHistroyAddr {
		if v == addr.String() {
			log.Trace("dile histroy", "len=", len(dialHistroyAddr), "restime:", time.Now().Unix()-fronttime)
			return false
		}
	}
	mutex.Lock()
	dialHistroyAddr = append(dialHistroyAddr, addr.String())
	mutex.Unlock()
	log.Debug("Connect:", "ip=", addr.String(), "id=", dest.ID, "time=", time.Now().Second())
	fd, err := srv.dialer.Dial(dest)
	if err != nil {
		log.Trace("Dial error", "task", t, "err", err)
		return false
	}
	mfd := newMeteredConn(fd, false)
	srv.SetupConn(mfd, t.flags, dest)
	return true
}

func (t *dialTask) String() string {
	return fmt.Sprintf("%v %x %v:%d", t.flags, t.dest.ID[:8], t.dest.IP, t.dest.TCP)
}

func (t waitExpireTask) Do(*Server) {
	time.Sleep(t.Duration)
}
func (t waitExpireTask) String() string {
	return fmt.Sprintf("wait for dial hist expire (%v)", t.Duration)
}

// Use only these methods to access or modify dialHistory.
func (h dialHistory) min() pastDial {
	return h[0]
}
func (h *dialHistory) add(id discover.NodeID, exp time.Time) {
	heap.Push(h, pastDial{id, exp})
}
func (h *dialHistory) remove(id discover.NodeID) bool {
	for i, v := range *h {
		if v.id == id {
			heap.Remove(h, i)
			return true
		}
	}
	return false
}
func (h dialHistory) contains(id discover.NodeID) bool {
	for _, v := range h {
		if v.id == id {
			return true
		}
	}
	return false
}
func (h *dialHistory) expire(now time.Time) {
	for h.Len() > 0 && h.min().exp.Before(now) {
		heap.Pop(h)
	}
}

// heap.Interface boilerplate
func (h dialHistory) Len() int           { return len(h) }
func (h dialHistory) Less(i, j int) bool { return h[i].exp.Before(h[j].exp) }
func (h dialHistory) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *dialHistory) Push(x interface{}) {
	*h = append(*h, x.(pastDial))
}
func (h *dialHistory) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
