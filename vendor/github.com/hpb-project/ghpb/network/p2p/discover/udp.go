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

package discover

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hpb-project/ghpb/common/crypto"
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/network/p2p/nat"
	"github.com/hpb-project/ghpb/network/p2p/netutil"
	"github.com/hpb-project/ghpb/common/rlp"
)

const Version = 0

// Errors
var (
	errPacketTooSmall   = errors.New("too small")
	errBadHash          = errors.New("bad hash")
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")
)

// Timeouts
const (
	respTimeout = 500 * time.Millisecond
	expiration  = 20 * time.Second

	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user
)

// RPC packet types
const (
	pingPacket = iota + 1 // zero is 'reserved'
	pongPacket
	findnodePacket
	neighborsPacket
)

// work for
const (
	tableService uint8 = iota + 1
	crowdService
)

// RPC request structures
type (
	ping struct {
		Version    uint
		From, To   rpcEndpoint
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong is the reply to ping.
	pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint

		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// findnode is a query for nodes close to the given target.
	findnode struct {
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// reply to findnode
	neighbors struct {
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	rpcNode struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		ID  NodeID
		ROLE uint8
	}

	rpcEndpoint struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
	}
)

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func (t *udp) nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*Node, error) {
	if rn.UDP <= 1024 {
		return nil, errors.New("low port")
	}
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict whitelist")
	}
	n := NewNode(rn.ID, rn.ROLE, rn.IP, rn.UDP, rn.TCP)
	err := n.validateComplete()
	return n, err
}

func nodeToRPC(n *Node) rpcNode {
	return rpcNode{ID: n.ID, ROLE: n.Role, IP: n.IP, UDP: n.UDP, TCP: n.TCP}
}

type packet interface {
	handle(t *udp, from *net.UDPAddr, fromID NodeID, workFor uint8, fromRole uint8, forRole uint8, mac []byte) error
	name() string
}

type conn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// udp implements the RPC protocol.
type udp struct {
	conn        conn
	netrestrict *netutil.Netlist
	priv        *ecdsa.PrivateKey
	ourRole     uint8
	ourEndpoint rpcEndpoint

	addpending chan *pending
	gotreply   chan reply

	closing chan struct{}
	closed  bool
	nat     nat.Interface

	lightTab *Table
	accessTab *Table
}

// pending represents a pending reply.
//
// some implementations of the protocol wish to send more than one
// reply packet to findnode. in general, any neighbors packet cannot
// be matched up with a specific findnode packet.
//
// our implementation handles this by storing a callback function for
// each pending reply. incoming packets from a node are dispatched
// to all the callback functions for that node.
type pending struct {
	// these fields must match in the reply.
	from  NodeID
	workFor uint8
	forRole uint8
	ptype byte

	// time when the request must complete
	deadline time.Time

	// callback is called when a matching reply arrives. if it returns
	// true, the callback is removed from the pending reply queue.
	// if it returns false, the reply is considered incomplete and
	// the callback will be invoked again for the next matching reply.
	callback func(resp interface{}) (done bool)

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	errc chan<- error
}

type reply struct {
	from  NodeID
	workFor uint8
	fromRole uint8
	forRole uint8
	ptype byte
	data  interface{}
	// loop indicates whether there was
	// a matching request by sending on this channel.
	matched chan<- bool
}

type Gather struct {
	LightTab     *Table
	AccessTab    *Table
	CommCrowd    *Crowd
	PreCommCrowd *Crowd
}

type commInfo struct {
	udpSt   transport     // for udp network communication
	ourId  NodeID        // our node id
	ourRole uint8         // our role
	ourAddr *net.UDPAddr  // our udp addr
	lvlDb   *nodeDB       // level db for network node connection
}

// ListenUDP returns a new table that listens for UDP packets on laddr.
func ListenUDP(priv *ecdsa.PrivateKey, ourRole uint8, laddr string, natm nat.Interface, NodeDBPath string, netrestrict *netutil.Netlist) (*Gather, error) {
	addr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	ga, _, err := newUDP(priv, ourRole, conn, natm, NodeDBPath, netrestrict)
	if err != nil {
		return nil, err
	}

	// either light_Tab or access_Tab has the same self, lightTab.self is used here.
	log.Info("discover -> UDP", "listener up, self", ga.LightTab.self)
	return ga, nil
}

func newUDP(priv *ecdsa.PrivateKey, ourRole uint8, c conn, natm nat.Interface, nodeDBPath string, netrestrict *netutil.Netlist) (*Gather, *udp, error) {
	udp := &udp{
		conn:        c,
		priv:        priv,
		ourRole:     ourRole,
		netrestrict: netrestrict,
		closing:     make(chan struct{}),
		gotreply:    make(chan reply),
		addpending:  make(chan *pending),
	}
	realaddr := c.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, udp.closing, "udp", realaddr.Port, realaddr.Port, "hpb discovery")
		}
		// TODO: react to external IP changes over time.
		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}
	// TODO: separate TCP port
	udp.ourEndpoint = makeEndpoint(realaddr, uint16(realaddr.Port))

	ga := new(Gather)

	db, dbErr := newDB(PubkeyID(&priv.PublicKey), nodeDBPath)
	if dbErr != nil {
		return ga, nil, dbErr
	}

	ci := commInfo{
		udpSt : udp,
		ourId : PubkeyID(&priv.PublicKey),
		ourRole : ourRole,
		ourAddr : realaddr,
		lvlDb : db,
	}

	light, err := newTable(ci, LightRole)
	ga.LightTab = light
	if err != nil {
		return ga, nil, err
	}
	access, err := newTable(ci, AccessRole)
	ga.AccessTab = access
	if err != nil {
		return ga, nil, err
	}

	comm, err := newCrowd(ci, HpRole)
	ga.CommCrowd = comm
	if err != nil {
		return ga, nil, err
	}
	pre, err := newCrowd(ci, PreRole)
	ga.PreCommCrowd = pre
	if err != nil {
		return ga, nil, err
	}

	udp.lightTab = light
	udp.accessTab = access

	go udp.loop()
	go udp.readLoop()

	return ga, udp, nil
}

func (t *udp) close() {
	if t.closed {
		return
	}
	close(t.closing)
	t.closed = true
	t.conn.Close()
	// TODO: wait for the loops to end.
}

// ping sends a ping message to the given node and waits for a reply.
func (t *udp) ping(toid NodeID, workFor uint8, role uint8, forRole uint8, toaddr *net.UDPAddr) error {
	// TODO: maybe check for ReplyTo field in callback to measure RTT
	errc := t.pending(toid, workFor, forRole, pongPacket, func(interface{}) bool { return true })
	t.send(toaddr, workFor, forRole, pingPacket, &ping{
		Version:    Version,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, 0), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	return <-errc
}

func (t *udp) waitping(from NodeID, workFor uint8, fromRole uint8, forRole uint8) error {
	return <-t.pending(from, workFor, fromRole, pingPacket, func(interface{}) bool { return true })
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
func (t *udp) findnode(toid NodeID, workFor uint8, forRole uint8, toaddr *net.UDPAddr, target NodeID) ([]*Node, error) {
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	errc := t.pending(toid, workFor, forRole, neighborsPacket, func(r interface{}) bool {
		reply := r.(*neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
			if err != nil {
				log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
				continue
			}
			if forRole == n.Role {
				nodes = append(nodes, n)
			}
		}
		return nreceived >= bucketSize
	})
	// findnode work for table only
	t.send(toaddr, tableService, forRole, findnodePacket, &findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	err := <-errc
	return nodes, err
}

// pending adds a reply callback to the pending reply queue.
// see the documentation of type pending for a detailed explanation.
func (t *udp) pending(id NodeID, workFor uint8, forRole uint8, ptype byte, callback func(interface{}) bool) <-chan error {
	ch := make(chan error, 1)
	p := &pending{from: id, workFor: workFor, forRole: forRole, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addpending <- p:
		// loop will handle it
	case <-t.closing:
		ch <- errClosed
	}
	return ch
}

func (t *udp) handleReply(from NodeID, workFor uint8, frmRole uint8, forRole uint8, ptype byte, req packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, workFor, frmRole, forRole, ptype, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closing:
		return false
	}
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *udp) loop() {
	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *pending // head of plist when timeout was last reset
		contTimeouts = 0      // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*pending)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closing:
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*pending).errc <- errClosed
			}
			return

		case p := <-t.addpending:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				// send for role and req for role must be consistent
				if p.from == r.from && p.ptype == r.ptype && p.workFor == r.workFor && p.forRole == r.forRole {
					matched = true
					// Remove the matcher if its callback indicatess
					// that all replies have been received. This is
					// required for packet types that expect multiple
					// reply packets.
					if p.callback(r.data) {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

const (
	macSize  = 256 / 8
	sigSize  = 520 / 8
	headSize = macSize + sigSize // space of packet frame data
)

var (
	headSpace = make([]byte, headSize)

	// Neighbors replies are sent across multiple packets to
	// stay below the 1280 byte limit. We compute the maximum number
	// of entries by stuffing a packet until it grows too large.
	maxNeighbors int
)

func init() {
	p := neighbors{Expiration: ^uint64(0)}
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
	for n := 0; ; n++ {
		p.Nodes = append(p.Nodes, maxSizeNode)
		size, _, err := rlp.EncodeToReader(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		if headSize+size+1 >= 1280 {
			maxNeighbors = n
			break
		}
	}
}

func (t *udp) send(toaddr *net.UDPAddr, workFor uint8, forRole uint8, ptype byte, req packet) error {
	packet, err := encodePacket(t.priv, workFor, t.ourRole, forRole, ptype, req)
	if err != nil {
		return err
	}
	_, err = t.conn.WriteToUDP(packet, toaddr)
	log.Trace(">> "+req.name(), "addr", toaddr, "err", err)
	return err
}

func encodePacket(priv *ecdsa.PrivateKey, workFor uint8, ourRole uint8, forRole uint8, ptype byte, req interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	b.WriteByte(ourRole)
	b.WriteByte(forRole)
	b.WriteByte(workFor)
	if err := rlp.Encode(b, req); err != nil {
		log.Error("Can't encode discv4 packet", "err", err)
		return nil, err
	}
	packet := b.Bytes()
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		log.Error("Can't sign discv4 packet", "err", err)
		return nil, err
	}
	copy(packet[macSize:], sig)
	// add the hash to the front. Note: this doesn't protect the
	// packet in any way. Our public key will be part of this hash in
	// The future.
	copy(packet, crypto.Keccak256(packet[macSize:]))
	return packet, nil
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *udp) readLoop() {
	defer t.conn.Close()
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	buf := make([]byte, 1280)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			log.Debug("UDP read error", "err", err)
			return
		}
		t.handlePacket(from, buf[:nbytes])
	}
}

func (t *udp) handlePacket(from *net.UDPAddr, buf []byte) error {
	packet, fromID, workFor, fromRole, forRole, hash, err := decodePacket(buf)
	if err != nil {
		log.Debug("Bad discv4 packet", "addr", from, "err", err)
		return err
	}
	err = packet.handle(t, from, fromID, workFor, fromRole, forRole, hash)
	log.Trace("<< "+packet.name(), "addr", from, "err", err)
	return err
}

func decodePacket(buf []byte) (packet, NodeID, uint8, uint8, uint8, []byte, error) {
	// +2, the first byte is pkt type(Stay consistent with the previous implementation)
	// the second byte represents node role
	if len(buf) < headSize + 3 {
		return nil, NodeID{}, tableService, UnKnowRole, UnKnowRole, nil, errPacketTooSmall
	}
	hash, sig, sigData := buf[:macSize], buf[macSize:headSize], buf[headSize:]
	shouldHash := crypto.Keccak256(buf[macSize:])
	if !bytes.Equal(hash, shouldHash) {
		return nil, NodeID{}, tableService, UnKnowRole, UnKnowRole, nil, errBadHash
	}
	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)
	if err != nil {
		return nil, NodeID{}, tableService, UnKnowRole, UnKnowRole, hash, err
	}
	nodeRole := sigData[1]
	forRole := sigData[2]
	workFor := sigData[3]
	var req packet
	switch ptype := sigData[0]; ptype {
	case pingPacket:
		req = new(ping)
	case pongPacket:
		req = new(pong)
	case findnodePacket:
		req = new(findnode)
	case neighborsPacket:
		req = new(neighbors)
	default:
		return nil, fromID, workFor, nodeRole, forRole, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	s := rlp.NewStream(bytes.NewReader(sigData[4:]), 0)
	err = s.Decode(req)
	return req, fromID, workFor, nodeRole, forRole, hash, err
}

func (req *ping) handle(t *udp, from *net.UDPAddr, fromID NodeID, workFor uint8, fromRole uint8, forRole uint8, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}

	t.send(from, workFor, forRole, pongPacket, &pong{
		To:         makeEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})

	if !t.handleReply(fromID, workFor, fromRole, forRole, pingPacket, req) {
		// only the ping work for table, our may bond peer node
		if workFor == tableService {
			// Note: we're ignoring the provided IP address right now
			switch fromRole {
			case BootRole:
				switch forRole {
				case LightRole:
					go t.lightTab.bond(true, fromID, fromRole, from, req.From.TCP)
				case AccessRole:
					go t.accessTab.bond(true, fromID, fromRole, from, req.From.TCP)
				}
			case LightRole:
				go t.lightTab.bond(true, fromID, fromRole, from, req.From.TCP)
			case AccessRole:
				go t.accessTab.bond(true, fromID, fromRole, from, req.From.TCP)
			default:
			}
		}
	}
	return nil
}

func (req *ping) name() string { return "PING" }

func (req *pong) handle(t *udp, from *net.UDPAddr, fromID NodeID, workFor uint8, fromRole uint8, forRole uint8, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, workFor, fromRole, forRole, pongPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func (req *pong) name() string { return "PONG" }

// don't care fromRole, because when you first set up the network, it might be the request sent by bootNode.
func (req *findnode) handle(t *udp, from *net.UDPAddr, fromID NodeID, workFor uint8, fromRole uint8, forRole uint8, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	switch forRole {
	case LightRole:
		err := req.sendNeibors(t, from, t.lightTab, fromID, fromRole, forRole); if err != nil {return err}
	case AccessRole:
		err := req.sendNeibors(t, from, t.accessTab, fromID, fromRole, forRole); if err != nil {return err}
	default:
	}
	return nil
}

func (req *findnode) name() string { return "FINDNODE" }

func (req *neighbors) handle(t *udp, from *net.UDPAddr, fromID NodeID, workFor uint8, fromRole uint8, forRole uint8, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, workFor, fromRole, forRole, neighborsPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func (req *neighbors) name() string { return "NEIGHBORS" }

func expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}

func (req *findnode)sendNeibors(trans *udp, from *net.UDPAddr, table *Table, fromID NodeID, fromRole uint8, forRole uint8) error {
	// TODO by xujl: because no HpRole and PreRole Table, so don't need confirm in tab.db
	if fromRole != HpRole && fromRole != PreRole {
		if table.db.node(fromID, nodeDBDiscoverRoot) == nil {
			// No bond exists, we don't process the packet. This prevents
			// an attack vector where the discovery protocol could be used
			// to amplify traffic in a DDOS attack. A malicious actor
			// would send a findnode request with the IP address and UDP
			// port of the target as the source address. The recipient of
			// the findnode packet would then send a neighbors packet
			// (which is a much bigger packet than findnode) to the victim.
			return errUnknownNode
		}
	}
	target := crypto.Keccak256Hash(req.Target[:])
	table.mutex.Lock()
	closest := table.closest(target, bucketSize).entries
	table.mutex.Unlock()
	dClosest := nodesDuplicate(closest)
	p := neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the 1280 byte limit.
	for i, n := range dClosest {
		if netutil.CheckRelayIP(from.IP, n.IP) != nil {
			continue
		}
		p.Nodes = append(p.Nodes, nodeToRPC(n))
		if len(p.Nodes) == maxNeighbors || i == len(dClosest)-1 {
			// sendNeibors only work for table
			trans.send(from, tableService, forRole, neighborsPacket, &p)
			p.Nodes = p.Nodes[:0]
		}
	}
	return nil
}
