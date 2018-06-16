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
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/common/mclock"
	"github.com/hpb-project/go-hpb/routinue"
	"github.com/hpb-project/go-hpb/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/common/rlp"
)

const (
	baseProtocolMaxMsgSize = 2 * 1024

	snappyProtocolVersion = 5

	pingInterval = 15 * time.Second
)

// protoHandshake is the RLP structure of the protocol handshake.
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []Cap
	ListenPort uint64
	ID         discover.NodeID

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// PeerEventType is the type of peer events emitted by a p2p.Server
type PeerEventType string

const (
	PeerEventAdd     routinue.EventType = 0x01
	PeerEventDrop    routinue.EventType = 0x02
	PeerEventMsgSend routinue.EventType = 0x03
	PeerEventMsgRecv routinue.EventType = 0x04
)

// PeerEvent is an event emitted when peers are either added or dropped from
// a p2p.Server or when a message is sent or received on a peer connection
type PeerEvent struct {
	//Type     PeerEventType   `json:"type"`
	Type     routinue.EventType `json:"type"`
	Peer     discover.NodeID    `json:"peer"`
	Error    string             `json:"error,omitempty"`
	Protocol string             `json:"protocol,omitempty"`
	MsgCode  *uint64            `json:"msg_code,omitempty"`
	MsgSize  *uint32            `json:"msg_size,omitempty"`
}

// Peer represents a connected remote node.
type peer struct {
	rw      *conn
	//running map[string]*protoRW
	running *protoRW
	log     log.Logger
	created mclock.AbsTime

	wg       sync.WaitGroup
	protoErr chan error
	closed   chan struct{}
	disc     chan DiscReason

	// events receives message send / receive events if set
	//events *event.Feed
	events   *routinue.Event

	////////////////////////////////////////////////////
	localType  discover.NodeType  //本端节点类型
	remoteType discover.NodeType  //远端验证后节点类型
}
/*
// NewPeer returns a peer for testing purposes.
func NewPeer(id discover.NodeID, name string, caps []Cap) *Peer {
	pipe, _ := net.Pipe()
	conn := &conn{fd: pipe, transport: nil, id: id, caps: caps, name: name}
	peer := newPeer(conn, nil)
	close(peer.closed) // ensures Disconnect doesn't block
	return peer
}
*/

func newpeer(conn *conn, proto Protocol) *peer {
	//protomap := matchProtocols(protocols, conn.caps, conn)
	protorw := &protoRW{Protocol: proto,in: make(chan Msg), w: conn}
	p := &peer{
		rw:       conn,
		running:  protorw,
		created:  mclock.Now(),
		disc:     make(chan DiscReason),
		protoErr: make(chan error, 1+1), // protocols + pingLoop
		closed:   make(chan struct{}),
		log:      log.New("id", conn.id, "conn", conn.flags),
	}
	return p
}

// ID returns the node's public key.
func (p *peer) ID() discover.NodeID {
	return p.rw.id
}

// Name returns the node name that the remote node advertised.
func (p *peer) Name() string {
	return p.rw.name
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
func (p *peer) Caps() []Cap {
	// TODO: maybe return copy
	return p.rw.caps
}

// RemoteAddr returns the remote address of the network connection.
func (p *peer) RemoteAddr() net.Addr {
	return p.rw.fd.RemoteAddr()
}

// LocalAddr returns the local address of the network connection.
func (p *peer) LocalAddr() net.Addr {
	return p.rw.fd.LocalAddr()
}

//  RemoteType returns the remote type of the node.
func (p *peer) RemoteType() discover.NodeType {
	return p.remoteType
}

func (p *peer) SetRemoteType(nt discover.NodeType) bool {
	p.remoteType = nt
	return true
}

// LocalType returns the local type of the node.
func (p *peer) LocalType() discover.NodeType {
	return p.localType
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
func (p *peer) Disconnect(reason DiscReason) {
	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

// String implements fmt.Stringer.
func (p *peer) String() string {
	return fmt.Sprintf("Peer %x %v", p.rw.id[:8], p.RemoteAddr())
}

func (p *peer) Log() log.Logger {
	return p.log
}

func (p *peer) run() (remoteRequested bool, err error) {
	var (
		writeStart = make(chan struct{}, 1)
		writeErr   = make(chan error, 1)
		readErr    = make(chan error, 1)
		reason     DiscReason // sent to the peer
	)
	p.wg.Add(2)
	go p.readLoop(readErr)
	go p.pingLoop()

	// Start all protocol handlers.
	writeStart <- struct{}{}
	p.startProtocols(writeStart, writeErr)

	// Wait for an error or disconnect.
loop:
	for {
		select {
		case err = <-writeErr:
			// A write finished. Allow the next write to start if
			// there was no error.
			if err != nil {
				reason = DiscNetworkError
				break loop
			}
			writeStart <- struct{}{}
		case err = <-readErr:
			if r, ok := err.(DiscReason); ok {
				remoteRequested = true
				reason = r
			} else {
				reason = DiscNetworkError
			}
			break loop
		case err = <-p.protoErr:
			reason = discReasonForError(err)
			break loop
		case err = <-p.disc:
			break loop
		}
	}

	close(p.closed)
	p.rw.close(reason)
	p.wg.Wait()
	return remoteRequested, err
}

func (p *peer) pingLoop() {
	ping := time.NewTimer(pingInterval)
	defer p.wg.Done()
	defer ping.Stop()
	for {
		select {
		case <-ping.C:
			if err := SendItems(p.rw, pingMsg); err != nil {
				p.protoErr <- err
				return
			}
			SendItems(p.rw, HpbTestMsg)
			ping.Reset(pingInterval)
		case <-p.closed:
			return
		}
	}
}

func (p *peer) readLoop(errc chan<- error) {
	defer p.wg.Done()
	for {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			errc <- err
			return
		}
		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil {
			errc <- err
			return
		}
	}
}

func (p *peer) handle(msg Msg) error {
	//log.Trace("Peer handle massage","Msg",msg.String())
	switch {
	case msg.Code == pingMsg:
		msg.Discard()
		go SendItems(p.rw, pongMsg)
	case msg.Code == pongMsg:

	case msg.Code == discMsg:
		var reason [1]DiscReason
		// This is the last message. We don't need to discard or
		// check errors because, the connection will be closed after it.
		rlp.Decode(msg.Payload, &reason)
		return reason[0]
	case msg.Code < baseMsgMax:
		// ignore other base protocol messages
		log.Error("Peer handle massage do not matched","Msg",msg.String())
		return msg.Discard()
	default:
		proto := p.running

		select {
		case proto.in <- msg:
			return nil
		case <-p.closed:
			return io.EOF
		}
	}
	return nil
}

func countMatchingProtocols(protocols []Protocol, caps []Cap) int {
	n := 0
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				n++
			}
		}
	}
	return n
}

func (p *peer) startProtocols(writeStart <-chan struct{}, writeErr chan<- error) {

	p.wg.Add(1)
	proto := p.running
	proto.closed = p.closed
	proto.wstart = writeStart
	proto.werr = writeErr
	var rw MsgReadWriter = proto
	if p.events != nil {
		rw = newMsgEventer(rw, p.events, p.ID(), proto.Name)
	}
	p.log.Trace(fmt.Sprintf("Starting protocol %s/%d", proto.Name, proto.Version))
	go func() {
		err := proto.Run(p, rw)
		if err == nil {
			p.log.Trace(fmt.Sprintf("Protocol %s/%d returned", proto.Name, proto.Version))
			err = errProtocolReturned
		} else if err != io.EOF {
			p.log.Trace(fmt.Sprintf("Protocol %s/%d failed", proto.Name, proto.Version), "err", err)
		}
		p.protoErr <- err
		p.wg.Done()
	}()
}

type protoRW struct {
	Protocol
	in     chan Msg        // receices read messages
	closed <-chan struct{} // receives when peer is shutting down
	wstart <-chan struct{} // receives when write may start
	werr   chan<- error    // for write results
	w      MsgWriter
}

func (rw *protoRW) WriteMsg(msg Msg) (err error) {
	//log.Trace("protoRW WriteMsg","msg",msg.String())
	select {
	case <-rw.wstart:
		err = rw.w.WriteMsg(msg)
		// Report write status back to Peer.run. It will initiate
		// shutdown if the error is non-nil and unblock the next write
		// otherwise. The calling protocol code should exit for errors
		// as well but we don't want to rely on that.
		if err != nil{
			log.Info("protoRW WriteMsg","error",err)
		}
		rw.werr <- err
	case <-rw.closed:
		err = fmt.Errorf("shutting down")
	}
	return err
}

func (rw *protoRW) ReadMsg() (Msg, error) {
	select {
	case msg := <-rw.in:
		//log.Trace("protoRW ReadMsg","Msg",msg)
		return msg, nil
	case <-rw.closed:
		return Msg{}, io.EOF
	}
}

// PeerInfo represents a short summary of the information known about a connected
// peer. Sub-protocol independent fields are contained and initialized here, with
// protocol specifics delegated to all connected sub-protocols.
type PeerInfo struct {
	ID      string   `json:"id"`   // Unique node identifier (also the encryption key)
	Name    string   `json:"name"` // Name of the node, including client type, version, OS, custom data
	Remote  string   `json:"remote"` //Remote node type
	Caps    []string `json:"caps"` // Sum-protocols advertised by this particular peer
	Network struct {
		LocalAddress  string `json:"localAddress"`  // Local endpoint of the TCP data connection
		RemoteAddress string `json:"remoteAddress"` // Remote endpoint of the TCP data connection
	} `json:"network"`
	Protocols map[string]interface{} `json:"protocols"` // Sub-protocol specific metadata fields
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *peer) Info() *PeerInfo {
	// Gather the protocol capabilities
	var caps []string
	for _, cap := range p.Caps() {
		caps = append(caps, cap.String())
	}
	// Assemble the generic peer metadata
	info := &PeerInfo{
		ID:        p.ID().String(),
		Name:      p.Name(),
		Remote:    p.remoteType.ToString(),
		Caps:      caps,
		Protocols: make(map[string]interface{}),
	}
	info.Network.LocalAddress = p.LocalAddr().String()
	info.Network.RemoteAddress = p.RemoteAddr().String()

	// Gather all the running protocol infos
	//for _, proto := range p.running {
		proto := p.running
		protoInfo := interface{}("unknown")
		if query := proto.Protocol.PeerInfo; query != nil {
			if metadata := query(p.ID()); metadata != nil {
				protoInfo = metadata
			} else {
				protoInfo = "handshake"
			}
		}
		info.Protocols[proto.Name] = protoInfo
	//}
	return info
}
