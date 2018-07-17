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
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/common"
	"math/big"
	"gopkg.in/fatih/set.v0"
	"github.com/hpb-project/go-hpb/network/p2p/iperf"
)

const (
	baseProtocolMaxMsgSize = 2 * 1024

	snappyProtocolVersion = 5

	pingInterval    = 15 * time.Second
	nodereqInterval = 10 * time.Second
	testBWDuration  = 3  //second
)

// PeerEventType is the type of peer events emitted by a p2p.Server
type PeerEventType string

const (
	PeerEventAdd     event.EventType = 0x01
	PeerEventDrop    event.EventType = 0x02
	PeerEventMsgSend event.EventType = 0x03
	PeerEventMsgRecv event.EventType = 0x04
)

type PeerEvent struct {
	Type     event.EventType    `json:"type"`
	Peer     discover.NodeID    `json:"peer"`
	Error    string             `json:"error,omitempty"`
	Protocol string             `json:"protocol,omitempty"`
	MsgCode  *uint64            `json:"msg_code,omitempty"`
	MsgSize  *uint32            `json:"msg_size,omitempty"`
}

// protoHandshake is the RLP structure of the protocol handshake.
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []Cap
	ID         discover.NodeID
	End          *discover.EndPoint

	DefaultAddr  common.Address
	RandNonce    []byte  //Every peer is not the same,this is temp.
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}


// Peer represents a connected remote node.
type PeerBase struct {
	rw      *conn
	running *protoRW
	log     log.Logger
	created mclock.AbsTime

	wg       sync.WaitGroup
	protoErr chan error
	closed   chan struct{}
	disc     chan DiscReason

	// events receives message send / receive events if set
	//events *event.Feed
	events   *event.SyncEvent

	////////////////////////////////////////////////////
	ntab       discoverTable
	localType  discover.NodeType
	remoteType discover.NodeType

}

type Peer struct {
	*PeerBase
	rw MsgReadWriter

	id        string
	version   uint
	txsRate   float64
	bandwidth float64

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	knownTxs    *set.Set // Set of transaction hashes known to be known by this peer
	knownBlocks *set.Set // Set of block hashes known to be known by this peer
}

func newPeerBase(conn *conn, proto Protocol, ntb discoverTable) *PeerBase {
	//protomap := matchProtocols(protocols, conn.caps, conn)
	protorw := &protoRW{Protocol: proto,in: make(chan Msg), w: conn}
	p := &PeerBase{
		rw:       conn,
		running:  protorw,
		created:  mclock.Now(),
		disc:     make(chan DiscReason),
		protoErr: make(chan error, 1+1), // protocols + pingLoop
		closed:   make(chan struct{}),
		log:      log.New("id", conn.id, "conn", conn.flags),
		ntab:     ntb,
	}
	return p
}

// ID returns the node's public key.
func (p *PeerBase) ID() discover.NodeID {
	return p.rw.id
}

// Name returns the node name that the remote node advertised.
func (p *PeerBase) Name() string {
	return p.rw.name
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
func (p *PeerBase) Caps() []Cap {
	// TODO: maybe return copy
	return p.rw.caps
}

// RemoteAddr returns the remote address of the network connection.
func (p *PeerBase) RemoteAddr() net.Addr {
	return p.rw.fd.RemoteAddr()
}
func (p *PeerBase) RemoteIP() string {
	return p.rw.fd.RemoteAddr().(*net.TCPAddr).IP.String()
}
func (p *PeerBase) RemoteListenPort() int {
	return p.rw.rport
}

// LocalAddr returns the local address of the network connection.
func (p *PeerBase) LocalAddr() net.Addr {
	return p.rw.fd.LocalAddr()
}

//  RemoteType returns the remote type of the node.
func (p *PeerBase) RemoteType() discover.NodeType {
	return p.remoteType
}

func (p *PeerBase) SetRemoteType(nt discover.NodeType) bool {
	p.remoteType = nt
	return true
}

// LocalType returns the local type of the node.
func (p *PeerBase) LocalType() discover.NodeType {
	return p.localType
}

func (p *PeerBase) Address() common.Address {
	return p.rw.raddr
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
func (p *PeerBase) Disconnect(reason DiscReason) {
	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

// String implements fmt.Stringer.
func (p *PeerBase) String() string {
	return fmt.Sprintf("Peer %x %v", p.rw.id[:8], p.RemoteAddr())
}

func (p *PeerBase) Log() log.Logger {
	return p.log
}

func (p *PeerBase) run() (remoteRequested bool, err error) {
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

func (p *PeerBase) pingLoop() {
	pingTime := time.NewTimer(pingInterval)
	nodeTime := time.NewTimer(nodereqInterval)
	defer p.wg.Done()
	defer pingTime.Stop()
	defer nodeTime.Stop()
	for {
		select {
		case <-pingTime.C:
			if err := sendItems(p.rw, pingMsg); err != nil {
				p.protoErr <- err
				return
			}
			pingTime.Reset(pingInterval)
		case <-nodeTime.C:
			if p.localType == discover.BootNode {
				return
			}

			if err := sendItems(p.rw, ReqNodesMsg); err != nil {
				p.protoErr <- err
				return
			}
			nodeTime.Reset(nodereqInterval)
		case <-p.closed:
			return
		}
	}
}

func (p *PeerBase) readLoop(errc chan<- error) {
	defer p.wg.Done()
	for {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			log.Error("peer read loop error","error",err)
			errc <- err
			return
		}
		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil {
			log.Error("peer handle msg error","error",err)
			errc <- err
			return
		}
	}
}

func (p *PeerBase) handle(msg Msg) error {
	//log.Trace("Peer handle massage","Msg",msg.String())
	switch {
	case msg.Code == pingMsg:
		msg.Discard()
		go sendItems(p.rw, pongMsg)
	case msg.Code == discMsg:
		var reason [1]DiscReason
		// This is the last message. We don't need to discard or
		// check errors because, the connection will be closed after it.
		rlp.Decode(msg.Payload, &reason)
		return reason[0]
	case msg.Code < baseMsgMax:
		// ignore other base protocol messages
		//log.Error("Peer handle massage do not matched","Msg",msg.String())
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

func (p *PeerBase) startProtocols(writeStart <-chan struct{}, writeErr chan<- error) {

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
func (p *PeerBase) Info() *PeerInfo {
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
	info.Network.LocalAddress  = p.LocalAddr().String()
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

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////



func NewPeer(version uint, pr *PeerBase, rw MsgReadWriter) *Peer {
	id := pr.ID()

	return &Peer{
		PeerBase:    pr,
		rw:          rw,
		version:     version,
		id:          fmt.Sprintf("%x", id[:8]),
		knownTxs:    set.New(),
		knownBlocks: set.New(),
	}
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *Peer) Info() *HpbPeerInfo {
	hash, td := p.Head()

	return &HpbPeerInfo{
		Version:    p.version,
		Difficulty: td,
		Head:       hash.Hex(),
	}
}


func (p *Peer) GetID() string {
	return  p.id
}

func (p *Peer) GetVersion() uint {
	return  p.version
}

// Head retrieves a copy of the current head hash and total difficulty of the
// peer.
func (p *Peer) Head() (hash common.Hash, td *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.head[:])
	return hash, new(big.Int).Set(p.td)
}

// SetHead updates the head hash and total difficulty of the peer.
func (p *Peer) SetHead(hash common.Hash, td *big.Int) {
	p.lock.Lock()
	defer p.lock.Unlock()

	copy(p.head[:], hash[:])
	p.td.Set(td)
}

func (p *Peer) TxsRate() float64 {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.txsRate
}

func (p *Peer) SetTxsRate(txs float64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.txsRate = txs
}

func (p *Peer) Bandwidth() float64 {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.bandwidth
}

func (p *Peer) KnownBlockAdd(hash common.Hash){
	for p.knownBlocks.Size() >= maxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(hash)
}

func (p *Peer) KnownBlockHas(hash common.Hash) bool{
	return p.knownBlocks.Has(hash)
}

func (p *Peer) KnownBlockSize() int{
	return p.knownBlocks.Size()
}

func (p *Peer) KnownTxsAdd(hash common.Hash){
	for p.knownTxs.Size() >= maxKnownTxs {
		p.knownTxs.Pop()
	}
	p.knownTxs.Add(hash)
}

func (p *Peer) KnownTxsHas(hash common.Hash) bool{
	return p.knownTxs.Has(hash)
}

func (p *Peer) KnownTxsSize() int{
	return p.knownTxs.Size()
}

func (p *Peer) SendData(msgCode uint64, data interface{}) error {
	return send(p.rw, msgCode, data)
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *Peer) Handshake(network uint64,td *big.Int, head common.Hash, genesis common.Hash) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		p.log.Trace("handshake send","NetworkId",network,"TD",td,"CurrentBlock",head,"GenesisBlock",genesis)
		errc <- p.SendData(StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
			TD:              td,
			CurrentBlock:    head,
			GenesisBlock:    genesis,
		})
	}()
	go func() {
		errc <- p.readStatus(network, &status, genesis)
		p.log.Trace("handshake read","NetworkId",status.NetworkId,"TD",status.TD,"CurrentBlock",status.CurrentBlock,"GenesisBlock",status.GenesisBlock)
	}()

	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-timeout.C:
			return DiscReadTimeout
		}
	}
	p.td, p.head = status.TD, status.CurrentBlock
	p.log.Info("handshake over","td",p.td,"head", p.head)
	return nil
}

func (p *Peer) readStatus(network uint64, status *statusData, genesis common.Hash) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return ErrResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}

	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return ErrResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if status.GenesisBlock != genesis {
		return ErrResp(ErrGenesisBlockMismatch, "%x (!= %x)", status.GenesisBlock[:8], genesis[:8])
	}
	if status.NetworkId != network {
		return ErrResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if uint(status.ProtocolVersion) != p.version {
		return ErrResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}

	return nil
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("hpb/%2d", p.version),
	)
}


func (p *Peer) testBandwidth() (error) {

	ch := make(chan struct{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("Test bandwidth panic.")
			}
		}()

		p.log.Debug("Test bandwidth start","ip",p.RemoteIP(),"port",p.RemoteListenPort()+100)
		result := iperf.StartTest(p.RemoteIP(), p.RemoteListenPort()+100, testBWDuration)
		p.lock.Lock()
		defer p.lock.Unlock()
		p.bandwidth = result
		p.log.Info("Test bandwidth ok","result",result)
		ch <- struct{}{}

	}()

	timeout := time.NewTimer(time.Second*5)
	defer timeout.Stop()

	select {
	case <-ch:
	case <-timeout.C:
		return errPeerBWTestTimeout
	}

	return nil
}

