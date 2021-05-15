// Copyright 2018 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2014 The go-ethereum Authors.
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
	"github.com/hashicorp/golang-lru"
	"io"
	"net"
	"sync"
	"time"

	"errors"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/mclock"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math/big"
	//"github.com/hpb-project/go-hpb/boe"
	//"github.com/hpb-project/go-hpb/boe"
)

const (
	baseProtocolMaxMsgSize = 80 * 1024        // the max msg size only for protocol handshake
	pingInterval           = 5 * time.Second  // ping msg loop for peer
	nodereqInterval        = 15 * time.Second //interval for request nodes
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
	Type     event.EventType `json:"type"`
	Peer     discover.NodeID `json:"peer"`
	Error    string          `json:"error,omitempty"`
	Protocol string          `json:"protocol,omitempty"`
	MsgCode  *uint64         `json:"msg_code,omitempty"`
	MsgSize  *uint32         `json:"msg_size,omitempty"`
}

// protoHandshake is the RLP structure of the protocol handshake.
type protoHandshake struct {
	Version uint64
	Name    string
	Caps    []Cap
	ID      discover.NodeID
	End     *discover.EndPoint

	CoinBase  common.Address
	RandNonce []byte
	Sign      []byte
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}
type hardwareTable struct {
	Version uint32
	Hdtab   []HwPair
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
	events *event.SyncEvent

	////////////////////////////////////////////////////
	ntab      discoverTable
	localType discover.NodeType

	remoteType discover.NodeType

	beatStart    time.Time
	lastpingpong time.Time
	count        uint64
	msgLooping   bool
	bremove      bool
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

	chbond chan *discover.Node

	knownTxsCache    *lru.Cache
	knownBlocksCache *lru.Cache

	statMining string
}

func newPeerBase(conn *conn, proto Protocol, ntb discoverTable) *PeerBase {
	protorw := &protoRW{Protocol: proto, in: make(chan Msg), w: conn}
	p := &PeerBase{
		rw:       conn,
		running:  protorw,
		created:  mclock.Now(),
		disc:     make(chan DiscReason),
		protoErr: make(chan error, 3), // protocols + pingLoop + updateNodesLoop
		closed:   make(chan struct{}),
		log:      log.New("id", conn.id, "port", conn.their.End.TCP),
		ntab:     ntb,
		bremove:  false,
	}
	return p
}

// ID returns the node's public key.
func (p *PeerBase) ID() discover.NodeID {
	return p.rw.id
}

func (p *PeerBase) Version() string {
	switch p.rw.their.Version {
	case 0x0001:
		return "[1.0.3.1 or before]&[N.A/0]"
	default:
		cps := len(p.Caps())
		if cps >= 3 {
			return p.Caps()[cps-2].String() + "&" + p.Caps()[cps-1].String()
		}
	}

	return "UnknownNode"
}

// Name returns the node name that the remote node advertised.
func (p *PeerBase) Name() string {
	return p.rw.their.Name
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
func (p *PeerBase) Caps() []Cap {
	return p.rw.their.Caps
}

// RemoteAddr returns the remote address of the network connection.
func (p *PeerBase) RemoteAddr() net.Addr {
	return p.rw.fd.RemoteAddr()
}
func (p *PeerBase) RemoteIP() string {
	return p.rw.fd.RemoteAddr().(*net.TCPAddr).IP.String()
}

func (p *PeerBase) RemoteListenPort() int {
	return int(p.rw.their.End.TCP)
}

func (p *PeerBase) RemoteIperfPort() int {
	return int(p.rw.their.End.TCP + 100)
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

	p.log.Debug("Set peer remote type", "from", p.remoteType, "to", nt.ToString())
	if p.remoteType != nt {
		p.log.Info("Set peer remote type", "to", nt.ToString())
		p.remoteType = nt
		return true
	}

	return false
}

// LocalType returns the local type of the node.
func (p *PeerBase) LocalType() discover.NodeType {
	return p.localType
}

func (p *PeerBase) Address() common.Address {
	return p.rw.their.CoinBase
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
func (p *PeerBase) Disconnect(reason DiscReason) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("maybe use closed channel:", "r", r)
		}
	}()
	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

// String implements fmt.Stringer.
func (p *PeerBase) String() string {
	return fmt.Sprintf("Peer %x %v", p.rw.id[:8], p.RemoteAddr())
}

func (p *PeerBase) run() (remoteRequested bool, err error) {
	var (
		writeStart = make(chan struct{}, 1)
		writeErr   = make(chan error, 1)
		readErr    = make(chan error, 1)
		reason     DiscReason // sent to the peer
	)
	p.wg.Add(3)
	go p.readLoop(readErr)
	go p.pingLoop()
	go p.updateNodesLoop()

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
				p.log.Debug("PeerBase run Write DiscNetwork Error")
				break loop
			}
			writeStart <- struct{}{}
		case err = <-readErr:
			if r, ok := err.(DiscReason); ok {
				remoteRequested = true
				p.log.Debug("PeerBase run Read Remote Requested DISCONNECTION", "error", err)
				reason = r
			} else {
				p.log.Debug("PeerBase run Read DiscNetwork Error", "error", err)
				reason = DiscNetworkError
			}
			break loop
		case err = <-p.protoErr:
			reason = discReasonForError(err)
			p.log.Debug("PeerBase run proto Error", "reason", reason, "error", err)
			break loop
		case err = <-p.disc:
			p.log.Debug("PeerBase run peer disc Error", "error", err)
			break loop
		}
	}
	p.log.Debug("PeerBase run loop stoped")
	p.bremove = true

	p.msgLooping = false
	close(p.closed)
	p.rw.close(reason)
	p.wg.Wait()
	p.log.Debug("PeerBase run loop exited")
	return remoteRequested, err
}

func (p *PeerBase) pingLoop() {
	pingTime := time.NewTimer(pingInterval)
	defer p.wg.Done()
	defer pingTime.Stop()
	defer p.log.Trace("peerbase pingloop stop")
	for {
		select {
		case <-pingTime.C:
			if err := sendItems(p.rw, pingMsg); err != nil {
				p.log.Debug("PeerBase Send heartbeat ERROR", "error", err)
				p.protoErr <- err
				return
			}
			pingTime.Reset(pingInterval)
		case <-p.closed:
			p.log.Debug("PeerBase pingLoop CLOSED")
			return
		}
	}

}

func (p *PeerBase) updateNodesLoop() {
	nodeTime := time.NewTimer(nodereqInterval) //TODO only send to bootnode
	defer p.wg.Done()
	defer nodeTime.Stop()
	defer p.log.Trace("peerbase updatenodesloop CLOSED")
	for {
		select {
		case <-nodeTime.C:
			if p.localType == discover.BootNode {
				p.log.Debug("BootNode do not need update nodes loop.")
				return
			}

			if p.remoteType != discover.BootNode {
				p.log.Debug("Only update nodes form BootNode.")
				return
			}
			p.log.Trace("PeerBase Send ReqNodesMsg")
			if err := sendItems(p.rw, ReqNodesMsg); err != nil {
				p.log.Debug("PeerBase Send ReqNodesMsg ERROR", "error", err)
				p.protoErr <- err
				return
			}
			nodeTime.Reset(8 * nodereqInterval)
		case <-p.closed:
			p.log.Debug("PeerBase update nodes loop CLOSED")
			return
		}
	}
}

func (p *PeerBase) readLoop(errc chan<- error) {
	defer p.wg.Done()
	defer p.log.Trace("readloop exit")
	defer p.running.Close()
	for {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			p.log.Trace("Peer base read loop error", "error", err)
			errc <- err
			return
		}
		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil {
			p.log.Trace("Peer base handle msg error", "error", err)
			errc <- err
			return
		}
	}
}

func (p *PeerBase) handle(msg Msg) error {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("maybe use closed channel:", "r", r)
		}
	}()
	switch {
	case msg.Code == pingMsg:
		msg.Discard()
		p.log.Trace("PeerBase send heartbeat from remote.")
		go sendItems(p.rw, pongMsg)
	case msg.Code == pongMsg:
		p.count = p.count + 1
		p.lastpingpong = time.Now()
		p.log.Trace("PeerBase receive heartbeat from remote.")
		msg.Discard()
	case msg.Code == discMsg:
		var reason [1]DiscReason
		// This is the last message. We don't need to discard or
		// check errors because, the connection will be closed after it.
		rlp.Decode(msg.Payload, &reason)
		return reason[0]
	case msg.Code < baseMsgMax:
		// ignore other base protocol messages
		log.Debug("Peer handle massage do not matched", "Msg", msg.String())
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
		p.log.Debug("######Protocol returned", "error", err)
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

func (rw *protoRW) Close() {
	close(rw.in)
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
		if err != nil {
			log.Debug("protoRW WriteMsg", "error", err)
		}
		rw.werr <- err
	case <-rw.closed:
		err = fmt.Errorf("shutting down")
	}
	return err
}

func (rw *protoRW) ReadMsg() (Msg, error) {
	select {
	case msg, ok := <-rw.in:
		if !ok {
			return Msg{}, errors.New("has been closed")
		}
		//log.Trace("protoRW ReadMsg","Msg",msg)
		return msg, nil
	case <-rw.closed:
		return Msg{}, io.EOF
	}
}

//////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////

func NewPeer(version uint, pr *PeerBase, rw MsgReadWriter) *Peer {
	id := pr.ID()

	p := &Peer{
		PeerBase: pr,
		rw:       rw,
		version:  version,
		id:       fmt.Sprintf("%x", id[:8]),
		chbond:   make(chan *discover.Node, 1),
	}
	p.knownBlocksCache, _ = lru.New(maxKnownBlocks)
	p.knownTxsCache, _ = lru.New(maxKnownTxs)
	return p
}

func (p *Peer) GetID() string {
	return p.id
}

func (p *Peer) GetVersion() uint {
	return p.version
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

func (p *Peer) KnownBlockAdd(hash common.Hash) {
	p.knownBlocksCache.Add(hash, struct{}{})
}

func (p *Peer) KnownBlockHas(hash common.Hash) bool {
	return p.knownBlocksCache.Contains(hash)
}

func (p *Peer) KnownBlockSize() int {
	return p.knownBlocksCache.Len()
}

func (p *Peer) KnownTxsAdd(hash common.Hash) {
	p.knownTxsCache.Add(hash, struct{}{})
}

func (p *Peer) KnownTxsHas(hash common.Hash) bool {
	return p.knownTxsCache.Contains(hash)
}

func (p *Peer) KnownTxsSize() int {
	return p.knownTxsCache.Len()
}

func SendData(p *Peer, msgCode uint64, data interface{}) error {
	if p == nil {
		log.Error("P2P SendData para of peer is nil.")
		return errors.New("send data para of peer is nil")
	}
	return send(p.rw, msgCode, data)
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *Peer) Handshake(network uint64, td *big.Int, head common.Hash, genesis common.Hash) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		p.log.Debug("Do hpb handshake send.", "networkid", network, "genesis", genesis.TerminalString(), "block", head.TerminalString(), "td", td)
		errc <- SendData(p, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
			TD:              td,
			CurrentBlock:    head,
			GenesisBlock:    genesis,
		})
	}()
	go func() {
		errc <- p.readStatus(network, &status, genesis)
		p.log.Debug("Do hpb handshake recv.", "networkid", status.NetworkId, "genesis", status.GenesisBlock, "block", status.CurrentBlock, "td", status.TD)
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
		return ErrResp(ErrGenesisBlockMismatch, "GenesisBlock %x (!= %x)", status.GenesisBlock[:8], genesis[:8])
	}
	if status.NetworkId != network {
		return ErrResp(ErrNetworkIdMismatch, "NetworkId %d (!= %d)", status.NetworkId, network)
	}
	if uint(status.ProtocolVersion) != p.version {
		return ErrResp(ErrProtocolVersionMismatch, "ProtocolVersion %d (!= %d)", status.ProtocolVersion, p.version)
	}

	return nil
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("hpb/%2d", p.version),
	)
}

////////////////////////////////////////////
type exchangeData struct {
	Version uint32
}

func (p *Peer) Exchange(our *exchangeData) (*exchangeData, error) {

	errc := make(chan error, 2)
	var there exchangeData

	go func() {
		p.log.Debug("Send exchange data")
		errc <- SendData(p, ExchangeMsg, &exchangeData{
			Version: our.Version,
		})
	}()
	go func() {
		errc <- p.readExchange(&there)
		p.log.Debug("Read exchange data", "remote", there)
	}()

	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				return nil, err
			}
		case <-timeout.C:
			return nil, DiscReadTimeout
		}
	}

	return &there, nil
}

func (p *Peer) readExchange(status *exchangeData) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}

	if msg.Code != ExchangeMsg {
		return ErrResp(ErrNoExchangeMsg, "Msg has code 0x%x (!= %x)", msg.Code, ExchangeMsg)
	}

	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return ErrResp(ErrDecode, "msg %v: %v", msg, err)
	}

	return nil
}
