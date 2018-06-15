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
	peers  *peerSet
	server *Server
	hpb    *HpbProto
}

var pm   *PeerManager
var lock *sync.Mutex = &sync.Mutex {}

func PeerMgrInst() *PeerManager {
	if pm == nil {
		lock.Lock()
		defer lock.Unlock()
		pm =&PeerManager{
			peers: newPeerSet(),
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


	prm.server = &Server{
		//Config:       config,
	}
	copy(prm.server.Protocols, hpb.Protocols())

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
func (prm *PeerManager) Register(p *peer) error {

	return prm.peers.Register(p)
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (prm *PeerManager) Unregister(id string) error {
	return prm.peers.Unregister(id)
}

// Peer retrieves the registered peer with the given id.
func (prm *PeerManager) Peer(id string) *peer {
	return prm.peers.Peer(id)
}

// Len returns if the current number of peers in the set.
func (prm *PeerManager) PeersCount() int {
	return prm.peers.Len()
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (prm *PeerManager) PeersWithoutBlock(hash common.Hash) []*peer {
	return nil
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (prm *PeerManager) PeersWithoutTx(hash common.Hash) []*peer {

	return nil
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (prm *PeerManager) BestPeer() *peer {
	return nil
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (prm *PeerManager) closePeers() {

}
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
//HPB 协议
type HpbProto struct {
	protos   []Protocol
}

const ProtoName        = "hpb"
const ProtoMaxMsg      = 10 * 1024 * 1024
var ProtocolVersions   = []uint{ProtoVersion100}
var ProtocolMsgLengths = []uint64{ProtoMsgLength}

// HPB 支持的协议消息
const ProtoVersion100  uint   = 100
const ProtoMsgLength   uint64 = 20


type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
	ErrExtraStatusMsg
	ErrSuspendedPeer
)

func NewProtos() (*HpbProto,error) {
	hpb :=&HpbProto{
		protos:  make([]Protocol, 0, len(ProtocolVersions)),
	}

	for _, version := range ProtocolVersions {
		hpb.protos = append(hpb.protos, Protocol{
			Name:    ProtoName,
			Version: version,
			Run: func(p *Peer, rw MsgReadWriter) error {
				peer := newpeer(version, p, rw)
				return hpb.handle(peer)
			},
			NodeInfo: func() interface{} {
				return hpb.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := PeerMgrInst().Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}

	if len(hpb.protos) == 0 {
		return nil, errors.New("protocols incompatible configuration")
	}

	return hpb,nil
}

func (s *HpbProto) Protocols() []Protocol {
	return s.protos
}

type HpbNodeInfo struct {
	Network    uint64      `json:"network"`    // Hpb network ID (1=Frontier, 2=Morden, Ropsten=3)
	Difficulty *big.Int    `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash `json:"genesis"`    // SHA3 hash of the host's genesis block
	Head       common.Hash `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (s *HpbProto) NodeInfo() *HpbNodeInfo {
	/*
	currentBlock := self.blockchain.CurrentBlock()
	return &HpbNodeInfo{
		Network:    self.networkId,
		Difficulty: self.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:    self.blockchain.Genesis().Hash(),
		Head:       currentBlock.Hash(),
	}
	*/
	return  nil
}

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}


// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (s *HpbProto) handle(p *peer) error {
	p.Log().Debug("Peer connected", "name", p.Name())

	//return errors.New("HpbProto debugging")
	// Execute the Hpb handshake
	//TODO: 调用blockchain接口，获取状态信息
	/*
	networkId,td, head, genesis := blockchain.Status()
	if err := p.Handshake(networkId, td, head, genesis); err != nil {
		p.Log().Debug("Handshake failed", "err", err)
		return err
	}
	*/

	/*
	//peer层性能统计
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	*/

	// Register the peer locally
	if err := PeerMgrInst().Register(p); err != nil {
		p.Log().Error("Hpb peer registration failed", "err", err)
		return err
	}
	defer s.removePeer(p.id)

	// main loop. handle incoming messages.
	for {
		if err := s.handleMsg(p); err != nil {
			p.Log().Debug("Message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (s *HpbProto) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	//log.Trace("HpbProto handle massage","Msg",msg.String())

	if msg.Size > ProtoMaxMsg {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtoMaxMsg)
	}

	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		return nil
	case msg.Code == GetBlockHeadersMsg:
		return nil

	case msg.Code == BlockHeadersMsg:
		return nil

	case msg.Code == GetBlockBodiesMsg:
		return nil

	case msg.Code == BlockBodiesMsg:
		return nil

	case msg.Code == GetNodeDataMsg:
		return nil

	case msg.Code == NodeDataMsg:
		return nil

	case msg.Code == GetReceiptsMsg:
		return nil

	case msg.Code == ReceiptsMsg:
		return nil

	case msg.Code == NewBlockHashesMsg:
		return nil

	case msg.Code == NewBlockMsg:
		return nil

	case msg.Code == TxMsg:
		return nil

	case msg.Code == HpbTestMsg:
		data := make([]byte,3)
		data[0] = 0x01
		data[1] = 0x02
		data[2] = 0x03

		err := p.SendData(HpbTestMsgResp,data)
		log.Info("HpbProto handle HpbTestMsg","Msg",msg.String(),"send err",err)
		return nil
	case msg.Code == HpbTestMsgResp:
		log.Info("HpbProto handle HpbTestMsgResp","Msg",msg.String())
		return nil

	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

func (s *HpbProto) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := PeerMgrInst().Peer(id)
	if peer == nil {
		return
	}
	log.Debug("Removing Hpb peer", "peer", id)

	// Unregister the peer from the downloader and Hpb peer set
	if err := PeerMgrInst().Unregister(id); err != nil {
		log.Error("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Disconnect(DiscUselessPeer)
	}
}
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
const (
	maxKnownTxs      = 1000000 // Maximum transactions hashes to keep in the known list (prevent DOS) //for testnet
	maxKnownBlocks   = 100000  // Maximum block hashes to keep in the known list (prevent DOS)  //for testnet
	//handshakeTimeout = 5 * time.Second
)

// PeerInfo represents a short summary of the Hpb sub-protocol metadata known
// about a connected peer.
type HpbPeerInfo struct {
	Version    uint      `json:"version"`   // Hpb protocol version negotiated
	Difficulty *big.Int `json:"difficulty"` // Total difficulty of the peer's blockchain
	Head       string   `json:"head"`       // SHA3 hash of the peer's best owned block
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

type peer struct {
	id string

	*Peer
	rw MsgReadWriter

	version  uint         // Protocol version negotiated

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	knownTxs    *set.Set // Set of transaction hashes known to be known by this peer
	knownBlocks *set.Set // Set of block hashes known to be known by this peer
}

func newpeer(version uint, p *Peer, rw MsgReadWriter) *peer {
	id := p.ID()

	return &peer{
		Peer:        p,
		rw:          rw,
		version:     version,
		id:          fmt.Sprintf("%x", id[:8]),
		knownTxs:    set.New(),
		knownBlocks: set.New(),
	}
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *peer) Info() *HpbPeerInfo {
	hash, td := p.Head()

	return &HpbPeerInfo{
		Version:    p.version,
		Difficulty: td,
		Head:       hash.Hex(),
	}
}

// Head retrieves a copy of the current head hash and total difficulty of the
// peer.
func (p *peer) Head() (hash common.Hash, td *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.head[:])
	return hash, new(big.Int).Set(p.td)
}

// SetHead updates the head hash and total difficulty of the peer.
func (p *peer) SetHead(hash common.Hash, td *big.Int) {
	p.lock.Lock()
	defer p.lock.Unlock()

	copy(p.head[:], hash[:])
	p.td.Set(td)
}

// MarkBlock marks a block as known for the peer, ensuring that the block will
// never be propagated to this particular peer.
func (p *peer) MarkBlock(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known block hash
	for p.knownBlocks.Size() >= maxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(hash)
}

// MarkTransaction marks a transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *peer) MarkTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownTxs.Size() >= maxKnownTxs {
		p.knownTxs.Pop()
	}
	p.knownTxs.Add(hash)
}


func (p *peer) SendData(msgCode uint64, data interface{}) error {
	return Send(p.rw, msgCode, data)
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *peer) Handshake(network uint64, td *big.Int, head common.Hash, genesis common.Hash) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		errc <- Send(p.rw, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
			TD:              td,
			CurrentBlock:    head,
			GenesisBlock:    genesis,
		})
	}()
	go func() {
		errc <- p.readStatus(network, &status, genesis)
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

func (p *peer) readStatus(network uint64, status *statusData, genesis common.Hash) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	//if msg.Size > ProtocolMaxMsgSize {
	//	return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	//}
	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if status.GenesisBlock != genesis {
		return errResp(ErrGenesisBlockMismatch, "%x (!= %x)", status.GenesisBlock[:8], genesis[:8])
	}
	if status.NetworkId != network {
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if uint(status.ProtocolVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}
	return nil
}

// String implements fmt.Stringer.
func (p *peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("hpb/%2d", p.version),
	)
}

// peerSet represents the collection of active peers currently participating in
// the Hpb sub-protocol.
type peerSet struct {
	peers  map[string]*peer
	lock   sync.RWMutex
	closed bool
}

// newPeerSet creates a new peer set to track the active participants.
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peer),
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
func (ps *peerSet) Register(p *peer) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	if ps.closed {
		return errClosed
	}
	if _, ok := ps.peers[p.id]; ok {
		return errAlreadyRegistered
	}
	ps.peers[p.id] = p
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	if _, ok := ps.peers[id]; !ok {
		return errNotRegistered
	}
	delete(ps.peers, id)
	return nil
}

// Peer retrieves the registered peer with the given id.
func (ps *peerSet) Peer(id string) *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (ps *peerSet) PeersWithoutBlock(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownBlocks.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (ps *peerSet) PeersWithoutTx(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownTxs.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (ps *peerSet) BestPeer() *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		bestPeer *peer
		bestTd   *big.Int
	)
	for _, p := range ps.peers {
		if _, td := p.Head(); bestPeer == nil || td.Cmp(bestTd) > 0 {
			bestPeer, bestTd = p, td
		}
	}
	return bestPeer
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (ps *peerSet) Close() {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, p := range ps.peers {
		p.Disconnect(DiscQuitting)
	}
	ps.closed = true
}





