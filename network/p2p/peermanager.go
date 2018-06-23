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
	"time"
	"fmt"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/synctrl"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"gopkg.in/fatih/set.v0"
	"github.com/hpb-project/go-hpb/config"
	"net"
	"github.com/hpb-project/go-hpb/network/rpc"
	"sync/atomic"
)

var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
	errIncomplete        = errors.New("PeerManager is incomplete creation")
)

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

type Peer struct {
	id string

	*PeerBase
	rw MsgReadWriter

	version  uint         // Protocol version negotiated

	txsRate  uint

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	knownTxs    *set.Set // Set of transaction hashes known to be known by this peer
	knownBlocks *set.Set // Set of block hashes known to be known by this peer
}


type PeerManager struct {
	peers  map[string]*Peer
	lock   sync.RWMutex
	closed bool

	rpc    *RpcMgr
	server *Server
	hpb    *HpbProto
}

var INSTANCE = atomic.Value{}

func PeerMgrInst() *PeerManager {
	if INSTANCE.Load() == nil {
		//Please init PeerManager
		pm :=&PeerManager{
			peers: make(map[string]*Peer),
			hpb: NewProtos(),
		}
		INSTANCE.Store(pm)
	}

	return INSTANCE.Load().(*PeerManager)
}

func (prm *PeerManager)Start(netCfg config.NetworkConfig) error {


	if prm.hpb == nil {
		return errIncomplete
	}

	prm.rpc    = &RpcMgr{
		//IpcEndpoint: ,
		//HttpEndpoint: ,
		//WsEndpoint: ,

		//IPCPath:     netCfg.IPCPath,
		HTTPHost:    netCfg.HTTPHost,
		HTTPPort:    netCfg.HTTPPort,
		HTTPCors:    netCfg.HTTPCors,
		HTTPModules: netCfg.HTTPModules,
		WSHost:      netCfg.WSHost,
		WSPort:      netCfg.WSPort,
		WSOrigins:   netCfg.WSOrigins,
		WSModules:   netCfg.WSModules,
		WSExposeAll: netCfg.WSExposeAll,
	}

	prm.server = &Server{
		Config: Config{
			PrivateKey: netCfg.PrivateKey,
			MaxPendingPeers: netCfg.MaxPendingPeers,
			Name: netCfg.Name,
			RoleType: netCfg.RoleType,
			//BootstrapNodes: netCfg.,
			//StaticNodes: netCfg.,
			//TrustedNodes: netCfg.,
			NetRestrict: netCfg.NetRestrict,
			NodeDatabase: netCfg.NodeDatabase,
			Protocols: prm.hpb.Protocols(),
			ListenAddr: netCfg.ListenAddr,
			NAT: netCfg.NAT,
			Dialer: netCfg.Dialer,
			NoDial: netCfg.NoDial,
			EnableMsgEvents: netCfg.EnableMsgEvents,
			//NetworkId: netCfg.NetworkId,
		},
	}
	//prm.hpb.networkId = networkId
	copy(prm.server.Protocols, prm.hpb.Protocols())

	//prm.rpc.startRPC()

	if err := prm.server.Start(); err != nil {
		log.Error("Hpb protocol","error",err)
		return err
	}

	return nil

}

func (prm *PeerManager)Stop(){
	prm.Close()

	//prm.rpc.stopRPC()

	prm.server.Stop()
	prm.server = nil

}


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
func (prm *PeerManager) Len() int {
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
func (prm *PeerManager) Close() {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	for _, p := range prm.peers {
		p.Disconnect(DiscQuitting)
	}
	prm.closed = true
}

////////////////////////////////////////////////////////

//HPB 协议
type HpbProto struct {
	networkId uint64
	protos   []Protocol
	callback map[uint64]func(interface{}) (bool)

	//gs *gatherShards

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





func NewProtos() *HpbProto {
	hpb :=&HpbProto{
		networkId: 0,
		protos:    make([]Protocol, 0, len(ProtocolVersions)),
		//gs:        &gatherShards{make(map[string]*blockShards)},
	}

	for _, version := range ProtocolVersions {
		hpb.protos = append(hpb.protos, Protocol{
			Name:    ProtoName,
			Version: version,
			Run: func(p *PeerBase, rw MsgReadWriter) error {
				peer := NewPeer(version, p, rw)
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
		return nil
	}

	return hpb
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
func (hp *HpbProto) NodeInfo() *HpbNodeInfo {

	currentBlock := bc.InstanceBlockChain().CurrentBlock()
	return &HpbNodeInfo{
		Network:    hp.networkId,
		Difficulty: bc.InstanceBlockChain().GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:    bc.InstanceBlockChain().Genesis().Hash(),
		Head:       currentBlock.Hash(),
	}

	return  nil
}

func ErrResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}


// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (hp *HpbProto) handle(p *Peer) error {
	p.Log().Debug("Peer connected", "name", p.Name())

	//return errors.New("HpbProto debugging")
	// Execute the Hpb handshake
	//TODO: 调用blockchain接口，获取状态信息

	td, head, genesis := bc.InstanceBlockChain().Status()
	if err := p.Handshake(hp.networkId, td, head, genesis); err != nil {
		p.Log().Debug("Handshake failed", "err", err)
		return err
	}

	//Peer 层性能统计
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}

	// Register the peer locally
	if err := PeerMgrInst().Register(p); err != nil {
		p.Log().Error("Hpb peer registration failed", "err", err)
		return err
	}
	defer hp.removePeer(p.id)

	// main loop. handle incoming messages.
	for {
		if err := hp.handleMsg(p); err != nil {
			p.Log().Debug("Message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (hp *HpbProto) handleMsg(p *Peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	//log.Trace("HpbProto handle massage","Msg",msg.String())

	if msg.Size > ProtoMaxMsg {
		return ErrResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtoMaxMsg)
	}

	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		cb := hp.callback[StatusMsg]
		cb(msg)
		return nil
	case msg.Code == GetBlockHeadersMsg:
		synctrl.HandleGetBlockHeadersMsg(p, msg)
		return nil

	case msg.Code == BlockHeadersMsg:
		synctrl.HandleBlockHeadersMsg(p, msg)
		return nil

	case msg.Code == GetBlockBodiesMsg:
		synctrl.HandleGetBlockBodiesMsg(p, msg)
		return nil

	case msg.Code == BlockBodiesMsg:
		synctrl.HandleBlockBodiesMsg(p, msg)
		return nil

	case msg.Code == GetNodeDataMsg:
		synctrl.HandleGetNodeDataMsg(p, msg)
		return nil

	case msg.Code == NodeDataMsg:
		synctrl.HandleNodeDataMsg(p, msg)
		return nil

	case msg.Code == GetReceiptsMsg:
		synctrl.HandleGetReceiptsMsg(p, msg)
		return nil

	case msg.Code == ReceiptsMsg:
		synctrl.HandleReceiptsMsg(p, msg)
		return nil

	case msg.Code == NewBlockHashesMsg:
		synctrl.HandleNewBlockHashesMsg(p, msg)
		return nil

	case msg.Code == NewBlockMsg:
		synctrl.HandleNewBlockMsg(p, msg)
		return nil

	case msg.Code == TxMsg:
		synctrl.HandleTxMsg(p, msg)
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
		return ErrResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

func (hp *HpbProto) removePeer(id string) {
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

func (p *Peer) TxsRate() uint {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.txsRate
}

func (p *Peer) SetTxsRate(txs uint) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.txsRate = txs
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
	return Send(p.rw, msgCode, data)
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *Peer) Handshake(network uint64, td *big.Int, head common.Hash, genesis common.Hash) error {
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

func (p *Peer) readStatus(network uint64, status *statusData, genesis common.Hash) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return ErrResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	//if msg.Size > ProtocolMaxMsgSize {
	//	return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	//}
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


////////////////////////////////////////////////////////////////////////////

// Node is a container on which services can be registered.
type RpcMgr struct {
	rpcAPIs       []rpc.API   // List of APIs currently provided by the node
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests

	//ipcEndpoint string       // IPC endpoint to listen at (empty = IPC disabled)
	ipcListener net.Listener // IPC RPC listener socket to serve API requests
	ipcHandler  *rpc.Server  // IPC RPC request handler to process the API requests

	//httpEndpoint  string       // HTTP endpoint (interface + port) to listen at (empty = HTTP disabled)
	httpWhitelist []string     // HTTP RPC modules to allow through this endpoint
	httpListener  net.Listener // HTTP RPC listener socket to server API requests
	httpHandler   *rpc.Server  // HTTP RPC request handler to process the API requests

	//wsEndpoint string       // Websocket endpoint (interface + port) to listen at (empty = websocket disabled)
	wsListener net.Listener // Websocket RPC listener socket to server API requests
	wsHandler  *rpc.Server  // Websocket RPC request handler to process the API requests

	lock sync.RWMutex

	IpcEndpoint   string       // IPC endpoint to listen at (empty = IPC disabled)
	HttpEndpoint  string       // HTTP endpoint (interface + port) to listen at (empty = HTTP disabled)
	WsEndpoint    string       // Websocket endpoint (interface + port) to listen at (empty = websocket disabled)

	// IPCPath is the requested location to place the IPC endpoint. If the path is
	// a simple file name, it is placed inside the data directory (or on the root
	// pipe path on Windows), whereas if it's a resolvable path name (absolute or
	// relative), then that specific path is enforced. An empty path disables IPC.
	IPCPath string `toml:",omitempty"`

	// HTTPHost is the host interface on which to start the HTTP RPC server. If this
	// field is empty, no HTTP API endpoint will be started.
	HTTPHost string `toml:",omitempty"`

	// HTTPPort is the TCP port number on which to start the HTTP RPC server. The
	// default zero value is/ valid and will pick a port number randomly (useful
	// for ephemeral nodes).
	HTTPPort int `toml:",omitempty"`

	// HTTPCors is the Cross-Origin Resource Sharing header to send to requesting
	// clients. Please be aware that CORS is a browser enforced security, it's fully
	// useless for custom HTTP clients.
	HTTPCors []string `toml:",omitempty"`

	// HTTPModules is a list of API modules to expose via the HTTP RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	HTTPModules []string `toml:",omitempty"`

	// WSHost is the host interface on which to start the websocket RPC server. If
	// this field is empty, no websocket API endpoint will be started.
	WSHost string `toml:",omitempty"`

	// WSPort is the TCP port number on which to start the websocket RPC server. The
	// default zero value is/ valid and will pick a port number randomly (useful for
	// ephemeral nodes).
	WSPort int `toml:",omitempty"`

	// WSOrigins is the list of domain to accept websocket requests from. Please be
	// aware that the server can only act upon the HTTP request the client sends and
	// cannot verify the validity of the request header.
	WSOrigins []string `toml:",omitempty"`

	// WSModules is a list of API modules to expose via the websocket RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	WSModules []string `toml:",omitempty"`

	// WSExposeAll exposes all API modules via the WebSocket RPC interface rather
	// than just the public ones.
	//
	// *WARNING* Only set this if the node is running in a trusted network, exposing
	// private APIs to untrusted users is a major security risk.
	WSExposeAll bool `toml:",omitempty"`

}

// startRPC is a helper method to start all the various RPC endpoint during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
func (n *RpcMgr) startRPC(apis []rpc.API) error {
	// Gather all the possible APIs to surface
	//apis := n.apis()

	// Start the various API endpoints, terminating all in case of errors
	if err := n.startInProc(apis); err != nil {
		return err
	}
	if err := n.startIPC(apis); err != nil {
		n.stopInProc()
		return err
	}
	if err := n.startHTTP(n.HttpEndpoint, apis, n.HTTPModules, n.HTTPCors); err != nil {
		n.stopIPC()
		n.stopInProc()
		return err
	}
	if err := n.startWS(n.WsEndpoint, apis, n.WSModules, n.WSOrigins, n.WSExposeAll); err != nil {
		n.stopHTTP()
		n.stopIPC()
		n.stopInProc()
		return err
	}
	// All API endpoints started successfully
	n.rpcAPIs = apis
	return nil
}
func (n *RpcMgr) stopRPC() {
	n.stopWS()
	n.stopHTTP()
	n.stopIPC()
}


// startInProc initializes an in-process RPC endpoint.
func (n *RpcMgr) startInProc(apis []rpc.API) error {
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
		log.Debug(fmt.Sprintf("InProc registered %T under '%s'", api.Service, api.Namespace))
	}
	n.inprocHandler = handler
	return nil
}

// stopInProc terminates the in-process RPC endpoint.
func (n *RpcMgr) stopInProc() {
	if n.inprocHandler != nil {
		n.inprocHandler.Stop()
		n.inprocHandler = nil
	}
}

// startIPC initializes and starts the IPC RPC endpoint.
func (n *RpcMgr) startIPC(apis []rpc.API) error {
	// Short circuit if the IPC endpoint isn't being exposed
	if n.IpcEndpoint == "" {
		return nil
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
		log.Debug(fmt.Sprintf("IPC registered %T under '%s'", api.Service, api.Namespace))
	}
	// All APIs registered, start the IPC listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = rpc.CreateIPCListener(n.IpcEndpoint); err != nil {
		return err
	}
	go func() {
		log.Info(fmt.Sprintf("IPC endpoint opened: %s", n.IpcEndpoint))

		for {
			conn, err := listener.Accept()
			if err != nil {
				// Terminate if the listener was closed
				n.lock.RLock()
				closed := n.ipcListener == nil
				n.lock.RUnlock()
				if closed {
					return
				}
				// Not closed, just some error; report and continue
				log.Error(fmt.Sprintf("IPC accept failed: %v", err))
				continue
			}
			go handler.ServeCodec(rpc.NewJSONCodec(conn), rpc.OptionMethodInvocation|rpc.OptionSubscriptions)
		}
	}()
	// All listeners booted successfully
	n.ipcListener = listener
	n.ipcHandler = handler

	return nil
}

// stopIPC terminates the IPC RPC endpoint.
func (n *RpcMgr) stopIPC() {
	if n.ipcListener != nil {
		n.ipcListener.Close()
		n.ipcListener = nil

		log.Info(fmt.Sprintf("IPC endpoint closed: %s", n.IpcEndpoint))
	}
	if n.ipcHandler != nil {
		n.ipcHandler.Stop()
		n.ipcHandler = nil
	}
}

// startHTTP initializes and starts the HTTP RPC endpoint.
func (n *RpcMgr) startHTTP(endpoint string, apis []rpc.API, modules []string, cors []string) error {
	// Short circuit if the HTTP endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
			log.Debug(fmt.Sprintf("HTTP registered %T under '%s'", api.Service, api.Namespace))
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return err
	}
	go rpc.NewHTTPServer(cors, handler).Serve(listener)
	log.Info(fmt.Sprintf("HTTP endpoint opened: http://%s", endpoint))

	// All listeners booted successfully
	n.HttpEndpoint = endpoint
	n.httpListener = listener
	n.httpHandler = handler

	return nil
}

// stopHTTP terminates the HTTP RPC endpoint.
func (n *RpcMgr) stopHTTP() {
	if n.httpListener != nil {
		n.httpListener.Close()
		n.httpListener = nil

		log.Info(fmt.Sprintf("HTTP endpoint closed: http://%s", n.HttpEndpoint))
	}
	if n.httpHandler != nil {
		n.httpHandler.Stop()
		n.httpHandler = nil
	}
}

// startWS initializes and starts the websocket RPC endpoint.
func (n *RpcMgr) startWS(endpoint string, apis []rpc.API, modules []string, wsOrigins []string, exposeAll bool) error {
	// Short circuit if the WS endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if exposeAll || whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
			log.Debug(fmt.Sprintf("WebSocket registered %T under '%s'", api.Service, api.Namespace))
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return err
	}
	go rpc.NewWSServer(wsOrigins, handler).Serve(listener)
	log.Info(fmt.Sprintf("WebSocket endpoint opened: ws://%s", listener.Addr()))

	// All listeners booted successfully
	n.WsEndpoint = endpoint
	n.wsListener = listener
	n.wsHandler = handler

	return nil
}

// stopWS terminates the websocket RPC endpoint.
func (n *RpcMgr) stopWS() {
	if n.wsListener != nil {
		n.wsListener.Close()
		n.wsListener = nil

		log.Info(fmt.Sprintf("WebSocket endpoint closed: ws://%s", n.WsEndpoint))
	}
	if n.wsHandler != nil {
		n.wsHandler.Stop()
		n.wsHandler = nil
	}
}

///////////////////////////////////////////////////////////////
/*
//shard case
type shardHead struct {
	hash    string  //block的哈希
	size    int     //payload size
	each    int     //
	mask    uint64  //最多64片.每位代表对应的shard。
	//0x0000 0000 0000 0000 ~ 0xFFFF FFFF FFFF FFFF
	//代表需要接收0~63个shard
	tail    []byte  //第0个分片
}

type shardData struct {
	hash    string //block的哈希
	index   int    //索引，代表piece对应的位置
	piece   []byte //索引指定的分片数据
}
// 区块分片数据
type blockShards struct {
	start    time.Time //
	mask     uint64    //
	each     int       //
	data     []byte    //
}

// 分片数据收集器
type gatherShards struct {
	blocks map[string]*blockShards
}

//
func (pm *HpbProto) SendBlockByShards(peers []*Peer, block * types.Block, td *big.Int) error {

	payload, err := rlp.EncodeToBytes([]interface{}{block, td})
	if err != nil {
		panic(fmt.Errorf("SendBlockByShards can't encode object: %v", err))
	}
	size := len(payload)
	hash := block.Hash()

	//len(peers) == (31-1) or (61-1) 其他所有hpnode
	copy := len(peers)
	if copy != 30 || copy != 60 {
		log.Warn("The number of synchronized peers is abnormal")
	}

	//计算分片数据的mask
	mask := uint64(^0)
	mask  = mask << uint(64 -copy)
	mask  = mask >> uint(64 -copy)

	//计算需要发送tail数据
	each := size / copy
	var tail []byte
	if (size % copy) == 0 {
		tail   = []byte{}
	}else {
		remain := size - (each*copy)
		tail    = payload[size-remain:]
	}

	for _, p := range peers {
		if err := p2p.Send(p.rw, ShardHeadMsg, &shardHead{hash:hash.String(),size:size,each:each,mask:mask,tail:tail}); err!=nil {
			log.Error("Send block tail shard data error","peer",p.id,"err",err)
		}
	}

	//正序一遍
	for index, p := range peers {
		piece := payload[index*int(each):(index+1)*int(each)]
		if err := p2p.Send(p.rw, ShardPieceMsg, &shardData{hash:hash.String(),index:index,piece:piece}); err!=nil {
			log.Error("Positively send block shard data error","index",index,"peer",p.id,"err",err)
		}
	}

	//反序一遍
	for index, p := range peers {
		piece := payload[(int(copy)- index-1)*int(each):(int(copy)- index)*int(each)]
		if err := p2p.Send(p.rw, ShardPieceMsg, &shardData{hash:hash.String(),index:index,piece:piece}); err!=nil {
			log.Error("Reversely send block shard data error","index",index,"peer",p.id,"err",err)
		}
	}

	//乱序一遍
	//for index, p := range peers {
	//	piece := payload[index*int(each):(index+1)*int(each)]
	//	if err := p2p.Send(p.rw, ShardPieceMsg, &shardData{hash:hash.String(),index:index,piece:piece}); err!=nil {
	//		log.Error("Disorderly send block shard data error","index",index,"peer",p.id,"err",err)
	//	}
	//}

	log.Trace("Send block shard data over")

	return nil
}

//
func (pm *HpbProto) ForwardBlockShards(peers []*peer, shard *shardData) error {

	for _, p := range peers {
		if err := p2p.Send(p.rw, ShardPieceMsg, shard); err!=nil {
			log.Error("Forward block shard data error","index",shard.index,"peer",p.id,"err",err)
		}
	}
	return nil
}

//
func (pm *HpbProto) ProcShardHeadMsg(peer *peer, msg p2p.Msg) error {
	var head shardHead
	if err := msg.Decode(&head); err != nil {
		return nil
	}

	//创建接收block的容器
	if pm.gs.blocks[head.hash] != nil {
		log.Warn("Duplicate shard head message data")
	}
	bs := &blockShards{start:time.Now(),mask:head.mask,each:head.each,data:make([]byte,head.size,head.size)}
	pm.gs.blocks[head.hash] = bs

	//复制可能存在的tail数据到payload尾部
	if len(head.tail) != 0 {
		n := copy(bs.data[int(head.size)-len(head.tail):],head.tail)
		if n != len(head.tail){
			log.Error("Copy tail shard data error")
		}
	}

	return nil
}

//
func (pm *HpbProto) ProcShardPieceMsg(peer *peer, msg p2p.Msg) *newBlockData {

	var shard shardData
	if err := msg.Decode(&shard); err != nil {
		return nil
	}

	bs := pm.gs.blocks[shard.hash]
	if bs == nil {
		log.Error("Could not find the shard piece belongs to")
		return nil
	}

	if len(shard.piece) != bs.each {
		log.Error("Copy shard data len error","expect",bs.each,"receive",len(shard.piece))
		return nil
	}

	n := copy(bs.data[bs.each*shard.index:bs.each*(shard.index+1)],shard.piece)
	if n != bs.each {
		log.Error("Copy tail shard data error")
	}

	// 把对应位 mask置0
	bs.mask = bs.mask &^ (uint64(1)<<uint(shard.index))

	// 继续等待其他分片数据
	if bs.mask != 0 {
		return nil
	}

	// 已经接收到全部分片数据
	var newBlock newBlockData
	if err := rlp.DecodeBytes(bs.data, &newBlock); err != nil {
		log.Error("NewBlockShardMsg DecodeBytes Err")
		return nil
	}

	log.Info("","block",newBlock.Block.Hash(),"td",newBlock.TD)
	return &newBlock
}
*/