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
	"math/big"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"time"
	"runtime/debug"
)

// Protocol represents a P2P subprotocol implementation.
type Protocol struct {
	Name     string
	Version  uint
	Run      func(p *PeerBase, rw MsgReadWriter) error
}

func (p Protocol) cap() Cap {
	return Cap{p.Name, p.Version}
}

type Cap struct {
	Name    string
	Version uint
}

func (cap Cap) String() string {
	return fmt.Sprintf("%s/%d", cap.Name, cap.Version)
}

////////////////////////////////////////////////////////
type HpbProto struct {
	networkId   uint64
	protos      []Protocol

	msgProcess  map[uint64]MsgProcessCB
	chanStatus  ChanStatusCB
	onAddPeer   OnAddPeerCB
	onDropPeer  OnDropPeerCB
}

// HPB 支持的协议消息
const ProtoName        = "hpb"
var ProtocolVersions   = []uint{ProtoVersion100}
const ProtoVersion100  uint   =  100

type MsgProcessCB func(p *Peer, msg Msg) error
type ChanStatusCB func()(td *big.Int, currentBlock common.Hash, genesisBlock common.Hash)

type OnAddPeerCB  func(p *Peer) error
type OnDropPeerCB func(p *Peer) error

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
	ErrNoExchangeMsg
)

func NewProtos() *HpbProto {
	hpb :=&HpbProto{
		protos:       make([]Protocol, 0, len(ProtocolVersions)),
		msgProcess:   make(map[uint64]MsgProcessCB),
	}

	for _, version := range ProtocolVersions {
		hpb.protos = append(hpb.protos, Protocol{
			Name:    ProtoName,
			Version: version,
			Run: func(p *PeerBase, rw MsgReadWriter) error {
				peer := NewPeer(version, p, rw)
				return hpb.handle(peer)
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


func ErrResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (hp *HpbProto) handle(p *Peer) error {

	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			p.log.Error("Handle hpb message panic.","r",r)
		}
	}()

	///////////////////////////////////////////
	///////////////////////////////////////////
	our := &exchangeData{
		Version: 0xFFAA,
	}
	p.log.Debug("Do hpb exchange data.","ours",our)
	there,err := p.Exchange(our)
	if  err != nil {
		p.log.Debug("Hpb exchange data failed in peer.", "err", err)
		return err
	}
	p.log.Info("Do hpb exchange data OK.","there",there)

	//TODO bonding hardware info
	//p.log.Info("Do do bond hardware OK.")

	///////////////////////////////////////////
	///////////////////////////////////////////
	if hp.chanStatus == nil {
		p.log.Error("this no chan status callback")
		return errProtNoStatusCB
	}
	td, head, genesis := hp.chanStatus()
	if err := p.Handshake(hp.networkId, td, head, genesis); err != nil {
		p.log.Error("Handshake failed in handle peer.", "err", err)
		return err
	}
	p.log.Info("Do hpb handshake OK.")

	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}

	// Register the peer locally
	if err := PeerMgrInst().Register(p); err != nil {
		p.log.Error("Hpb peer registration failed", "err", err)
		return err
	}
	//defer hp.protocolRemovePeer(p.id)

	//&& p.remoteType!=discover.BootNode &&
	if  p.localType!=discover.BootNode && p.remoteType != discover.BootNode  && hp.onAddPeer != nil{
		hp.onAddPeer(p)
		p.log.Debug("Network has register peer to syncer")
	}

	// main loop. handle incoming messages.
	p.log.Info("Start hpb message loop.")
	for {
		if err := hp.handleMsg(p); err != nil {
			p.log.Debug("Message handling failed", "err", err)
			//if  p.localType!=discover.BootNode && p.remoteType != discover.BootNode && hp.onDropPeer != nil {
			//	hp.onDropPeer(p)
			//	p.log.Debug("Network has drop peer to notify syncer")
			//}
			p.log.Error("Stop hpb message loop.","error",err)
			return err
		}
	}
}

func (hp *HpbProto) regMsgProcess(msg uint64,cb MsgProcessCB) {
	hp.msgProcess[msg] = cb
}

func (hp *HpbProto) regChanStatus(cb ChanStatusCB) {
	hp.chanStatus = cb
}

func (hp *HpbProto) regOnAddPeer(cb OnAddPeerCB) {
	hp.onAddPeer = cb
}

func (hp *HpbProto) regOnDropPeer(cb OnDropPeerCB) {
	hp.onDropPeer = cb
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (hp *HpbProto) handleMsg(p *Peer) error {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		log.Error("Hpb protocol read msg error","error",err)
		return err
	}
	p.log.Trace("Protocol handle massage","Msg",msg.String())
	defer msg.Discard()

	if msg.Size > MaxMsgSize {
		log.Error("Hpb protocol massage too large.","msg",msg)
		return ErrResp(ErrMsgTooLarge, "%v > %v", msg.Size, MaxMsgSize)
	}

	// Handle the message depending on its contents
	switch  msg.Code {
	case  StatusMsg, ExchangeMsg:
		p.log.Error("Uncontrolled massage","msg",msg)

	case ReqNodesMsg, ResNodesMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			cb(p,msg)
			p.log.Debug("Handle nodes information message.","msg",msg)
		}
		return nil

	case ReqBWTestMsg, ResBWTestMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			cb(p,msg)
			p.log.Trace("Handle bandwidth test message.","msg",msg)
		}
		return nil

	case GetBlockHeadersMsg, GetBlockBodiesMsg,GetNodeDataMsg,GetReceiptsMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			cb(p,msg)
			p.log.Trace("Process syn get msg","msg",msg)
		}
		return nil

	case BlockHeadersMsg,BlockBodiesMsg,NodeDataMsg,ReceiptsMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			cb(p,msg)
			p.log.Trace("Process syn msg","msg",msg)
		}
		return nil

	case NewBlockHashesMsg,NewBlockMsg,NewHashBlockMsg,TxMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			cb(p,msg)
			p.log.Trace("Process syn new msg","msg",msg)
		}
		return nil

	default:
		p.log.Error("there is no handle to process msg","code", msg.Code)
	}
	return nil
}

//func (hp *HpbProto) protocolRemovePeer(id string) {
//	// Short circuit if the peer was already removed
//	peer := PeerMgrInst().Peer(id)
//	if peer == nil {
//		return
//	}
//	log.Error("###### NEED P2P TO REMOVE PEER! ######", "peer", id)
//
//	// Unregister the peer from the downloader and Hpb peer set
//	if err := PeerMgrInst().unregister(id); err != nil {
//		log.Error("Peer removal failed", "peer", id, "err", err)
//	}
//	// Hard disconnect at the networking layer
//	if peer != nil {
//		peer.Disconnect(DiscUselessPeer)
//	}
//}

////////////////////////////////////////////////////////
type nodeRes struct {
	Version    uint64
	Nodes      []*discover.Node
}

func HandleReqNodesMsg(p *Peer, msg Msg) error {
	nodes := p.ntab.FindNodes()
	resp := nodeRes{Version:0x01,Nodes:nodes}

	// Send in a new thread
	errc := make(chan error, 1)
	go func() {
		errc <- SendData(p,ResNodesMsg, &resp)
	}()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	select {
	case err := <-errc:
		if err != nil {
			return err
		}
	case <-timeout.C:
		p.log.Error("Send node to remote timeout")
	}

	return nil
}

func HandleResNodesMsg(p *Peer, msg Msg) error {
	var request nodeRes
	if err := msg.Decode(&request); err != nil {
		log.Error("Received nodes from remote","msg", msg, "error", err)
		return ErrResp(ErrDecode, "msg %v: %v", msg, err)
	}
	log.Trace("Received nodes from remote","request", request)


	self := p.ntab.Self().ID
	toBondNode := make([]*discover.Node, 0, len(request.Nodes))
	//log.Error("############","self",self,"Nodes",request.Nodes)
	//log.Error("############","Peers",PeerMgrInst().PeersAll())
	for _, n := range request.Nodes {
		if self == n.ID {
			continue
		}

		pid := fmt.Sprintf("%x", n.ID[0:8])
		//p.log.Error("############","pid",pid,"peer", PeerMgrInst().Peer(pid))
		if PeerMgrInst().Peer(pid) == nil{
			toBondNode = append(toBondNode,n)
		}
	}

	//log.Error("############","len",len(toBondNode))
	if len(toBondNode) > 0{
		log.Debug("Discovery new nodes to bonding.","Nodes",toBondNode)
		go p.ntab.Bondall(toBondNode)
	}


	return nil
}


