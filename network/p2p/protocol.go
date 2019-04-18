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
	"runtime/debug"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
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
	return fmt.Sprintf("[%s/%d]", cap.Name, cap.Version)
}

////////////////////////////////////////////////////////
type HpbProto struct {
	networkId   uint64
	protos      []Protocol

	msgProcess  map[uint64]MsgProcessCB
	chanStatus  ChanStatusCB
	onAddPeer   OnAddPeerCB
	onDropPeer  OnDropPeerCB

	statMining  StatMining
}

// HPB 支持的协议消息
const ProtoName        = "hpb"
var ProtocolVersions   = []uint{ProtoVersion100}
const ProtoVersion100  uint   =  100

type MsgProcessCB func(p *Peer, msg Msg) error
type ChanStatusCB func()(td *big.Int, currentBlock common.Hash, genesisBlock common.Hash)

type OnAddPeerCB  func(p *Peer) error
type OnDropPeerCB func(p *Peer) error

type StatMining func() bool


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
		p.msgLooping = false
		if r := recover(); r != nil {
			debug.PrintStack()
			p.log.Error("Handle hpb message panic.","r",r)
		}
	}()

	///////////////////////////////////////////
	///////////////////////////////////////////


	//our := &exchangeData{
	//	Version: 0xFFAA,
	//}
	//p.log.Debug("Do hpb exchange data.","ours",our)
	//there,err := p.Exchange(our)
	//if  err != nil {
	//	p.log.Debug("Hpb exchange data failed in peer.", "err", err)
	//	return err
	//}
	//p.log.Info("Do hpb exchange data OK.","there",there)



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
		p.log.Debug("Handshake failed in handle peer.", "err", err)
		return err
	}
	p.log.Debug("Do hpb handshake OK.")

	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}

	// Register the peer locally
	if err := PeerMgrInst().Register(p); err != nil {
		p.log.Debug("Hpb peer registration failed", "err", err)
		return err
	}
	//defer hp.protocolRemovePeer(p.id)

	//&& p.remoteType!=discover.BootNode &&
	if  p.localType!=discover.BootNode && p.remoteType != discover.BootNode  && hp.onAddPeer != nil{
		hp.onAddPeer(p)
		p.msgLooping = true

		defer hp.onDropPeer(p)
		p.log.Info("Network has register peer to syncer")
	}

	// main loop. handle incoming messages.
	p.log.Info("Start hpb message loop.")
	if p.localType != discover.BootNode && p.remoteType == discover.BootNode {
		go hp.proBondall(p)
	}

	for {
		if err := hp.handleMsg(p); err != nil {
			p.log.Debug("Stop hpb message loop.","error",err)
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

func (hp *HpbProto) regStatMining(cb StatMining) {
	hp.statMining = cb
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (hp *HpbProto) handleMsg(p *Peer) error {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		log.Debug("Hpb protocol read msg error","error",err)
		return err
	}
	p.log.Trace("Protocol handle massage","Msg",msg.String())
	defer msg.Discard()

	if msg.Size > MaxMsgSize {
		log.Error("Hpb protocol massage too large.","msg",msg)
		return ErrResp(ErrMsgTooLarge, "msg too large %v > %v", msg.Size, MaxMsgSize)
	}

	// Handle the message depending on its contents
	switch  msg.Code {
	case  StatusMsg, ExchangeMsg:
		p.log.Error("Uncontrolled massage","msg",msg)

	case ReqNodesMsg, ResNodesMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			err := cb(p,msg)
			p.log.Trace("Handle nodes information message.","msg",msg,"err",err)
			if err != nil {
				return err
			}
		}
		return nil

	case ReqBWTestMsg, ResBWTestMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			err := cb(p,msg)
			p.log.Trace("Handle bandwidth test message.","msg",msg,"err",err)
		}
		return nil

	case GetBlockHeadersMsg, GetBlockBodiesMsg,GetNodeDataMsg,GetReceiptsMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			err := cb(p,msg)
			p.log.Trace("Process syn get msg", "msg", msg, "err", err)
			if err != nil {
				return err
			}
		}
		return nil

	case BlockHeadersMsg,BlockBodiesMsg,NodeDataMsg,ReceiptsMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			err := cb(p,msg)
			p.log.Trace("Process syn msg","msg",msg,"err",err)
		}
		return nil

	case NewBlockHashesMsg,NewBlockMsg,NewHashBlockMsg,TxMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			err := cb(p,msg)
			p.log.Trace("Process syn new msg","msg",msg,"err",err)
		}
		return nil

	case ReqRemoteStateMsg,ResRemoteStateMsg:
		if cb := hp.msgProcess[msg.Code]; cb != nil{
			err := cb(p,msg)
			p.log.Trace("Process syn new msg","msg",msg,"err",err)
		}
		return nil

	default:
		p.log.Error("there is no handle to process msg","code", msg.Code)
	}
	return nil
}

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
	timeout := time.NewTimer(time.Second*5)
	defer timeout.Stop()
	select {
	case err := <-errc:
		if err != nil {
			return err
		}
	case <-timeout.C:
		p.log.Error("Send node to remote timeout")
		return DiscReadTimeout
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
	nodes := p.ntab.FindNodes()
	log.Debug("Received nodes from remote", "requestlen", len(request.Nodes), "len buckets", len(nodes))
	log.Trace("nodeInfo", "received:", request.Nodes, "buckets", nodes)
	btest := true
	for _, n := range request.Nodes {
		if self == n.ID {
			continue
		}
		bInbuckets := false
		pid := fmt.Sprintf("%x", n.ID[0:8])
		//p.log.Error("############","pid",pid,"peer", PeerMgrInst().Peer(pid))
		if btest {
			for _, node := range nodes {
				nodeid := fmt.Sprintf("%x", node.ID[0:8])
				if pid == nodeid {
					bInbuckets = true
					break
				}
			}
			if bInbuckets {
				continue
			}
		}
		if PeerMgrInst().Peer(pid) == nil {
			toBondNode = append(toBondNode, n)
			p.chbond <- n
		}
	}

	//if len(toBondNode) > 0 {
	//	log.Trace("Discovery new nodes to bonding.", "Nodes", toBondNode)
	//	go p.ntab.Bondall(toBondNode)

	//}

	return nil
}
////////////////////////////////////////////////////////

func (hp *HpbProto) proBondall(p *Peer) {
	log.Info("proBondall start")
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	toBondNode := make([]*discover.Node, 0, 100)
	var lock sync.RWMutex
	//这里还缺少一个退出机制
	for {
		select {
		case <-timer.C:
			if len(toBondNode) > 0 {
				log.Info("start proBondall", "lenbond", len(toBondNode))
				lock.RLock()
				p.ntab.Bondall(toBondNode)
				lock.RUnlock()
				lock.Lock()
				toBondNode = append(toBondNode[0:0], toBondNode[0:0]...)
				lock.Unlock()
				log.Info("end proBondall", "lenbond", len(toBondNode))
			}
			timer.Reset(15 * time.Second)
		case bondnode := <-p.chbond:
			btobond := true
			bondnodeid := fmt.Sprintf("%x", bondnode.ID[:])
			//log.Info("node:", "bondinfo", bondnodeid)
			for _, node := range toBondNode {
				tobondid := fmt.Sprintf("%x", node.ID[:])
				//log.Info("node:", "nodeinfo", tobondid)
				if tobondid == bondnodeid {
					btobond = false
					break
				}
			}
			if btobond {
				lock.Lock()
				toBondNode = append(toBondNode, bondnode)
				lock.Unlock()
			}
		}
	}
}



////////////////////////////////////////////////////////
type StatDetail struct {
	ID      uint
	Detail  string
}

type statusRes struct {
	Version    uint64
	Status     []StatDetail
}

func HandleReqRemoteStateMsg(p *Peer, msg Msg) error {
	resp := statusRes{Version:0x01}

	mining := "false"
	if PeerMgrInst().hpbpro.statMining() {
		mining = "true"
	}
	resp.Status = append(resp.Status, StatDetail{0x00, mining})

	// Send in a new thread
	errc := make(chan error, 1)
	go func() {
		errc <- SendData(p,ResRemoteStateMsg, &resp)
	}()
	timeout := time.NewTimer(time.Second*5)
	defer timeout.Stop()
	select {
	case err := <-errc:
		if err != nil {
			return err
		}
	case <-timeout.C:
		p.log.Error("Send status to remote timeout")
		return DiscReadTimeout
	}

	return nil
}



func HandleResRemoteStateMsg(p *Peer, msg Msg) error {
	var request statusRes
	if err := msg.Decode(&request); err != nil {
		log.Error("Received status from remote","msg", msg, "error", err)
		return ErrResp(ErrDecode, "msg %v: %v", msg, err)
	}
	log.Trace("Received status from remote","request", request)

	for _, sta := range request.Status {
		switch {
		case sta.ID == 0x00:
			p.statMining = sta.Detail
			break

		default:
			break
		}
	}

	return nil
}

////////////////////////////////////////////////////////