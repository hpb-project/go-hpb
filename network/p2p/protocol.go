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
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
)

// Protocol represents a P2P subprotocol implementation.
type Protocol struct {
	Name     string
	Version  uint
	Length   uint64
	Run      func(p *PeerBase, rw MsgReadWriter) error
	NodeInfo func() interface{}
	PeerInfo func(id discover.NodeID) interface{}
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
//HPB 协议
type HpbProto struct {
	networkId  uint64
	protos     []Protocol
	procFun    map[uint64]MsgCallback
}

const ProtoName        = "hpb"
const ProtoMaxMsg      = 10 * 1024 * 1024
var ProtocolVersions   = []uint{ProtoVersion100}
var ProtocolMsgLengths = []uint64{ProtoMsgLength}

// HPB 支持的协议消息
const ProtoVersion100  uint   =  100
const ProtoMsgLength   uint64 =  20

type MsgCallback func(p *Peer, msg Msg) error

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
)

func NewProtos() *HpbProto {
	hpb :=&HpbProto{
		networkId: 0,
		protos:    make([]Protocol, 0, len(ProtocolVersions)),
		procFun:   make(map[uint64]MsgCallback),
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

func (hp *HpbProto) regMsgCall(msg uint64,cb MsgCallback) {
	hp.procFun[msg] = cb
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
		if cb := hp.procFun[StatusMsg]; cb != nil{
			cb(p,msg)
		}
		return nil
	case msg.Code == GetBlockHeadersMsg:
		if cb := hp.procFun[GetBlockHeadersMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == BlockHeadersMsg:
		if cb := hp.procFun[BlockHeadersMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == GetBlockBodiesMsg:
		if cb := hp.procFun[GetBlockBodiesMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == BlockBodiesMsg:
		if cb := hp.procFun[BlockBodiesMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == GetNodeDataMsg:
		if cb := hp.procFun[GetNodeDataMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == NodeDataMsg:
		if cb := hp.procFun[NodeDataMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == GetReceiptsMsg:
		if cb := hp.procFun[GetReceiptsMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == ReceiptsMsg:
		if cb := hp.procFun[ReceiptsMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == NewBlockHashesMsg:
		if cb := hp.procFun[NewBlockHashesMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == NewBlockMsg:
		if cb := hp.procFun[NewBlockMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == TxMsg:
		if cb := hp.procFun[TxMsg]; cb != nil{
			cb(p,msg)
		}
		return nil

	case msg.Code == HpbTestMsg:
		data :=[] byte {0x4C,0x51,0x48}
		err := p.SendData(HpbTestMsgResp,data)
		log.Debug("handleMsg test send ...","peer",p.id, "Msg",msg.String(),"send err",err)
		return nil
	case msg.Code == HpbTestMsgResp:
		log.Debug("handleMsg rest recv ...","peer",p.id, "Msg",msg.String())
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

