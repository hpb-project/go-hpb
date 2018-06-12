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
	"errors"

	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math/big"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/log"
)

// Protocol represents a P2P subprotocol implementation.
type Protocol struct {
	Name string
	Version uint
	Length uint64
	Run func(peer *Peer, rw MsgReadWriter) error
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

/*
func (cap Cap) RlpData() interface{} {
	return []interface{}{cap.Name, cap.Version}
}

type capsByNameAndVersion []Cap

func (cs capsByNameAndVersion) Len() int      { return len(cs) }
func (cs capsByNameAndVersion) Swap(i, j int) { cs[i], cs[j] = cs[j], cs[i] }
func (cs capsByNameAndVersion) Less(i, j int) bool {
	return cs[i].Name < cs[j].Name || (cs[i].Name == cs[j].Name && cs[i].Version < cs[j].Version)
}
*/
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
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
				//peer := manager.newPeer(version, p, rw)
				p.protorw = newMeteredMsgWriter(rw)
				return hpb.handle(p)
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
func (s *HpbProto) handle(p *Peer) error {
	p.Log().Debug("Peer connected", "name", p.Name())

	return errors.New("HpbProto debugging")
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
func (s *HpbProto) handleMsg(p *Peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.running.ReadMsg()
	if err != nil {
		return err
	}
	log.Info("HpbProto handle massage","Msg",msg.String())

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


