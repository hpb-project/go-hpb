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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/event"
)


// message of control

const (
	handshakeMsg    uint64 = 0x0000
	discMsg         uint64 = 0x0001
	pingMsg         uint64 = 0x0002
	pongMsg         uint64 = 0x0003

	hardwareMsg     uint64 = 0x0010

	baseMsgMax      uint64 = 0x0FFF
)

// message of hpb protocol
const (
	StatusMsg          uint64 = 0x1010
	ExchangeMsg        uint64 = 0x1011
	ReqNodesMsg        uint64 = 0x1020
	ResNodesMsg        uint64 = 0x1021
	ReqBWTestMsg       uint64 = 0x1030
	ResBWTestMsg       uint64 = 0x1031
	ReqRemoteStateMsg  uint64 = 0x1040
	ResRemoteStateMsg  uint64 = 0x1041

	NewBlockHashesMsg  uint64 = 0x2012
	TxMsg              uint64 = 0x2013
	GetBlockHeadersMsg uint64 = 0x2014
	BlockHeadersMsg    uint64 = 0x2015
	GetBlockBodiesMsg  uint64 = 0x2016
	BlockBodiesMsg     uint64 = 0x2017
	NewBlockMsg        uint64 = 0x2018
	GetNodeDataMsg     uint64 = 0x2019
	NodeDataMsg        uint64 = 0x201a
	GetReceiptsMsg     uint64 = 0x201b
	ReceiptsMsg        uint64 = 0x201c

	NewHashBlockMsg    uint64 = 0x2020


)



// Msg defines the structure of a p2p message.
//
// Note that a Msg can only be sent once since the Payload reader is
// consumed during sending. It is not possible to create a Msg and
// send it any number of times. If you want to reuse an encoded
// structure, encode the payload into a byte array and create a
// separate Msg with a bytes.Reader as Payload for each send.
type Msg struct {
	Code       uint64
	Size       uint32 // size of the paylod
	Payload    io.Reader
	ReceivedAt time.Time
}

// Decode parses the RLP content of a message into
// the given value, which must be a pointer.
//
// For the decoding rules, please see package rlp.
func (msg Msg) Decode(val interface{}) error {
	s := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if err := s.Decode(val); err != nil {
		return newPeerError(errInvalidMsg, "(code %x) (size %d) %v", msg.Code, msg.Size, err)
	}
	return nil
}

func (msg Msg) String() string {
	return fmt.Sprintf("msg #0x%x (%v bytes)", msg.Code, msg.Size)
}

// Discard reads any remaining payload data into a black hole.
func (msg Msg) Discard() error {
	_, err := io.Copy(ioutil.Discard, msg.Payload)
	return err
}

type MsgReader interface {
	ReadMsg() (Msg, error)
}

type MsgWriter interface {
	// WriteMsg sends a message. It will block until the message's
	// Payload has been consumed by the other end.
	//
	// Note that messages can be sent only once because their
	// payload reader is drained.
	WriteMsg(Msg) error
}

// MsgReadWriter provides reading and writing of encoded messages.
// Implementations should ensure that ReadMsg and WriteMsg can be
// called simultaneously from multiple goroutines.
type MsgReadWriter interface {
	MsgReader
	MsgWriter
}

// Send writes an RLP-encoded message with the given code.
// data should encode as an RLP list.
func send(w MsgWriter, msgcode uint64, data interface{}) error {
	size, r, err := rlp.EncodeToReader(data)
	if err != nil {
		return err
	}
	return w.WriteMsg(Msg{Code: msgcode, Size: uint32(size), Payload: r})
}

func sendItems(w MsgWriter, msgcode uint64, elems ...interface{}) error {
	return send(w, msgcode, elems)
}

// ExpectMsg reads a message from r and verifies that its
// code and encoded RLP content match the provided values.
// If content is nil, the payload is discarded and not verified.
func ExpectMsg(r MsgReader, code uint64, content interface{}) error {
	msg, err := r.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != code {
		return fmt.Errorf("message code mismatch: got %d, expected %d", msg.Code, code)
	}
	if content == nil {
		return msg.Discard()
	} else {
		contentEnc, err := rlp.EncodeToBytes(content)
		if err != nil {
			panic("content encode error: " + err.Error())
		}
		if int(msg.Size) != len(contentEnc) {
			return fmt.Errorf("message size mismatch: got %d, want %d", msg.Size, len(contentEnc))
		}
		actualContent, err := ioutil.ReadAll(msg.Payload)
		if err != nil {
			return err
		}
		if !bytes.Equal(actualContent, contentEnc) {
			return fmt.Errorf("message payload mismatch:\ngot:  %x\nwant: %x", actualContent, contentEnc)
		}
	}
	return nil
}

// msgEventer wraps a MsgReadWriter and sends events whenever a message is sent
// or received
type msgEventer struct {
	MsgReadWriter

	feed     *event.SyncEvent
	peerID   discover.NodeID
	Protocol string
}

// newMsgEventer returns a msgEventer which sends message events to the given
// feed
func newMsgEventer(rw MsgReadWriter, feed *event.SyncEvent, peerID discover.NodeID, proto string) *msgEventer {
	return &msgEventer{
		MsgReadWriter: rw,
		feed:          feed,
		peerID:        peerID,
		Protocol:      proto,
	}
}

// ReadMsg reads a message from the underlying MsgReadWriter and emits a
// "message received" event
func (self *msgEventer) ReadMsg() (Msg, error) {
	msg, err := self.MsgReadWriter.ReadMsg()
	if err != nil {
		return msg, err
	}
	self.feed.Notify(PeerEventMsgRecv,&PeerEvent{
		Type:     PeerEventMsgRecv,
		Peer:     self.peerID,
		Protocol: self.Protocol,
		MsgCode:  &msg.Code,
		MsgSize:  &msg.Size,
	})

	return msg, nil
}

// WriteMsg writes a message to the underlying MsgReadWriter and emits a
// "message sent" event
func (self *msgEventer) WriteMsg(msg Msg) error {
	err := self.MsgReadWriter.WriteMsg(msg)
	if err != nil {
		return err
	}
	self.feed.Notify(PeerEventMsgSend,&PeerEvent{
		Type:     PeerEventMsgSend,
		Peer:     self.peerID,
		Protocol: self.Protocol,
		MsgCode:  &msg.Code,
		MsgSize:  &msg.Size,
	})
	return nil
}

// Close closes the underlying MsgReadWriter if it implements the io.Closer
// interface
func (self *msgEventer) Close() error {
	if v, ok := self.MsgReadWriter.(io.Closer); ok {
		return v.Close()
	}
	return nil
}
