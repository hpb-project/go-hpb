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

package synctrl

import (
	"fmt"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

const (
	pk_Header          = 0x00
	pk_Body            = 0x01
	pk_Receipt         = 0x02
	pk_State           = 0x03
)

type pkFactory struct {
}

func (this pkFactory) create(tp int) dataPack {
	switch tp {
	case pk_Header:
		return new(headerPack)
	case pk_Body:
		return new(bodyPack)
	case pk_Receipt:
		return new(receiptPack)
	case pk_State:
		return new(statePack)
	default:
		return nil
	}
}

// dataPack is a data message returned by a peer for some query.
type dataPack interface {
	PeerId() string
	Items() int
	Stats() string
}

// headerPack is a batch of block headers returned by a peer.
type headerPack struct {
	peerId  string
	headers []*types.Header
}

func (p *headerPack) PeerId() string { return p.peerId }
func (p *headerPack) Items() int     { return len(p.headers) }
func (p *headerPack) Stats() string  { return fmt.Sprintf("%d", len(p.headers)) }

// bodyPack is a batch of block bodies returned by a peer.
type bodyPack struct {
	peerId       string
	transactions [][]*types.Transaction
	uncles       [][]*types.Header
}

func (p *bodyPack) PeerId() string { return p.peerId }
func (p *bodyPack) Items() int {
	if len(p.transactions) <= len(p.uncles) {
		return len(p.transactions)
	}
	return len(p.uncles)
}
func (p *bodyPack) Stats() string { return fmt.Sprintf("%d:%d", len(p.transactions), len(p.uncles)) }

// receiptPack is a batch of receipts returned by a peer.
type receiptPack struct {
	peerId   string
	receipts [][]*types.Receipt
}

func (p *receiptPack) PeerId() string { return p.peerId }
func (p *receiptPack) Items() int     { return len(p.receipts) }
func (p *receiptPack) Stats() string  { return fmt.Sprintf("%d", len(p.receipts)) }

// statePack is a batch of states returned by a peer.
type statePack struct {
	peerId string
	states [][]byte
}

func (p *statePack) PeerId() string { return p.peerId }
func (p *statePack) Items() int     { return len(p.states) }
func (p *statePack) Stats() string  { return fmt.Sprintf("%d", len(p.states)) }
