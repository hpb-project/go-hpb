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

// slice.go implements the CommNode and PreCommNode keep-live Protocol.
package discover

import(
	"fmt"
	"net"
	"sync"
)

type Slice struct {
	mutex   sync.Mutex
	members []*Node
	db      *nodeDB
	net     transport
	self    *Node
}

func (sl *Slice) Self() *Node {
	return sl.self
}

func newSlice (t transport, ourID NodeID, ourRole uint8, ourAddr *net.UDPAddr, nodes []*Node, orgnode *Node, db *nodeDB) (*Slice, error) {
	slice := &Slice{
		net: t,
		db: db,
		self: NewNode(ourID, ourRole, ourAddr.IP, uint16(ourAddr.Port), uint16(ourAddr.Port)),
	}

	if 0 == len(nodes) {
		// TODO by xujl: 传入slice为空，则从orgnode拉取，如果再失败则从本地db加载
		go slice.pullSlice(orgnode)
		slice.loadFromDB(db)
	}

	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return nil, fmt.Errorf("bad slice node %q (%v)", n, err)
		}
		slice.members = append(slice.members, n)
	}

	go slice.keepLiveLoop()

	return slice, nil
}

func (sl *Slice) keepLiveLoop()  {
	for _, n := range sl.members {
		go func(node * Node) {

		} (n)
	}
	
}

func (sl *Slice) loadFromDB(db *nodeDB) {

}

func (sl *Slice) pullSlice(node *Node) {

}