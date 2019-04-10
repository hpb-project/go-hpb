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

package voting

import (
	//"math"
	//"strconv"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	//"github.com/hpb-project/go-hpb/common"
	//"github.com/hpb-project/go-hpb/consensus"
	// "math/big"
	"github.com/hpb-project/go-hpb/consensus/snapshots"

	"bytes"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math/rand"
)

// 从网络中获取最优化的
func GetCadNodeFromNetwork(random []byte, rankingdata map[common.Address]float64) ([]*snapshots.CadWinner, []byte, error) {

	bestCadWinners := []*snapshots.CadWinner{}
	peerp2ps := p2p.PeerMgrInst().PeersAll()
	fmt.Println("######### peers length is:", len(peerp2ps))
	peers := make([]*p2p.Peer, 0, len(peerp2ps))

	for i := 0; i < len(peerp2ps); i++ {
		_, ok := rankingdata[peerp2ps[i].Address()]
		if peerp2ps[i].RemoteType() != discover.BootNode && peerp2ps[i].RemoteType() != discover.SynNode && ok {
			peers = append(peers, peerp2ps[i])
		}
	}

	//order the hpsmaptemp by put it into []common.address
	delhpsmap := make(common.Addresses, 0, len(rankingdata))
	selectres := make(common.Addresses, 0, consensus.NumberPrehp)
	for key, _ := range rankingdata {
		delhpsmap = append(delhpsmap, key)
	}
	//sort.Sort(delhpsmap)
	//sort by addr
	if 1 < len(delhpsmap) {
		for i := 0; i < len(delhpsmap); i++ {
			for j := 0; j < len(delhpsmap)-i-1; j++ {
				if bytes.Compare(delhpsmap[j][:], delhpsmap[j+1][:]) > 0 {
					delhpsmap[j], delhpsmap[j+1] = delhpsmap[j+1], delhpsmap[j]
				}
			}
		}
	}

	//sort by ranking
	for i := 0; i < len(delhpsmap); i++ {
		for j := 0; j < len(delhpsmap)-i-1; j++ {
			if rankingdata[delhpsmap[j]] > rankingdata[delhpsmap[j+1]] {
				delhpsmap[j], delhpsmap[j+1] = delhpsmap[j+1], delhpsmap[j]
			}
		}
	}

	for i := 0; i < len(delhpsmap); i++ {
		log.Trace(">>>>>>>>>>>>>order by there element<<<<<<<<<<<<<<<", "addr", delhpsmap[i], "ranking value", rankingdata[delhpsmap[i]])
	}

	input := random
	for i := 0; i < consensus.NumberPrehp; i++ {
		err, output := snapshots.GenRand(input)
		if nil != err {
			return nil, nil, err
		}
		tempbigint := new(big.Int).SetBytes(output)
		random := tempbigint.Uint64()
		offset := int(random % uint64(len(delhpsmap)))
		input = output
		log.Debug("qwer randsethp rand selectable offset", "value", offset, "out", common.Bytes2Hex(output))
		selectres = append(selectres, delhpsmap[offset])
		if 0 < offset && 1 < len(delhpsmap) {
			for j := offset - 1; j >= 0; j-- {
				delhpsmap[j+1] = delhpsmap[j]
			}
		}

		if 1 < len(delhpsmap) {
			delhpsmap = delhpsmap[1:]
		}
		if 1 == len(delhpsmap) {
			selectres = append(selectres, delhpsmap[0])
			break
		}
	}
	delhpsmap = selectres

	//sort by addr
	if 1 < len(delhpsmap) {
		for i := 0; i < len(delhpsmap); i++ {
			for j := 0; j < len(delhpsmap)-i-1; j++ {
				if bytes.Compare(delhpsmap[j][:], delhpsmap[j+1][:]) > 0 {
					delhpsmap[j], delhpsmap[j+1] = delhpsmap[j+1], delhpsmap[j]
				}
			}
		}
		//sort by ranking
		for i := 0; i < len(delhpsmap); i++ {
			for j := 0; j < len(delhpsmap)-i-1; j++ {
				if rankingdata[delhpsmap[j]] > rankingdata[delhpsmap[j+1]] {
					delhpsmap[j], delhpsmap[j+1] = delhpsmap[j+1], delhpsmap[j]
				}
			}
		}
	}
	for i := 0; i < len(delhpsmap); i++ {
		bestCadWinners = append(bestCadWinners, &snapshots.CadWinner{NetworkId: "", Address: delhpsmap[i], VoteIndex: uint64(rankingdata[delhpsmap[i]] * 100)})
		log.Debug("bestCadWinners info", "addr", delhpsmap[i], "ranking", uint64(rankingdata[delhpsmap[i]]))
	}

	if len(bestCadWinners) == 0 {
		return nil, nil, nil
	}

	//log.Error("-------------best cad winner--------------", "addr", bestCadWinners[0], "selectres len", len(delhpsmap))
	winners := make([]*snapshots.CadWinner, 0, 2)
	winners = append(winners, bestCadWinners[0]) //返回最优的
	if len(peers) > 0 {
		temp := rand.Intn(len(peers))
		addr1 := peers[temp].Address()
		addr2 := peers[(temp+1)%len(peers)].Address()
		if bytes.Compare(bestCadWinners[0].Address[:], addr1[:]) != 0 {
			winners = append(winners, &snapshots.CadWinner{NetworkId: "", Address: addr1, VoteIndex: uint64(rankingdata[addr1])})
		} else {
			winners = append(winners, &snapshots.CadWinner{NetworkId: "", Address: addr2, VoteIndex: uint64(rankingdata[addr2])})
		}
	} else {
		winners = append(winners, bestCadWinners[1:][rand.Intn(len(bestCadWinners)-1)]) //返回随机
	}

	var resbandwith [2]byte
	for _, peer := range peers {
		if peer.Address() == winners[0].Address {
			//test---------------------------------
			//log.Error("--------winners[0]---------- get bandwith", "id", peer.GetID(), "vaule", peer.Bandwidth()/ (1024 * 8))

			//var bigbandwith *big.Int
			if peer.Bandwidth()/(1024*8) > consensus.BandwithLimit {
				//resbandwith[0] = consensus.BandwithLimit
				resbandwith[0] = byte(rand.Intn(consensus.BandwithLimit)) //for test
			} else {
				resbandwith[0] = byte(peer.Bandwidth() / (1024 * 8))
			}
		}
		if peer.Address() == winners[1].Address {
			//test---------------------------------
			//log.Error("---------winners[1]----------- get bandwith", "id", peer.GetID(), "vaule", peer.Bandwidth()/ (1024 * 8))

			if peer.Bandwidth()/(1024*8) > consensus.BandwithLimit {
				//resbandwith[1] = consensus.BandwithLimit
				resbandwith[1] = byte(rand.Intn(consensus.BandwithLimit)) //for test
			} else {
				resbandwith[1] = byte(peer.Bandwidth() / (1024 * 8))
			}
		}
	}
	return winners, resbandwith[:], nil
}

func Contain(obj interface{}, target interface{}) (bool, error) {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true, nil
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true, nil
		}
	}

	return false, errors.New("not in array")
}
