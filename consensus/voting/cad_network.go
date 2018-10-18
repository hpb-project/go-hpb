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
	"math/rand"
	"reflect"

	//"github.com/hpb-project/go-hpb/common"
	//"github.com/hpb-project/go-hpb/consensus"
	// "math/big"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	//"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math"
)

// 从网络中获取最优化的
func GetCadNodeFromNetwork(state *state.StateDB, voteres map[common.Address]big.Int) ([]*snapshots.CadWinner, []byte, error) {

	bigaddr, _ := new(big.Int).SetString("0000000000000000000000000000000000000000", 16)
	address := common.BigToAddress(bigaddr)

	bestCadWinners := []*snapshots.CadWinner{}
	peers := p2p.PeerMgrInst().PeersAll()
	fmt.Println("######### peers length is:", len(peers))
	if len(peers) == 0 {
		return nil, nil, nil
	}

	for _, peer := range peers {

		if peer.RemoteType() != discover.BootNode && peer.RemoteType() != discover.SynNode {
			if len(peer.Address()) == 0 || peer.Address() == address {
				continue
			}
			//transactionNum := peer.TxsRate() * float64(0.6)
			//TODO: modify power for hp node -----------------done
			networkBandwidth := peer.Bandwidth() * float64(0.5) //from 0.9 -0.5
			//log.Error("GetCadNodeFromNetwork print peer addr", "addr", peer.Address().Str())
			bigval := new(big.Float).SetInt(state.GetBalance(peer.Address()))

			onether2weis := big.NewInt(10)
			onether2weis.Exp(onether2weis, big.NewInt(18), nil)
			onether2weisf := new(big.Float).SetInt(onether2weis)
			bigval.Quo(bigval, onether2weisf)

			val64, _ := bigval.Float64()
			balanceIndex := val64 * float64(0.1)

			var vote float64
			if nil != voteres {
				tempvote, ok := voteres[peer.Address()]
				if !ok {
					continue
				}
				vote = float64(tempvote.Uint64()) * float64(0.4)
			} else {
				vote = 0
			}

			VoteIndex := networkBandwidth + balanceIndex + vote

			if peer.Address() != address {
				bestCadWinners = append(bestCadWinners, &snapshots.CadWinner{peer.GetID(), peer.Address(), uint64(VoteIndex)})
			}
		}
	}

	if len(bestCadWinners) == 0 {
		return nil, nil, nil
	}

	// 先获取长度，然后进行随机获取
	var lnlen int
	if len(bestCadWinners) > 1 {
		lnlen = int(math.Log2(float64(len(bestCadWinners))))
	} else {
		lnlen = 1
	}

	var lastCadWinners []*snapshots.CadWinner

	for i := 0; i < lnlen; i++ {
		lastCadWinners = append(lastCadWinners, bestCadWinners[rand.Intn(len(bestCadWinners))])
	}

	//开始进行排序获取最大值
	winners := []*snapshots.CadWinner{}
	lastCadWinnerToChain := &snapshots.CadWinner{}
	voteIndexTemp := uint64(0)

	for _, lastCadWinner := range lastCadWinners {
		if lastCadWinner.VoteIndex >= voteIndexTemp {
			voteIndexTemp = lastCadWinner.VoteIndex
			lastCadWinnerToChain = lastCadWinner
		}
	}

	winners = append(winners, lastCadWinnerToChain) //返回最优的

	winners = append(winners, bestCadWinners[rand.Intn(lnlen)]) //返回随机

	for _, peer := range peers {
		if peer.Address() == lastCadWinnerToChain.Address {
			//test---------------------------------
			log.Debug("-------------------------- get bandwith", "id", peer.GetID(), "vaule", peer.Bandwidth())

			var bigbandwith *big.Int
			if peer.Bandwidth() > consensus.BandwithLimit {
				bigbandwith = big.NewInt(consensus.BandwithLimit)
			} else {
				bigbandwith = big.NewInt(int64(peer.Bandwidth()))
				log.Debug("qazwsx set candaddress peer`s bandwith", "big value", bigbandwith, "string value", common.Bytes2Hex(bigbandwith.Bytes()))
			}

			return winners, bigbandwith.Bytes(), nil
		}
	}
	return winners, nil, nil
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
