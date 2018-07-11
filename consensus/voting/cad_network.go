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
	"math"
	//"strconv"
	"math/rand"
    "fmt"
    "reflect"
    "errors"
    
	//"github.com/hpb-project/go-hpb/common"
	//"github.com/hpb-project/go-hpb/consensus"
   // "math/big"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	//"github.com/hpb-project/go-hpb/blockchain/storage"
	//"github.com/hpb-project/go-hpb/network/p2p"
)


// 从网络中获取最优化的
func GetBestCadNodeFromNetwork(snap *snapshots.HpbNodeSnap,csnap *snapshots.CadNodeSnap) (*snapshots.CadWinner, error) {
		//str := strconv.FormatUint(number, 10)
		// 模拟从外部获取		
		//type CadWinners []*snapshots.CadWinner
		bestCadWinners := []*snapshots.CadWinner{} 
		
		hpbAddresses := snap.GetHpbNodes()
		cadWinners := csnap.CadWinners		
		
		for _, cadWinner := range cadWinners {
			if ok, _ := Contain(cadWinner.Address, hpbAddresses); !ok {
				bestCadWinners = append(bestCadWinners,&snapshots.CadWinner{cadWinner.NetworkId,cadWinner.Address,cadWinner.VoteIndex})
			}
		}
		
		// 先获取长度，然后进行随机获取
		lnlen := int(math.Log2(float64(len(bestCadWinners))))
		
		var lastCadWinners []*snapshots.CadWinner
		
		for i := 0 ; i < lnlen; i++{
			lastCadWinners = append(lastCadWinners,bestCadWinners[rand.Intn(len(bestCadWinners)-1)])
		}
		
		//开始进行排序获取最大值
		//bigaddr, _ := new(big.Int).SetString("d3b686a79f4da9a415c34ef95926719bb8dfcafd", 16)
		//address := common.BigToAddress(bigaddr)
		//lastCadWinnerToChain := &snapshots.CadWinner{"192.168.2.33",address,uint64(0)}
		
		var lastCadWinnerToChain *snapshots.CadWinner
		voteIndexTemp := uint64(0)
		
		for _, lastCadWinner := range lastCadWinners {
	        if(lastCadWinner.VoteIndex > voteIndexTemp){
	        	  voteIndexTemp = lastCadWinner.VoteIndex
	        	  lastCadWinnerToChain = lastCadWinner //返回最优的
	        }
	    }
		//fmt.Println("len:", voteIndexTemp)
		fmt.Println("Best VoteIndex:", lastCadWinnerToChain.VoteIndex)
		return lastCadWinnerToChain,nil
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

/*
func GetCadNodeMap(db hpbdb.Database,chain consensus.ChainReader, number uint64, hash common.Hash) (map[string]*snapshots.CadWinner, error) {

	cadWinnerms := make(map[string]*snapshots.CadWinner)

	if cadNodeSnapformap, err  := GetCadNodeSnap(db, chain, number, hash); err == nil{
		for _, cws := range cadNodeSnapformap.CadWinners {
		    cadWinnerms[cws.NetworkId] = &snapshots.CadWinner{cws.NetworkId,cws.Address,cws.VoteIndex}
		}
	}

    return cadWinnerms,nil
}
*/


