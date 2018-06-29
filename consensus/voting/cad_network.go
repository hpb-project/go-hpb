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
	"strconv"
	"math/rand"
    "fmt"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/consensus"
   // "math/big"
	"github.com/hpb-project/ghpb/consensus/snapshots"
	"github.com/hpb-project/ghpb/storage"
)


// 从网络中获取最优化的
func GetBestCadNodeFromNetwork(db hpbdb.Database, chain consensus.ChainReader, number uint64, hash common.Hash) (*snapshots.CadWinner, error) {
		//str := strconv.FormatUint(number, 10)
		// 模拟从外部获取		
		type CadWinners []*snapshots.CadWinner
		cadWinners := []*snapshots.CadWinner{} 
		
		//cadNodeMap,_ := GetCadNodeMap(db,chain,number, hash)
		
		// 模拟从peer中获取
		for i := 0; i < 1000; i++ {
			//加权算法
			networkBandwidth := float64(rand.Intn(1000)) * float64(0.3)
			transactionNum := float64(rand.Intn(1000)) * float64(0.7)
			VoteIndex := networkBandwidth + transactionNum
			
			strnum := strconv.Itoa(i)
			//cadNodeMap[uint64(VoteIndex)] = &snapshots.CadWinner{"192.168.2"+strnum,"0xd3b686a79f4da9a415c34ef95926719bb8dfcaf"+strnum,uint64(VoteIndex)}
			
			//在候选列表中获取，如果候选列表中含有，在进行加入
			//if _,exists := cadNodeMap["192.168.2"+strnum]; exists == true{
				cadWinners = append(cadWinners,&snapshots.CadWinner{"192.168.2"+strnum,"0xd3b686a79f4da9a415c34ef95926719bb8dfcaf"+strnum,uint64(VoteIndex)})
			//}
		}
		
		// 先获取长度，然后进行随机获取
		lnlen := int(math.Log2(float64(len(cadWinners))))
		
		var lastCadWinners []*snapshots.CadWinner
		
		for i := 0 ; i < lnlen; i++{
			lastCadWinners = append(lastCadWinners,cadWinners[rand.Intn(len(cadWinners)-1)])
		}
		
		//开始进行排序获取最大值
		lastCadWinnerToChain := &snapshots.CadWinner{"192.168.2.33","0xd3b686a79f4da9a415c34ef95926719bb8dfcafd",uint64(0)}
		voteIndexTemp := uint64(0)
		
		
		for _, lastCadWinner := range lastCadWinners {
	        if(lastCadWinner.VoteIndex > voteIndexTemp){
	        	  voteIndexTemp = lastCadWinner.VoteIndex
	        	  lastCadWinnerToChain = lastCadWinner //返回最优的
	        }
	    }
		
		//fmt.Println("len:", voteIndexTemp)
		fmt.Println("len:", lastCadWinnerToChain.VoteIndex)
		return lastCadWinnerToChain,nil
}

func GetCadNodeMap(db hpbdb.Database,chain consensus.ChainReader, number uint64, hash common.Hash) (map[string]*snapshots.CadWinner, error) {

	cadNodeSnapformap,_  := GetCadNodeSnap(db, chain, number, hash)
	
	cadWinnerms := make(map[string]*snapshots.CadWinner)
	
	for _, cws := range cadNodeSnapformap.CadWinners {
	    cadWinnerms[cws.NetworkId] = &snapshots.CadWinner{cws.NetworkId,cws.Address,cws.VoteIndex}
	}

    return cadWinnerms,nil
}


