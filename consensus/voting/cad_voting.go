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
	//"math/rand"
   // "fmt"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core/types"

	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/consensus/snapshots"
	"github.com/hpb-project/ghpb/storage"
)

const (
	checkpointInterval   = 1024 // 投票间隔
	inmemoryHistorysnaps = 128  // 内存中的快照个数
	inmemorySignatures   = 4096 // 内存中的签名个数
	comCheckpointInterval   = 2 // 社区投票间隔
	cadCheckpointInterval   = 2 // 社区投票间隔
)

// 获取候选选举的快照
func GetCadNodeSnap(db hpbdb.Database,chain consensus.ChainReader, number uint64, hash common.Hash) (*snapshots.CadNodeSnap, error) {
	
	//业务逻辑
	var (
	 header  *types.Header
	 latestCadCheckPointHash common.Hash
	)
	
	// 进来的请求恰好在投票检查点，此时重新计票
	log.Error("current number:",strconv.FormatUint(number, 10))
	if number%cadCheckpointInterval == 0 {
		if cadNodeSnap, err0 := CalcuCadNodeSnap(db,number, hash); err0 == nil {
			return cadNodeSnap,nil
		}
	}
	
	//不在投票点开始获取数据库中的内容
	
	latestCheckPointNumber :=  uint64(math.Floor(float64(number/comCheckpointInterval)))*comCheckpointInterval
	log.Error("current latestCheckPointNumber:",strconv.FormatUint(latestCheckPointNumber, 10))

	header = chain.GetHeaderByNumber(uint64(latestCheckPointNumber))
	latestCadCheckPointHash = header.Hash()
	
	if cadNodeSnap, err := snapshots.LoadCadNodeSnap(db, latestCadCheckPointHash); err == nil {
		log.Info("Prometheus： Loaded voting comNodeSnap form disk", "number", number, "hash", hash)
		return cadNodeSnap,nil
	} else { //数据库中没有正常的获取，再次去统计
		if cadNodeSnap, err1 := CalcuCadNodeSnap(db,number, hash); err1 == nil {
			return cadNodeSnap,nil
		}
	}
	return nil,nil
}

// Get snap in community by elections,
func CalcuCadNodeSnap(db hpbdb.Database, number uint64, hash common.Hash) (*snapshots.CadNodeSnap, error) {

		//开始读取智能合约
		// 
		//
		//str := strconv.FormatUint(number, 10)
		// 模拟从外部获取		
		//type CadWinners []*snapshots.CadWinner
		//w1 := &snapshots.CadWinner{"192.168.2.14","0xfa7b9770ca4cb04296cac84f37736d4041251cdf",uint64(10)}
		//w2 := &snapshots.CadWinner{"192.168.2.12","0x058fee5c36a11fc9be56b2a5b2c40372c983c4a2",uint64(10)}
		//w3 := &snapshots.CadWinner{"192.168.2.33","0xd3b686a79f4da9a415c34ef95926719bb8dfcafd",uint64(10)}
		
		//cadWinners := CadWinners([]*snapshots.CadWinner{w1, w2, w3}) 
		//cadWinners := []*snapshots.CadWinner{} 
		//var cadWinners [10]*snapshots.CadWinner{} 
		//从peers中获取
		// 模拟从peer中获取
		
		//cadWinners := make([]*snapshots.CadWinner,10)
		
		
		/* 使用 make 函数 */
		//CadWinnerMap := make(map[uint64]*snapshots.CadWinner)
		
		// 模拟从peer中获取
		/*
		for i := 0; i < 10; i++ {
			
			//加权算法
			networkBandwidth := float64(rand.Intn(1000)) * float64(0.3)
			transactionNum := float64(rand.Intn(1000)) * float64(0.7)
			VoteIndex := networkBandwidth + transactionNum
			
			strnum := strconv.Itoa(i)
			//CadWinnerMap[uint64(VoteIndex)] = &snapshots.CadWinner{"192.168.2"+strnum,"0xd3b686a79f4da9a415c34ef95926719bb8dfcaf"+strnum,uint64(VoteIndex)}
		    cadWinners = append(cadWinners,&snapshots.CadWinner{"192.168.2"+strnum,"0xd3b686a79f4da9a415c34ef95926719bb8dfcaf"+strnum,VoteIndex})
		}
		*/
		/*
		// 先获取长度，然后进行随机获取
		lnlen := int(math.Log2(float64(len(cadWinners))))
		
		var lastCadWinners []*snapshots.CadWinner
		
		for i := 0 ; i < lnlen; i++{
			lastCadWinners = append(lastCadWinners,cadWinners[rand.Intn(len(cadWinners)-1)])
		}
		
		//fmt.Println("len:", len(lastCadWinners))
		
		//开始进行排序获取最大值
		lastCadWinnerToChain := &snapshots.CadWinner{"192.168.2.33","0xd3b686a79f4da9a415c34ef95926719bb8dfcafd",float64(10)}
		voteIndexTemp := float64(0)
		
		for _, lastCadWinner := range lastCadWinners {
	        if(lastCadWinner.VoteIndex > voteIndexTemp){
	        	  voteIndexTemp = lastCadWinner.VoteIndex
	        	  lastCadWinnerToChain = lastCadWinner
	        }
	    }
		
		fmt.Println("len:", voteIndexTemp)
		fmt.Println("len:", lastCadWinnerToChain.VoteIndex)

		cadNodeSnap := snapshots.NewCadNodeSnap(number,hash,cadWinners)

        log.Info("get Com form outside************************************", cadNodeSnap.CadWinners[0].Address)
		
		// 存储到数据库中
		if err := cadNodeSnap.Store(db); err != nil {
				log.Error("Stored Error")
				return nil, err
		}
		log.Trace("Stored genesis voting CadNodeSnap to disk")
		*/
		//return cadNodeSnap,nil
		return nil,nil
}