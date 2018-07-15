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
	"math/big"
	"strconv"
	"math/rand"
    "fmt"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/consensus"
	//"github.com/hpb-project/go-hpb/blockchain/types"

	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus/snapshots"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/network/p2p"
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
	//var (
	// header  *types.Header
	// latestCadCheckPointHash common.Hash
	//)
	
	/*
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
	*/
	//number = uint64(0)
	//header = chain.GetHeaderByNumber(number)
	//latestCadCheckPointHash = header.Hash()
	
	//log.Info("Prometheus： 0x0846911b8271e737c976ae5dd869e1d8fa389958cac48595f9914054a354e05f", "number", number, "hash", latestCadCheckPointHash)
	
	//if cadNodeSnap, err := snapshots.LoadCadNodeSnap(db, latestCadCheckPointHash); err == nil {
	//	log.Info("Prometheus： Loaded voting comNodeSnap form disk", "number", number, "hash", latestCadCheckPointHash)
	//	return cadNodeSnap,nil
	//} else {
	//	log.Error("read failed:", err)
		
		if cadNodeSnap, err1 := CalcuCadNodeSnap(db,number, hash); err1 == nil {
			return cadNodeSnap,nil
		}
	//}
	return nil,nil
}

// Get snap in community by elections,
func CalcuCadNodeSnap(db hpbdb.Database, number uint64, hash common.Hash) (*snapshots.CadNodeSnap, error) {

		
		cadWinners := []snapshots.CadWinner{} 
		
		//cadNodeMap,_ := GetHpbNodeSnap(db,chain,number, hash)
		// all nodes = Candidate node + HPB node
		peers := p2p.PeerMgrInst().PeersAll()
		
		fmt.Println("######### peers length is:", len(peers))
		
		for _, peer := range peers {
			fmt.Println("this is Address:", peer.Address())
			fmt.Println("this is TxsRate:", peer.TxsRate())
			fmt.Println("this is Bandwidth:", peer.Bandwidth())
			networkBandwidth := float64(peer.Bandwidth()) * float64(0.3)
			transactionNum := float64(peer.TxsRate()) * float64(0.7)
			VoteIndex := networkBandwidth + transactionNum
			fmt.Println("VoteIndex:", strconv.FormatFloat(VoteIndex, 'g', 1, 64))
		}
				
		// 模拟从peer中获取
		for i := 0; i < 9; i++ {
			//加权算法
			networkBandwidth := float64(rand.Intn(1000)) * float64(0.3)
			transactionNum := float64(rand.Intn(1000)) * float64(0.7)
			VoteIndex := networkBandwidth + transactionNum
			strnum := strconv.Itoa(i)
			//在候选列表中获取，如果候选列表中含有，在进行加入
			//if cad,exists := cadNodeMap[string(i)]; exists == true{
			bigaddr, _ := new(big.Int).SetString("d3b686a79f4da9a415c34ef95926719bb8dfcaf"+strnum, 16)
		    address := common.BigToAddress(bigaddr)
			//if ok, _ := Contain(address, hpbAddresses); !ok {
			cadWinners = append(cadWinners,snapshots.CadWinner{"192.168.2."+strnum,address,uint64(VoteIndex)})
			//}
		}
		
		cadNodeSnap := snapshots.NewCadNodeSnap(number,hash,cadWinners)

        log.Info("get Com form outside************************************", cadNodeSnap.CadWinners[0].Address)
		
		// 存储到数据库中
		if err := cadNodeSnap.Store(db); err != nil {
				log.Error("Stored Error")
				return nil, err
		}
		log.Trace("Stored genesis voting CadNodeSnap to disk")
		
		return cadNodeSnap,nil
}