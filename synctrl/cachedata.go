package synctrl

import (
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
//	"github.com/hpb-project/go-hpb/common/compress"
	"github.com/hpb-project/go-hpb/common/log"
//	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/network/p2p"
	"math/big"
	"sync"
	"time"
)

const interval = 5
const maxCacheBlocksLen = 10000
const maxCacheBlockSize = 3 * 1024 * 1024

//var waitSendMap = make(map[string]CachePeerOfBlocks)

var waitSendMap = CacheMap{
	m:    make(map[string]*CachePeerOfBlocks),
	lock: new(sync.RWMutex),
}

type CacheMap struct {
	m    map[string]*CachePeerOfBlocks
	lock *sync.RWMutex
}

func (this *CacheMap) Put(key string, value *CachePeerOfBlocks) {
	this.lock.Lock()
	defer this.lock.Unlock()
	this.m[key] = value
}

func (this *CacheMap) Delete(key string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	delete(this.m, key)
}

func (this *CacheMap) Get(key string) (*CachePeerOfBlocks, bool) {
	this.lock.RLock()
	defer this.lock.RUnlock()
	if val, ok := this.m[key]; ok {
		return val, ok
	}
	return nil, false
}

// 并发状态需要在持锁时使用
func (this *CacheMap) Clear() {
	this.m = make(map[string]*CachePeerOfBlocks)
}

func init() {
	ticker1 := time.NewTicker(interval * time.Second)
	go func(t *time.Ticker) {
		for {
			<-t.C
			log.Debug("loop waitSendMap", "txcache map size:", len(waitSendMap.m))
			//	fmt.Println("loop waitSendMap", time.Now().Format("2006-01-02 15:04:05"), "map size:", len(waitSendMap))
			waitSendMap.lock.Lock()
			for _, e := range waitSendMap.m {
				//e.sendDataTxs()
				log.Debug("send condition in ticker", "peer", e.Peer.RemoteAddr().String())
			}
			waitSendMap.Clear()
			waitSendMap.lock.Unlock()
		}
	}(ticker1)
}

type CacheStatus struct {
	LastSendTime int64
	LastMsgLen   int
	LastMsgSize  int
}

type CachePeerOfBlocks struct {
	Peer     *p2p.Peer
	BlockTds []*BlockTd
	HashNums []HashNum
	Txs      types.Transactions
	Status   CacheStatus
}

type BlockTd struct {
	Block *types.Block
	Td    *big.Int
}

type HashNum struct {
	Hashes  []common.Hash
	Numbers []uint64
}

//func CacheSendDataTransactions(peer *p2p.Peer, txs types.Transactions) {
//	len, size := 0, 0
//	for _, tx := range txs {
//		peer.KnownTxsAdd(tx.Hash())
//		len++
//		size += tx.GetDataSize()
//	}
//	if cache, ok := waitSendMap.Get(peer.GetID()); ok {
//		cache.Status.LastMsgLen += len
//		cache.Status.LastMsgSize += size
//		cache.Txs = cache.Txs.Append(txs)
//		if cache.isNeedSend() {
//			cache.sendDataTxs()
//			waitSendMap.Delete(cache.Peer.GetID())
//		}
//	} else {
//		c := &CachePeerOfBlocks{
//			Peer: peer,
//			Txs:  txs,
//			Status: CacheStatus{
//				LastSendTime: time.Now().Unix(),
//				LastMsgLen:   len,
//				LastMsgSize:  size,
//			},
//		}
//		waitSendMap.Put(peer.GetID(), c)
//	}
//}
//
//func (cache *CachePeerOfBlocks) isNeedSend() bool {
//	if cache.Status.LastMsgSize > maxCacheBlockSize ||
//		cache.Status.LastMsgLen > maxCacheBlocksLen {
//		//||cache.Status.LastSendTime + interval < time.Now().Unix()
//		log.Debug("send condition", "lastMsgSize", cache.Status.LastMsgSize, "lastMsgLen", cache.Status.LastMsgLen, "lastSendTime", cache.Status.LastSendTime, "nowTime", time.Now().Unix())
//		return true
//	}
//	return false
//}
//
//func (cache *CachePeerOfBlocks) sendDataTxs() {
//	log.Debug("tx number", "", cache.Peer.RemoteAddr(), "", cache.Txs.Len())
//	size, reader, err := rlp.EncodeToReader(cache.Txs)
//
//	if err != nil {
//		return
//	}
//	p := make([]byte, size)
//	n, err := reader.Read(p)
//	if n > 0 {
//		p = p[:n]
//	}
//	result, err := compress.ZlibCompress(p, compress.BestCompression)
//	if err != nil {
//		log.Error("zlib compress error", "", err)
//		return
//	}
//	err = p2p.SendData(cache.Peer, p2p.CompressTxMsg, []interface{}{&result})
//	if err != nil {
//		log.Error("send data to peer error", "", err)
//		return
//	}
//	cache.Status.LastSendTime = time.Now().Unix()
//}

/*func CacheSendDataBlockTd(peer *p2p.Peer, block *types.Block, td *big.Int){
	size, _, err := rlp.EncodeToReader(block)
	if err != nil {
		return
	}
	blockTd := &BlockTd{
		Block:block,
		Td:td,
	}
	if cache, ok := waitSendMap[peer.GetID()]; ok {
		cache.BlockTds = append(cache.BlockTds, blockTd)
		cache.Status.LastMsgLen += 1
		cache.Status.LastMsgSize += size
		if cache.isNeedSend() {
			cache.sendData()
		}
	}else{
		waitSendMap[peer.GetID()] = CachePeerOfBlocks{
			Peer:peer,
			BlockTds:[]*BlockTd{blockTd},
			Status: CacheStatus {
				LastSendTime:time.Now().Unix(),
				LastMsgLen:1,
				LastMsgSize:size,
			},
		}
	}
	peer.KnownBlockAdd(block.Hash())
}
*/

/*func CacheSendDataHashNum(peer *p2p.Peer, hashes []common.Hash, numbers []uint64){
	for _, hash := range hashes {
		peer.KnownBlockAdd(hash)
	}
	hashNum := HashNum{
		Hashes:hashes,
		Numbers:numbers,
	}
	size, _, err := rlp.EncodeToReader(hashNum)
	if err != nil {
		return
	}
	if cache, ok := waitSendMap[peer.GetID()]; ok {
		cache.HashNums = append(cache.HashNums, hashNum)
		cache.Status.LastMsgLen += 1
		cache.Status.LastMsgSize += size
		if cache.isNeedSend() {
			cache.sendData()
		}
	}else{
		waitSendMap[peer.GetID()] = CachePeerOfBlocks{
			Peer:peer,
			HashNums:[]HashNum{hashNum},
			Status: CacheStatus {
				LastSendTime:time.Now().Unix(),
				LastMsgLen:1,
				LastMsgSize:size,
			},
		}
	}
}*/

/*func (cache CachePeerOfBlocks)sendData(){
	size, reader, err := rlp.EncodeToReader(cache.BlockTds)
	if err != nil {
		return
	}
	p := make([]byte, size)
	n, err := reader.Read(p)
	if n > 0 {
		p =  p[:n]
	}
	result, err := compress.ZlibCompress(p, compress.BestCompression)
	if err != nil {
		return
	}
	p2p.SendData(cache.Peer, p2p.CompressBlockHashMsg, []interface{}{result})
	delete(waitSendMap, cache.Peer.GetID())
}*/
