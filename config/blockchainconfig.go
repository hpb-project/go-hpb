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

package config

import (
	"fmt"
	"math/big"
	"time"

	"github.com/hpb-project/go-hpb/common"
)

var (
	MainnetGenesisHash = common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3") // Mainnet genesis hash to enforce below configs on
	TestnetGenesisHash = common.HexToHash("0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d") // Testnet genesis hash to enforce below configs on
)

// MainnetChainConfig is the chain parameters to run a node on the main network.
var MainnetChainConfig = &ChainConfig{
	ChainId: big.NewInt(1),
	Prometheus: &PrometheusConfig{
		Period: 3,
		Epoch:  30000,
	},
}

//同步控制逻辑参数
const (
	forceSyncCycle = 10 * time.Second //区块同步周期时间
	txChanSize     = 20000            //接收交易事件缓冲，等待广播
	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024 // 一般情况下状态包的大小，为了减小发送次数
)

//同步peer的记忆配置
const (
	//记忆peer的最大交易数量
	maxKnownTxs    = 1000000 // Maximum transactions hashes to keep in the known list (prevent DOS) //记忆peer的最大区块数量
	maxKnownBlocks = 100000  // Maximum block hashes to keep in the known list (prevent DOS)
)

//同步对peer的配置
const (
	//同步的peer最大允许缺少hash项
	maxLackingHashes = 4096 // Maximum number of entries allowed on the list or lacking items
	//计算吞吐量的一个参数
	measurementImpact = 0.1 // The impact a single measurement has on a peer's final throughput value.
)

//同步任务队列最大缓冲区块数
var blockCacheLimit = 8192 // Maximum number of blocks to cache before throttling the download

//拉取的一些参数配置
const (
	//拉取区块超时时间
	arriveTimeout = 500 * time.Millisecond // Time allowance before an announced block is explicitly requested
	gatherSlack   = 100 * time.Millisecond // Interval used to collate almost-expired announces with fetches
	fetchTimeout  = 5 * time.Second        // Maximum allotted time to return an explicitly requested block
	maxUncleDist  = 7                      // Maximum allowed backward distance from the chain head
	maxQueueDist  = 32                     // Maximum allowed distance from the chain head to queue
	hashLimit     = 256                    // Maximum number of unique blocks a peer may have announced
	blockLimit    = 64                     // Maximum number of unique blocks a peer may have delivered
)

//同步器配置参数
var (
	MaxHashFetch    = 512 // Amount of hashes to be fetched per retrieval request
	MaxBlockFetch   = 128 // Amount of blocks to be fetched per retrieval request
	MaxHeaderFetch  = 192 // Amount of block headers to be fetched per retrieval request
	MaxSkeletonSize = 128 // Number of header fetches to need for a skeleton assembly
	MaxBodyFetch    = 128 // Amount of block bodies to be fetched per retrieval request
	MaxReceiptFetch = 256 // Amount of transaction receipts to allow fetching per request
	MaxStateFetch   = 384 // Amount of node state values to allow fetching per request

	MaxForkAncestry  = 3 * EpochDuration // Maximum chain reorganisation
	rttMinEstimate   = 2 * time.Second   // Minimum round-trip time to target for sync requests
	rttMaxEstimate   = 20 * time.Second  // Maximum rount-trip time to target for sync requests
	rttMinConfidence = 0.1               // Worse confidence factor in our estimated RTT value
	ttlScaling       = 3                 // Constant scaling factor for RTT -> TTL conversion
	ttlLimit         = time.Minute       // Maximum TTL allowance to prevent reaching crazy timeouts

	qosTuningPeers   = 5    // Number of peers to tune based on (best peers)
	qosConfidenceCap = 10   // Number of peers above which not to modify RTT confidence
	qosTuningImpact  = 0.25 // Impact that a new tuning target has on the previous value

	maxQueuedHeaders  = 32 * 1024 // Maximum number of headers to queue for import (DOS protection)
	maxHeadersProcess = 2048      // Number of header sync results to import at once into the chain
	maxResultsProcess = 2048      // Number of content sync results to import at once into the chain

	fsHeaderCheckFrequency = 100        // Verification frequency of the sync headers during fast sync
	fsHeaderSafetyNet      = 2048       // Number of headers to discard in case a chain violation is detected
	fsHeaderForceVerify    = 24         // Number of headers to verify before and after the pivot to accept it
	fsPivotInterval        = 256        // Number of headers out of which to randomize the pivot point
	fsMinFullBlocks        = 64         // Number of blocks to retrieve fully even in fast sync
	fsCriticalTrials       = uint32(32) // Number of times to retry in the cricical section before bailing
)

//可兼容的ChainID : 除了当前ChainId 还能兼容的另外的ChainId
var (
	CompatibleChainId = big.NewInt(269)
)

type ChainConfig struct {
	ChainId    *big.Int          `json:"chainId"` // Chain id identifies the current chain and is used for replay protection
	Prometheus *PrometheusConfig `json:"prometheus"`
}

var DefaultBlockChainConfig = ChainConfig{
	ChainId:    MainnetChainConfig.ChainId,
	Prometheus: &DefaultPrometheusConfig,
}

var (
	GasLimitBoundDivisor   = big.NewInt(1024)                  // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit            = big.NewInt(5000)                  // Minimum the gas limit may ever be.
	GenesisGasLimit        = big.NewInt(100000000)             // Gas limit of the Genesis block. //for testnet
	TargetGasLimit         = new(big.Int).Set(GenesisGasLimit) // The artificial target
	DifficultyBoundDivisor = big.NewInt(2048)                  // The bound divisor of the difficulty, used in the update calculations.
	GenesisDifficulty      = big.NewInt(131072)                // Difficulty of the Genesis block.
	MinimumDifficulty      = big.NewInt(131072)                // The minimum that the difficulty may ever be.
	DurationLimit          = big.NewInt(13)                    // The decision boundary on the blocktime duration used to determine whether difficulty should go up or not.
)

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64) *ConfigCompatError {
	bhead := new(big.Int).SetUint64(height)

	// Iterate checkCompatible to find the lowest conflict.
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead)
		if err == nil || (lasterr != nil && err.RewindTo == lasterr.RewindTo) {
			break
		}
		lasterr = err
		bhead.SetUint64(err.RewindTo)
	}
	return lasterr
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, head *big.Int) *ConfigCompatError {
	return nil
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string
	// block numbers of the stored and new configurations
	StoredConfig, NewConfig *big.Int
	// the block number to which the local chain must be rewound to correct the error
	RewindTo uint64
}

// GasTable returns the gas table corresponding to the current phase (homestead or homestead reprice).
//
// The returned GasTable's fields shouldn't, under any circumstances, be changed.
func (c *ChainConfig) GasTable(num *big.Int) GasTable {
	return GasTableEIP158
}

// String implements the fmt.Stringer interface.
func (c *ChainConfig) String() string {
	return fmt.Sprintf("{ChainID: %v Engine: %v}",
		c.ChainId,
		"Prometheus",
	)
}

func (err *ConfigCompatError) Error() string {
	return fmt.Sprintf("mismatching %s in database (have %d, want %d, rewindto %d)", err.What, err.StoredConfig, err.NewConfig, err.RewindTo)
}
