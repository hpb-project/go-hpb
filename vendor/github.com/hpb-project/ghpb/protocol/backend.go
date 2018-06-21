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

// Package eth implements the Hpb protocol.
package hpb

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/common/hexutil"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/consensus/prometheus"

	"github.com/hpb-project/ghpb/common/constant"
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/common/rlp"
	"github.com/hpb-project/ghpb/core"
	"github.com/hpb-project/ghpb/core/bloombits"
	"github.com/hpb-project/ghpb/core/event"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/core/vm"
	"github.com/hpb-project/ghpb/internal/hpbapi"
	"github.com/hpb-project/ghpb/network/p2p"
	"github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/ghpb/node"
	"github.com/hpb-project/ghpb/protocol/downloader"
	"github.com/hpb-project/ghpb/protocol/filters"
	"github.com/hpb-project/ghpb/protocol/gasprice"
	"github.com/hpb-project/ghpb/protocol/miner"
	"github.com/hpb-project/ghpb/storage"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
}

// Hpb implements the Hpb full node service.
type Hpb struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan  chan bool    // Channel for shutting down the hpb
	stopDbUpgrade func() error // stop chain db sequential key upgrade

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb hpbdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	ApiBackend *HpbApiBackend

	miner     *miner.Miner
	gasPrice  *big.Int
	hpberbase common.Address

	networkId     uint64
	netRPCService *hpbapi.PublicNetAPI

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and hpberbase)
}

func (s *Hpb) AddLesServer(ls LesServer) {
	s.lesServer = ls
}

// New creates a new Hpb object (including the
// initialisation of the common Hpb object)
func New(ctx *node.ServiceContext, config *Config) (*Hpb, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run hpb.Hpb in light sync mode, use lhs.LightHpb")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	if err != nil {
		return nil, err
	}
	stopDbUpgrade := upgradeDeduplicateData(chainDb)
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	hpb := &Hpb{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, config, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		stopDbUpgrade:  stopDbUpgrade,
		networkId:      config.NetworkId,
		gasPrice:       config.GasPrice,
		hpberbase:      config.Hpberbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks),
	}

	log.Info("Initialising Hpb protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	if !config.SkipBcVersionCheck {
		bcVersion := core.GetBlockChainVersion(chainDb)
		if bcVersion != core.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run geth upgradedb.\n", bcVersion, core.BlockChainVersion)
		}
		core.WriteBlockChainVersion(chainDb, core.BlockChainVersion)
	}

	vmConfig := vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
	hpb.blockchain, err = core.NewBlockChain(chainDb, hpb.chainConfig, hpb.engine, vmConfig)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		hpb.blockchain.SetHead(compat.RewindTo)
		core.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	hpb.bloomIndexer.Start(hpb.blockchain.CurrentHeader(), hpb.blockchain.SubscribeChainEvent)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	hpb.txPool = core.NewTxPool(config.TxPool, hpb.chainConfig, hpb.blockchain)

	if hpb.protocolManager, err = NewProtocolManager(hpb.chainConfig, config.SyncMode, config.NetworkId, hpb.eventMux, hpb.txPool, hpb.engine, hpb.blockchain, chainDb); err != nil {
		return nil, err
	}
	hpb.miner = miner.New(hpb, hpb.chainConfig, hpb.EventMux(), hpb.engine)
	hpb.miner.SetExtra(makeExtraData(config.ExtraData))

	hpb.ApiBackend = &HpbApiBackend{hpb, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	hpb.ApiBackend.gpo = gasprice.NewOracle(hpb.ApiBackend, gpoParams)

	return hpb, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.ServiceContext, config *Config, name string) (hpbdb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*hpbdb.LDBDatabase); ok {
		db.Meter("hpb/db/chaindata/")
	}
	return db, nil
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Hpb service
func CreateConsensusEngine(ctx *node.ServiceContext, config *Config, chainConfig *params.ChainConfig, db hpbdb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if chainConfig.Prometheus == nil {
		chainConfig.Prometheus = params.MainnetChainConfig.Prometheus
	}
	return prometheus.New(chainConfig.Prometheus, db)
}

// APIs returns the collection of RPC services the hpb package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Hpb) APIs() []rpc.API {
	apis := hpbapi.GetAPIs(s.ApiBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "hpb",
			Version:   "1.0",
			Service:   NewPublicHpbAPI(s),
			Public:    true,
		}, {
			Namespace: "hpb",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "hpb",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Hpb) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Hpb) Hpberbase() (eb common.Address, err error) {
	s.lock.RLock()
	hpberbase := s.hpberbase
	s.lock.RUnlock()

	if hpberbase != (common.Address{}) {
		return hpberbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			return accounts[0].Address, nil
		}
	}
	return common.Address{}, fmt.Errorf("hpberbase address must be explicitly specified")
}

// set in js console via admin interface or wrapper from cli flags
func (self *Hpb) SetHpberbase(hpberbase common.Address) {
	self.lock.Lock()
	self.hpberbase = hpberbase
	self.lock.Unlock()

	self.miner.SetHpberbase(hpberbase)
}

func (s *Hpb) StartMining(local bool) error {
	eb, err := s.Hpberbase()
	if err != nil {
		log.Error("Cannot start mining without hpberbase", "err", err)
		return fmt.Errorf("hpberbase missing: %v", err)
	}
	if prometheus, ok := s.engine.(*prometheus.Prometheus); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Hpberbase account unavailable locally", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		prometheus.Authorize(eb, wallet.SignHash)
	} else {
		log.Error("Cannot start mining without prometheus", "err", s.engine)
	}
	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so noone will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)
	}
	go s.miner.Start(eb)
	return nil
}

func (s *Hpb) StopMining()         { s.miner.Stop() }
func (s *Hpb) IsMining() bool      { return s.miner.Mining() }
func (s *Hpb) Miner() *miner.Miner { return s.miner }

func (s *Hpb) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Hpb) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Hpb) TxPool() *core.TxPool               { return s.txPool }
func (s *Hpb) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Hpb) Engine() consensus.Engine           { return s.engine }
func (s *Hpb) ChainDb() hpbdb.Database            { return s.chainDb }
func (s *Hpb) IsListening() bool                  { return true } // Always listening
func (s *Hpb) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *Hpb) NetVersion() uint64                 { return s.networkId }
func (s *Hpb) Downloader() *downloader.Downloader { return s.protocolManager.downloader }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *Hpb) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}

// Start implements node.Service, starting all internal goroutines needed by the
// Hpb protocol implementation.
func (s *Hpb) Start(srvr *p2p.Server) error {
	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = hpbapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		maxPeers -= s.config.LightPeers
		if maxPeers < srvr.MaxPeers/2 {
			maxPeers = srvr.MaxPeers / 2
		}
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Hpb protocol.
func (s *Hpb) Stop() error {
	if s.stopDbUpgrade != nil {
		s.stopDbUpgrade()
	}
	s.bloomIndexer.Close()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.miner.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
