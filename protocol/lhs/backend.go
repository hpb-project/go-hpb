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

// Package lhs implements the Light Hpb Subprotocol.
package lhs

import (
	"fmt"
	"sync"
	"time"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/common/constant"
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core"
	"github.com/hpb-project/ghpb/core/event"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/internal/hpbapi"
	"github.com/hpb-project/ghpb/network/p2p"
	"github.com/hpb-project/ghpb/network/p2p/discv5"
	rpc "github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/ghpb/node"
	"github.com/hpb-project/ghpb/protocol"
	"github.com/hpb-project/ghpb/protocol/downloader"
	"github.com/hpb-project/ghpb/protocol/filters"
	"github.com/hpb-project/ghpb/protocol/gasprice"
	"github.com/hpb-project/ghpb/protocol/light"
	"github.com/hpb-project/ghpb/storage"
)

type LightHpb struct {
	odr         *LesOdr
	relay       *LesTxRelay
	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	shutdownChan chan bool
	// Handlers
	peers           *peerSet
	txPool          *light.TxPool
	blockchain      *light.LightChain
	protocolManager *ProtocolManager
	serverPool      *serverPool
	reqDist         *requestDistributor
	retriever       *retrieveManager
	// DB interfaces
	chainDb hpbdb.Database // Block chain database

	ApiBackend *LhsApiBackend

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	networkId     uint64
	netRPCService *hpbapi.PublicNetAPI

	wg sync.WaitGroup
}

func New(ctx *node.ServiceContext, config *hpb.Config) (*LightHpb, error) {
	chainDb, err := hpb.CreateDB(ctx, config, "lightchaindata")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, isCompat := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !isCompat {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	peers := newPeerSet()
	quitSync := make(chan struct{})

	hpb := &LightHpb{
		chainConfig:    chainConfig,
		chainDb:        chainDb,
		eventMux:       ctx.EventMux,
		peers:          peers,
		reqDist:        newRequestDistributor(peers, quitSync),
		accountManager: ctx.AccountManager,
		engine:         hpb.CreateConsensusEngine(ctx, config, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		networkId:      config.NetworkId,
	}

	hpb.relay = NewLesTxRelay(peers, hpb.reqDist)
	hpb.serverPool = newServerPool(chainDb, quitSync, &hpb.wg)
	hpb.retriever = newRetrieveManager(peers, hpb.reqDist, hpb.serverPool)
	hpb.odr = NewLesOdr(chainDb, hpb.retriever)
	if hpb.blockchain, err = light.NewLightChain(hpb.odr, hpb.chainConfig, hpb.engine); err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		hpb.blockchain.SetHead(compat.RewindTo)
		core.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}

	hpb.txPool = light.NewTxPool(hpb.chainConfig, hpb.blockchain, hpb.relay)
	if hpb.protocolManager, err = NewProtocolManager(hpb.chainConfig, true, config.NetworkId, hpb.eventMux, hpb.engine, hpb.peers, hpb.blockchain, nil, chainDb, hpb.odr, hpb.relay, quitSync, &hpb.wg); err != nil {
		return nil, err
	}
	hpb.ApiBackend = &LhsApiBackend{hpb, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	hpb.ApiBackend.gpo = gasprice.NewOracle(hpb.ApiBackend, gpoParams)
	return hpb, nil
}

func lesTopic(genesisHash common.Hash) discv5.Topic {
	return discv5.Topic("LHS@" + common.Bytes2Hex(genesisHash.Bytes()[0:8]))
}

type LightDummyAPI struct{}

// Hpberbase is the address that mining rewards will be send to
func (s *LightDummyAPI) Hpberbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Coinbase is the address that mining rewards will be send to (alias for Hpberbase)
func (s *LightDummyAPI) Coinbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Mining returns an indication if this node is currently mining.
func (s *LightDummyAPI) Mining() bool {
	return false
}

// APIs returns the collection of RPC services the hpb package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *LightHpb) APIs() []rpc.API {

	return append(hpbapi.GetAPIs(s.ApiBackend), []rpc.API{
		{
			Namespace: "hpb",
			Version:   "1.0",
			Service:   &LightDummyAPI{},
			Public:    true,
		}, {
			Namespace: "hpb",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "hpb",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, true),
			Public:    true,
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *LightHpb) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *LightHpb) BlockChain() *light.LightChain      { return s.blockchain }
func (s *LightHpb) TxPool() *light.TxPool              { return s.txPool }
func (s *LightHpb) Engine() consensus.Engine           { return s.engine }
func (s *LightHpb) LesVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *LightHpb) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *LightHpb) EventMux() *event.TypeMux           { return s.eventMux }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *LightHpb) Protocols() []p2p.Protocol {
	return s.protocolManager.SubProtocols
}

// Start implements node.Service, starting all internal goroutines needed by the
// Hpb protocol implementation.
func (s *LightHpb) Start(srvr *p2p.Server) error {
	log.Warn("Light client mode is an experimental feature")
	s.netRPCService = hpbapi.NewPublicNetAPI(srvr, s.networkId)
	s.serverPool.start(srvr, lesTopic(s.blockchain.Genesis().Hash()))
	s.protocolManager.Start()
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Hpb protocol.
func (s *LightHpb) Stop() error {
	s.odr.Stop()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	s.txPool.Stop()

	s.eventMux.Stop()

	time.Sleep(time.Millisecond * 200)
	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
