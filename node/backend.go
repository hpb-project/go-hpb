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
package node

import (
	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/internal/hpbapi"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/worker"
	"github.com/hpb-project/go-hpb/txpool"
	"github.com/hpb-project/go-hpb/synctrl"
	"github.com/hpb-project/go-hpb/node/filters"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
}

/*func (s *Node) AddLesServer(ls LesServer) {
	s.lesServer = ls*/






// APIs returns the collection of RPC services the hpb package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Node) APIs() []rpc.API {
	apis := hpbapi.GetAPIs(s.ApiBackend)

	// Append all the local APIs and return
	apis = append(apis, []rpc.API{
		{
			Namespace: "hpb",
			Version:   "1.0",
			Service:   NewPublicHpbAPI(s),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		},{ //TODO lsl
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
			Service:   NewPrivateDebugAPI(&s.Hpbconfig.BlockChain, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   hpbapi.NewPublicNetAPI(p2p.PeerMgrInst().P2pSvr(), s.networkId), //s.netRPCService,
			Public:    true,
		},
	}...)


	// Append any APIs exposed explicitly by the consensus engine
	if s.Hpbengine != nil {
		apis = append(apis, s.Hpbengine.APIs(s.BlockChain())...)
		apis = append(apis, []rpc.API{
			{Namespace: "hpb",
				Version:   "1.0",
					Service:   synctrl.NewPublicSyncerAPI(s.Hpbsyncctr.Syncer(), s.newBlockMux),
					Public:    true,
			},
		}...)

	}
	return apis
}

func (s *Node) StopMining()         { s.miner.Stop() }
func (s *Node) IsMining() bool      { return s.miner.Mining() }
func (s *Node) Miner() *worker.Miner { return s.miner }

func (s *Node) APIAccountManager() *accounts.Manager  { return s.accman }
func (s *Node) BlockChain() *bc.BlockChain         { return s.Hpbbc }
func (s *Node) TxPool() *txpool.TxPool             { return s.Hpbtxpool }
//func (s *Node) EventMux() *event.T       		   { return s.eventMux }
func (s *Node) Engine() consensus.Engine           { return s.Hpbengine }
func (s *Node) ChainDb() hpbdb.Database            { return s.HpbDb }
func (s *Node) IsListening() bool                  { return true } // Always listening
func (s *Node) EthVersion() int                    { return int(s.Hpbpeermanager.Protocol()[0].Version)}
func (s *Node) NetVersion() uint64                 { return s.networkId }
//func (s *Node) Downloader() *downloader.Downloader { return s.Hpbsyncctr.downloader }
