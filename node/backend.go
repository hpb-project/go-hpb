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
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/prometheus"

	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"

	"github.com/hpb-project/go-hpb/internal/hpbapi"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/node"
	"github.com/hpb-project/go-hpb/config"
	"github.com/go-hpb-backkup/txpool"
	"github.com/hpb-project/go-hpb/synctrl"
	"github.com/hpb-project/go-hpb/event"
	//"github.com/hpb-project/go-hpb/synctrl"
	"github.com/go-hpb-backkup/worker"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
}

/*func (s *Node) AddLesServer(ls LesServer) {
	s.lesServer = ls*/
}





// APIs returns the collection of RPC services the hpb package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Node) APIs() []rpc.API {
	apis := hpbapi.GetAPIs(s.ApiBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.Hpbengine.APIs(s.BlockChain())...)

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
			Service:   NewPrivateDebugAPI(&s.Hpbconfig.BlockChain, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Node) StopMining()         { s.Stop() }
func (s *Node) IsMining() bool      { return s.miner.Mining() }
func (s *Node) Miner() *miner.Miner { return s.miner }

func (s *Node) APIAccountManager() *accounts.Manager  { return s.accountManager }
func (s *Node) BlockChain() *bc.BlockChain         { return s.Hpbbc }
func (s *Node) TxPool() *core.TxPool               { return s.Hpbtxpool }
//func (s *Node) EventMux() *event.T       		   { return s.eventMux }
func (s *Node) Engine() consensus.Engine           { return s.Hpbengine }
func (s *Node) ChainDb() hpbdb.Database            { return s.chainDb }
func (s *Node) IsListening() bool                  { return true } // Always listening
func (s *Node) EthVersion() int                    { return int(s.Hpbsyncctr.SubProtocols[0].Version) }
func (s *Node) NetVersion() uint64                 { return s.networkId }
//func (s *Node) Downloader() *downloader.Downloader { return s.Hpbsyncctr.downloader }
