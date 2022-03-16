// Copyright 2018 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2014 The go-ethereum Authors.
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

// ghpb is the official command-line client for Hpb.
package main

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	bc "github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"

	accounts "github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/account/keystore"
	"github.com/hpb-project/go-hpb/cmd/utils"
	"github.com/hpb-project/go-hpb/common/console"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/metrics"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/internal/debug"
	"github.com/hpb-project/go-hpb/node"
	"gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "ghpb" // Client identifier to advertise over the network
)

var (
	// GitCommit SHA1 commit hash of the release (set via linker flags)
	GitCommit = gitCommit
	gitCommit = ""
	// The app that holds all commands and flags.
	app = utils.NewApp(gitCommit, "the go-hpb command line interface")
	// flags that configure the node
	nodeFlags = []cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.BootnodesV4Flag,
		utils.BootnodesV5Flag,
		utils.DataDirFlag,
		utils.KeyStoreDirFlag,
		utils.NoUSBFlag,
		utils.TxPoolPriceLimitFlag,
		utils.TxPoolPriceBumpFlag,
		utils.TxPoolAccountSlotsFlag,
		utils.TxPoolGlobalSlotsFlag,
		utils.TxPoolAccountQueueFlag,
		utils.TxPoolGlobalQueueFlag,
		utils.TxPoolLifetimeFlag,
		utils.FastSyncFlag,
		utils.LightModeFlag,
		utils.SyncModeFlag,
		utils.LightServFlag,
		utils.LightPeersFlag,
		utils.LightKDFFlag,
		utils.CacheFlag,
		utils.TrieCacheGenFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.HpberbaseFlag,
		utils.GasPriceFlag,
		utils.MinerThreadsFlag,
		utils.MiningEnabledFlag,
		utils.TargetGasLimitFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DevModeFlag,
		utils.TestnetFlag,
		utils.RinkebyFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.RPCCORSDomainFlag,
		utils.HpbStatsURLFlag,
		utils.MetricsEnabledFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.ExtraDataFlag,
		utils.NodeTypeFlag,
		utils.TestModeFlag,
		utils.RPCVirtualHostsFlag,
		utils.TestCodeStageFlag,
		utils.ConfigFileFlag,
		utils.HpNumFlag,
		utils.HpVoteRndSelScpFlag,
		utils.IgnRewardRetErrFlag,
		utils.GenBlkSecsFlag,
		utils.BNodeidsFlag,
		utils.StartNumberFlag,
		utils.CriticalFlag,
		utils.CriticalBackBlockFlag,
		utils.ArchivedBlockFalg,
		utils.TestFlag,
	}

	rpcFlags = []cli.Flag{
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
	}
)

func init() {
	// Initialize the CLI app and start Geth
	app.Action = ghpb
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2018 The go-hpb Authors "
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		initcadCommand,
		importCommand,
		exportCommand,
		copydbCommand,
		removedbCommand,
		dumpCommand,
		// See monitorcmd.go:
		monitorCommand,
		// See accountcmd.go:
		accountCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		versionCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
		boeUpdateCommand,
		boeDetectCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = append(app.Flags, nodeFlags...)
	app.Flags = append(app.Flags, rpcFlags...)
	app.Flags = append(app.Flags, consoleFlags...)
	app.Flags = append(app.Flags, debug.Flags...)

	app.Before = func(ctx *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		// Start system runtime metrics collection
		go metrics.CollectProcessMetrics(3 * time.Second)

		utils.SetupNetwork(ctx)
		return nil
	}

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ghpb is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func ghpb(ctx *cli.Context) error {
	cfg := MakeConfigNode(ctx)
	hpbnode, err := createNode(cfg)
	if err != nil {
		utils.Fatalf("Failed to create node")
		return err
	}
	startNode(ctx, hpbnode, cfg)
	hpbnode.Wait()
	return nil
}

//create node object
func createNode(conf *config.HpbConfig) (*node.Node, error) {
	//create node object
	stack, err := node.New(conf)
	if err != nil {
		utils.Fatalf("Failed to create node: %v", err)
		return nil, err
	}
	return stack, nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node, conf *config.HpbConfig) {

	// Unlock any account specifically requested
	ks := stack.AccountManager().KeyStore().(*keystore.KeyStore)

	passwords := utils.MakePasswordList(ctx)
	unlocks := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for i, account := range unlocks {
		if trimmed := strings.TrimSpace(account); trimmed != "" {
			unlockAccount(ctx, ks, trimmed, i, passwords)
		}
	}

	if unlocks[0] != "" {
		account, err := utils.MakeAddress(ks, strings.TrimSpace(unlocks[0]))
		if err != nil {
			utils.Fatalf("Could not list accounts: %v", err)
		}
		conf.Node.DefaultAddress = account.Address
	}

	// Start up the node itself
	utils.StartNode(stack)
	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	var testflag = ctx.GlobalInt64(utils.TestFlag.Name)
	if testflag != 0 {
		if false {
			// tx process test.
			var blocknumber uint64 = 13965331
			db := stack.ChainDb()
			memdb := state.NewDatabase(db)
			block := stack.Hpbbc.GetBlockByNumber(blocknumber)
			parent := stack.Hpbbc.GetBlockByNumber(blocknumber - 1)

			statedb, err := state.New(parent.Root(), memdb)
			if err != nil {
				log.Error("state new failed", "err", err)
			}
			var txs = make([]types.Transaction, 0)
			blocktxs := block.Transactions()
			for i := 0; i < 300000; i++ {
				tx := blocktxs[0]
				txs = append(txs, *tx)
			}

			var boesigner = types.NewBoeSigner(stack.Hpbbc.Config().ChainId)
			var pointtxs = make([]*types.Transaction, 0, len(txs))
			for _, tx := range txs {
				ntx := tx
				ptx := &ntx
				pointtxs = append(pointtxs, ptx)
			}
			author := block.Header().Coinbase

			if testflag == 1 {
				// boe async sender.
				for i := 0; i < len(pointtxs); i++ {
					types.ASynSender(boesigner, pointtxs[i])
				}
			}

			var start = time.Now()
			var last = start

			for i := 0; i < len(pointtxs); i++ {
				var gp bc.GasPool = 200000
				// types.Sender(boesigner, pointtxs[i])
				bc.ApplyTransactionNonContractNonFinallize(stack.Hpbbc.Config(), stack.Hpbbc, &author,
					&gp, statedb, block.Header(), pointtxs[i], new(big.Int))
				statedb.Reset(parent.Root())
				if time.Now().After(last.Add(time.Second)) {
					log.Info("process tx ", "total", i+1, "cost", time.Now().Sub(start).Seconds())
					last = time.Now()
				}
			}
		}
		if true {
			// block process test.
			var blocknumber uint64 = 1756677
			db := stack.ChainDb()
			memdb := state.NewDatabase(db)
			block := stack.Hpbbc.GetBlockByNumber(blocknumber)
			parent := stack.Hpbbc.GetBlockByNumber(blocknumber - 1)

			blocks := make([]*types.Block, 0)
			for i := 0; i < 1000; i++ {
				b := bc.GetBlock(stack.ChainDb(), block.Hash(), block.NumberU64()) // get more real instance.
				blocks = append(blocks, b)
			}

			statedb, err := state.New(parent.Root(), memdb)
			if err != nil {
				log.Error("state new failed", "err", err)
			}

			synsigner := types.MakeSigner(stack.Hpbbc.Config())
			processer := bc.NewStateProcessor(stack.Hpbbc.Config(), stack.BlockChain(), stack.Hpbbc.Engine())

			var start = time.Now()
			var last = start

			for i, b := range blocks {
				if testflag == 1 {
					// boe use hardware.
					go func(txs types.Transactions) {
						for _, tx := range txs {
							types.ASynSender(synsigner, tx)
						}
					}(b.Transactions())
				}
				processer.Process(b, statedb)
				statedb.Reset(parent.Root())
				if time.Now().After(last.Add(time.Second)) {
					log.Info("process block ", "total", i+1, "cost", time.Now().Sub(start).Seconds())
					last = time.Now()
				}
			}
		}
	}

	go func() {

		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// Start auxiliary services if enabled
	if ctx.GlobalBool(utils.MiningEnabledFlag.Name) && (conf.Network.RoleType == "") {
		// Set the gas price to the limits from the CLI and start mining
		stack.TxPool().SetGasPrice(utils.GlobalBig(ctx, utils.GasPriceFlag.Name))
		log.Debug("set default gasprice ", "price", utils.GlobalBig(ctx, utils.GasPriceFlag.Name))
		if err := stack.StartMining(true); err != nil {
			utils.Fatalf("Failed to start mining: %v", err)
		}
	}
}
