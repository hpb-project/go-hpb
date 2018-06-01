package main

import (

	"os"

	"github.com/hpb-project/go-hpb/cmd/utils"
	"github.com/hpb-project/go-hpb/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/node"
	"gopkg.in/urfave/cli.v1"
)

func MakeConfigNode(ctx *cli.Context) (*node.Node, *config.HpbConfig) {
	// Load defaults config
	cfg ,err := config.GetHpbConfigInstance()
	if err == nil{
		log.Error("Get Hpb config fail, so exit")
		os.Exit(1)
	}
	// Apply flags.
	utils.SetNodeConfig(ctx, cfg)
	stack, err := node.New(&cfg.Node)
	if err != nil {
	utils.Fatalf("Failed to create the protocol stack: %v", err)
	}

	utils.SetTxPool(ctx, &cfg.TxPool)
	if ctx.GlobalIsSet(utils.HpbStatsURLFlag.Name) {
	cfg.HpbStats.URL = ctx.GlobalString(utils.HpbStatsURLFlag.Name)
	}

	return stack, cfg
}