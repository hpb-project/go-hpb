package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/account/keystore"
	"github.com/hpb-project/go-hpb/cmd/utils"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/console"
	"github.com/hpb-project/go-hpb/protocol"
	"github.com/hpb-project/go-hpb/internal/debug"
	"github.com/hpb-project/go-hpb/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/node"
	"gopkg.in/urfave/cli.v1"
)

func makeConfigNode(ctx *cli.Context) (*node.Node, hpbConfig) {
	// Load defaults config
	cfg ,err = config.GetHpbConfigInstance()
	if err == nil{
		log.Error("Get Hpb config fail, so exit")
		os.Exit(1)
	}



	// Apply flags.
	utils.SetNodeConfig(ctx, &cfg.Node)
	stack, err := node.New(&cfg.Node)
	if err != nil {
	utils.Fatalf("Failed to create the protocol stack: %v", err)
	}
	utils.SetHpbConfig(ctx, stack, &cfg.Hpb)
	if ctx.GlobalIsSet(utils.HpbStatsURLFlag.Name) {
	cfg.HpbStats.URL = ctx.GlobalString(utils.HpbStatsURLFlag.Name)
	}

	return stack, cfg
}