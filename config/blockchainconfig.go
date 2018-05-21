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
	"math/big"
	"fmt"
)



var (
	MainnetGenesisHash = common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3") // Mainnet genesis hash to enforce below configs on
	TestnetGenesisHash = common.HexToHash("0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d") // Testnet genesis hash to enforce below configs on
)
const (
	MaximumExtraDataSize  uint64 = 32    // Maximum size extra data may be after Genesis.
)

var (
	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = &ChainConfig{
		ChainId: big.NewInt(1),

		Prometheus: &PrometheusConfig{
			Period: 15,
			Epoch:  30000,
			Random: "0",
		},
	}

	// TestnetChainConfig contains the chain parameters to run a node on the Ropsten test network.
	TestnetChainConfig = &ChainConfig{
		ChainId: big.NewInt(3),

		Prometheus: &PrometheusConfig{
			Period: 15,
			Epoch:  30000,
			Random: "0",
		},
	}

	// MainnetChainConfig is the chain parameters to run a node on the main network.
	PrivatenetChainConfig = &ChainConfig{
		ChainId: big.NewInt(1000),

		Prometheus: &PrometheusConfig{
			Period: 15,
			Epoch:  30000,
			Random: "0",
		},
	}
)

type ChainConfig struct {
	ChainId *big.Int `json:"chainId"` // Chain id identifies the current chain and is used for replay protection

	Prometheus *PrometheusConfig `json:"prometheus,omitempty"`
}

var DefaultBlockChainConfig = ChainConfig{
	ChainId: params.MainnetChainConfig.ChainId,
	Prometheus:
		}

var (
	GasLimitBoundDivisor   = big.NewInt(1024)                  // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit            = big.NewInt(5000)                  // Minimum the gas limit may ever be.
	GenesisGasLimit        = big.NewInt(100000000)               // Gas limit of the Genesis block. //for testnet
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
	var engine interface{}
	switch {
	case c.Prometheus != nil:
		engine = c.Prometheus
	default:
		engine = "unknown"
	}
	return fmt.Sprintf("{ChainID: %v Engine: %v}",
		c.ChainId,
		engine,
	)
}
