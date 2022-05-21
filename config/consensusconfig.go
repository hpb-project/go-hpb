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

package config

var DefaultPrometheusConfig = PrometheusConfig{
	//for test,change from 3 to 6 seconds
	Period: 6,
	Epoch:  30000,
}

type PrometheusConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	Epoch  uint64 `json:"epoch"`  // Epoch length to reset votes and checkpoint
}

// PrometheusConfig is the consensus engine configs for proof-of-authority based sealing.
// String implements the stringer interface, returning the consensus engine details.
func (c *PrometheusConfig) String() string {
	return "prometheusConfig"
}

var (
	MaxBlockForever uint64 = 9999999999999999
	HpbNodenumber          = 31    //hpb nodes number
	NumberPrehp            = 20    //nodes num from 151 nodes select
	IgnoreRetErr           = false //ignore finalize return err

	StageNumberII  uint64 = 260000
	StageNumberIII uint64 = 1200000
	StageNumberIV  uint64 = 2560000
	StageNumberV   uint64 = 999999000000 // unused forever
	StageNumberVI  uint64 = 2561790
	StageNumberVII uint64 = 2896000

	StageNumberRealRandom uint64 = 5159000               // used to enable real random.
	StateNumberNewHash           = StageNumberRealRandom // used to enable fpga hashV2 and limit continue gen block.

	StageNumberUpgradedEVM uint64 = 8685000 // used to upgraded EVM .

	StageNumberNewPrecompiledContract uint64 = 11850000

	ContinuousGenBlkLimit uint64 = 2

	NewContractVersion        uint64 = 3788000
	CadNodeCheckpointInterval uint64 = 200

	StageElectionKey             = "ElectionBlock"
	StageNumberElection   uint64 = MaxBlockForever // got from contract, otherwise forever not used.
	StageNumberEvmBugFork uint64 = 12414000        // fix contract bug for unlimited generate HPB coin happend at 2021-10-20
	StageNumberEvmV2      uint64 = 14633000
	StageNumberEvmRevert  uint64 = 14633300 // critical revert evm to old version at 14633300.
	StageNumberEvmV3      uint64 = 18000000
)

func UseNewEvm(height uint64) bool {
	if (height >= StageNumberEvmV2 && height < StageNumberEvmRevert) || height >= StageNumberEvmV3 {
		return true
	}
	return false
}
