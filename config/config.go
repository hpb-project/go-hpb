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
	"bufio"
	"errors"
	"reflect"
	"unicode"

	"fmt"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/naoina/toml"
	"os"
	"sync/atomic"
)

var HpbConfigIns *HpbConfig

const (
	DatadirPrivateKey      = "nodekey"            // Path within the datadir to the node's private key
	DatadirDefaultKeyStore = "keystore"           // Path within the datadir to the keystore
	DatadirStaticNodes     = "static-nodes.json"  // Path within the datadir to the static node list
	DatadirTrustedNodes    = "trusted-nodes.json" // Path within the datadir to the trusted node list
	DatadirNodeDatabase    = "nodes"              // Path within the datadir to store the node infos
)

const (
	MaximumExtraDataSize  uint64 = 32    // Maximum size extra data may be after Genesis.
	ExpByteGas            uint64 = 10    // Times ceil(log256(exponent)) for the EXP instruction.
	SloadGas              uint64 = 50    // Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added.
	CallValueTransferGas  uint64 = 9000  // Paid for CALL when the value transfer is non-zero.
	CallNewAccountGas     uint64 = 25000 // Paid for CALL when the destination address didn't exist prior.
	TxGas                 uint64 = 10    // Per transaction not creating a contract. NOTE: Not payable on data of calls between transactions. //for testnet
	TxGasContractCreation uint64 = 53000 // Per transaction that creates a contract. NOTE: Not payable on data of calls between transactions.
	TxDataZeroGas         uint64 = 1     // Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions. //for testnet
	QuadCoeffDiv          uint64 = 512   // Divisor for the quadratic particle of the memory cost equation.
	SstoreSetGas          uint64 = 20000 // Once per SLOAD operation.
	LogDataGas            uint64 = 8     // Per byte in a LOG* operation's data.
	CallStipend           uint64 = 2300  // Free gas given at beginning of call.

	Sha3Gas          uint64 = 30    // Once per SHA3 operation.
	Sha3WordGas      uint64 = 6     // Once per word of the SHA3 operation's data.
	SstoreResetGas   uint64 = 5000  // Once per SSTORE operation if the zeroness changes from zero.
	SstoreClearGas   uint64 = 5000  // Once per SSTORE operation if the zeroness doesn't change.
	SstoreRefundGas  uint64 = 15000 // Once per SSTORE operation if the zeroness changes to zero.
	JumpdestGas      uint64 = 1     // Refunded gas, once per SSTORE operation if the zeroness changes to zero.
	EpochDuration    uint64 = 30000 // Duration between proof-of-work epochs.
	CallGas          uint64 = 40    // Once per CALL operation & message call transaction.
	CreateDataGas    uint64 = 200   //
	CallCreateDepth  uint64 = 1024  // Maximum depth of call/create stack.
	ExpGas           uint64 = 10    // Once per EXP instruction
	LogGas           uint64 = 375   // Per LOG* operation.
	CopyGas          uint64 = 3     //
	StackLimit       uint64 = 1024  // Maximum size of VM stack allowed.
	TierStepGas      uint64 = 0     // Once per operation, for a selection of them.
	LogTopicGas      uint64 = 375   // Multiplied by the * of the LOG*, per LOG transaction. e.g. LOG0 incurs 0 * c_txLogTopicGas, LOG4 incurs 4 * c_txLogTopicGas.
	CreateGas        uint64 = 32000 // Once per CREATE operation & contract-creation transaction.
	SuicideRefundGas uint64 = 24000 // Refunded following a suicide operation.
	MemoryGas        uint64 = 3     // Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL.
	TxDataNonZeroGas uint64 = 1     // Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions. //for testnet

	MaxCodeSize = 24576 // Maximum bytecode to permit for a contract

	// Precompiled contract gas prices

	EcrecoverGas            uint64 = 3000   // Elliptic curve sender recovery gas price
	Sha256BaseGas           uint64 = 60     // Base price for a SHA256 operation
	Sha256PerWordGas        uint64 = 12     // Per-word price for a SHA256 operation
	Ripemd160BaseGas        uint64 = 600    // Base price for a RIPEMD160 operation
	Ripemd160PerWordGas     uint64 = 120    // Per-word price for a RIPEMD160 operation
	IdentityBaseGas         uint64 = 15     // Base price for a data copy operation
	IdentityPerWordGas      uint64 = 3      // Per-work price for a data copy operation
	ModExpQuadCoeffDiv      uint64 = 20     // Divisor for the quadratic particle of the big int modular exponentiation
	Bn256AddGas             uint64 = 500    // Gas needed for an elliptic curve addition
	Bn256ScalarMulGas       uint64 = 40000  // Gas needed for an elliptic curve scalar multiplication
	Bn256PairingBaseGas     uint64 = 100000 // Base price for an elliptic curve pairing check
	Bn256PairingPerPointGas uint64 = 80000  // Per-point price for an elliptic curve pairing check
)
const (
	// These are the multipliers for hpber denominations.
	// Example: To get the wei value of an amount in 'douglas', use
	//
	//    new(big.Int).Mul(value, big.NewInt(params.Douglas))
	//
	Wei      = 1
	Ada      = 1e3
	Babbage  = 1e6
	Shannon  = 1e9
	Szabo    = 1e12
	Finney   = 1e15
	Hpber    = 1e18
	Einstein = 1e21
	Douglas  = 1e42
)

// config instance
var INSTANCE = atomic.Value{}

type hpbStatsConfig struct {
	URL string `toml:",omitempty"`
}

// Config represents a small collection of configuration values to fine tune the
// P2P network layer of a protocol stack. These values can be further extended by
// all registered services.
type HpbConfig struct {
	Node Nodeconfig
	// Configuration of peer-to-peer networking.
	Network NetworkConfig

	//configuration of txpool
	TxPool TxPoolConfiguration

	//configuration of blockchain
	BlockChain ChainConfig

	//configuration of consensus
	Prometheus PrometheusConfig

	Gas GasConfig

	HpbStats hpbStatsConfig
}

// These settings ensure that TOML keys use the same names as Go struct fields.
var tomlSettings = toml.Config{
	NormFieldName: func(rt reflect.Type, key string) string {
		return key
	},
	FieldToKey: func(rt reflect.Type, field string) string {
		return field
	},
	MissingField: func(rt reflect.Type, field string) error {
		link := ""
		if unicode.IsUpper(rune(rt.Name()[0])) && rt.PkgPath() != "main" {
			link = fmt.Sprintf(", see https://godoc.org/%s#%s for available fields", rt.PkgPath(), rt.Name())
		}
		return fmt.Errorf("field '%s' is not defined in %s%s", field, rt.String(), link)
	},
}

func loadConfig(file string, cfg *HpbConfig) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tomlSettings.NewDecoder(bufio.NewReader(f)).Decode(cfg)
	// Add file name to errors that have a line number.
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(file + ", " + err.Error())
	}
	return err
}
func New() *HpbConfig {
	if INSTANCE.Load() != nil {
		return INSTANCE.Load().(*HpbConfig)
	}

	if HpbConfigIns == nil {
		HpbConfigIns := &HpbConfig{
			Node: defaultNodeConfig(),
			// Configuration of peer-to-peer networking.
			Network: DefaultNetworkConfig(),

			//configuration of txpool
			TxPool: DefaultTxPoolConfig,

			//configuration of blockchain
			BlockChain: DefaultBlockChainConfig,
			//configuration of consensus
			Prometheus: DefaultPrometheusConfig,

			Gas: DefaultGasConfig,
		}
		log.Info("Create New HpbConfig object")
		INSTANCE.Store(HpbConfigIns)
		return HpbConfigIns
	}

	INSTANCE.Store(HpbConfigIns)
	return HpbConfigIns

}
func GetHpbConfigInstance() *HpbConfig {
	if INSTANCE.Load() != nil {
		return INSTANCE.Load().(*HpbConfig)
	}
	HpbConfigIns := &HpbConfig{
		Node: defaultNodeConfig(),
		// Configuration of peer-to-peer networking.
		Network: DefaultNetworkConfig(),

		//configuration of txpool
		TxPool: DefaultTxPoolConfig,

		//configuration of blockchain
		BlockChain: DefaultBlockChainConfig,
		//configuration of consensus
		Prometheus: DefaultPrometheusConfig,

		Gas: DefaultGasConfig,
	}
	log.Info("Create New HpbConfig object")
	INSTANCE.Store(HpbConfigIns)
	return INSTANCE.Load().(*HpbConfig)
}
