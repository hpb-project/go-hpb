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

package bc

import (
	"encoding/json"
	"math/big"

	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/hvm"
	"github.com/hpb-project/go-hpb/hvm/evm"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *config.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *config.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Hpb rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, *big.Int, error) {
	var (
		receipts     types.Receipts
		receipt      *types.Receipt
		errs         error
		totalUsedGas = big.NewInt(0)
		header       = block.Header()
		allLogs      []*types.Log
		gp           = new(GasPool).AddGas(block.GasLimit())
	)
	bNewVersion := block.Number().Uint64() > consensus.NewContractVersion
	synsigner := types.MakeSigner(p.config)
	go func(txs types.Transactions) {
		for _, tx := range txs {
			types.ASynSender(synsigner, tx)
		}
	}(block.Transactions())

	// Iterate over and process the individual transactions
	author, _ := p.engine.Author(block.Header())
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		//the tx without contract
		if bNewVersion {
			if (tx.To() == nil && len(tx.Data()) > 0) || (tx.To() != nil && len(statedb.GetCode(*tx.To())) > 0) {
				receipt, _, errs = ApplyTransactionNonFinallize(p.config, p.bc, &author, gp, statedb, header, tx, totalUsedGas)
				if errs != nil {
					return nil, nil, nil, errs
				}
			} else {
				receipt, _, errs = ApplyTransactionNonContractNonFinallize(p.config, p.bc, &author, gp, statedb, header, tx, totalUsedGas)
				if errs != nil {
					return nil, nil, nil, errs
				}
			}
		} else {
			if len(tx.Data()) > 0 {
				receipt, _, errs = ApplyTransactionNonFinallize(p.config, p.bc, &author, gp, statedb, header, tx, totalUsedGas)
				if errs != nil {
					return nil, nil, nil, errs
				}
			} else {
				receipt, _, errs = ApplyTransactionNonContractNonFinallize(p.config, p.bc, &author, gp, statedb, header, tx, totalUsedGas)
				if errs != nil {
					return nil, nil, nil, errs
				}
			}
		}

		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	ApplyTransactionFinalize(statedb)

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	if _, errfinalize := p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), receipts); nil != errfinalize {
		return nil, nil, nil, errfinalize
	}

	return receipts, allLogs, totalUsedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *config.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int) (string, *types.Receipt, *big.Int, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config))
	if err != nil {
		log.Error("Asmessage err", "err", err)
		return "", nil, nil, err
	}
	cfg := evm.Config{}
	// Create a new context to be used in the EVM environment
	context := hvm.NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := evm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(vmenv, msg, gp)
	statediff, errs := json.Marshal(vmenv.GetStateDiff())
	log.Debug("evm json----", "jsons", string(statediff), "errs", errs)
	if err != nil {
		log.Error("ApplyMessage err", "err", err)
		return "", nil, nil, err
	}

	// Update the state with pending changes
	var root []byte

	statedb.Finalise(true)

	usedGas.Add(usedGas, gas)

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return string(statediff), receipt, gas, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransactionNonContract(config *config.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int) (*types.Receipt, *big.Int, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config))
	if err != nil {
		log.Error("Asmessage err", "err", err)
		return nil, nil, err
	}

	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessageNonContract(msg, bc, author, gp, statedb, header)
	if err != nil {
		log.Error("ApplyMessageNonContract err", "err", err)
		return nil, nil, err
	}

	// Update the state with pending changes
	var root []byte

	statedb.Finalise(true)

	usedGas.Add(usedGas, gas)
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransactionNonFinallize(config *config.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int) (*types.Receipt, *big.Int, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config))
	if err != nil {
		log.Error("Asmessage err", "err", err)
		return nil, nil, err
	}
	cfg := evm.Config{}
	// Create a new context to be used in the EVM environment
	context := hvm.NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := evm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {
		log.Error("ApplyMessage err", "err", err)
		return nil, nil, err
	}

	// Update the state with pending changes
	var root []byte

	statedb.ClearRefund()
	usedGas.Add(usedGas, gas)

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransactionNonContractNonFinallize(config *config.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int) (*types.Receipt, *big.Int, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config))
	if err != nil {
		log.Error("Asmessage err", "err", err)
		return nil, nil, err
	}

	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessageNonContract(msg, bc, author, gp, statedb, header)
	if err != nil {
		log.Error("ApplyMessageNonContract err", "err", err)
		return nil, nil, err
	}

	// Update the state with pending changes
	var root []byte
	statedb.ClearRefund()
	usedGas.Add(usedGas, gas)
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}
func ApplyTransactionFinalize(statedb *state.StateDB) {
	statedb.Finalise(true)
}
