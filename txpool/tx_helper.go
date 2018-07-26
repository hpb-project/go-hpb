package txpool

import (
	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/orcaman/concurrent-map"
	"math/big"
	"sync"
)

// SendTxArgs represents the arguments to submit a new transaction into the transaction pool.
type SendTxArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Big    `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Data     hexutil.Bytes   `json:"data"`
	Nonce    *hexutil.Uint64 `json:"nonce"`
}

const (
	defaultGas      = 90000
	defaultGasPrice = 50 * config.Shannon
)

var addrLocker = cmap.New()

// prepareSendTxArgs is a helper function that fills in default values for unspecified tx fields.
func (args *SendTxArgs) setDefaults() error {
	if args.Gas == nil {
		args.Gas = (*hexutil.Big)(big.NewInt(defaultGas))
	}
	if args.GasPrice == nil {
		args.GasPrice = (*hexutil.Big)(big.NewInt(defaultGasPrice))
	}
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	if args.Nonce == nil {
		nonce := GetTxPool().State().GetNonce(args.From)
		args.Nonce = (*hexutil.Uint64)(&nonce)
	}
	return nil
}

func (args *SendTxArgs) toTransaction() *types.Transaction {
	if args.To == nil {
		return types.NewContractCreation(uint64(*args.Nonce), (*big.Int)(args.Value), (*big.Int)(args.Gas), (*big.Int)(args.GasPrice), args.Data)
	}
	return types.NewTransaction(uint64(*args.Nonce), *args.To, (*big.Int)(args.Value), (*big.Int)(args.Gas), (*big.Int)(args.GasPrice), args.Data)
}

//SubmitTx try to submit transaction from local RPC call into tx_pool and return transaction's hash.
func SubmitTx(args SendTxArgs) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}

	wallet, err := accounts.GetManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}
	//1.build Transaction object and set default value for nil arguments in sendTxArgs.
	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		locker, ok := addrLocker.Get(args.From.String())
		if ok {
			locker.(*sync.Mutex).Lock()
			defer locker.(*sync.Mutex).Unlock()
		} else {
			locker := new(sync.Mutex)
			addrLocker.Set(args.From.String(), locker)
			defer locker.Unlock()
		}
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()
	//2.sign Transaction using local private keystore.
	//TODO read from blockchain config
	var chainID *big.Int
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	//3.call tx_pool's addTx() push tx into tx_pool.
	if err := GetTxPool().AddTx(signed); err != nil {
		return common.Hash{}, err
	}
	//4.return the transaction's hash.
	if tx.To() == nil {
		//TODO read from blockchain
		signer := types.NewBoeSigner(chainID)
		from, err := types.Sender(signer, tx)
		if err != nil {
			return common.Hash{}, err
		}
		crypto.CreateAddress(from, tx.Nonce())
		//log.Info("Submitted contract creation", "fullhash", tx.Hash().Hex(), "contract", addr.Hex())
	} else {
		//log.Info("Submitted transaction", "fullhash", tx.Hash().Hex(), "recipient", tx.To())
	}
	return signed.Hash(), nil
}

//SubmitRawTx try to decode rlp data and submit transaction from remote RPC call into tx_pool and return transaction's hash.
func SubmitRawTx(encodedTx hexutil.Bytes) (common.Hash, error) {
	//1.decode raw transaction data to Transaction object.
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return common.Hash{}, err
	}
	//2.call tx_pool's addTx() push tx into tx_pool.
	if err := GetTxPool().AddTx(tx); err != nil {
		return common.Hash{}, err
	}
	//3.return the transaction's hash.
	if tx.To() == nil {
		//TODO read from blockchain
		var chainID *big.Int
		signer := types.NewBoeSigner(chainID)
		from, err := types.Sender(signer, tx)
		if err != nil {
			return common.Hash{}, err
		}
		crypto.CreateAddress(from, tx.Nonce())
		//log.Info("Submitted contract creation", "fullhash", tx.Hash().Hex(), "contract", addr.Hex())
	} else {
		//log.Info("Submitted transaction", "fullhash", tx.Hash().Hex(), "recipient", tx.To())
	}
	return tx.Hash(), nil
}

//SubmitRawTx try to decode rlp data and submit transaction from remote RPC call into tx_pool and return transaction's hash.
func SubmitRawTxFromP2P(encodedTx hexutil.Bytes) (common.Hash, error) {
	//1.decode raw transaction data to Transaction object.
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return common.Hash{}, err
	}
	//2.call tx_pool's addTx() push tx into tx_pool.
	tx.SetFromP2P(true)
	if err := GetTxPool().AddTx(tx); err != nil {
		return common.Hash{}, err
	}
	//3.return the transaction's hash.
	if tx.To() == nil {
		//TODO read from blockchain
		var chainID *big.Int
		signer := types.NewBoeSigner(chainID)
		from, err := types.Sender(signer, tx)
		if err != nil {
			return common.Hash{}, err
		}
		crypto.CreateAddress(from, tx.Nonce())
		//log.Info("Submitted contract creation", "fullhash", tx.Hash().Hex(), "contract", addr.Hex())
	} else {
		//log.Info("Submitted transaction", "fullhash", tx.Hash().Hex(), "recipient", tx.To())
	}
	return tx.Hash(), nil
}
