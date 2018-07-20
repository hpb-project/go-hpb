package txpool
//
//import (
//	"fmt"
//	"github.com/btcsuite/btcd/btcjson"
//	"github.com/hpb-project/go-hpb/account"
//	"github.com/hpb-project/go-hpb/account/keystore"
//	"github.com/hpb-project/go-hpb/common"
//	"github.com/hpb-project/go-hpb/common/crypto"
//	"github.com/hpb-project/go-hpb/common/hexutil"
//	"github.com/hpb-project/go-hpb/config"
//	"github.com/hpb-project/go-hpb/storage"
//	"github.com/hpb-project/go-hpb/storage/state"
//	"math/big"
//	"testing"
//)
//
//func prepare() (*keystore.KeyStore, *TxPool) {
//	am, _, _ := MockAccountManager(false, "", "")
//	ks := am.KeyStore()
//	var (
//		db, _      = hpbdb.NewMemDatabase()
//		key, _     = crypto.GenerateKey()
//		address    = crypto.PubkeyToAddress(key.PublicKey)
//		statedb, _ = state.New(common.Hash{}, state.NewDatabase(db))
//		trigger    = false
//	)
//
//	// setup pool with 2 transaction in it
//	statedb.SetBalance(address, new(big.Int).SetUint64(config.Ether))
//	blockchain := &testChain{&testBlockChain{statedb, big.NewInt(1000000000)}, address, &trigger}
//	pool := NewTxPool(testTxPoolConfig, config.MainnetChainConfig, blockchain)
//	return ks.(*keystore.KeyStore), pool
//}
//
//func TestSubmitTx(t *testing.T) {
//	ks, _ := prepare()
//
//	from := accounts.Account{Address: testAddress}
//
//	accountTo, err := ks.NewAccount("ABC")
//	if err != nil {
//		t.Fatalf("Failed to create account: %v", err)
//	}
//	fmt.Printf("Address To: {%x}\n", accountTo.Address)
//
//	sendTxArgs := SendTxArgs{
//		From:     from.Address,
//		To:       &accountTo.Address,
//		Gas:      (*hexutil.Big)(big.NewInt(100)),
//		GasPrice: (*hexutil.Big)(big.NewInt(1000)),
//		Value:    (*hexutil.Big)(big.NewInt(10000)),
//		Data:     hexutil.Bytes([]byte{}),
//		Nonce:    (*hexutil.Uint64)(btcjson.Uint64(1)),
//	}
//	hash, err := SubmitTx(sendTxArgs)
//	if err != nil {
//		t.Error("error SubmitTx", err)
//	}
//	t.Log(hash)
//
//}
//
//func TestSubmitRawTx(t *testing.T) {
//}
