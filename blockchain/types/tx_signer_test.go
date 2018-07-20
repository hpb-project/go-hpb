package types

import (
	"testing"
	"crypto/ecdsa"
	"math/big"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/common/crypto"
)

func makeTransaction(nonce uint64, gaslimit, gasprice *big.Int, key *ecdsa.PrivateKey) *Transaction {
	//tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(100), gaslimit, gasprice, nil)
	tx, _ := SignTx(NewTransaction(nonce, common.Address{}, big.NewInt(1), gaslimit, gasprice, nil), NewBoeSigner(config.MainnetChainConfig.ChainId), key)
	return tx
}

func TestBoeSigner_Sender(t *testing.T) {
	key, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(key.PublicKey)
	signer := NewBoeSigner(config.MainnetChainConfig.ChainId)
	tx := makeTransaction(0, big.NewInt(1000), big.NewInt(1000), key)
	sender, _ := signer.Sender(tx)
	t.Logf("sender : %x",sender)
	t.Logf("address : %x",address)
	if sender != address{
		t.Fatal("not equal")
	}
}
