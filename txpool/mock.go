package txpool
//
//import (
//	"github.com/hpb-project/go-hpb/account"
//	"github.com/hpb-project/go-hpb/account/keystore"
//	"github.com/hpb-project/go-hpb/common/crypto"
//	"github.com/hpb-project/go-hpb/config"
//	"github.com/hpb-project/go-hpb/consensus/solo"
//	"github.com/hpb-project/go-hpb/blockchain"
//	"github.com/hpb-project/go-hpb/storage"
//	"github.com/hpb-project/go-hpb/storage/state"
//	"github.com/hpb-project/go-hpb/blockchain/types"
//	"io/ioutil"
//	"math/big"
//	"os"
//	"path/filepath"
//	"github.com/hpb-project/go-hpb/blockchain/storage"
//)
//
//var (
//	testdb, _   = hpbdb.NewMemDatabase()
//	testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
//	testAddress = crypto.PubkeyToAddress(testKey.PublicKey)
//	genesis     = bc.GenesisBlockForTesting(testdb, testAddress, big.NewInt(1000000000))
//)
//
//func MockBlockChain() *bc.BlockChain {
//	engine := solo.New()
//	blockchain, err := core.NewBlockChain(testdb, config.MainnetChainConfig, engine)
//	if err != nil {
//		panic(err)
//	}
//	blockchain.SetValidator(bproc{})
//	return blockchain
//}
//
//type bproc struct{}
//
//func (bproc) ValidateBody(*types.Block) error { return nil }
//func (bproc) ValidateState(block, parent *types.Block, state *state.StateDB, receipts types.Receipts, usedGas *big.Int) error {
//	return nil
//}
//func (bproc) Process(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, *big.Int, error) {
//	return nil, nil, new(big.Int), nil
//}
//
//var datadirDefaultKeyStore = "keystore" // Path within the datadir to the keystore
//
//func MockAccountManager(useLightweightKDF bool, keyStoreDir string, dataDir string) (*accounts.Manager, string, error) {
//	scryptN := keystore.StandardScryptN
//	scryptP := keystore.StandardScryptP
//	if useLightweightKDF {
//		scryptN = keystore.LightScryptN
//		scryptP = keystore.LightScryptP
//	}
//
//	var (
//		keydir    string
//		ephemeral string
//		err       error
//	)
//	switch {
//	case filepath.IsAbs(keyStoreDir):
//		keydir = keyStoreDir
//	case dataDir != "":
//		if keyStoreDir == "" {
//			keydir = filepath.Join(dataDir, datadirDefaultKeyStore)
//		} else {
//			keydir, err = filepath.Abs(keyStoreDir)
//		}
//	case keyStoreDir != "":
//		keydir, err = filepath.Abs(keyStoreDir)
//	default:
//		// There is no datadir.
//		keydir, err = ioutil.TempDir("", "ghpb-keystore")
//		ephemeral = keydir
//	}
//	if err != nil {
//		return nil, "", err
//	}
//	if err := os.MkdirAll(keydir, 0700); err != nil {
//		return nil, "", err
//	}
//	return accounts.NewManager(keystore.NewKeyStore(keydir, scryptN, scryptP)), ephemeral, nil
//}
