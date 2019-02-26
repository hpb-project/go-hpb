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

package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"sync"

	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
)

var (
	ErrInvalidChainId        = errors.New("invalid chain id for signer")
	ErrInvalidAsynsinger     = errors.New("invalid chain id  Asyn Send OK for signer")
)

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

//var singerRWLock sync.RWMutex

type Smap struct {
	Data map[common.Hash]common.Address
	L    sync.RWMutex
}

var (
	Asynsinger = &Smap{Data: make(map[common.Hash]common.Address)}
)

func SMapDelete(m *Smap, khash common.Hash) error {
	m.L.Lock()
	defer m.L.Unlock()

	delete(m.Data, khash)
	kvalue, ok := m.Data[khash]
	if ok == true {
		log.Debug("SMapDelete err", "m.Data[khash]", kvalue)
		return errors.New("SMapDelete err")
	}
	log.Trace(" SMapDelete OK", "khash", khash, "kvalue", kvalue)
	return nil
}

func SMapGet(m *Smap, khash common.Hash) (common.Address, error) {
	m.L.Lock()
	defer m.L.Unlock()

	kvalue, ok := m.Data[khash]
	if ok != true {
		log.Debug("SMapGet hash values is null error", "m.Data[khash]", m.Data[khash])
		return common.Address{}, errors.New("SMapGet hash values is null")
	}
	log.Trace(" SMapGet OK", "khash", khash, "kvalue", kvalue)
	return kvalue, nil
}

func SMapSet(m *Smap, khash common.Hash, kaddress common.Address) error {
	m.L.Lock()
	defer m.L.Unlock()

	m.Data[khash] = kaddress
	from, ok := m.Data[khash]
	if ok != true {
		log.Error("SMapSet hash values is null error", "from", from)
		return errors.New("SMapSet hash values is null")
	}
	log.Trace("SMapSet ok", "SMapSet from", from)
	return nil
}
func Deletesynsinger(signer Signer, tx *Transaction) {
	log.Trace("lenSigner", "len(synsigner)", len(Asynsinger.Data))
	SMapDelete(Asynsinger, signer.Hash(tx))
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *config.ChainConfig) Signer {
	return NewBoeSigner(config.ChainId)
}

// SignTx signs the transaction using the given signer and private key
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	//if (tx.from.Load() != nil && reflect.TypeOf(tx.from.Load()) == reflect.TypeOf(common.Address{}) && tx.from.Load().(common.Address) != common.Address{}) {
	//	return tx.from.Load().(common.Address), nil
	//}
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.2
		if sigCache.signer.Equal(signer) {
			log.Debug("Sender get Cache address ok", "tx.hash", tx.Hash(), "signer.Hash(tx)", signer.Hash(tx))
			return sigCache.from, nil
		}
	}
	asynAddress, err := SMapGet(Asynsinger, signer.Hash(tx))
	if err == nil {
		log.Debug("SenderFunc find ASynSenderCache OK", "common.Address", asynAddress, "signer.Hash(tx)", signer.Hash(tx), "tx.hash", tx.Hash())
		tx.from.Store(sigCache{signer: signer, from: asynAddress})
		return asynAddress, nil
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(sigCache{signer: signer, from: addr})
	errSet := SMapSet(Asynsinger, signer.Hash(tx), addr)
	if errSet != nil {
		log.Info("Sender SMapSet error!")
	}
	log.Trace("Sender send ok", "tx.hash", tx.Hash(), "signer.Hash(tx)", signer.Hash(tx))
	return addr, nil
}
func ASynSender(signer Signer, tx *Transaction) (common.Address, error) {

	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		if sigCache.signer.Equal(signer) {
			log.Debug("ASynSender Cache get OK", "sigCache.from", sigCache.from, "tx.Hash()", tx.Hash())
			return sigCache.from, nil
		}
	}

	asynAddress, err := SMapGet(Asynsinger, signer.Hash(tx))
	if err == nil {
		log.Debug("ASynSender SMapGet OK", "common.Address", asynAddress, "signer.Hash(tx)", signer.Hash(tx), "tx.hash", tx.Hash())
		tx.from.Store(sigCache{signer: signer, from: asynAddress})
		return asynAddress, nil
	}
	addr, err := signer.ASynSender(tx)
	if err != nil {
		return common.Address{}, err
	}
	return addr, ErrInvalidAsynsinger
}

// Signer encapsulates transaction signature handling. Note that this interface is not a
// stable API and may change at any time to accommodate new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)
	ASynSender(tx *Transaction) (common.Address, error)
	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	// Hash returns the hash to be signed.
	Hash(tx *Transaction) common.Hash
	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

// EIP155Transaction implements Signer using the EIP155 rules.
type BoeSigner struct {
	chainId, chainIdMul *big.Int
}

func NewBoeSigner(chainId *big.Int) BoeSigner {
	if chainId == nil {
		chainId = new(big.Int)
	}
	boe.BoeGetInstance().RegisterRecoverPubCallback(boecallback)

	return BoeSigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s BoeSigner) Equal(s2 Signer) bool {
	eip155, ok := s2.(BoeSigner)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

var big8 = big.NewInt(8)

func (s BoeSigner) Sender(tx *Transaction) (common.Address, error) {
	if !tx.Protected() {
		//return HomesteadSigner{}.Sender(tx)
		//TODO transaction can be unprotected ?
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
	V.Sub(V, big8)
	return recoverPlain(s.Hash(tx), tx.data.R, tx.data.S, V)
}

func (s BoeSigner) ASynSender(tx *Transaction) (common.Address, error) {
	if !tx.Protected() {
		//return HomesteadSigner{}.Sender(tx)
		log.Warn("ASynSender tx.Protected()")
		//TODO transaction can be unprotected ?
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		log.Warn("ASynSender tx.Protected()")
		return common.Address{}, ErrInvalidChainId
	}
	V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
	V.Sub(V, big8)

	return ASynrecoverPlain(s.Hash(tx), tx.data.R, tx.data.S, V)
}

// WithSignature returns a new transaction with the given signature. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s BoeSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	R = new(big.Int).SetBytes(sig[:32])
	S = new(big.Int).SetBytes(sig[32:64])
	V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	if s.chainId.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.chainIdMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s BoeSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
		s.chainId, uint(0), uint(0),
	})
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int) (common.Address, error) {
	//if Vb.BitLen() > 8 {
	//	return common.Address{}, ErrInvalidSig
	//}
	//V := byte(Vb.Uint64() - 27)
	////TODO replace homestead param
	//if !crypto.ValidateSignatureValues(V, R, S, true) {
	//	return common.Address{}, ErrInvalidSig
	//}
	//// encode the snature in uncompressed format
	//r, s := R.Bytes(), S.Bytes()
	//// recover the public key from the snature
	////pub, err := crypto.Ecrecover(sighash[:], sig)
	////64 bytes public key returned.
	//pub, err := boe.BoeGetInstance().ValidateSign(sighash[:], r, s, V)
	////xInt, yInt := elliptic.Unmarshal(crypto.S256(), result)
	////pub := &ecdsa.PublicKey{Curve: crypto.S256(), X: xInt, Y: yInt}
	//if err != nil {
	//	return common.Address{}, err
	//}
	//if len(pub) == 0 { //|| pub[0] != 4
	//	return common.Address{}, errors.New("invalid public key")
	//}
	//var addr common.Address
	//copy(addr[:], crypto.Keccak256(pub[0:])[12:])
	//return addr, nil
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, true) {
		return common.Address{}, ErrInvalidSig
	}

	// encode the snature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	//sig := make([]byte, 65)
	/*copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V*/

	pub, err := boe.BoeGetInstance().ValidateSign(sighash.Bytes(), r, s, V)
	if err != nil {
		log.Trace("boe validatesign error")
		return common.Address{}, err
	}
	// recover the public key from the snature
	/*pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}*/
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	log.Trace("boe validatesign success")
	return addr, nil
}

func ASynrecoverPlain(sighash common.Hash, R, S, Vb *big.Int) (common.Address, error) {

	if Vb.BitLen() > 8 {
		log.Error("ASynrecoverPlain Vb.BitLen() > 8")
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, true) {
		log.Error("ASynrecoverPlain !crypto.ValidateSignatureValues")
		return common.Address{}, ErrInvalidSig
	}
	r, s := R.Bytes(), S.Bytes()

	err := boe.BoeGetInstance().ASyncValidateSign(sighash.Bytes(), r, s, V)
	if err != nil {
		log.Trace("boe validatesign error")
		return common.Address{}, err
	}
	log.Trace("ASynrecoverPlain Send to BOE OK", "sighash", sighash)
	return common.Address{}, ErrInvalidAsynsinger
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}

func boecallback(rs boe.RecoverPubkey, err error) {
	if err != nil {
		log.Error("boecallback boe validatesign error")
	}
	if len(rs.Pub) == 0 || rs.Pub[0] != 4 {
		log.Error("boecallback boe invalid public key")
	}

	var addr = common.Address{}
	copy(addr[:], crypto.Keccak256(rs.Pub[1:])[12:])

	var comhash common.Hash
	copy(comhash[0:], rs.Hash[0:])

	errSet := SMapSet(Asynsinger, comhash, addr)
	if errSet != nil {
		log.Error("boecallback SMapSet error!")
	}
	log.Trace("boecallback boe rec singer data success", "comhash", comhash, "rs.hash", rs.Hash, "addr", addr)

}
