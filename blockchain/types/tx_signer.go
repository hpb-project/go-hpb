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

package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
)

var (
	ErrInvalidChainId    = errors.New("invalid chain id for signer")
	ErrInvalidAsynsinger = errors.New("invalid chain id  Asyn Send OK for signer")
)

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
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

	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.2
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}
	txhash := tx.Hash()
	address, err := Sendercache.Get(txhash)
	if err == nil {
		tx.from.Store(sigCache{signer: signer, from: address})
		return address, nil
	}
	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	Sendercache.GetOrSet(txhash, addr)
	tx.from.Store(sigCache{signer: signer, from: addr})

	return addr, nil
}
func ASynSender(signer Signer, tx *Transaction) (common.Address, error) {

	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	asynAddress, err := Sendercache.Get(tx.Hash())
	if err == nil {
		tx.from.Store(sigCache{signer: signer, from: asynAddress})
		return asynAddress, nil
	}
	return signer.ASynSender(tx)
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
	// Compable Hash, returns the hash with tx.ChainId(), only used to recover pubkey, can't used to signTx.
	CompableHash(tx *Transaction) common.Hash
	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

// EIP155Transaction implements Signer using the EIP155 rules.
type BoeSigner struct {
	chainId, chainIdMul *big.Int
}

func CheckChainIdCompatible(chainId *big.Int) bool {
	return chainId.Cmp(config.CompatibleChainId) == 0
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

	return ok && (CheckChainIdCompatible(eip155.chainId) || (eip155.chainId.Cmp(s.chainId) == 0))
}

var big8 = big.NewInt(8)

func compableV(v *big.Int) bool {
	// we compable the transaction with chainId = 1,
	// so matched v value is 37 or 38. (v = chainId * 2 + 35 or v = chainId * 2 + 36)
	return (v.Cmp(big.NewInt(37)) == 0) || (v.Cmp(big.NewInt(38)) == 0)
}

func (s BoeSigner) Sender(tx *Transaction) (common.Address, error) {
if !CheckChainIdCompatible(tx.ChainId()) && (tx.ChainId().Cmp(s.chainId) != 0) {
		return common.Address{}, ErrInvalidChainId
	}
	if compableV(tx.data.V) {
		compableChainId := config.CompatibleChainId
		compableChainIdMul := new(big.Int).Mul(compableChainId, big.NewInt(2))
		V := new(big.Int).Sub(tx.data.V, compableChainIdMul)
		V.Sub(V, big8)
		return recoverPlain(s.CompableHash(tx), tx.data.R, tx.data.S, V)
	} else {
		V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
		V.Sub(V, big8)
		return recoverPlain(s.Hash(tx), tx.data.R, tx.data.S, V)
	}
}

func (s BoeSigner) ASynSender(tx *Transaction) (common.Address, error) {
	if !CheckChainIdCompatible(tx.ChainId()) && (tx.ChainId().Cmp(s.chainId) != 0) {
		log.Warn("ASynSender tx.Protected()")
		return common.Address{}, ErrInvalidChainId
	}

	if compableV(tx.data.V) {
		compableChainId := config.CompatibleChainId
		compableChainIdMul := new(big.Int).Mul(compableChainId, big.NewInt(2))
		V := new(big.Int).Sub(tx.data.V, compableChainIdMul)
		V.Sub(V, big8)
		return ASynrecoverPlain(tx.Hash(), s.CompableHash(tx), tx.data.R, tx.data.S, V)
	} else {
		V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
		V.Sub(V, big8)
		return ASynrecoverPlain(tx.Hash(), s.Hash(tx), tx.data.R, tx.data.S, V)
	}

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

// CompableHash returns the hash with tx.ChainId(), used to recover the pubkey , can't use to signTx.
func (s BoeSigner) CompableHash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
		tx.ChainId(), uint(0), uint(0),
	})
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, true) {
		return common.Address{}, ErrInvalidSig
	}

	// encode the snature in uncompressed format
	r, s := R.Bytes(), S.Bytes()

	pub, err := boe.BoeGetInstance().ValidateSign(sighash.Bytes(), r, s, V)
	if err != nil {
		log.Trace("boe validatesign error")
		return common.Address{}, err
	}

	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

func ASynrecoverPlain(txhash common.Hash, sighash common.Hash, R, S, Vb *big.Int) (common.Address, error) {

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

	err := boe.BoeGetInstance().ASyncValidateSign(txhash.Bytes(), sighash.Bytes(), r, s, V)
	if err != nil {
		log.Trace("boe validatesign error")
		return common.Address{}, err
	}
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
	copy(comhash[0:], rs.TxHash[0:])

	Sendercache.GetOrSet(comhash, addr)
}
