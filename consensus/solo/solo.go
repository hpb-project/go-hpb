package solo

import (
	"errors"
	"math/big"
	"time"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/blockchain/state"

	"github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

// Solo protocol constants.
var (
	blockPeriod = uint64(5)
)

func (c *Solo) Prepare(chain consensus.ChainReader, header *types.Header) error {
	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()
	log.Info("Prepare the parameters for mining")
	header.Difficulty = big.NewInt(3)
	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(blockPeriod))
	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}
	return nil
}

type Solo struct {
}

func New() *Solo {
	return &Solo{}
}

func (c *Solo) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (c *Solo) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return nil
}

func (c *Solo) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Solo) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	return nil
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Solo) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *Solo) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (c *Solo) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(true)
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Seal implements consensus.Engine, attempting to create a sealed block.
func (c *Solo) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()
	header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, errors.New("no genesis")
	}
	return block.WithSeal(header), nil
}

func (c *Solo) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{}
}
