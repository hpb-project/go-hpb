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

package node

import (
	"time"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/bitutil"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/blockchain/bloombits"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

const (
	// bloomServiceThreads is the number of goroutines used globally by an Hpb
	// instance to service bloombits lookups for all running filters.
	bloomServiceThreads = 16

	// bloomFilterThreads is the number of goroutines used locally per filter to
	// multiplex requests onto the global servicing goroutines.
	bloomFilterThreads = 3

	// bloomRetrievalBatch is the maximum number of bloom bit retrievals to service
	// in a single batch.
	bloomRetrievalBatch = 16

	// bloomRetrievalWait is the maximum time to wait for enough bloom bit requests
	// to accumulate request an entire batch (avoiding hysteresis).
	bloomRetrievalWait = time.Duration(0)
)

// startBloomHandlers starts a batch of goroutines to accept bloom bit database
// retrievals from possibly a range of filters and serving the data to satisfy.
func (h *Node) startBloomHandlers() {
	for i := 0; i < bloomServiceThreads; i++ {
		go func() {
			for {
				select {
				case <-h.shutdownChan:
					return

				case request := <-h.bloomRequests:
					task := <-request

					task.Bitsets = make([][]byte, len(task.Sections))
					for i, section := range task.Sections {
						head := bc.GetCanonicalHash(h.HpbDb, (section+1)*config.BloomBitsBlocks-1)
						blob, err := bitutil.DecompressBytes(bc.GetBloomBits(h.HpbDb, task.Bit, section, head), int(config.BloomBitsBlocks)/8)
						if err != nil {
							panic(err)
						}
						task.Bitsets[i] = blob
					}
					request <- task
				}
			}
		}()
	}
}

const (
	// bloomConfirms is the number of confirmation blocks before a bloom section is
	// considered probably final and its rotated bits are calculated.
	bloomConfirms = 256

	// bloomThrottling is the time to wait between processing two consecutive index
	// sections. It's useful during chain upgrades to prevent disk overload.
	bloomThrottling = 100 * time.Millisecond
)

// BloomIndexer implements a bc.ChainIndexer, building up a rotated bloom bits index
// for the Hpb header bloom filters, permitting blazing fast filtering.
type BloomIndexer struct {
	size uint64 // section size to generate bloombits for

	db  hpbdb.Database       // database instance to write index data and metadata into
	gen *bloombits.Generator // generator to rotate the bloom bits crating the bloom index

	section uint64      // Section is the section number being processed currently
	head    common.Hash // Head is the hash of the last header processed
}

// NewBloomIndexer returns a chain indexer that generates bloom bits data for the
// canonical chain for fast logs filtering.
func NewBloomIndexer(db hpbdb.Database, size uint64) *bc.ChainIndexer {
	backend := &BloomIndexer{
		db:   db,
		size: size,
	}
	table := hpbdb.NewTable(db, string(bc.BloomBitsIndexPrefix))

	return bc.NewChainIndexer(db, table, backend, size, bloomConfirms, bloomThrottling, "bloombits")
}

// Reset implements bc.ChainIndexerBackend, starting a new bloombits index
// section.
func (b *BloomIndexer) Reset(section uint64) {
	gen, err := bloombits.NewGenerator(uint(b.size))
	if err != nil {
		panic(err)
	}
	b.gen, b.section, b.head = gen, section, common.Hash{}
}

// Process implements bc.ChainIndexerBackend, adding a new header's bloom into
// the index.
func (b *BloomIndexer) Process(header *types.Header) {
	b.gen.AddBloom(uint(header.Number.Uint64()-b.section*b.size), header.Bloom)
	b.head = header.Hash()
}

// Commit implements bc.ChainIndexerBackend, finalizing the bloom section and
// writing it out into the database.
func (b *BloomIndexer) Commit() error {
	batch := b.db.NewBatch()

	for i := 0; i < types.BloomBitLength; i++ {
		bits, err := b.gen.Bitset(uint(i))
		if err != nil {
			return err
		}
		bc.WriteBloomBits(batch, uint(i), b.section, b.head, bitutil.CompressBytes(bits))
	}
	return batch.Write()
}
