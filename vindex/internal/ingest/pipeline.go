// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ingest

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/metrics"
	"github.com/transparency-dev/tessera/api/layout"
)

// IngestionPipeline manages the 3-stage asynchronous leaf fetch, parallel mapping, and resequencing pipeline.
type IngestionPipeline struct {
	fetcher           TileFetcher
	cache             TileCache
	mapper            LeafMapper
	numWorkers        int
	numFetchWorkers   int
	fetchBatchBundles uint64
	bundleSize        uint64
	bundleTimeout     time.Duration
	chanCap           int
}

// DefaultPipelineChannelCapacity calculates the recommended buffer capacity for ingestion channels.
// Performance optimization: sizing channels to min(2048, max(512, GOMAXPROCS*32)) provides ample
// buffer slack for WASM mapping workers and parallel fetchers to stay fully utilized during batch commits.
func DefaultPipelineChannelCapacity() int {
	c := runtime.GOMAXPROCS(0) * 32
	if c > 2048 {
		c = 2048
	}
	if c < 512 {
		c = 512
	}
	return c
}

// DefaultFetchWorkers returns the recommended default number of concurrent tile fetch workers.
// Performance optimization: 4 parallel fetch workers prevent input starvation in the mapping pool.
func DefaultFetchWorkers() int {
	return 4
}

// DefaultFetchBatchBundles returns the default number of bundles fetched per worker batch in Stage 1.
// Performance optimization: batching 50 bundles per FetchTiles call amortizes syscalls,
// errorgroup allocation, and atomic loop overhead while maintaining streaming throughput.
func DefaultFetchBatchBundles() int {
	return 50
}

// NewPipeline creates a new IngestionPipeline instance.
func NewPipeline(fetcher TileFetcher, cache TileCache, mapper LeafMapper, numWorkers int) *IngestionPipeline {
	if numWorkers <= 0 {
		numWorkers = runtime.GOMAXPROCS(0) - 1
		if numWorkers < 1 {
			numWorkers = 1
		}
	}
	return &IngestionPipeline{
		fetcher:           fetcher,
		cache:             cache,
		mapper:            mapper,
		numWorkers:        numWorkers,
		numFetchWorkers:   DefaultFetchWorkers(),
		fetchBatchBundles: uint64(DefaultFetchBatchBundles()),
		bundleSize:        uint64(layout.EntryBundleWidth),
		bundleTimeout:     0,
		chanCap:           DefaultPipelineChannelCapacity(),
	}
}

// SetBundleTimeout sets the execution timeout per bundle for mapping workers.
func (p *IngestionPipeline) SetBundleTimeout(d time.Duration) {
	p.bundleTimeout = d
}

// SetChannelCapacity sets the buffer capacity of internal pipeline channels.
// Performance optimization: tuning channel capacity modulates the queueing latency and backpressure threshold.
func (p *IngestionPipeline) SetChannelCapacity(c int) {
	if c < 1 {
		c = 1
	}
	p.chanCap = c
}

// ChannelCapacity returns the configured buffer capacity of internal pipeline channels.
func (p *IngestionPipeline) ChannelCapacity() int {
	if p.chanCap <= 0 {
		return DefaultPipelineChannelCapacity()
	}
	return p.chanCap
}

// SetFetchWorkers sets the number of concurrent tile fetch worker goroutines.
// Performance optimization: parallelizing tile readers prevents input starvation in the mapping pool.
func (p *IngestionPipeline) SetFetchWorkers(n int) {
	if n < 1 {
		n = 1
	}
	p.numFetchWorkers = n
}

// FetchWorkers returns the configured number of concurrent tile fetch worker goroutines.
func (p *IngestionPipeline) FetchWorkers() int {
	if p.numFetchWorkers <= 0 {
		return 1
	}
	return p.numFetchWorkers
}

// SetFetchBatchBundles sets the number of bundles fetched per worker batch in Stage 1.
func (p *IngestionPipeline) SetFetchBatchBundles(n int) {
	if n < 1 {
		n = 1
	}
	p.fetchBatchBundles = uint64(n)
}

// FetchBatchBundles returns the configured number of bundles fetched per worker batch in Stage 1.
func (p *IngestionPipeline) FetchBatchBundles() int {
	if p.fetchBatchBundles == 0 {
		return DefaultFetchBatchBundles()
	}
	return int(p.fetchBatchBundles)
}

// NewIngestionPipeline creates a new IngestionPipeline instance (alias for NewPipeline).
func NewIngestionPipeline(fetcher TileFetcher, cache TileCache, mapper LeafMapper, numWorkers int) *IngestionPipeline {
	return NewPipeline(fetcher, cache, mapper, numWorkers)
}

// BundleSize returns the configured bundle capacity.
func (p *IngestionPipeline) BundleSize() uint64 {
	return p.bundleSize
}

// StreamBatches streams ordered MappedBatch items in range [fromLeafIdx, targetSize) with zero Pebble WAL writes.
func (p *IngestionPipeline) StreamBatches(ctx context.Context, fromLeafIdx, targetSize uint64) (<-chan *MappedBatch, <-chan error) {
	chanCap := p.ChannelCapacity()
	outBatches := make(chan *MappedBatch, chanCap)
	errChan := make(chan error, 1)

	if fromLeafIdx >= targetSize {
		close(outBatches)
		close(errChan)
		return outBatches, errChan
	}

	pipeCtx, cancelPipe := context.WithCancel(ctx)

	var (
		errMu    sync.Mutex
		firstErr error
	)
	recordError := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		cancelPipe()
	}

	leafBundleChan := make(chan *LeafBundle, chanCap)
	unorderedBatchChan := make(chan *MappedBatch, chanCap)

	var (
		fetchWg sync.WaitGroup
		mapWg   sync.WaitGroup
		reseqWg sync.WaitGroup
	)

	// Stage 1: TileFetcher & Cache
	numFetchWorkers := p.FetchWorkers()
	startBundle := fromLeafIdx / p.bundleSize
	endBundle := (targetSize + p.bundleSize - 1) / p.bundleSize
	nextBundleIdx := startBundle
	batchBundles := uint64(p.FetchBatchBundles())


	for w := 0; w < numFetchWorkers; w++ {
		fetchWg.Add(1)
		go func() {
			defer fetchWg.Done()
			for {
				startB := atomic.AddUint64(&nextBundleIdx, batchBundles) - batchBundles
				if startB >= endBundle {
					return
				}
				endB := startB + batchBundles
				if endB > endBundle {
					endB = endBundle
				}

				currIdx := startB * p.bundleSize
				if currIdx < fromLeafIdx {
					currIdx = fromLeafIdx
				}
				taskEndIdx := endB * p.bundleSize
				if taskEndIdx > targetSize {
					taskEndIdx = targetSize
				}

				for currIdx < taskEndIdx {
					select {
					case <-pipeCtx.Done():
						return
					default:
					}

					bundleIdx := currIdx / p.bundleSize
					var bundle *LeafBundle
					if p.cache != nil {
						if b, err := p.cache.GetBundle(bundleIdx); err == nil && b != nil {
							bEnd := b.StartLeafIdx + uint64(len(b.Leaves))
							if currIdx < bEnd && (uint64(len(b.Leaves)) == p.bundleSize || bEnd >= targetSize) {
								bundle = b
							}
						}
					}

					if bundle == nil {
						count := taskEndIdx - currIdx
						bundles, err := p.fetcher.FetchTiles(pipeCtx, currIdx, count)
						if err != nil {
							recordError(fmt.Errorf("fetch tiles [%d, %d) failed: %w", currIdx, currIdx+count, err))
							return
						}
						if len(bundles) == 0 {
							recordError(fmt.Errorf("fetch tiles [%d, %d) returned 0 bundles", currIdx, currIdx+count))
							return
						}
						for i, b := range bundles {
							if p.cache != nil {
								if err := p.cache.PutBundle(b); err != nil {
									for _, rem := range bundles[i:] {
										rem.Release()
									}
									recordError(fmt.Errorf("failed to cache bundle %d: %w", b.BundleIdx, err))
									return
								}
							}
							select {
							case <-pipeCtx.Done():
								for _, rem := range bundles[i:] {
									rem.Release()
								}
								return
							case leafBundleChan <- b:
							}
							nextIdx := b.StartLeafIdx + uint64(len(b.Leaves))
							if nextIdx <= currIdx {
								nextIdx = (b.BundleIdx + 1) * p.bundleSize
							}
							currIdx = nextIdx
						}
					} else {
						select {
						case <-pipeCtx.Done():
							return
						case leafBundleChan <- bundle:
						}
						nextIdx := bundle.StartLeafIdx + uint64(len(bundle.Leaves))
						if nextIdx <= currIdx {
							nextIdx = (bundle.BundleIdx + 1) * p.bundleSize
						}
						currIdx = nextIdx
					}
				}
			}
		}()
	}

	go func() {
		fetchWg.Wait()
		close(leafBundleChan)
	}()

	// Stage 2: MapWorkerPool
	for i := 0; i < p.numWorkers; i++ {
		mapWg.Add(1)
		go func() {
			defer mapWg.Done()

			workerCtx, cancelWorker := context.WithCancel(pipeCtx)
			defer cancelWorker()

			workerMapper := p.mapper
			if host, ok := p.mapper.(*WASMHost); ok {
				runner, err := host.NewRunner(workerCtx)
				if err != nil {
					recordError(fmt.Errorf("failed to create worker wasm runner: %w", err))
					return
				}
				defer func() { _ = runner.Close(context.Background()) }()
				workerMapper = runner
			} else if rp, ok := p.mapper.(RunnerProvider); ok {
				runner, err := rp.NewRunner(workerCtx)
				if err != nil {
					recordError(fmt.Errorf("failed to create worker runner: %w", err))
					return
				}
				defer func() { _ = runner.Close(context.Background()) }()
				workerMapper = runner
			}

			for bundle := range leafBundleChan {
				select {
				case <-pipeCtx.Done():
					bundle.Release()
					return
				default:
				}

				startIdx := bundle.StartLeafIdx
				if fromLeafIdx > startIdx {
					startIdx = fromLeafIdx
				}
				endIdx := bundle.StartLeafIdx + uint64(len(bundle.Leaves))
				if targetSize < endIdx {
					endIdx = targetSize
				}
				if startIdx >= endIdx {
					bundle.Release()
					continue
				}

				bundleCtx := workerCtx
				var bundleCancel context.CancelFunc
				if p.bundleTimeout > 0 {
					bundleCtx, bundleCancel = context.WithTimeout(workerCtx, p.bundleTimeout)
				}

				subLeaves := bundle.Leaves[startIdx-bundle.StartLeafIdx : endIdx-bundle.StartLeafIdx]
				keyMap := make(map[[32]byte][]uint64, len(subLeaves))
				var canonicalKeys map[[32]byte]string
				recordEntry := func(e MappedEntry, leafIdx uint64) error {
					kh := e.KeyHash
					if e.Key != "" {
						if err := ValidatePreimageKey([]byte(e.Key)); err != nil {
							return fmt.Errorf("invalid canonical key on leaf %d: %w", leafIdx, err)
						}
						if kh == ([32]byte{}) {
							kh = sha256.Sum256([]byte(e.Key))
						}
						if canonicalKeys == nil {
							canonicalKeys = make(map[[32]byte]string, len(subLeaves))
						}
						canonicalKeys[kh] = e.Key
					}
					keyMap[kh] = append(keyMap[kh], leafIdx)
					return nil
				}
				var mapErr error
				var numLeavesMapped int
				var totalKeysGenerated int
				startMapBundle := time.Now()

				if bm, ok := workerMapper.(BundleMapper); ok {
					bundleResults, err := bm.MapBundle(bundleCtx, subLeaves)
					if err != nil {
						metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
						if bundleCancel != nil && bundleCtx.Err() == context.DeadlineExceeded && pipeCtx.Err() == nil {
							mapErr = fmt.Errorf("mapper timed out on bundle %d: %w", bundle.BundleIdx, context.DeadlineExceeded)
						} else {
							mapErr = fmt.Errorf("mapper failed on bundle %d: %w", bundle.BundleIdx, err)
						}
					} else {
						for offset, entries := range bundleResults {
							leafIdx := startIdx + uint64(offset)
							numLeavesMapped++
							totalKeysGenerated += len(entries)

							for _, e := range entries {
								if err := recordEntry(e, leafIdx); err != nil {
									metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
									mapErr = err
									break
								}
							}
							if mapErr != nil {
								break
							}
						}
					}
				} else {
					for j, leaf := range bundle.Leaves {
						leafIdx := bundle.StartLeafIdx + uint64(j)
						if leafIdx < startIdx || leafIdx >= endIdx {
							continue
						}
						entries, err := workerMapper.MapLeaf(bundleCtx, leaf)
						if err != nil {
							metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
							if bundleCancel != nil && bundleCtx.Err() == context.DeadlineExceeded && pipeCtx.Err() == nil {
								mapErr = fmt.Errorf("mapper timed out on bundle %d (leaf %d): %w", bundle.BundleIdx, leafIdx, context.DeadlineExceeded)
							} else {
								mapErr = fmt.Errorf("mapper failed on leaf %d: %w", leafIdx, err)
							}
							break
						}
						numLeavesMapped++
						totalKeysGenerated += len(entries)

						if len(entries) > 1 {
							seenInLeaf := make(map[[32]byte]bool, len(entries))
							for _, e := range entries {
								kh := e.KeyHash
								if e.Key != "" && kh == ([32]byte{}) {
									kh = sha256.Sum256([]byte(e.Key))
								}
								if !seenInLeaf[kh] {
									seenInLeaf[kh] = true
									if err := recordEntry(e, leafIdx); err != nil {
										metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
										mapErr = err
										break
									}
								}
							}
						} else {
							for _, e := range entries {
								if err := recordEntry(e, leafIdx); err != nil {
									metrics.MapErrorsTotal.WithLabelValues("HALT").Inc()
									mapErr = err
									break
								}
							}
						}
						if mapErr != nil {
							break
						}
					}
				}
				if bundleCancel != nil {
					bundleCancel()
				}
				metrics.MapDurationSeconds.Observe(time.Since(startMapBundle).Seconds())

				if mapErr != nil {
					bundle.Release()
					recordError(mapErr)
					return
				}

				metrics.LeavesMappedTotal.Add(float64(numLeavesMapped))
				metrics.KeysMappedTotal.Add(float64(totalKeysGenerated))

				batch := &MappedBatch{
					BundleIdx:     bundle.BundleIdx,
					StartLeafIdx:  startIdx,
					EndLeafIdx:    endIdx,
					Count:         uint32(endIdx - startIdx),
					KeyMap:        keyMap,
					CanonicalKeys: canonicalKeys,
				}
				bundle.Release()

				select {
				case <-pipeCtx.Done():
					return
				case unorderedBatchChan <- batch:
				}
			}
		}()
	}

	go func() {
		mapWg.Wait()
		close(unorderedBatchChan)
	}()

	// Stage 3: Resequencer
	reseqWg.Add(1)
	go func() {
		defer reseqWg.Done()
		defer close(outBatches)

		expectedStartLeafIdx := fromLeafIdx
		pq := &batchPriorityQueue{}
		heap.Init(pq)

		for {
			select {
			case <-pipeCtx.Done():
				return
			case batch, ok := <-unorderedBatchChan:
				if !ok {
					for pq.Len() > 0 && (*pq)[0].StartLeafIdx == expectedStartLeafIdx {
						nextBatch := heap.Pop(pq).(*MappedBatch)
						select {
						case <-pipeCtx.Done():
							return
						case outBatches <- nextBatch:
						}
						expectedStartLeafIdx = nextBatch.EndLeafIdx
					}
					goto finishedDrain
				}

				heap.Push(pq, batch)
				for pq.Len() > 0 && (*pq)[0].StartLeafIdx == expectedStartLeafIdx {
					nextBatch := heap.Pop(pq).(*MappedBatch)
					select {
					case <-pipeCtx.Done():
						return
					case outBatches <- nextBatch:
					}
					expectedStartLeafIdx = nextBatch.EndLeafIdx
				}
			}
		}

	finishedDrain:
		if expectedStartLeafIdx != targetSize || pq.Len() > 0 {
			if ctx.Err() != nil {
				recordError(ctx.Err())
			} else if pipeCtx.Err() != nil {
				// Handled by recordError from upstream worker
			} else {
				recordError(fmt.Errorf("resequencer incomplete: processed up to leaf %d, want target size %d (%d batches unconsumed)", expectedStartLeafIdx, targetSize, pq.Len()))
			}
		}
	}()

	// Stage 4: Completion barrier
	go func() {
		fetchWg.Wait()
		mapWg.Wait()
		reseqWg.Wait()
		cancelPipe()

		errMu.Lock()
		if firstErr != nil {
			errChan <- firstErr
		} else if ctx.Err() != nil {
			errChan <- ctx.Err()
		}
		errMu.Unlock()
		close(errChan)
	}()

	return outBatches, errChan
}

type batchPriorityQueue []*MappedBatch

func (pq batchPriorityQueue) Len() int           { return len(pq) }
func (pq batchPriorityQueue) Less(i, j int) bool { return pq[i].StartLeafIdx < pq[j].StartLeafIdx }
func (pq batchPriorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }
func (pq *batchPriorityQueue) Push(x any)        { *pq = append(*pq, x.(*MappedBatch)) }
func (pq *batchPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}
