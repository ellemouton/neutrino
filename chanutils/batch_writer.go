package chanutils

import (
	"sync"
	"time"

	"github.com/btcsuite/btclog"
)

// BatchWriterConfig holds the configuration options for BatchWriter.
type BatchWriterConfig[T any] struct {
	// QueueBufferSize sets the buffer size of the output channel of the
	// concurrent queue used by the BatchWriter.
	QueueBufferSize int

	// MaxBatch is the maximum number of filters to be persisted to the DB
	// in one go.
	MaxBatch int

	// DBWritesTickerDuration is the time after receiving a filter that the
	// writer will wait for more filters before writing the current batch
	// to the DB.
	DBWritesTickerDuration time.Duration

	// Logger is the logger that the BatchWriter should use for any logs.
	Logger btclog.Logger

	// PutFilters will be used by the BatchWriter to persist filters in
	// batches.
	PutItems func(...T) error
}

// BatchWriter manages writing Filters to the DB and tries to batch the writes
// as much as possible.
type BatchWriter[T any] struct {
	started sync.Once
	stopped sync.Once

	cfg *BatchWriterConfig[T]

	queue *ConcurrentQueue[T]

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewBatchWriter constructs a new BatchWriter using the given
// BatchWriterConfig.
func NewBatchWriter[T any](cfg *BatchWriterConfig[T]) *BatchWriter[T] {
	return &BatchWriter[T]{
		cfg:   cfg,
		queue: NewConcurrentQueue[T](cfg.QueueBufferSize),
		quit:  make(chan struct{}),
	}
}

// Start starts the BatchWriter.
func (b *BatchWriter[T]) Start() {
	b.started.Do(func() {
		b.queue.Start()

		b.wg.Add(1)
		go b.manageNewItems()
	})
}

// Stop stops the BatchWriter.
func (b *BatchWriter[T]) Stop() {
	b.stopped.Do(func() {
		close(b.quit)
		b.wg.Wait()

		b.queue.Stop()
	})
}

// AddItem adds a given item to the BatchWriter queue.
func (b *BatchWriter[T]) AddItem(item T) {
	b.queue.ChanIn() <- item
}

// manageFilters manages collecting filters and persisting them to the DB.
// There are two conditions for writing a batch of filters to the DB: the first
// is if a certain threshold (MaxBatch) of filters has been collected and the
// other is if at least one filter has been collected and a timeout has been
// reached.
//
// NOTE: this must be run in a goroutine.
func (b *BatchWriter[T]) manageNewItems() {
	defer b.wg.Done()

	batch := make(chan T, b.cfg.MaxBatch)

	writeBatch := func() {
		if len(batch) == 0 {
			return
		}

		filterList := make([]T, 0, len(batch))
		for {
			select {
			case filter := <-batch:
				filterList = append(filterList, filter)
				continue
			case <-b.quit:
				return
			default:
			}

			err := b.cfg.PutItems(filterList...)
			if err != nil {
				b.cfg.Logger.Warnf("Couldn't write filters to "+
					"filterDB: %v", err)
			}

			return
		}

	}

	ticker := time.NewTicker(b.cfg.DBWritesTickerDuration)
	ticker.Stop()

	for {
		// Collect filters.
		select {
		case filter, ok := <-b.queue.ChanOut():
			if !ok {
				return
			}

			select {
			case batch <- filter:
			case <-b.quit:
				return
			}

			switch len(batch) {
			case b.cfg.MaxBatch:
				// Batch is full, so stop the timer & write
				// the batch to disk.
				ticker.Stop()
				writeBatch()
			default:
				// reset timer
				ticker.Reset(b.cfg.DBWritesTickerDuration)
			}

		case <-ticker.C:
			ticker.Stop()

			writeBatch()

		case <-b.quit:
			return
		}
	}
}
