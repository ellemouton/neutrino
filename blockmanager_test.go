package neutrino

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/blockntfns"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/lightninglabs/neutrino/query"
)

const (
	// maxHeight is the height we will generate filter headers up to. We use an odd
	// number of checkpoints to ensure we can test cases where the block manager is
	// only able to fetch filter headers for one checkpoint interval rather than
	// two.
	maxHeight = 21 * uint32(wire.CFCheckptInterval)

	dbOpenTimeout = time.Second * 10
)

// mockDispatcher implements the query.Dispatcher interface and allows us to
// set up a custom Query method during tests.
type mockDispatcher struct {
	query func(requests []*query.Request,
		options ...query.QueryOption) chan error
}

var _ query.Dispatcher = (*mockDispatcher)(nil)

func (m *mockDispatcher) Query(requests []*query.Request,
	options ...query.QueryOption) chan error {

	return m.query(requests, options...)
}

// setupBlockManager initialises a blockManager to be used in tests.
func setupBlockManager() (*blockManager, headerfs.BlockHeaderStore,
	headerfs.FilterHeaderStore, func(), error) {

	// Set up the block and filter header stores.
	tempDir, err := ioutil.TempDir("", "neutrino")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to create "+
			"temporary directory: %s", err)
	}

	db, err := walletdb.Create(
		"bdb", tempDir+"/weks.db", true, dbOpenTimeout,
	)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, nil, nil, nil, fmt.Errorf("Error opening DB: %s",
			err)
	}

	cleanUp := func() {
		db.Close()
		os.RemoveAll(tempDir)
	}

	hdrStore, err := headerfs.NewBlockHeaderStore(
		tempDir, db, &chaincfg.SimNetParams,
	)
	if err != nil {
		cleanUp()
		return nil, nil, nil, nil, fmt.Errorf("Error creating block "+
			"header store: %s", err)
	}

	cfStore, err := headerfs.NewFilterHeaderStore(
		tempDir, db, headerfs.RegularFilter, &chaincfg.SimNetParams,
		nil,
	)
	if err != nil {
		cleanUp()
		return nil, nil, nil, nil, fmt.Errorf("Error creating filter "+
			"header store: %s", err)
	}

	// Set up a blockManager with the chain service we defined.
	bm, err := newBlockManager(&blockManagerCfg{
		ChainParams:      chaincfg.SimNetParams,
		BlockHeaders:     hdrStore,
		RegFilterHeaders: cfStore,
		QueryDispatcher:  &mockDispatcher{},
		BanPeer:          func(string, banman.Reason) error { return nil },
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unable to create "+
			"blockmanager: %v", err)
	}

	return bm, hdrStore, cfStore, cleanUp, nil
}

// headers wraps the different headers and filters used throughout the tests.
type headers struct {
	blockHeaders []headerfs.BlockHeader
	cfHeaders    []headerfs.FilterHeader
	checkpoints  []*chainhash.Hash
	filterHashes []chainhash.Hash
}

// generateHeaders generates block headers, filter header and hashes, and
// checkpoints from the given genesis. The onCheckpoint method will be called
// with the current cf header on each checkpoint to modify the derivation of
// the next interval.
func generateHeaders(genesisBlockHeader *wire.BlockHeader,
	genesisFilterHeader *chainhash.Hash,
	onCheckpoint func(*chainhash.Hash)) (*headers, error) {

	var blockHeaders []headerfs.BlockHeader
	blockHeaders = append(blockHeaders, headerfs.BlockHeader{
		BlockHeader: genesisBlockHeader,
		Height:      0,
	})

	var cfHeaders []headerfs.FilterHeader
	cfHeaders = append(cfHeaders, headerfs.FilterHeader{
		HeaderHash: genesisBlockHeader.BlockHash(),
		FilterHash: *genesisFilterHeader,
		Height:     0,
	})

	// The filter hashes (not the filter headers!) will be sent as
	// part of the CFHeaders response, so we also keep track of
	// them.
	genesisFilter, err := builder.BuildBasicFilter(
		chaincfg.SimNetParams.GenesisBlock, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to build genesis filter: %v",
			err)
	}

	genesisFilterHash, err := builder.GetFilterHash(genesisFilter)
	if err != nil {
		return nil, fmt.Errorf("unable to get genesis filter hash: %v",
			err)
	}

	var filterHashes []chainhash.Hash
	filterHashes = append(filterHashes, genesisFilterHash)

	// Also keep track of the current filter header. We use this to
	// calculate the next filter header, as it commits to the
	// previous.
	currentCFHeader := *genesisFilterHeader

	// checkpoints will be the checkpoints passed to
	// getCheckpointedCFHeaders.
	var checkpoints []*chainhash.Hash

	for height := uint32(1); height <= maxHeight; height++ {
		header := heightToHeader(height)
		blockHeader := headerfs.BlockHeader{
			BlockHeader: header,
			Height:      height,
		}

		blockHeaders = append(blockHeaders, blockHeader)

		// It doesn't really matter what filter the filter
		// header commit to, so just use the height as a nonce
		// for the filters.
		filterHash := chainhash.Hash{}
		binary.BigEndian.PutUint32(filterHash[:], height)
		filterHashes = append(filterHashes, filterHash)

		// Calculate the current filter header, and add to our
		// slice.
		currentCFHeader = chainhash.DoubleHashH(
			append(filterHash[:], currentCFHeader[:]...),
		)
		cfHeaders = append(cfHeaders, headerfs.FilterHeader{
			HeaderHash: header.BlockHash(),
			FilterHash: currentCFHeader,
			Height:     height,
		})

		// Each interval we must record a checkpoint.
		if height%wire.CFCheckptInterval == 0 {
			// We must make a copy of the current header to
			// avoid mutation.
			cfh := currentCFHeader
			checkpoints = append(checkpoints, &cfh)

			if onCheckpoint != nil {
				onCheckpoint(&currentCFHeader)
			}
		}
	}

	return &headers{
		blockHeaders: blockHeaders,
		cfHeaders:    cfHeaders,
		checkpoints:  checkpoints,
		filterHashes: filterHashes,
	}, nil
}

// generateResponses generates the MsgCFHeaders messages from the given queries
// and headers.
func generateResponses(msgs []wire.Message,
	headers *headers) ([]*wire.MsgCFHeaders, error) {

	// Craft a response for each message.
	var responses []*wire.MsgCFHeaders
	for _, msg := range msgs {
		// Only GetCFHeaders expected.
		q, ok := msg.(*wire.MsgGetCFHeaders)
		if !ok {
			return nil, fmt.Errorf("got unexpected message %T",
				msg)
		}

		// The start height must be set to a checkpoint height+1.
		if q.StartHeight%wire.CFCheckptInterval != 1 {
			return nil, fmt.Errorf("unexpexted start height %v",
				q.StartHeight)
		}

		var prevFilterHeader chainhash.Hash
		switch q.StartHeight {

		// If the start height is 1 the prevFilterHeader is set to the
		// genesis header.
		case 1:
			genesisFilterHeader := headers.cfHeaders[0].FilterHash
			prevFilterHeader = genesisFilterHeader

		// Otherwise we use one of the created checkpoints.
		default:
			j := q.StartHeight/wire.CFCheckptInterval - 1
			prevFilterHeader = *headers.checkpoints[j]
		}

		resp := &wire.MsgCFHeaders{
			FilterType:       q.FilterType,
			StopHash:         q.StopHash,
			PrevFilterHeader: prevFilterHeader,
		}

		// Keep adding filter hashes until we reach the stop hash.
		for h := q.StartHeight; ; h++ {
			resp.FilterHashes = append(
				resp.FilterHashes, &headers.filterHashes[h],
			)

			blockHash := headers.blockHeaders[h].BlockHash()
			if blockHash == q.StopHash {
				break
			}
		}

		responses = append(responses, resp)
	}

	return responses, nil
}

// TestBlockManagerInitialInterval tests that the block manager is able to
// handle checkpointed filter header query responses in out of order, and when
// a partial interval is already written to the store.
func TestBlockManagerInitialInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		// permute indicates whether responses should be permutated.
		permute bool

		// partialInterval indicates whether we should write parts of
		// the first checkpoint interval to the filter header store
		// before starting the test.
		partialInterval bool

		// repeat indicates whether responses should be repeated.
		repeat bool
	}

	// Generate all combinations of testcases.
	var testCases []testCase
	b := []bool{false, true}
	for _, perm := range b {
		for _, part := range b {
			for _, rep := range b {
				testCases = append(testCases, testCase{
					permute:         perm,
					partialInterval: part,
					repeat:          rep,
				})
			}
		}
	}

	for _, test := range testCases {
		test := test
		testDesc := fmt.Sprintf("permute=%v, partial=%v, repeat=%v",
			test.permute, test.partialInterval, test.repeat)

		bm, hdrStore, cfStore, cleanUp, err := setupBlockManager()
		if err != nil {
			t.Fatalf("unable to set up ChainService: %v", err)
		}
		defer cleanUp()

		// Keep track of the filter headers and block headers. Since
		// the genesis headers are written automatically when the store
		// is created, we query it to add to the slices.
		genesisBlockHeader, _, err := hdrStore.ChainTip()
		if err != nil {
			t.Fatal(err)
		}

		genesisFilterHeader, _, err := cfStore.ChainTip()
		if err != nil {
			t.Fatal(err)
		}

		headers, err := generateHeaders(genesisBlockHeader,
			genesisFilterHeader, nil)
		if err != nil {
			t.Fatalf("unable to generate headers: %v", err)
		}

		// Write all block headers but the genesis, since it is already
		// in the store.
		if err = hdrStore.WriteHeaders(headers.blockHeaders[1:]...); err != nil {
			t.Fatalf("Error writing batch of headers: %s", err)
		}

		// We emulate the case where a few filter headers are already
		// written to the store by writing 1/3 of the first interval.
		if test.partialInterval {
			err = cfStore.WriteHeaders(
				headers.cfHeaders[1 : wire.CFCheckptInterval/3]...,
			)
			if err != nil {
				t.Fatalf("Error writing batch of headers: %s",
					err)
			}
		}

		// We set up a custom query batch method for this test, as we
		// will use this to feed the blockmanager with our crafted
		// responses.
		bm.cfg.QueryDispatcher.(*mockDispatcher).query = func(
			requests []*query.Request,
			options ...query.QueryOption) chan error {

			var msgs []wire.Message
			for _, q := range requests {
				msgs = append(msgs, q.Req)
			}

			responses, err := generateResponses(msgs, headers)
			if err != nil {
				t.Fatalf("unable to generate responses: %v",
					err)
			}

			// We permute the response order if the test signals
			// that.
			perm := rand.Perm(len(responses))

			errChan := make(chan error, 1)
			go func() {
				for i, v := range perm {
					index := i
					if test.permute {
						index = v
					}

					// Before handling the response we take
					// copies of the message, as we cannot
					// guarantee that it won't be modified.
					resp := *responses[index]
					resp2 := *responses[index]

					// Let the blockmanager handle the
					// message.
					progress := requests[index].HandleResp(
						msgs[index], &resp, "",
					)

					if !progress.Finished {
						errChan <- fmt.Errorf("got "+
							"response false on "+
							"send of index %d: %v",
							index, testDesc)
						return
					}

					// If we are not testing repeated
					// responses, go on to the next
					// response.
					if !test.repeat {
						continue
					}

					// Otherwise resend the response we
					// just sent.
					progress = requests[index].HandleResp(
						msgs[index], &resp2, "",
					)
					if !progress.Finished {
						errChan <- fmt.Errorf("got "+
							"response false on "+
							"resend of index %d: "+
							"%v", index, testDesc)
						return
					}

				}
				errChan <- nil
			}()

			return errChan
		}

		// We should expect to see notifications for each new filter
		// header being connected.
		startHeight := uint32(1)
		if test.partialInterval {
			startHeight = wire.CFCheckptInterval / 3
		}
		go func() {
			for i := startHeight; i <= maxHeight; i++ {
				ntfn := <-bm.blockNtfnChan
				if _, ok := ntfn.(*blockntfns.Connected); !ok {
					t.Error("expected block connected " +
						"notification")
					return
				}
			}
		}()

		// Call the get checkpointed cf headers method with the
		// checkpoints we created to start the test.
		bm.getCheckpointedCFHeaders(
			headers.checkpoints, cfStore, wire.GCSFilterRegular,
		)

		// Finally make sure the filter header tip is what we expect.
		tip, tipHeight, err := cfStore.ChainTip()
		if err != nil {
			t.Fatal(err)
		}

		if tipHeight != maxHeight {
			t.Fatalf("expected tip height to be %v, was %v",
				maxHeight, tipHeight)
		}

		lastCheckpoint := headers.checkpoints[len(headers.checkpoints)-1]
		if *tip != *lastCheckpoint {
			t.Fatalf("expected tip to be %v, was %v",
				lastCheckpoint, tip)
		}
	}
}

// TestBlockManagerInvalidInterval tests that the block manager is able to
// determine it is receiving corrupt checkpoints and filter headers.
func TestBlockManagerInvalidInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		// wrongGenesis indicates whether we should start deriving the
		// filters from a wrong genesis.
		wrongGenesis bool

		// intervalMisaligned indicates whether each interval prev hash
		// should not line up with the previous checkpoint.
		intervalMisaligned bool

		// invalidPrevHash indicates whether the interval responses
		// should have a prev hash that doesn't mathc that interval.
		invalidPrevHash bool

		// partialInterval indicates whether we should write parts of
		// the first checkpoint interval to the filter header store
		// before starting the test.
		partialInterval bool

		// firstInvalid is the first interval response we expect the
		// blockmanager to determine is invalid.
		firstInvalid int
	}

	testCases := []testCase{
		// With a set of checkpoints and filter headers calculated from
		// the wrong genesis, the block manager should be able to
		// determine that the first interval doesn't line up.
		{
			wrongGenesis: true,
			firstInvalid: 0,
		},

		// With checkpoints calculated from the wrong genesis, and a
		// partial set of filter headers already written, the first
		// interval response should be considered invalid.
		{
			wrongGenesis:    true,
			partialInterval: true,
			firstInvalid:    0,
		},

		// With intervals not lining up, the second interval response
		// should be determined invalid.
		{
			intervalMisaligned: true,
			firstInvalid:       0,
		},

		// With misaligned intervals and a partial interval written, the
		// second interval response should be considered invalid.
		{
			intervalMisaligned: true,
			partialInterval:    true,
			firstInvalid:       0,
		},

		// With responses having invalid prev hashes, the second
		// interval response should be deemed invalid.
		{
			invalidPrevHash: true,
			firstInvalid:    1,
		},
	}

	for _, test := range testCases {
		test := test
		bm, hdrStore, cfStore, cleanUp, err := setupBlockManager()
		if err != nil {
			t.Fatalf("unable to set up ChainService: %v", err)
		}
		defer cleanUp()

		// Create a mock peer to prevent panics when attempting to ban
		// a peer that served an invalid filter header.
		mockPeer := newServerPeer(&ChainService{}, false)
		mockPeer.Peer, err = peer.NewOutboundPeer(
			newPeerConfig(mockPeer), "127.0.0.1:8333",
		)
		if err != nil {
			t.Fatal(err)
		}

		// Keep track of the filter headers and block headers. Since
		// the genesis headers are written automatically when the store
		// is created, we query it to add to the slices.
		genesisBlockHeader, _, err := hdrStore.ChainTip()
		if err != nil {
			t.Fatal(err)
		}

		genesisFilterHeader, _, err := cfStore.ChainTip()
		if err != nil {
			t.Fatal(err)
		}
		// To emulate a full node serving us filter headers derived
		// from different genesis than what we have, we flip a bit in
		// the genesis filter header.
		if test.wrongGenesis {
			genesisFilterHeader[0] ^= 1
		}

		headers, err := generateHeaders(genesisBlockHeader,
			genesisFilterHeader,
			func(currentCFHeader *chainhash.Hash) {
				// If we are testing that each interval doesn't
				// line up properly with the previous, we flip
				// a bit in the current header before
				// calculating the next interval checkpoint.
				if test.intervalMisaligned {
					currentCFHeader[0] ^= 1
				}
			})
		if err != nil {
			t.Fatalf("unable to generate headers: %v", err)
		}

		// Write all block headers but the genesis, since it is already
		// in the store.
		if err = hdrStore.WriteHeaders(headers.blockHeaders[1:]...); err != nil {
			t.Fatalf("Error writing batch of headers: %s", err)
		}

		// We emulate the case where a few filter headers are already
		// written to the store by writing 1/3 of the first interval.
		if test.partialInterval {
			err = cfStore.WriteHeaders(
				headers.cfHeaders[1 : wire.CFCheckptInterval/3]...,
			)
			if err != nil {
				t.Fatalf("Error writing batch of headers: %s",
					err)
			}
		}

		bm.cfg.QueryDispatcher.(*mockDispatcher).query = func(
			requests []*query.Request,
			options ...query.QueryOption) chan error {

			var msgs []wire.Message
			for _, q := range requests {
				msgs = append(msgs, q.Req)
			}
			responses, err := generateResponses(msgs, headers)
			if err != nil {
				t.Fatalf("unable to generate responses: %v",
					err)
			}

			// Since we used the generated checkpoints when
			// creating the responses, we must flip the
			// PrevFilterHeader bit back before sending them if we
			// are checking for misaligned intervals. This to
			// ensure we don't hit the invalid prev hash case.
			if test.intervalMisaligned {
				for i := range responses {
					if i == 0 {
						continue
					}
					responses[i].PrevFilterHeader[0] ^= 1
				}
			}

			// If we are testing for intervals with invalid prev
			// hashes, we flip a bit to corrup them, regardless of
			// whether we are testing misaligned intervals.
			if test.invalidPrevHash {
				for i := range responses {
					if i == 0 {
						continue
					}
					responses[i].PrevFilterHeader[1] ^= 1
				}
			}

			errChan := make(chan error, 1)
			go func() {

				// Check that the success of the callback match what we
				// expect.
				for i := range responses {
					progress := requests[i].HandleResp(
						msgs[i], responses[i], "",
					)
					if i == test.firstInvalid {
						if progress.Finished {
							t.Errorf("expected interval "+
								"%d to be invalid", i)
							return
						}
						errChan <- fmt.Errorf("invalid interval")
						break
					}

					if !progress.Finished {
						t.Errorf("expected interval %d to be "+
							"valid", i)
						return
					}
				}

				errChan <- nil
			}()

			return errChan
		}

		// We should expect to see notifications for each new filter
		// header being connected.
		startHeight := uint32(1)
		if test.partialInterval {
			startHeight = wire.CFCheckptInterval / 3
		}
		go func() {
			for i := startHeight; i <= maxHeight; i++ {
				ntfn := <-bm.blockNtfnChan
				if _, ok := ntfn.(*blockntfns.Connected); !ok {
					t.Error("expected block connected " +
						"notification")
					return
				}
			}
		}()

		// Start the test by calling the get checkpointed cf headers
		// method with the checkpoints we created.
		bm.getCheckpointedCFHeaders(
			headers.checkpoints, cfStore, wire.GCSFilterRegular,
		)
	}
}

// buildNonPushScriptFilter creates a CFilter with all output scripts except all
// OP_RETURNS with push-only scripts.
//
// NOTE: this is not a valid filter, only for tests.
func buildNonPushScriptFilter(block *wire.MsgBlock) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := builder.WithKeyHash(&blockHash)

	for _, tx := range block.Transactions {
		for _, txOut := range tx.TxOut {
			// The old version of BIP-158 skipped OP_RETURNs that
			// had a push-only script.
			if txOut.PkScript[0] == txscript.OP_RETURN &&
				txscript.IsPushOnlyScript(txOut.PkScript[1:]) {
				continue
			}

			b.AddEntry(txOut.PkScript)
		}
	}

	return b.Build()
}

// buildAllPkScriptsFilter creates a CFilter with all output scripts, including
// OP_RETURNS.
//
// NOTE: this is not a valid filter, only for tests.
func buildAllPkScriptsFilter(block *wire.MsgBlock) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := builder.WithKeyHash(&blockHash)

	for _, tx := range block.Transactions {
		for _, txOut := range tx.TxOut {
			// An old version of BIP-158 included all output
			// scripts.
			b.AddEntry(txOut.PkScript)
		}
	}

	return b.Build()
}

func assertBadPeers(expBad map[string]struct{}, badPeers []string) error {
	remBad := make(map[string]struct{})
	for p := range expBad {
		remBad[p] = struct{}{}
	}
	for _, peer := range badPeers {
		_, ok := remBad[peer]
		if !ok {
			return fmt.Errorf("did not expect %v to be bad", peer)
		}
		delete(remBad, peer)
	}

	if len(remBad) != 0 {
		return fmt.Errorf("did expect more bad peers")
	}

	return nil
}

// TestBlockManagerDetectBadPeers checks that we detect bad peers, like peers
// not responding to our filter query, serving inconsistent filters etc.
func TestBlockManagerDetectBadPeers(t *testing.T) {
	t.Parallel()

	var (
		stopHash        = chainhash.Hash{}
		prev            = chainhash.Hash{}
		startHeight     = uint32(100)
		badIndex        = uint32(5)
		targetIndex     = startHeight + badIndex
		fType           = wire.GCSFilterRegular
		filterBytes, _  = correctFilter.NBytes()
		filterHash, _   = builder.GetFilterHash(correctFilter)
		blockHeader     = wire.BlockHeader{}
		targetBlockHash = block.BlockHash()

		peers  = []string{"good1:1", "good2:1", "bad:1", "good3:1"}
		expBad = map[string]struct{}{
			"bad:1": {},
		}
	)

	testCases := []struct {
		// filterAnswers is used by each testcase to set the anwers we
		// want each peer to respond with on filter queries.
		filterAnswers func(string, map[string]wire.Message)
	}{
		{
			// We let the "bad" peers not respond to the filter
			// query. They should be marked bad because they are
			// unresponsive. We do this to ensure peers cannot
			// only respond to us with headers, and stall our sync
			// by not responding to filter requests.
			filterAnswers: func(p string,
				answers map[string]wire.Message) {

				if strings.Contains(p, "bad") {
					return
				}

				answers[p] = wire.NewMsgCFilter(
					fType, &targetBlockHash, filterBytes,
				)
			},
		},
		{
			// We let the "bad" peers serve filters that don't hash
			// to the filter headers they have sent.
			filterAnswers: func(p string,
				answers map[string]wire.Message) {

				filterData := filterBytes
				if strings.Contains(p, "bad") {
					filterData, _ = fakeFilter1.NBytes()
				}

				answers[p] = wire.NewMsgCFilter(
					fType, &targetBlockHash, filterData,
				)
			},
		},
	}

	for _, test := range testCases {
		// Create a mock block header store. We only need to be able to
		// serve a header for the target index.
		blockHeaders := newMockBlockHeaderStore()
		blockHeaders.heights[targetIndex] = blockHeader

		// We set up the mock queryAllPeers to only respond according to
		// the active testcase.
		answers := make(map[string]wire.Message)
		queryAllPeers := func(
			queryMsg wire.Message,
			checkResponse func(sp *ServerPeer, resp wire.Message,
				quit chan<- struct{}, peerQuit chan<- struct{}),
			options ...QueryOption) {

			for p, resp := range answers {
				pp, err := peer.NewOutboundPeer(&peer.Config{}, p)
				if err != nil {
					panic(err)
				}

				sp := &ServerPeer{
					Peer: pp,
				}
				checkResponse(sp, resp, make(chan struct{}), make(chan struct{}))
			}
		}

		for _, peer := range peers {
			test.filterAnswers(peer, answers)
		}

		// For the CFHeaders, we pretend all peers responded with the same
		// filter headers.
		msg := &wire.MsgCFHeaders{
			FilterType:       fType,
			StopHash:         stopHash,
			PrevFilterHeader: prev,
		}

		for i := uint32(0); i < 2*badIndex; i++ {
			_ = msg.AddCFHash(&filterHash)
		}

		headers := make(map[string]*wire.MsgCFHeaders)
		for _, peer := range peers {
			headers[peer] = msg
		}

		bm := &blockManager{
			cfg: &blockManagerCfg{
				BlockHeaders:  blockHeaders,
				queryAllPeers: queryAllPeers,
			},
		}

		// Now trying to detect which peers are bad, we should detect the
		// bad ones.
		badPeers, err := bm.detectBadPeers(
			headers, targetIndex, badIndex, fType,
		)
		if err != nil {
			t.Fatalf("failed to detect bad peers: %v", err)
		}

		if err := assertBadPeers(expBad, badPeers); err != nil {
			t.Fatal(err)
		}
	}
}

var (
	block1 = &wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			{
				TxOut: []*wire.TxOut{
					{
						PkScript: script1,
					},
				},
			},
			{
				TxOut: []*wire.TxOut{
					{
						PkScript: script2,
					},
				},
			},
		},
	}
	block2 = &wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			{
				TxOut: []*wire.TxOut{
					{
						PkScript: script1,
					},
				},
			},
		},
	}
	block1Filter, _     = builder.BuildBasicFilter(block1, nil)
	block1FilterHash, _ = builder.GetFilterHash(block1Filter)
	block2Filter, _     = builder.BuildBasicFilter(block2, nil)
	block2FilterHash, _ = builder.GetFilterHash(block2Filter)

	peer1    = "peer1:1"
	peer2    = "peer2:1"
	peer3    = "peer3:1"
	addr1, _ = peer.NewOutboundPeer(&peer.Config{}, peer1)
	addr2, _ = peer.NewOutboundPeer(&peer.Config{}, peer2)
	addr3, _ = peer.NewOutboundPeer(&peer.Config{}, peer3)
)

func newMockPeers(t *testing.T, peers map[string]*mockPeer,
	nextPeers ...*mockPeer) *mockPeers {

	return &mockPeers{
		t:           t,
		peers:       peers,
		nextPeers:   nextPeers,
		bannedPeers: make(map[string]bool),
	}
}

type mockPeers struct {
	t         *testing.T
	peers     map[string]*mockPeer
	nextPeers []*mockPeer

	bannedPeers map[string]bool
}

type mockPeer struct {
	peer                  *ServerPeer
	checkpoints           []*chainhash.Hash
	filterHeaders         []*chainhash.Hash
	filters               []*gcs.Filter
	blockHashToFilterHash map[chainhash.Hash]chainhash.Hash
}

func (m *mockPeers) banPeer(addr string, _ banman.Reason) error {
	m.bannedPeers[addr] = true
	delete(m.peers, addr)

	if len(m.nextPeers) == 0 {
		return nil
	}

	newPeer := m.nextPeers[0]
	m.nextPeers = m.nextPeers[1:]
	m.peers[newPeer.peer.Addr()] = newPeer
	return nil
}

func (m *mockPeers) queryAllPeers(queryMsg wire.Message,
	checkResponse func(sp *ServerPeer, resp wire.Message,
		quit chan<- struct{}, peerQuit chan<- struct{}),
	_ ...QueryOption) {

	for _, p := range m.peers {
		switch msg := queryMsg.(type) {
		case *wire.MsgGetCFCheckpt:
			filterHash, ok := p.blockHashToFilterHash[msg.StopHash]
			if !ok {
				checkResponse(p.peer, nil, make(chan struct{}),
					make(chan struct{}))
				return
			}

			resp := &wire.MsgCFCheckpt{
				FilterType: wire.GCSFilterRegular,
				StopHash:   msg.StopHash,
			}

			for _, cp := range p.checkpoints {
				resp.FilterHeaders = append(
					resp.FilterHeaders, cp,
				)

				if *cp == filterHash {
					break
				}
			}

			checkResponse(
				p.peer, resp, make(chan struct{}),
				make(chan struct{}),
			)

		case *wire.MsgGetCFHeaders:

			resp := &wire.MsgCFHeaders{
				FilterType: wire.GCSFilterRegular,
				StopHash:   msg.StopHash,
			}

			prevFilterHeight := msg.StartHeight - 1
			if len(p.filterHeaders) > int(prevFilterHeight) {

				resp.PrevFilterHeader = *p.filterHeaders[prevFilterHeight]
			}

			for i, h := range p.filterHeaders {
				if i < int(msg.StartHeight) {
					continue
				}

				resp.FilterHashes = append(
					resp.FilterHashes, h,
				)
			}

			checkResponse(
				p.peer, resp, make(chan struct{}),
				make(chan struct{}),
			)

		case *wire.MsgGetCFilters:
			for i, f := range p.filters {
				if i < int(msg.StartHeight) {
					continue
				}

				b, _ := f.NBytes()

				resp := &wire.MsgCFilter{
					FilterType: wire.GCSFilterRegular,
					Data:       b,
					BlockHash:  msg.StopHash,
				}

				checkResponse(
					p.peer, resp, make(chan struct{}),
					make(chan struct{}),
				)
			}
		default:
			m.t.Fatalf("unexpected query message type: %T", msg)
		}
	}
}

func TestResolveConflicts(t *testing.T) {
	tests := []struct {
		name                string
		cpInputs            map[string][]*chainhash.Hash
		cfg                 *blockManagerCfg
		peers               map[string]*mockPeer
		expectedCPs         []*chainhash.Hash
		expectedGoodPeers   []string
		expectedBannedPeers []string
		expectErr           bool
	}{
		{
			name: "Pass hardcoded CP check",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.MainNetParams,
				CFCheckpointInterval: 100000,
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
			},
			expectedCPs: []*chainhash.Hash{
				hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
			},
			expectedGoodPeers: []string{peer1, peer2},
		},
		{
			name: "One peer fails hardcoded CP check",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.MainNetParams,
				CFCheckpointInterval: 100000,
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
			},
			expectedCPs: []*chainhash.Hash{
				hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
			},
			expectedGoodPeers:   []string{peer2},
			expectedBannedPeers: []string{peer1},
		},
		{
			name: "All peers fails hardcoded CP check",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.MainNetParams,
				CFCheckpointInterval: 100000,
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				},
			},
			expectedBannedPeers: []string{peer1, peer2},
			expectErr:           true,
		},
		{
			name: "Initial mismatch. Ensure that peers who dont " +
				"respond with filter headers are banned.",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.RegressionNetParams,
				CFCheckpointInterval: 2,
				MaxCFHeadersPerMsg:   1,
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
				},
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				},
			},
			expectedCPs: []*chainhash.Hash{
				hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
			},
			expectedGoodPeers:   []string{peer1},
			expectedBannedPeers: []string{peer2},
		},
		{
			name: "Initial mismatch. Ensure that the filter headers" +
				"served by peers match the checkpoints they " +
				"served.",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.RegressionNetParams,
				CFCheckpointInterval: 2,
				MaxCFHeadersPerMsg:   1,
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				},
			},
			expectedCPs: []*chainhash.Hash{
				hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
			},
			expectedGoodPeers:   []string{peer1},
			expectedBannedPeers: []string{peer2},
		},
		{
			name: "Peers respond with filter headers with " +
				"differing baselines.",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.RegressionNetParams,
				CFCheckpointInterval: 2,
				MaxCFHeadersPerMsg:   1,
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr("432d9c9198e2dba0739e85aab6875cb951c36297b95a2d51131aa6919753b55d"),
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr("713d9c9198e2dba0739e85aab6875cb951c36297b95a2d51131aa6919753b55d"),
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr(""),
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr(""),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				},
			},
			expectErr: true,
		},
		{
			name: "No peer is serving filters",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.RegressionNetParams,
				CFCheckpointInterval: 2,
				MaxCFHeadersPerMsg:   1,
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filterHeaders: []*chainhash.Hash{
						hashFromStr("713d9c9198e2dba0739e85aab6875cb951c36297b95a2d51131aa6919753b55d"),
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
						hashFromStr("0dafdff27269a70293c120b14b1f5e9a72a5e8688098cfc6140b9d64f8325b99"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					filterHeaders: []*chainhash.Hash{
						hashFromStr("713d9c9198e2dba0739e85aab6875cb951c36297b95a2d51131aa6919753b55d"),
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
						hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
					},
				},
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr(""),
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("abcde471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr(""),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					hashFromStr("f28cbc1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
				},
			},
			expectErr:           true,
			expectedBannedPeers: []string{peer1, peer2},
		},
		{
			name: "Peers are serving filters but one is serving " +
				"filters that don't match the headers it sent.",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.RegressionNetParams,
				CFCheckpointInterval: 2,
				MaxCFHeadersPerMsg:   1,
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						&block1FilterHash,
					},
					filters: []*gcs.Filter{
						{},
						{},
						block1Filter,
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						&block2FilterHash,
					},
					filters: []*gcs.Filter{
						{},
						{},
						block1Filter,
					},
				},
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr(""),
					&block1FilterHash,
				},
				peer2: {
					hashFromStr(""),
					&block2FilterHash,
				},
			},
			expectedCPs: []*chainhash.Hash{
				hashFromStr(""),
				&block1FilterHash,
			},
			expectedGoodPeers:   []string{peer1},
			expectedBannedPeers: []string{peer2},
		},
		{
			name: "Both peers are serving filters matching the " +
				"headers they sent. So the block is fetched " +
				"to help determine good peer.",
			cfg: &blockManagerCfg{
				ChainParams:          chaincfg.RegressionNetParams,
				CFCheckpointInterval: 2,
				MaxCFHeadersPerMsg:   1,
				GetBlock: func(chainhash.Hash, ...QueryOption) (
					*btcutil.Block, error) {

					return btcutil.NewBlock(block1), nil
				},
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						&block1FilterHash,
					},
					filters: []*gcs.Filter{
						{},
						{},
						block1Filter,
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					filterHeaders: []*chainhash.Hash{
						hashFromStr(""),
						hashFromStr(""),
						&block2FilterHash,
					},
					filters: []*gcs.Filter{
						{},
						{},
						block2Filter,
					},
				},
			},
			cpInputs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr(""),
					&block1FilterHash,
				},
				peer2: {
					hashFromStr(""),
					&block2FilterHash,
				},
			},
			expectedCPs: []*chainhash.Hash{
				hashFromStr(""),
				&block1FilterHash,
			},
			expectedGoodPeers:   []string{peer1},
			expectedBannedPeers: []string{peer2},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			peers := newMockPeers(t, test.peers)
			test.cfg.BanPeer = peers.banPeer
			test.cfg.queryAllPeers = peers.queryAllPeers
			test.cfg.RegFilterHeaders = &mockFilterHeaderStore{
				headers: []*chainhash.Hash{
					hashFromStr("55551471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
			}
			test.cfg.BlockHeaders = &mockBlockHeaderStore{
				headers: map[chainhash.Hash]wire.BlockHeader{},
				heights: map[uint32]wire.BlockHeader{
					0: {},
					2: {},
				},
			}

			bm, err := newBlockManager(test.cfg)
			require.NoError(t, err)
			cps, goodPeers, err := bm.resolveConflict(
				test.cpInputs, bm.cfg.RegFilterHeaders,
				wire.GCSFilterRegular,
			)

			require.Len(t, peers.bannedPeers, len(test.expectedBannedPeers))
			for _, p := range test.expectedBannedPeers {
				require.True(t, peers.bannedPeers[p])
			}

			if test.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.True(
				t, compareCheckpoints(test.expectedCPs, cps),
			)

			require.Len(t, goodPeers, len(test.expectedGoodPeers))
			for _, p := range test.expectedGoodPeers {
				require.True(t, goodPeers[p])
			}
		})
	}
}

func TestSyncCheckpoints(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *blockManagerCfg
		peers           map[string]*mockPeer
		maxTries        int
		lastBlockHeight uint32
		lastBlockHash   *chainhash.Hash
		lastBlockCP     chaincfg.Checkpoint
		nextPeers       []*mockPeer
		expectedGoodCPs []*chainhash.Hash
		expectedAllCPs  map[string][]*chainhash.Hash
	}{
		{
			name: "Happy case. All peers serve same checkpoints.",
			cfg: &blockManagerCfg{
				ChainParams: chaincfg.RegressionNetParams,
			},
			maxTries:        1,
			lastBlockHeight: 2,
			lastBlockHash:   hashFromStr(""),
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					checkpoints: []*chainhash.Hash{
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
						hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
					},
					blockHashToFilterHash: map[chainhash.Hash]chainhash.Hash{
						*hashFromStr(""): *hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					checkpoints: []*chainhash.Hash{
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
					blockHashToFilterHash: map[chainhash.Hash]chainhash.Hash{
						*hashFromStr(""): *hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
			},
			expectedAllCPs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
				peer2: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
				},
			},
			expectedGoodCPs: []*chainhash.Hash{
				hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
			},
		},
		{
			name: "Ensure last block cp is given prio",
			cfg: &blockManagerCfg{
				ChainParams: chaincfg.RegressionNetParams,
			},
			maxTries:        1,
			lastBlockHeight: 2,
			lastBlockHash:   hashFromStr("123"),
			lastBlockCP: chaincfg.Checkpoint{
				Height: 3,
				Hash:   hashFromStr(""),
			},
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					checkpoints: []*chainhash.Hash{
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
						hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
					},
					blockHashToFilterHash: map[chainhash.Hash]chainhash.Hash{
						*hashFromStr(""): *hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					checkpoints: []*chainhash.Hash{
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
			},
			expectedAllCPs: map[string][]*chainhash.Hash{
				peer1: {
					hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
				},
			},
			expectedGoodCPs: []*chainhash.Hash{
				hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
			},
		},
		{
			name: "let resolve conflict return nothing. ie: conflict" +
				"and make it ban peers. then ensure that checkpints are " +
				"fetched from next peer in queue. ",
			cfg: &blockManagerCfg{
				ChainParams: chaincfg.RegressionNetParams,
			},
			maxTries:        2,
			lastBlockHeight: 2,
			lastBlockHash:   hashFromStr(""),
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					checkpoints: []*chainhash.Hash{
						hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					},
					blockHashToFilterHash: map[chainhash.Hash]chainhash.Hash{
						*hashFromStr(""): *hashFromStr("12345c1ab369eb01b7b5fe8bf59763abb73a31471fe404a26a06be4153aa7fa5"),
					},
				},
				peer2: {
					peer: &ServerPeer{Peer: addr2},
					checkpoints: []*chainhash.Hash{
						hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
					blockHashToFilterHash: map[chainhash.Hash]chainhash.Hash{
						*hashFromStr(""): *hashFromStr("e5031471732f4fbfe7a25f6a03acc1413300d5c56ae8e06b95046b8e4c0f32b3"),
					},
				},
			},
			nextPeers: []*mockPeer{
				{
					peer: &ServerPeer{Peer: addr3},
					checkpoints: []*chainhash.Hash{
						hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
					},
					blockHashToFilterHash: map[chainhash.Hash]chainhash.Hash{
						*hashFromStr(""): *hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
					},
				},
			},
			expectedAllCPs: map[string][]*chainhash.Hash{
				peer3: {
					hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
				},
			},
			expectedGoodCPs: []*chainhash.Hash{
				hashFromStr("96a31467f9edcaa3297770bc6cdf66926d5d17dfad70cb0cac285bfe9075c494"),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			peers := newMockPeers(t, test.peers, test.nextPeers...)
			test.cfg.BanPeer = peers.banPeer
			test.cfg.CFCheckpointInterval = 2
			test.cfg.queryAllPeers = peers.queryAllPeers
			test.cfg.RegFilterHeaders = &mockFilterHeaderStore{
				headers: []*chainhash.Hash{
					hashFromStr(""),
				},
			}
			test.cfg.BlockHeaders = &mockBlockHeaderStore{
				headers: map[chainhash.Hash]wire.BlockHeader{},
				heights: map[uint32]wire.BlockHeader{
					0: {},
					2: {},
				},
			}

			fm, err := newBlockManager(test.cfg)
			require.NoError(t, err)

			allCPCheckpoints := make(map[string][]*chainhash.Hash)
			var goodCPs []*chainhash.Hash
			goodCPs, allCPCheckpoints = fm.syncCheckpoints(
				test.lastBlockHeight, test.lastBlockHash,
				test.lastBlockCP, allCPCheckpoints,
				time.Millisecond*100, test.maxTries,
			)

			require.True(t, compareCheckpoints(test.expectedGoodCPs, goodCPs))
			require.True(t, compareCheckpointMaps(test.expectedAllCPs, allCPCheckpoints))
		})
	}
}

func TestHandleInvalidFilter(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 *blockManagerCfg
		peers               map[string]*mockPeer
		filterStore         []*chainhash.Hash
		maxTries            int
		nextPeers           []*mockPeer
		expectedBadPeers    []string
		expectedFilterStore []chainhash.Hash
	}{
		{
			name: "peer serves correct filter.",
			cfg: &blockManagerCfg{
				ChainParams: chaincfg.RegressionNetParams,
				BestCFCheckpoint: func(wire.BitcoinNet,
					wire.FilterType) (uint32,
					*chainhash.Hash, bool) {

					return 0, nil, false
				},
			},
			filterStore: []*chainhash.Hash{
				hashFromStr(""),
				hashFromStr(""),
			},
			maxTries: 1,
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filters: []*gcs.Filter{
						{},
						{},
						block1Filter,
					},
				},
			},
			expectedFilterStore: []chainhash.Hash{
				*hashFromStr(""),
				*hashFromStr(""),
			},
		},
		{
			name: "first 2 peers serve bad filter. Rollback",
			cfg: &blockManagerCfg{
				ChainParams: chaincfg.RegressionNetParams,
				BestCFCheckpoint: func(wire.BitcoinNet,
					wire.FilterType) (uint32,
					*chainhash.Hash, bool) {

					hash := hashFromStr("bde0854d0b2f4386a860462547140e0c6817f5b4b2ab515ef70e204e377598f8")

					return 1, hash, true
				},
			},
			filterStore: []*chainhash.Hash{
				hashFromStr("bde0854d0b2f4386a860462547140e0c6817f5b4b2ab515ef70e204e377598f8"),
				hashFromStr(""),
			},
			maxTries: 3,
			peers: map[string]*mockPeer{
				peer1: {
					peer: &ServerPeer{Peer: addr1},
					filters: []*gcs.Filter{
						{},
						{},
						block2Filter,
					},
				},
			},
			nextPeers: []*mockPeer{
				{
					peer: &ServerPeer{Peer: addr2},
					filters: []*gcs.Filter{
						{},
						{},
						block2Filter,
					},
				},
				{
					peer: &ServerPeer{Peer: addr3},
					filters: []*gcs.Filter{
						{},
						{},
						block1Filter,
					},
				},
			},
			expectedBadPeers: []string{peer1, peer2},
			expectedFilterStore: []chainhash.Hash{
				*hashFromStr("bde0854d0b2f4386a860462547140e0c6817f5b4b2ab515ef70e204e377598f8"),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			peers := newMockPeers(t, test.peers, test.nextPeers...)
			test.cfg.BanPeer = peers.banPeer
			test.cfg.queryAllPeers = peers.queryAllPeers
			cfStore := &mockFilterHeaderStore{
				headers: test.filterStore,
			}
			test.cfg.RegFilterHeaders = cfStore
			test.cfg.BlockHeaders = &mockBlockHeaderStore{
				headers: map[chainhash.Hash]wire.BlockHeader{},
				heights: map[uint32]wire.BlockHeader{
					1: {},
				},
			}

			bm, err := newBlockManager(test.cfg)
			require.NoError(t, err)

			block := btcutil.NewBlock(block1)
			block.SetHeight(2)

			badPeers, err := bm.verifyFiltersAgainstBlock(
				block, time.Millisecond*100, test.maxTries,
			)
			require.NoError(t, err)

			require.Len(t, peers.bannedPeers, len(test.expectedBadPeers))
			for _, p := range test.expectedBadPeers {
				require.True(t, peers.bannedPeers[p])
			}

			require.Len(t, badPeers, len(test.expectedBadPeers))
			for _, p := range test.expectedBadPeers {
				require.True(t, badPeers[p])
			}

			require.Len(t, cfStore.headers, len(test.expectedFilterStore))
			for i, h := range test.expectedFilterStore {
				require.Equal(t, h, *cfStore.headers[i])
			}
		})
	}
}

func compareCheckpointMaps(a, b map[string][]*chainhash.Hash) bool {
	if len(a) != len(b) {
		return false
	}

	for k, cps := range a {
		if !compareCheckpoints(cps, b[k]) {
			return false
		}
	}

	return true
}

func compareCheckpoints(a, b []*chainhash.Hash) bool {
	if len(a) != len(b) {
		return false
	}

	for i, aa := range a {
		if *aa != *b[i] {
			return false
		}
	}

	return true
}

// hashFromStr makes a chainhash.Hash from a valid hex string. If the string is
// invalid, a nil pointer will be returned.
func hashFromStr(hexStr string) *chainhash.Hash {
	hash, _ := chainhash.NewHashFromStr(hexStr)
	return hash
}

type mockFilterHeaderStore struct {
	headerfs.FilterHeaderStore

	headers []*chainhash.Hash
}

func (m *mockFilterHeaderStore) FetchHeaderByHeight(height uint32) (
	*chainhash.Hash, error) {

	if len(m.headers) == 0 {
		return nil, errors.New("no headers")
	}

	return m.headers[height], nil
}

func (m *mockFilterHeaderStore) ChainTip() (*chainhash.Hash, uint32, error) {
	if len(m.headers) == 0 {
		return nil, 0, errors.New("no headers")
	}

	tipHeight := len(m.headers) - 1
	return m.headers[tipHeight], uint32(tipHeight), nil
}

func (m *mockFilterHeaderStore) RollbackToBlock(newTip *chainhash.Hash) (
	*headerfs.BlockStamp, error) {

	i := len(m.headers) - 1
	for ; i >= 0; i-- {
		if *m.headers[i] == *newTip {
			break
		}

		m.headers = m.headers[:i]
	}

	return &headerfs.BlockStamp{
		Height: int32(i),
		Hash:   *m.headers[i],
	}, nil
}
