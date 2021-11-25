package neutrino

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/chainsync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/neutrino/headerfs"
)

type FilterManager interface{}

var _ FilterManager = (*filterMan)(nil)

type FilterManConfig struct {
	FilterType         wire.FilterType
	ChainParams        chaincfg.Params
	CPInterval         uint32
	MaxCFHeadersPerMsg uint32
	FilterHeaderStore  headerfs.FilterHeaderStore
	BlockHeaderStore   headerfs.BlockHeaderStore

	BanPeer func(addr string, reason banman.Reason) error

	GetBlock func(chainhash.Hash) (*btcutil.Block, error)

	queryAllPeers func(
		queryMsg wire.Message,
		checkResponse func(sp *ServerPeer, resp wire.Message,
			quit chan<- struct{}, peerQuit chan<- struct{}),
		options ...QueryOption)
}

type filterMan struct {
	cfg *FilterManConfig
}

func NewFilterManager(cfg *FilterManConfig) *filterMan {
	return &filterMan{
		cfg: cfg,
	}
}

func (f *filterMan) Sync() {
	// Subscribe to new block header notifications. Wait till block headers
	// are current OR filter headers are lagging by CP interval.
}

func (f *filterMan) resolveConflicts(checkpoints map[string][]*chainhash.Hash) (
	[]*chainhash.Hash, map[string]bool, error) {

	// Check the served checkpoints against the hardcoded ones. Ban any
	// peers serving the wrong filters.
	for peer, cp := range checkpoints {
		for i, header := range cp {
			height := uint32(i+1) * f.cfg.CPInterval
			err := chainsync.ControlCFHeader(
				f.cfg.ChainParams, f.cfg.FilterType, height,
				header,
			)
			if err == chainsync.ErrCheckpointMismatch {
				log.Warnf("Banning peer=%v since served "+
					"checkpoints didn't match our "+
					"checkpoint at height %d", peer, height)

				err := f.cfg.BanPeer(
					peer,
					banman.InvalidFilterHeaderCheckpoint,
				)
				if err != nil {
					log.Errorf("Unable to ban peer %v: %v",
						peer, err)
				}
				delete(checkpoints, peer)
				break
			}
			if err != nil {
				return nil, nil, err
			}
		}
	}

	if len(checkpoints) == 0 {
		return nil, nil, fmt.Errorf("no peer is serving good " +
			"cfheader checkpoints")
	}

	// Of the remaining checkpoints, check that they all are in agreement.
	// If not, we get the lowest height at which a mismatch is found.
	heightDiff, err := checkCFCheckptSanity(
		checkpoints, f.cfg.FilterHeaderStore, int(f.cfg.CPInterval),
	)
	if err != nil {
		return nil, nil, err
	}

	// If we got -1, we have full agreement between all peers and the store.
	if heightDiff == -1 {
		// Get a list of the peers that were serving the valid headers.
		goodPeers := make(map[string]bool)
		for p, _ := range checkpoints {
			goodPeers[p] = true
		}

		// Take the first peer's checkpoint list and return it.
		for _, checkpts := range checkpoints {
			return checkpts, goodPeers, nil
		}
	}

	log.Warnf("Detected mismatch at index=%v for checkpoints!!!", heightDiff)

	// Delete any responses that have fewer checkpoints than where we see a
	// mismatch.
	for peer, checkpts := range checkpoints {
		if len(checkpts) < heightDiff {
			delete(checkpoints, peer)
		}
	}

	// We detected a mismatch in checkpoints served by our peers. We now
	// want to investigate further, so we fetch all filter headers from our
	// peers starting from the height of the checkpoint that they don't
	// agree on.
	startHeight := uint32(heightDiff) * f.cfg.CPInterval
	headers, numHeaders := f.getCFHeadersForAllPeers(startHeight)

	// Delete any checkpoint lists that don't have matching headers, as
	// these are peers that didn't respond, and ban them from future
	// queries. For those that did respond, check that the filter headers
	// they served matches the checkpoints they served.
	for peer, cps := range checkpoints {
		hds, ok := headers[peer]
		if !ok {
			err := f.cfg.BanPeer(
				peer, banman.InvalidFilterHeaderCheckpoint,
			)
			if err != nil {
				log.Errorf("Unable to ban peer %v: %v", peer,
					err)
			}
			delete(checkpoints, peer)
			continue
		}

		for i := heightDiff; i <= len(cps); i++ {
			cpHeight := uint32(i) * f.cfg.CPInterval

			if cpHeight < startHeight ||
				cpHeight >= startHeight+
					uint32(len(hds.FilterHashes)) {

				break
			}

			if *hds.FilterHashes[cpHeight-startHeight] != *cps[i] {
				err := f.cfg.BanPeer(
					peer, banman.InvalidFilterHeaderCheckpoint,
				)
				if err != nil {
					log.Errorf("Unable to ban peer %v: %v",
						peer, err)
				}
				delete(checkpoints, peer)
				break
			}
		}

	}

	if len(checkpoints) == 0 {
		return nil, nil, fmt.Errorf("no peer is serving good cfheaders")
	}

	// Make sure we're working off the same baseline. Otherwise, we want to
	// go back and get checkpoints again.
	// TODO(elle): this could result in endless loop since no peers are
	// banned here.
	var hash chainhash.Hash
	for _, msg := range headers {
		if hash == zeroHash {
			hash = msg.PrevFilterHeader
		} else if hash != msg.PrevFilterHeader {
			return nil, nil, fmt.Errorf("mismatch between filter " +
				"headers expected to be the same")
		}
	}

	// Now iterate over each peer's served headers and check that they all
	// match. If we find a difference then we will fetch the actual block.
	// From the block, we can calculate the filter and determine which
	// peer is serving the correct filter header.
	for i := 0; i < numHeaders; i++ {
		if checkForCFHeaderMismatch(headers, i) {
			// Get the block header for this height, along with the
			// block as well.
			targetHeight := startHeight + uint32(i)

			badPeers, err := f.detectBadPeers(
				headers, targetHeight, uint32(i),
			)
			if err != nil {
				return nil, nil, err
			}

			log.Warnf("Banning %v peers due to invalid filter "+
				"headers", len(badPeers))

			for _, peer := range badPeers {
				err := f.cfg.BanPeer(
					peer, banman.InvalidFilterHeader,
				)
				if err != nil {
					log.Errorf("Unable to ban peer %v: %v",
						peer, err)
				}
				delete(headers, peer)
				delete(checkpoints, peer)
			}
		}
	}

	if len(checkpoints) == 0 {
		return nil, nil, fmt.Errorf("no peer is serving good cfilters")
	}

	// Check sanity again. If we're sane, return a matching checkpoint
	// list. If not, return an error and download checkpoints from
	// remaining peers.
	heightDiff, err = checkCFCheckptSanity(
		checkpoints, f.cfg.FilterHeaderStore, int(f.cfg.CPInterval),
	)
	if err != nil {
		return nil, nil, err
	}

	// If we got -1, we have full agreement between all peers and the store.
	if heightDiff == -1 {
		// Get a list of the peers that were serving the valid headers.
		goodPeers := make(map[string]bool)
		for p, _ := range checkpoints {
			goodPeers[p] = true
		}

		// Take the first peer's checkpoint list and return it.
		for _, checkpts := range checkpoints {
			return checkpts, goodPeers, nil
		}
	}

	// Otherwise, return an error and allow the loop which calls this
	// function to call it again with the new set of peers.
	return nil, nil, fmt.Errorf("got mismatched checkpoints")
}

// checkCFCheckptSanity checks whether all peers which have responded agree.
// If so, it returns -1; otherwise, it returns the earliest index at which at
// least one of the peers differs. The checkpoints are also checked against the
// existing store up to the tip of the store. If all of the peers match but
// the store doesn't, the height at which the mismatch occurs is returned.
func checkCFCheckptSanity(cp map[string][]*chainhash.Hash,
	headerStore headerfs.FilterHeaderStore, cpInterval int) (int, error) {

	// Get the known best header to compare against checkpoints.
	_, storeTip, err := headerStore.ChainTip()
	if err != nil {
		return 0, err
	}

	// Determine the maximum length of each peer's checkpoint list. If they
	// differ, we don't return yet because we want to make sure they match
	// up to the shortest one.
	maxLen := 0
	for _, checkpoints := range cp {
		if len(checkpoints) > maxLen {
			maxLen = len(checkpoints)
		}
	}

	// Compare the actual checkpoints against each other and anything
	// stored in the header store.
	for i := 0; i < maxLen; i++ {
		var checkpoint chainhash.Hash
		for _, checkpoints := range cp {
			if i >= len(checkpoints) {
				continue
			}
			if checkpoint == zeroHash {
				checkpoint = *checkpoints[i]
			}
			if checkpoint != *checkpoints[i] {
				log.Warnf("mismatch at %v, expected %v got "+
					"%v", i, checkpoint, checkpoints[i])
				return i, nil
			}
		}

		ckptHeight := uint32((i + 1) * cpInterval)

		if ckptHeight <= storeTip {
			header, err := headerStore.FetchHeaderByHeight(
				ckptHeight,
			)
			if err != nil {
				return i, err
			}

			if *header != checkpoint {
				log.Warnf("mismatch at height %v, expected %v got "+
					"%v", ckptHeight, header, checkpoint)
				return i, nil
			}
		}
	}

	return -1, nil
}

// checkForCFHeaderMismatch checks all peers' responses at a specific position
// and detects a mismatch. It returns true if a mismatch has occurred.
func checkForCFHeaderMismatch(headers map[string]*wire.MsgCFHeaders,
	idx int) bool {

	// First, see if we have a mismatch.
	hash := zeroHash
	for _, msg := range headers {
		if len(msg.FilterHashes) <= idx {
			continue
		}

		if hash == zeroHash {
			hash = *msg.FilterHashes[idx]
			continue
		}

		if hash != *msg.FilterHashes[idx] {
			// We've found a mismatch!
			return true
		}
	}

	return false
}

// detectBadPeers fetches filters and the block at the given height to attempt
// to detect which peers are serving bad filters.
func (f *filterMan) detectBadPeers(headers map[string]*wire.MsgCFHeaders,
	targetHeight, filterIndex uint32) ([]string, error) {

	log.Warnf("Detected cfheader mismatch at height=%v!!!", targetHeight)

	// Get the block header for this height.
	header, err := f.cfg.BlockHeaderStore.FetchHeaderByHeight(targetHeight)
	if err != nil {
		return nil, err
	}

	// Fetch filters from the peers in question.
	// TODO(halseth): query only peers from headers map.
	filtersFromPeers := f.fetchFilterFromAllPeers(
		targetHeight, header.BlockHash(), f.cfg.FilterType,
	)

	var badPeers []string
	for peer, msg := range headers {
		filter, ok := filtersFromPeers[peer]

		// If a peer did not respond, ban it immediately.
		if !ok {
			log.Warnf("Peer %v did not respond to filter "+
				"request, considering bad", peer)
			badPeers = append(badPeers, peer)
			continue
		}

		// If the peer is serving filters that isn't consistent with
		// its filter hashes, ban it.
		hash, err := builder.GetFilterHash(filter)
		if err != nil {
			return nil, err
		}
		if hash != *msg.FilterHashes[filterIndex] {
			log.Warnf("Peer %v serving filters not consistent "+
				"with filter hashes, considering bad.", peer)
			badPeers = append(badPeers, peer)
		}
	}

	if len(badPeers) != 0 {
		return badPeers, nil
	}

	// If all peers responded with consistent filters and hashes, get the
	// block and use it to detect who is serving bad filters.
	block, err := f.cfg.GetBlock(header.BlockHash())
	if err != nil {
		return nil, err
	}

	log.Warnf("Attempting to reconcile cfheader mismatch amongst %v peers",
		len(headers))

	return resolveFilterMismatchFromBlock(
		block.MsgBlock(), f.cfg.FilterType, filtersFromPeers,

		// We'll require a strict majority of our peers to agree on
		// filters.
		(len(filtersFromPeers)+2)/2,
	)
}

// resolveFilterMismatchFromBlock will attempt to cross-reference each filter
// in filtersFromPeers with the given block, based on what we can reconstruct
// and verify from the filter in question. We'll return all the peers that
// returned what we believe to be an invalid filter. The threshold argument is
// the minimum number of peers we need to agree on a filter before banning the
// other peers.
//
// We'll use a few strategies to figure out which peers we believe serve
// invalid filters:
//	1. If a peers' filter doesn't match on a script that must match, we know
//	the filter is invalid.
//	2. If a peers' filter matches on a script that _should not_ match, it
//	is potentially invalid. In this case we ban peers that matches more
//	such scripts than other peers.
//	3. If we cannot detect which filters are invalid from the block
//	contents, we ban peers serving filters different from the majority of
//	peers.
func resolveFilterMismatchFromBlock(block *wire.MsgBlock,
	fType wire.FilterType, filtersFromPeers map[string]*gcs.Filter,
	threshold int) ([]string, error) {

	badPeers := make(map[string]struct{})

	log.Infof("Attempting to pinpoint mismatch in cfheaders for block=%v",
		block.Header.BlockHash())

	// Based on the type of filter, our verification algorithm will differ.
	// Only regular filters are currently defined.
	if fType != wire.GCSFilterRegular {
		return nil, fmt.Errorf("unknown filter: %v", fType)
	}

	// Since we don't expect OP_RETURN scripts to be included in the block,
	// we keep a counter for how many matches for each peer. Since there
	// might be false positives, an honest peer might still match on
	// OP_RETURNS, but we can attempt to ban peers that have more matches
	// than other peers.
	opReturnMatches := make(map[string]int)

	// We'll now run through each peer and ensure that each output
	// script is included in the filter that they responded with to
	// our query.
	for peerAddr, filter := range filtersFromPeers {
		// We'll ensure that all the filters include every output
		// script within the block. From the scriptSig and witnesses of
		// the inputs we can also derive most of the scripts of the
		// outputs being spent (at least for standard scripts).
		numOpReturns, err := VerifyBasicBlockFilter(
			filter, btcutil.NewBlock(block),
		)
		if err != nil {
			// Mark peer bad if we cannot verify its filter.
			log.Warnf("Unable to check filter match for "+
				"peer %v, marking as bad: %v", peerAddr, err)

			badPeers[peerAddr] = struct{}{}
			continue
		}
		opReturnMatches[peerAddr] = numOpReturns

		// TODO(roasbeef): eventually just do a comparison against
		// decompressed filters
	}

	// TODO: We can add an after-the-fact countermeasure here against
	// eclipse attacks. If the checkpoints don't match the store, we can
	// check whether the store or the checkpoints we got from the network
	// are correct.

	// Return the bad peers if we have already found some.
	if len(badPeers) > 0 {
		invalidPeers := make([]string, 0, len(badPeers))
		for peer := range badPeers {
			invalidPeers = append(invalidPeers, peer)
		}

		return invalidPeers, nil
	}

	// If we couldn't immediately detect bad peers, we check if some peers
	// were matching more OP_RETURNS than the rest.
	mostMatches := 0
	for _, cnt := range opReturnMatches {
		if cnt > mostMatches {
			mostMatches = cnt
		}
	}

	// Gather up the peers with the most OP_RETURN matches.
	var potentialBans []string
	for peer, cnt := range opReturnMatches {
		if cnt == mostMatches {
			potentialBans = append(potentialBans, peer)
		}
	}

	// If only a few peers had matching OP_RETURNS, we assume they are bad.
	numRemaining := len(filtersFromPeers) - len(potentialBans)
	if len(potentialBans) > 0 && numRemaining >= threshold {
		log.Warnf("Found %d peers serving filters with unexpected "+
			"OP_RETURNS. %d peers remaining", len(potentialBans),
			numRemaining)

		return potentialBans, nil
	}

	// If all peers where serving filters consistent with the block, we
	// cannot know for sure which one is dishonest (since we don't have the
	// prevouts to deterministically reconstruct the filter). In this
	// situation we go with the majority.
	count := make(map[chainhash.Hash]int)
	best := 0
	for _, filter := range filtersFromPeers {
		hash, err := builder.GetFilterHash(filter)
		if err != nil {
			return nil, err
		}

		count[hash]++
		if count[hash] > best {
			best = count[hash]
		}
	}

	// If the number of peers serving the most common filter didn't match
	// our threshold, there's not more we can do.
	if best < threshold {
		return nil, fmt.Errorf("only %d peers serving consistent "+
			"filters, need %d", best, threshold)
	}

	// Mark all peers serving a filter other than the most common one as
	// bad.
	for peerAddr, filter := range filtersFromPeers {
		hash, err := builder.GetFilterHash(filter)
		if err != nil {
			return nil, err
		}

		if count[hash] < best {
			log.Warnf("Peer %v is serving filter with hash(%v) "+
				"other than majority, marking as bad",
				peerAddr, hash)
			badPeers[peerAddr] = struct{}{}
		}
	}

	invalidPeers := make([]string, 0, len(badPeers))
	for peer := range badPeers {
		invalidPeers = append(invalidPeers, peer)
	}

	return invalidPeers, nil
}

// fetchFilterFromAllPeers attempts to fetch a filter for the target filter
// type and blocks from all peers connected to the block manager. This method
// returns a map which allows the caller to match a peer to the filter it
// responded with.
func (f *filterMan) fetchFilterFromAllPeers(
	height uint32, blockHash chainhash.Hash,
	filterType wire.FilterType) map[string]*gcs.Filter {

	// We'll use this map to collate all responses we receive from each
	// peer.
	filterResponses := make(map[string]*gcs.Filter)

	// We'll now request the target filter from each peer, using a stop
	// hash at the target block hash to ensure we only get a single filter.
	filterReqMsg := wire.NewMsgGetCFilters(filterType, height, &blockHash)
	f.cfg.queryAllPeers(
		filterReqMsg,
		func(sp *ServerPeer, resp wire.Message, quit chan<- struct{},
			peerQuit chan<- struct{}) {

			switch response := resp.(type) {
			// We're only interested in "cfilter" messages.
			case *wire.MsgCFilter:
				// If the response doesn't match our request.
				// Ignore this message.
				if blockHash != response.BlockHash ||
					filterType != response.FilterType {
					return
				}

				// Now that we know we have the proper filter,
				// we'll decode it into an object the caller
				// can utilize.
				gcsFilter, err := gcs.FromNBytes(
					builder.DefaultP, builder.DefaultM,
					response.Data,
				)
				if err != nil {
					// Malformed filter data. We can ignore
					// this message.
					return
				}

				// Now that we're able to properly parse this
				// filter, we'll assign it to its source peer,
				// and wait for the next response.
				filterResponses[sp.Addr()] = gcsFilter

			default:
			}
		},
	)

	return filterResponses
}

// getCFHeadersForAllPeers runs a query for cfheaders at a specific height and
// returns a map of responses from all peers. The second return value is the
// number for cfheaders in each response.
func (f *filterMan) getCFHeadersForAllPeers(height uint32) (
	map[string]*wire.MsgCFHeaders, int) {

	// Create the map we're returning.
	headers := make(map[string]*wire.MsgCFHeaders)

	// Get the header we expect at either the tip of the block header store
	// or at the end of the maximum-size response message, whichever is
	// larger.
	stopHeader, stopHeight, err := f.cfg.BlockHeaderStore.ChainTip()
	if err != nil {
		return nil, 0
	}
	if stopHeight-height >= f.cfg.MaxCFHeadersPerMsg {
		stopHeader, err = f.cfg.BlockHeaderStore.FetchHeaderByHeight(
			height + f.cfg.MaxCFHeadersPerMsg - 1,
		)
		if err != nil {
			return nil, 0
		}

		// We'll make sure we also update our stopHeight so we know how
		// many headers to expect below.
		stopHeight = height + f.cfg.MaxCFHeadersPerMsg - 1
	}

	// Calculate the hash and use it to create the query message.
	stopHash := stopHeader.BlockHash()
	msg := wire.NewMsgGetCFHeaders(f.cfg.FilterType, height, &stopHash)
	numHeaders := int(stopHeight - height + 1)

	// Send the query to all peers and record their responses in the map.
	f.cfg.queryAllPeers(
		msg,
		func(sp *ServerPeer, resp wire.Message, quit chan<- struct{},
			peerQuit chan<- struct{}) {

			m, isHeaders := resp.(*wire.MsgCFHeaders)
			if isHeaders {
				if m.StopHash == stopHash &&
					m.FilterType == f.cfg.FilterType &&
					len(m.FilterHashes) == numHeaders {

					headers[sp.Addr()] = m

					// We got an answer from this peer so
					// that peer's goroutine can stop.
					close(peerQuit)
				}
			}
		},
	)

	return headers, numHeaders
}
