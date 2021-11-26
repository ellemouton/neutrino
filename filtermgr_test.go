package neutrino

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcutil/gcs"

	"github.com/btcsuite/btcd/peer"

	"github.com/btcsuite/btcutil/gcs/builder"

	"github.com/lightninglabs/neutrino/headerfs"

	"github.com/lightninglabs/neutrino/banman"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"

	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestResolveConflicts(t *testing.T) {
	tests := []struct {
		name                string
		cpInputs            map[string][]*chainhash.Hash
		cfg                 *FilterManConfig
		peers               map[string]*mockPeer
		expectedCPs         []*chainhash.Hash
		expectedGoodPeers   []string
		expectedBannedPeers []string
		expectErr           bool
	}{
		{
			name: "Pass hardcoded CP check",
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.MainNetParams.Net,
				},
				CPInterval: 100000,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.MainNetParams.Net,
				},
				CPInterval: 100000,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.MainNetParams.Net,
				},
				CPInterval: 100000,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
				CPInterval:         2,
				MaxCFHeadersPerMsg: 1,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
				CPInterval:         2,
				MaxCFHeadersPerMsg: 1,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
				CPInterval:         2,
				MaxCFHeadersPerMsg: 1,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
				CPInterval:         2,
				MaxCFHeadersPerMsg: 1,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
				CPInterval:         2,
				MaxCFHeadersPerMsg: 1,
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
				CPInterval:         2,
				MaxCFHeadersPerMsg: 1,
				GetBlock: func(_ chainhash.Hash) (*btcutil.Block, error) {
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
		t.Run(test.name, func(t *testing.T) {
			peers := newMockPeers(t, test.peers)
			test.cfg.BanPeer = peers.banPeer
			test.cfg.queryAllPeers = peers.queryAllPeers
			test.cfg.FilterType = wire.GCSFilterRegular
			test.cfg.FilterHeaderStore = &mockFilterHeaderStore{
				headers: []*chainhash.Hash{
					hashFromStr(""),
				},
			}
			test.cfg.BlockHeaderStore = &mockBlockHeaderStore{
				headers: map[chainhash.Hash]wire.BlockHeader{},
				heights: map[uint32]wire.BlockHeader{
					0: {},
					2: {},
				},
			}

			fm := NewFilterManager(test.cfg)

			cps, goodPeers, err := fm.resolveConflicts(test.cpInputs)

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
		cfg             *FilterManConfig
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
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
			cfg: &FilterManConfig{
				ChainParams: chaincfg.Params{
					Net: chaincfg.RegressionNetParams.Net,
				},
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
		t.Run(test.name, func(t *testing.T) {
			peers := newMockPeers(t, test.peers, test.nextPeers...)
			test.cfg.BanPeer = peers.banPeer
			test.cfg.CPInterval = 2
			test.cfg.FilterType = wire.GCSFilterRegular
			test.cfg.queryAllPeers = peers.queryAllPeers
			test.cfg.FilterHeaderStore = &mockFilterHeaderStore{
				headers: []*chainhash.Hash{
					hashFromStr(""),
				},
			}
			test.cfg.BlockHeaderStore = &mockBlockHeaderStore{
				headers: map[chainhash.Hash]wire.BlockHeader{},
				heights: map[uint32]wire.BlockHeader{
					0: {},
					2: {},
				},
			}

			fm := NewFilterManager(test.cfg)
			fm.lastBlockCP = test.lastBlockCP

			goodCPs := fm.syncCheckpoints(
				test.lastBlockHeight, test.lastBlockHash,
				time.Millisecond*100, test.maxTries,
			)

			require.True(t, compareCheckpoints(test.expectedGoodCPs, goodCPs))
			require.True(t, compareCheckpointMaps(test.expectedAllCPs, fm.allCFCheckpoints))
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
	filterHeaders         []*chainhash.Hash
	checkpoints           []*chainhash.Hash
	filters               []*gcs.Filter
	blockHashToFilterHash map[chainhash.Hash]chainhash.Hash
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
			if prevFilterHeight >= 0 &&
				len(p.filterHeaders) > int(prevFilterHeight) {

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
