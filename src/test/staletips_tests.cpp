// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/cs_main.h>
#include <staletips.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(staletips_tests, BasicTestingSetup)

namespace {

struct BlockTree
{
    std::deque<uint256> hashes;
    std::vector<std::unique_ptr<CBlockIndex>> blocks;
    CChain active_chain;
    uint32_t next_nonce{1};

    CBlockIndex* Add(CBlockIndex* prev,
                     bool active,
                      bool have_data = false,
                      uint32_t bits = 0x1d00ffff,
                      uint256 merkle_root = uint256::ZERO) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = prev ? prev->GetBlockHash() : uint256::ZERO;
        header.hashMerkleRoot = merkle_root == uint256::ZERO ? uint256{static_cast<uint8_t>(next_nonce)} : merkle_root;
        header.nTime = 1'700'000'000 + next_nonce;
        header.nBits = bits;
        header.nNonce = next_nonce++;

        hashes.push_back(header.GetHash());
        auto block{std::make_unique<CBlockIndex>(header)};
        block->phashBlock = &hashes.back();
        block->pprev = prev;
        block->nHeight = prev ? prev->nHeight + 1 : 0;
        block->nChainWork = (prev ? prev->nChainWork : arith_uint256{}) + arith_uint256{1};
        block->nStatus = BLOCK_VALID_TREE;
        if (have_data) block->nStatus |= BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        block->BuildSkip();
        CBlockIndex* ret{block.get()};
        blocks.push_back(std::move(block));
        if (active) active_chain.SetTip(*ret);
        return ret;
    }
};

/** Number of stale blocks between the fork point and the stale tip. */
int ForkLength(const StaleFork& fork)
{
    return fork.tip.get().nHeight - fork.fork_point.get().nHeight;
}

} // namespace

BOOST_AUTO_TEST_CASE(staletip_tracker_basic)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* tip{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 4; ++i) tip = tree.Add(tip, true, true);

    CBlockIndex* stale{tree.Add(Assert(tip->pprev), false)};
    StaleTipTracker tips;

    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale));
    const auto forks{tips.GetStaleTips(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(forks.size(), 1U);
    BOOST_CHECK_EQUAL(forks[0].tip.get().GetBlockHash().ToString(), stale->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(forks[0].fork_point.get().GetBlockHash().ToString(), tip->pprev->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(ForkLength(forks[0]), 1);
}

BOOST_AUTO_TEST_CASE(staletip_tracker_returns_tips_in_discovery_order)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 4; ++i) active = tree.Add(active, true, true);

    StaleTipTracker tips;
    CBlockIndex* first{tree.Add(Assert(Assert(Assert(active->pprev)->pprev)->pprev), false)};
    CBlockIndex* second{tree.Add(Assert(Assert(active->pprev)->pprev), false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, first));
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, second));

    // Extending the first tip reuses its slot, but the extension was learned
    // last, so it is returned last.
    CBlockIndex* first_child{tree.Add(first, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, first_child));

    const auto forks{tips.GetStaleTips(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(forks.size(), 2U);
    BOOST_CHECK_EQUAL(&forks[0].tip.get(), second);
    BOOST_CHECK_EQUAL(&forks[1].tip.get(), first_child);
}

BOOST_AUTO_TEST_CASE(staletip_tracker_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    CBlockIndex* old_fork{active};
    for (int i{0}; i < 10; ++i) active = tree.Add(active, true, true);

    StaleTipTracker tips{/*recent_window=*/3, /*max_headers=*/2};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, tree.Add(old_fork, false)));

    CBlockIndex* fork{Assert(Assert(active->pprev)->pprev)};
    CBlockIndex* stale{tree.Add(fork, false)};
    stale = tree.Add(stale, false);
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale));
    BOOST_REQUIRE_EQUAL(tips.GetStaleTips(tree.active_chain).size(), 1U);

    CBlockIndex* too_long{tree.Add(stale, false)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, too_long));
}

BOOST_AUTO_TEST_CASE(staletip_tracker_extending_tip_replaces_old_tip)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* stale{tree.Add(Assert(Assert(active->pprev)->pprev), false)};
    StaleTipTracker tips;
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale));
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, stale));

    CBlockIndex* stale_child{tree.Add(stale, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale_child));
    // An ancestor of a tracked tip is not tracked separately.
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, stale));

    const auto forks{tips.GetStaleTips(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(forks.size(), 1U);
    BOOST_CHECK_EQUAL(forks[0].tip.get().GetBlockHash().ToString(), stale_child->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(ForkLength(forks[0]), 2);
}

BOOST_AUTO_TEST_CASE(staletip_tracker_expiry)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 10; ++i) active = tree.Add(active, true, true);

    StaleTipTracker tips{/*recent_window=*/5, MAX_STALETIP_HEADERS};
    CBlockIndex* below_window{tree.Add(Assert(active->GetAncestor(active->nHeight - 7)), false)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, below_window));

    // A tip exactly at the edge of the window is tracked, until the active
    // chain grows past it.
    CBlockIndex* at_edge{tree.Add(Assert(active->GetAncestor(active->nHeight - 6)), false)};
    BOOST_CHECK_EQUAL(active->nHeight - at_edge->nHeight, 5);
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, at_edge));
    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), 1U);
    active = tree.Add(active, true, true);
    BOOST_CHECK(tips.GetStaleTips(tree.active_chain).empty());

    // A tracked tip expires once one of its ancestors is found invalid.
    CBlockIndex* invalid_child{tree.Add(active->pprev, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, invalid_child));
    invalid_child->nStatus |= BLOCK_FAILED_CHILD;
    BOOST_CHECK(tips.GetStaleTips(tree.active_chain).empty());
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, invalid_child));
}

/** An active chain of 21 blocks and an empty stale-tip tracker. */
struct StaleTipTrackerSetup : public BasicTestingSetup {
    BlockTree tree;
    StaleTipTracker tips;
    CBlockIndex* active{nullptr};

    StaleTipTrackerSetup()
    {
        LOCK(::cs_main);
        active = tree.Add(nullptr, true, true);
        for (int i{0}; i < 20; ++i) active = tree.Add(active, true, true);
    }

    /** Fill the tracker with stale tips that fork off `fork`. */
    std::vector<CBlockIndex*> Fill(CBlockIndex* fork) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        std::vector<CBlockIndex*> stale_tips;
        for (size_t i{0}; i < MAX_ADVERTISED_STALETIPS; ++i) {
            stale_tips.push_back(tree.Add(fork, false));
            BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale_tips.back()));
        }
        return stale_tips;
    }

    bool IsTracked(const CBlockIndex* block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return std::ranges::any_of(tips.GetStaleTips(tree.active_chain), [&](const StaleFork& fork) { return &fork.tip.get() == block; });
    }
};

BOOST_FIXTURE_TEST_CASE(staletip_tracker_uses_free_slots_and_evicts_least_work_tip, StaleTipTrackerSetup)
{
    LOCK(::cs_main);

    std::vector<CBlockIndex*> stale_tips;
    for (size_t i{0}; i < MAX_ADVERTISED_STALETIPS; ++i) {
        const int fork_depth{static_cast<int>(MAX_ADVERTISED_STALETIPS - i)};
        CBlockIndex* fork{Assert(active->GetAncestor(active->nHeight - fork_depth))};
        stale_tips.push_back(tree.Add(fork, false));
        BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale_tips.back()));
        BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), i + 1);
    }

    CBlockIndex* replacement_fork{Assert(active->GetAncestor(active->nHeight - 5))};
    CBlockIndex* replacement{tree.Add(replacement_fork, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, replacement));

    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), MAX_ADVERTISED_STALETIPS);
    BOOST_CHECK(!IsTracked(stale_tips.front()));
    BOOST_CHECK(IsTracked(stale_tips.at(1)));
    BOOST_CHECK(IsTracked(stale_tips.at(4)));
    BOOST_CHECK(IsTracked(replacement));
}

BOOST_FIXTURE_TEST_CASE(staletip_tracker_prunes_expired_tips, StaleTipTrackerSetup)
{
    LOCK(::cs_main);

    CBlockIndex* fork{active->pprev};
    const auto stale_tips{Fill(fork)};

    // A lower-work tip cannot evict any of the tracked tips...
    CBlockIndex* candidate{tree.Add(fork->pprev, false)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, candidate));
    BOOST_CHECK(!IsTracked(candidate));

    // ...but takes the slot of one that has since been found invalid, even
    // though the invalid tip has more work.
    stale_tips.front()->nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, candidate));

    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), MAX_ADVERTISED_STALETIPS);
    BOOST_CHECK(IsTracked(candidate));
}

BOOST_FIXTURE_TEST_CASE(staletip_tracker_full_keeps_equal_work_tips, StaleTipTrackerSetup)
{
    LOCK(::cs_main);

    CBlockIndex* fork{active->pprev};
    const auto stale_tips{Fill(fork)};

    CBlockIndex* candidate{tree.Add(fork, false)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, candidate));

    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), MAX_ADVERTISED_STALETIPS);
    for (const CBlockIndex* stale_tip : stale_tips) BOOST_CHECK(IsTracked(stale_tip));
    BOOST_CHECK(!IsTracked(candidate));
}

BOOST_FIXTURE_TEST_CASE(staletip_tracker_evicts_by_work_not_height, StaleTipTrackerSetup)
{
    LOCK(::cs_main);

    CBlockIndex* fork{active->pprev};
    const auto stale_tips{Fill(fork)};
    // Give one tracked tip less work than a candidate at a lower height.
    CBlockIndex* low_work{stale_tips.back()};
    low_work->nChainWork = fork->nChainWork - arith_uint256{1};

    CBlockIndex* candidate{tree.Add(fork->pprev, false)};
    BOOST_CHECK(candidate->nHeight < low_work->nHeight);
    BOOST_CHECK(candidate->nChainWork > low_work->nChainWork);
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, candidate));

    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), MAX_ADVERTISED_STALETIPS);
    BOOST_CHECK(!IsTracked(low_work));
    BOOST_CHECK(IsTracked(candidate));
}

BOOST_AUTO_TEST_CASE(staletip_tracker_network_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* fork{active->pprev};
    CBlockIndex* headers_only{tree.Add(fork, false)};
    StaleTipTracker signet_tips{ChainType::SIGNET};
    BOOST_CHECK(!signet_tips.AddStaleTip(tree.active_chain, headers_only));

    headers_only->nStatus |= BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    BOOST_CHECK(signet_tips.AddStaleTip(tree.active_chain, headers_only));
    // The block was validated, so pruning it keeps the tip eligible.
    headers_only->nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_CHECK_EQUAL(signet_tips.GetStaleTips(tree.active_chain).size(), 1U);

    CBlockIndex* low_difficulty{tree.Add(fork, false, true, /*bits=*/0x207fffff)};
    StaleTipTracker testnet_tips{ChainType::TESTNET};
    BOOST_CHECK(!testnet_tips.AddStaleTip(tree.active_chain, low_difficulty));
    StaleTipTracker testnet4_tips{ChainType::TESTNET4};
    BOOST_CHECK(!testnet4_tips.AddStaleTip(tree.active_chain, low_difficulty));

    // A target just below the limit is accepted, one just above it is not.
    CBlockIndex* above_limit{tree.Add(fork, false, true, /*bits=*/0x1a100000)};
    BOOST_CHECK(!testnet_tips.AddStaleTip(tree.active_chain, above_limit));
    CBlockIndex* at_limit{tree.Add(fork, false, true, /*bits=*/0x1a0fffff)};
    BOOST_CHECK(testnet_tips.AddStaleTip(tree.active_chain, at_limit));
}

BOOST_AUTO_TEST_CASE(staletip_tracker_signet_variant_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* fork{Assert(Assert(active->pprev)->pprev)};
    const uint256 shared_merkle_root{uint8_t{42}};
    CBlockIndex* first_variant{tree.Add(fork, false, true, /*bits=*/0x1d00ffff, shared_merkle_root)};
    CBlockIndex* second_variant{tree.Add(fork, false, true, /*bits=*/0x1d00ffff, shared_merkle_root)};

    StaleTipTracker tips{ChainType::SIGNET};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, first_variant));
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, second_variant));

    CBlockIndex* extended_second{tree.Add(second_variant, false, true)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, extended_second));
    const auto forks{tips.GetStaleTips(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(forks.size(), 1U);
    BOOST_CHECK_EQUAL(forks.front().tip.get().GetBlockHash().ToString(), extended_second->GetBlockHash().ToString());

    CBlockIndex* active_variant{tree.Add(active->pprev, false, true, /*bits=*/0x1d00ffff, active->hashMerkleRoot)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, active_variant));
}

BOOST_AUTO_TEST_CASE(staletip_tracker_signet_variant_becomes_active)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* fork{active->pprev};
    const uint256 shared_merkle_root{uint8_t{42}};
    CBlockIndex* stale{tree.Add(fork, false, true, /*bits=*/0x1d00ffff, shared_merkle_root)};

    StaleTipTracker tips{ChainType::SIGNET};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale));
    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), 1U);

    // Reorg onto a branch whose block at the tracked tip's height is a
    // variant of it. The tip is no longer eligible, as if it were added now.
    CBlockIndex* variant{tree.Add(fork, false, true, /*bits=*/0x1d00ffff, shared_merkle_root)};
    tree.Add(variant, true, true);
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, stale));
    BOOST_CHECK(tips.GetStaleTips(tree.active_chain).empty());

    // It stays tracked, and is eligible again once the variant is reorged out.
    tree.active_chain.SetTip(*active);
    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
