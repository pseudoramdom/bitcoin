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

CBlockIndex* AddBlockIndex(node::BlockManager& blockman, CBlockIndex*& best_header, const CBlockIndex* prev, uint32_t nonce) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    CBlockHeader header;
    header.nVersion = 4;
    header.hashPrevBlock = prev ? prev->GetBlockHash() : uint256::ZERO;
    header.hashMerkleRoot = uint256{static_cast<uint8_t>(nonce)};
    header.nTime = 1'700'000'000 + nonce;
    header.nBits = 0x1d00ffff;
    header.nNonce = nonce;

    return blockman.AddToBlockIndex(header, best_header);
}

} // namespace

BOOST_AUTO_TEST_CASE(staletip_cache_basic)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* tip{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 4; ++i) tip = tree.Add(tip, true, true);

    CBlockIndex* stale{tree.Add(Assert(tip->pprev), false)};
    StaleTipCache tips;

    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale));
    const auto forks{tips.GetStaleTips(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(forks.size(), 1U);
    BOOST_CHECK_EQUAL(forks[0].tip.get().GetBlockHash().ToString(), stale->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(forks[0].fork_point.get().GetBlockHash().ToString(), tip->pprev->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(ForkLength(forks[0]), 1);
}

BOOST_AUTO_TEST_CASE(staletip_cache_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    CBlockIndex* old_fork{active};
    for (int i{0}; i < 10; ++i) active = tree.Add(active, true, true);

    StaleTipCache tips{/*recent_window=*/3, /*max_headers=*/2};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, tree.Add(old_fork, false)));

    CBlockIndex* fork{Assert(Assert(active->pprev)->pprev)};
    CBlockIndex* stale{tree.Add(fork, false)};
    stale = tree.Add(stale, false);
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale));
    BOOST_REQUIRE_EQUAL(tips.GetStaleTips(tree.active_chain).size(), 1U);

    CBlockIndex* too_long{tree.Add(stale, false)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, too_long));
}

BOOST_AUTO_TEST_CASE(staletip_cache_extending_tip_replaces_old_tip)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* stale{tree.Add(Assert(Assert(active->pprev)->pprev), false)};
    StaleTipCache tips;
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

BOOST_AUTO_TEST_CASE(staletip_cache_expiry)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 10; ++i) active = tree.Add(active, true, true);

    StaleTipCache tips{/*recent_window=*/5, MAX_STALETIP_HEADERS};
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

/** An active chain of 21 blocks and an empty stale-tip cache. */
struct StaleTipCacheSetup : public BasicTestingSetup {
    BlockTree tree;
    StaleTipCache tips;
    CBlockIndex* active{nullptr};

    StaleTipCacheSetup()
    {
        LOCK(::cs_main);
        active = tree.Add(nullptr, true, true);
        for (int i{0}; i < 20; ++i) active = tree.Add(active, true, true);
    }

    /** Fill the cache with stale tips that fork off `fork`. */
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

BOOST_FIXTURE_TEST_CASE(staletip_cache_uses_free_slots_and_evicts_least_work_tip, StaleTipCacheSetup)
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

BOOST_FIXTURE_TEST_CASE(staletip_cache_prunes_expired_tips, StaleTipCacheSetup)
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

BOOST_FIXTURE_TEST_CASE(staletip_cache_full_replaces_oldest_equal_work_tip, StaleTipCacheSetup)
{
    LOCK(::cs_main);

    CBlockIndex* fork{active->pprev};
    const auto stale_tips{Fill(fork)};

    CBlockIndex* replacement{tree.Add(fork, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, replacement));

    BOOST_CHECK_EQUAL(tips.GetStaleTips(tree.active_chain).size(), MAX_ADVERTISED_STALETIPS);
    BOOST_CHECK(!IsTracked(stale_tips.front()));
    BOOST_CHECK(IsTracked(stale_tips.at(1)));
    BOOST_CHECK(IsTracked(replacement));
}

BOOST_FIXTURE_TEST_CASE(staletip_cache_evicts_by_work_not_height, StaleTipCacheSetup)
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

BOOST_AUTO_TEST_CASE(staletip_cache_network_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* fork{active->pprev};
    CBlockIndex* headers_only{tree.Add(fork, false)};
    StaleTipCache signet_tips{ChainType::SIGNET};
    BOOST_CHECK(!signet_tips.AddStaleTip(tree.active_chain, headers_only));

    headers_only->nStatus |= BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    BOOST_CHECK(signet_tips.AddStaleTip(tree.active_chain, headers_only));

    CBlockIndex* low_difficulty{tree.Add(fork, false, true, /*bits=*/0x207fffff)};
    StaleTipCache testnet_tips{ChainType::TESTNET};
    BOOST_CHECK(!testnet_tips.AddStaleTip(tree.active_chain, low_difficulty));
    StaleTipCache testnet4_tips{ChainType::TESTNET4};
    BOOST_CHECK(!testnet4_tips.AddStaleTip(tree.active_chain, low_difficulty));

    // A target just below the limit is accepted, one just above it is not.
    CBlockIndex* above_limit{tree.Add(fork, false, true, /*bits=*/0x1a100000)};
    BOOST_CHECK(!testnet_tips.AddStaleTip(tree.active_chain, above_limit));
    CBlockIndex* at_limit{tree.Add(fork, false, true, /*bits=*/0x1a0fffff)};
    BOOST_CHECK(testnet_tips.AddStaleTip(tree.active_chain, at_limit));
}

BOOST_AUTO_TEST_CASE(staletip_cache_signet_variant_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);

    CBlockIndex* fork{Assert(Assert(active->pprev)->pprev)};
    const uint256 shared_merkle_root{uint8_t{42}};
    CBlockIndex* first_variant{tree.Add(fork, false, true, /*bits=*/0x1d00ffff, shared_merkle_root)};
    CBlockIndex* second_variant{tree.Add(fork, false, true, /*bits=*/0x1d00ffff, shared_merkle_root)};

    StaleTipCache tips{ChainType::SIGNET};
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

BOOST_FIXTURE_TEST_CASE(staletip_initialize_orders_candidates_deterministically, ChainTestingSetup)
{
    LOCK(::cs_main);

    auto& blockman{m_node.chainman->m_blockman};
    CBlockIndex* best_header{nullptr};
    CChain active_chain;

    CBlockIndex* active{nullptr};
    for (uint32_t nonce{1}; nonce <= 5; ++nonce) {
        active = AddBlockIndex(blockman, best_header, active, nonce);
        active_chain.SetTip(*active);
    }

    CBlockIndex* lower_tip{AddBlockIndex(blockman, best_header, active->GetAncestor(active->nHeight - 2), 100)};
    CBlockIndex* same_height_a{AddBlockIndex(blockman, best_header, active->pprev, 101)};
    CBlockIndex* same_height_b{AddBlockIndex(blockman, best_header, active->pprev, 102)};

    std::vector<const CBlockIndex*> same_height{same_height_a, same_height_b};
    std::ranges::sort(same_height, [](const CBlockIndex* a, const CBlockIndex* b) {
        return a->GetBlockHash() < b->GetBlockHash();
    });

    StaleTipCache tips;
    tips.Initialize(blockman, active_chain);
    const auto stale_tips{tips.GetStaleTips(active_chain)};

    BOOST_REQUIRE_EQUAL(stale_tips.size(), 3U);
    BOOST_CHECK_EQUAL(stale_tips[0].tip.get().GetBlockHash().ToString(), same_height[0]->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(stale_tips[1].tip.get().GetBlockHash().ToString(), same_height[1]->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(stale_tips[2].tip.get().GetBlockHash().ToString(), lower_tip->GetBlockHash().ToString());
}

BOOST_FIXTURE_TEST_CASE(staletip_initialize_rejects_signet_active_tip_variant, ChainTestingSetup)
{
    LOCK(::cs_main);

    auto& blockman{m_node.chainman->m_blockman};
    CBlockIndex* best_header{nullptr};
    CChain active_chain;

    CBlockIndex* active{nullptr};
    for (uint32_t nonce{1}; nonce <= 5; ++nonce) {
        active = AddBlockIndex(blockman, best_header, active, nonce);
        active_chain.SetTip(*active);
    }

    CBlockHeader variant_header{active->GetBlockHeader()};
    ++variant_header.nNonce;
    CBlockIndex* active_variant{blockman.AddToBlockIndex(variant_header, best_header)};
    active_variant->nStatus |= BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;

    StaleTipCache tips{ChainType::SIGNET};
    tips.Initialize(blockman, active_chain);
    BOOST_CHECK(tips.GetStaleTips(active_chain).empty());
}

BOOST_AUTO_TEST_SUITE_END()
