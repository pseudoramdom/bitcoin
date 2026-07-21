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
    auto info{tips.GetStaleTipInfo(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(info.size(), 1U);
    BOOST_CHECK_EQUAL(info[0].hash.ToString(), stale->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(info[0].fork_point.ToString(), tip->pprev->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(info[0].fork_length, 1);
    BOOST_CHECK(!info[0].have_block);

    stale->nStatus |= BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    info = tips.GetStaleTipInfo(tree.active_chain);
    BOOST_REQUIRE_EQUAL(info.size(), 1U);
    BOOST_CHECK(info[0].have_block);
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
    BOOST_REQUIRE_EQUAL(tips.GetStaleTipInfo(tree.active_chain).size(), 1U);

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

    CBlockIndex* stale_child{tree.Add(stale, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale_child));

    const auto info{tips.GetStaleTipInfo(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(info.size(), 1U);
    BOOST_CHECK_EQUAL(info[0].hash.ToString(), stale_child->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(info[0].fork_length, 2);
}

BOOST_AUTO_TEST_CASE(staletip_cache_uses_free_slots_and_evicts_lowest_tip)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 20; ++i) active = tree.Add(active, true, true);

    StaleTipCache tips;
    std::vector<CBlockIndex*> stale_tips;
    for (size_t i{0}; i < MAX_RETAINED_STALETIPS; ++i) {
        const int fork_depth{static_cast<int>(MAX_RETAINED_STALETIPS - i)};
        CBlockIndex* fork{Assert(active->GetAncestor(active->nHeight - fork_depth))};
        stale_tips.push_back(tree.Add(fork, false));
        BOOST_CHECK(tips.AddStaleTip(tree.active_chain, stale_tips.back()));
        BOOST_CHECK_EQUAL(tips.GetStaleTipInfo(tree.active_chain).size(), i + 1);
    }

    const auto is_tracked = [&](const CBlockIndex* block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        for (const auto& tip : tips.GetStaleTipInfo(tree.active_chain)) {
            if (tip.hash == block->GetBlockHash()) return true;
        }
        return false;
    };

    CBlockIndex* replacement_fork{Assert(active->GetAncestor(active->nHeight - 5))};
    CBlockIndex* replacement{tree.Add(replacement_fork, false)};
    BOOST_CHECK(tips.AddStaleTip(tree.active_chain, replacement));

    BOOST_CHECK_EQUAL(tips.GetStaleTipInfo(tree.active_chain).size(), MAX_RETAINED_STALETIPS);
    BOOST_CHECK(!is_tracked(stale_tips.front()));
    BOOST_CHECK(is_tracked(stale_tips.at(1)));
    BOOST_CHECK(is_tracked(stale_tips.at(4)));
    BOOST_CHECK(is_tracked(replacement));
}

BOOST_AUTO_TEST_CASE(staletip_cache_full_without_lower_tip_drops_candidate)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 20; ++i) active = tree.Add(active, true, true);

    StaleTipCache tips;
    CBlockIndex* fork{active->pprev};
    for (size_t i{0}; i < MAX_RETAINED_STALETIPS; ++i) {
        BOOST_CHECK(tips.AddStaleTip(tree.active_chain, tree.Add(fork, false)));
    }
    BOOST_CHECK_EQUAL(tips.GetStaleTipInfo(tree.active_chain).size(), MAX_RETAINED_STALETIPS);

    CBlockIndex* dropped{tree.Add(fork, false)};
    BOOST_CHECK(!tips.AddStaleTip(tree.active_chain, dropped));

    const auto info{tips.GetStaleTipInfo(tree.active_chain)};
    BOOST_CHECK_EQUAL(info.size(), MAX_RETAINED_STALETIPS);
    BOOST_CHECK(std::ranges::none_of(info, [&](const StaleTipInfo& tip) { return tip.hash == dropped->GetBlockHash(); }));
}

BOOST_AUTO_TEST_SUITE_END()
