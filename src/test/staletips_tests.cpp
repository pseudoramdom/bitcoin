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
    const auto info{tips.GetStaleTipInfo(tree.active_chain)};
    BOOST_REQUIRE_EQUAL(info.size(), 1U);
    BOOST_CHECK_EQUAL(info.front().hash.ToString(), extended_second->GetBlockHash().ToString());

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
    BOOST_CHECK_EQUAL(stale_tips[0].tip->GetBlockHash().ToString(), same_height[0]->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(stale_tips[1].tip->GetBlockHash().ToString(), same_height[1]->GetBlockHash().ToString());
    BOOST_CHECK_EQUAL(stale_tips[2].tip->GetBlockHash().ToString(), lower_tip->GetBlockHash().ToString());
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
    BOOST_CHECK(!tips.AddStaleTip(active_chain, active_variant));

    tips.Initialize(blockman, active_chain);
    BOOST_CHECK(tips.GetStaleTips(active_chain).empty());
}

BOOST_AUTO_TEST_SUITE_END()
