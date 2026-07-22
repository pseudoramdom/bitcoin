// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/staletiptracker.h>

#include <arith_uint256.h>
#include <chain.h>
#include <node/blockstorage.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <cstddef>
#include <vector>

namespace node {

namespace {

/** Maximum target of a stale tip tracked on testnet3 and testnet4: a
 *  difficulty of about 1,000,000 (2^20), the example threshold in BIP 332. */
constexpr uint256 TESTNET_MAX_TARGET{"0000000000000fffffffffffffffffffffffffffffffffffffffffffffffffff"};

/** Whether `block` is a header variant of the block at its height on the
 *  branch ending at `branch_tip`: both have the same previous block and merkle
 *  root. A block is a variant of itself. On signet, varying nBits can turn a
 *  valid block into another valid variant, so only one is tracked (see the
 *  "Signet" section of BIP 332). */
bool IsVariantOnBranch(const CBlockIndex& block, const CBlockIndex& branch_tip)
{
    if (block.nHeight > branch_tip.nHeight) return false;
    const CBlockIndex& other{*Assert(branch_tip.GetAncestor(block.nHeight))};
    return block.pprev == other.pprev && block.hashMerkleRoot == other.hashMerkleRoot;
}

} // namespace

bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor)
{
    return block.nHeight >= ancestor.nHeight && block.GetAncestor(ancestor.nHeight) == &ancestor;
}

StaleTipMessage MakeStaleTipMessage(const StaleFork& fork, bool have_block)
{
    AssertLockHeld(::cs_main);
    const CBlockIndex& tip{*fork.tip};
    Assert(HasAncestor(tip, *fork.fork_point));

    const int fork_length{tip.nHeight - fork.fork_point->nHeight};
    Assert(fork_length > 0);
    Assert(static_cast<size_t>(fork_length) <= MAX_STALETIP_HEADERS);

    StaleTipMessage msg{.fork_point = fork.fork_point->GetBlockHash(), .have_block = have_block};
    const CBlockIndex* pindex{&tip};
    msg.headers.resize(fork_length);
    for (int i{fork_length - 1}; i >= 0; --i) {
        msg.headers.at(i) = {
            .version = pindex->nVersion,
            .merkle_root = pindex->hashMerkleRoot,
            .time = pindex->nTime,
            .bits = pindex->nBits,
            .nonce = pindex->nNonce,
        };
        pindex = pindex->pprev;
    }
    return msg;
}

StaleTipTracker::StaleTipTracker(ChainType chain_type, int recent_window, size_t max_headers)
    : m_require_validated_block{chain_type == ChainType::SIGNET},
      m_dedup_header_variants{chain_type == ChainType::SIGNET},
      m_recent_window{recent_window},
      m_max_headers{max_headers}
{
    if (chain_type == ChainType::TESTNET || chain_type == ChainType::TESTNET4) {
        m_max_target = UintToArith256(TESTNET_MAX_TARGET);
    }
}

const CBlockIndex* StaleTipTracker::GetEligibleForkPoint(const CChain& active_chain, const CBlockIndex& stale_tip) const
{
    const CBlockIndex* active_tip{active_chain.Tip()};
    if (active_tip == nullptr) return nullptr;
    if (active_chain.Contains(stale_tip)) return nullptr;
    if (IsExpired(active_chain, stale_tip)) return nullptr;
    if (stale_tip.nChainWork > active_tip->nChainWork) return nullptr;

    // Only one variant of a block is tracked, and the active chain's block
    // counts as seen first, even if it became active later.
    if (m_dedup_header_variants && IsVariantOnBranch(stale_tip, *active_tip)) return nullptr;

    if (m_max_target) {
        arith_uint256 target;
        target.SetCompact(stale_tip.nBits);
        if (target > *m_max_target) return nullptr;
    }

    const CBlockIndex* fork_point{active_chain.FindFork(stale_tip)};
    if (fork_point == nullptr) return nullptr;

    const int fork_length{stale_tip.nHeight - fork_point->nHeight};
    if (static_cast<size_t>(fork_length) > m_max_headers) return nullptr;

    return fork_point;
}

bool StaleTipTracker::IsExpired(const CChain& active_chain, const CBlockIndex& stale_tip) const
{
    if (stale_tip.nStatus & BLOCK_FAILED_VALID) return true;
    const CBlockIndex* active_tip{active_chain.Tip()};
    return active_tip != nullptr && stale_tip.nHeight < active_tip->nHeight - m_recent_window;
}

void StaleTipTracker::PruneExpired(const CChain& active_chain)
{
    AssertLockHeld(::cs_main);
    std::erase_if(m_tips, [&](const CBlockIndex* tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return IsExpired(active_chain, *tip);
    });
}

bool StaleTipTracker::Add(const CBlockIndex& stale_tip)
{
    AssertLockHeld(::cs_main);

    // Nothing to do if the tip, or one of its descendants, is tracked, or
    // when deduplicating variants, if a tracked branch contains a variant of
    // the tip.
    for (const CBlockIndex* tip : m_tips) {
        if (HasAncestor(*tip, stale_tip)) return false;
        if (m_dedup_header_variants && IsVariantOnBranch(stale_tip, *tip)) return false;
    }

    // The tip replaces any tracked ancestors and, when deduplicating variants,
    // tracked tips that are variants of a block on its branch.
    std::erase_if(m_tips, [&](const CBlockIndex* tip) {
        return HasAncestor(stale_tip, *tip) ||
               (m_dedup_header_variants && IsVariantOnBranch(*tip, stale_tip));
    });

    if (m_tips.size() == MAX_ADVERTISED_STALETIPS) {
        // Evict the tip with the least work, if it has less than the new
        // tip. min_element returns the first, so the oldest, of equals.
        const auto evict{std::ranges::min_element(m_tips, {}, [](const CBlockIndex* tip) { return tip->nChainWork; })};
        if ((*evict)->nChainWork >= stale_tip.nChainWork) return false;
        m_tips.erase(evict);
    }

    m_tips.push_back(&stale_tip);
    return true;
}

void StaleTipTracker::SeedFromBlockIndex(const node::BlockManager& blockman, const CChain& active_chain)
{
    AssertLockHeld(::cs_main);

    std::vector<const CBlockIndex*> candidates;
    for (const auto& [_, block_index] : blockman.m_block_index) {
        if (GetEligibleForkPoint(active_chain, block_index) != nullptr) candidates.push_back(&block_index);
    }

    // Add descendants before their ancestors, so that Add() keeps only the
    // most extended tip of each branch. Break ties by hash so that the
    // tracked tips and their order are the same on every start.
    std::ranges::sort(candidates, [](const CBlockIndex* a, const CBlockIndex* b) {
        if (a->nChainWork != b->nChainWork) return a->nChainWork > b->nChainWork;
        return a->GetBlockHash() < b->GetBlockHash();
    });

    for (const CBlockIndex* candidate : candidates) AddStaleTip(active_chain, *candidate);
}

bool StaleTipTracker::AddStaleTip(const CChain& active_chain, const CBlockIndex& stale_tip)
{
    AssertLockHeld(::cs_main);
    // Validation is never undone, so this is only checked when a tip is added.
    if (m_require_validated_block && !stale_tip.IsValid(BLOCK_VALID_TRANSACTIONS)) return false;
    if (GetEligibleForkPoint(active_chain, stale_tip) == nullptr) return false;

    PruneExpired(active_chain);
    return Add(stale_tip);
}

bool StaleTipTracker::CanRequestStaleTipBlock(const CChain& active_chain, const CBlockIndex& stale_tip) const
{
    AssertLockHeld(::cs_main);
    return GetEligibleForkPoint(active_chain, stale_tip) != nullptr;
}

bool StaleTipTracker::CanServeStaleBranchBlock(const CChain& active_chain, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    if (!(block.nStatus & BLOCK_HAVE_DATA)) return false;

    for (const CBlockIndex* tip : m_tips) {
        if (!(tip->nStatus & BLOCK_HAVE_DATA)) continue;

        const CBlockIndex* fork_point{GetEligibleForkPoint(active_chain, *tip)};
        if (fork_point == nullptr) continue;
        if (block.nHeight > fork_point->nHeight && HasAncestor(*tip, block)) return true;
    }
    return false;
}

std::vector<StaleFork> StaleTipTracker::GetStaleTips(const CChain& active_chain) const
{
    AssertLockHeld(::cs_main);

    std::vector<StaleFork> tips;
    tips.reserve(m_tips.size());
    for (const CBlockIndex* tip : m_tips) {
        const CBlockIndex* fork_point{GetEligibleForkPoint(active_chain, *tip)};
        if (fork_point == nullptr) continue;
        tips.push_back({.fork_point = fork_point, .tip = tip});
    }

    return tips;
}

bool StaleTipTracker::IsTracked(const CBlockIndex& tip) const
{
    AssertLockHeld(::cs_main);
    return std::ranges::find(m_tips, &tip) != m_tips.end();
}

} // namespace node
