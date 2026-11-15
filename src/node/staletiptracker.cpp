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
#include <optional>
#include <utility>
#include <vector>

namespace node {

namespace {

/** Maximum target of a stale tip tracked on testnet3 and testnet4: a
 *  difficulty of about 1,000,000 (2^20), the example threshold in BIP 332. */
constexpr uint256 TESTNET_MAX_TARGET{"0000000000000fffffffffffffffffffffffffffffffffffffffffffffffffff"};

/** Whether the headers of two signet blocks settle if they are variants. A
 *  different previous block, version or time is signed data that differs.
 *  With the same header merkle root the transactions are the same, so the
 *  BIP 325 merkle root is too; only unsigned header fields such as nBits can
 *  differ. A block is a variant of itself.
 *
 * @return std::nullopt if the BIP 325 merkle roots must be compared.
 */
std::optional<bool> IsHeaderVariant(const CBlockIndex& block, const CBlockIndex& other)
{
    if (block.pprev != other.pprev || block.nVersion != other.nVersion || block.nTime != other.nTime) return false;
    if (block.hashMerkleRoot == other.hashMerkleRoot) return true;
    return std::nullopt;
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
    : m_signet{chain_type == ChainType::SIGNET},
      m_recent_window{recent_window},
      m_max_headers{max_headers}
{
    if (chain_type == ChainType::TESTNET || chain_type == ChainType::TESTNET4) {
        m_max_target = UintToArith256(TESTNET_MAX_TARGET);
    }
}

void StaleTipTracker::SetSignetRootReader(SignetRootReader reader)
{
    AssertLockHeld(::cs_main);
    m_read_signet_root = std::move(reader);
}

std::optional<uint256> StaleTipTracker::GetSignetRoot(const CBlockIndex& block, bool read_blocks)
{
    AssertLockHeld(::cs_main);
    if (const auto cached{std::ranges::find(m_signet_roots, &block, [](const auto& entry) { return entry.first; })}; cached != m_signet_roots.end()) {
        std::rotate(cached, cached + 1, m_signet_roots.end());
        return m_signet_roots.back().second;
    }
    if (!read_blocks || !m_read_signet_root) return std::nullopt;
    if (!(block.nStatus & BLOCK_HAVE_DATA) || !block.IsValid(BLOCK_VALID_TRANSACTIONS)) return std::nullopt;

    const auto root{m_read_signet_root(block)};
    if (!root) return std::nullopt;
    if (m_signet_roots.size() == MAX_CACHED_SIGNET_ROOTS) m_signet_roots.erase(m_signet_roots.begin());
    m_signet_roots.emplace_back(&block, *root);
    return root;
}

std::optional<bool> StaleTipTracker::IsVariant(const CBlockIndex& block, const CBlockIndex& other, bool read_blocks)
{
    AssertLockHeld(::cs_main);
    if (const auto settled{IsHeaderVariant(block, other)}) return settled;
    const auto root{GetSignetRoot(block, read_blocks)};
    if (!root) return std::nullopt;
    const auto other_root{GetSignetRoot(other, read_blocks)};
    if (!other_root) return std::nullopt;
    return *root == *other_root;
}

std::optional<bool> StaleTipTracker::IsVariantOnBranch(const CBlockIndex& block, const CBlockIndex& branch_tip, bool read_blocks)
{
    AssertLockHeld(::cs_main);
    if (block.nHeight > branch_tip.nHeight) return false;
    return IsVariant(block, *Assert(branch_tip.GetAncestor(block.nHeight)), read_blocks);
}

bool StaleTipTracker::IsHiddenByActiveChain(const CChain& active_chain, const TrackedTip& tip) const
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* active_block{active_chain[tip.index->nHeight]};
    if (active_block == nullptr) return false;
    if (const auto settled{IsHeaderVariant(*tip.index, *active_block)}) return *settled;
    return tip.compared_with != active_block || tip.is_variant;
}

void StaleTipTracker::RefreshSignetVariants(const CChain& active_chain)
{
    AssertLockHeld(::cs_main);
    if (!m_signet) return;
    for (TrackedTip& tip : m_tips) {
        if (GetEligibleForkPoint(active_chain, *tip.index) == nullptr) continue;
        const CBlockIndex* active_block{active_chain[tip.index->nHeight]};
        if (active_block == nullptr || active_block == tip.compared_with) continue;
        // If the blocks cannot be read, the tip stays hidden until they can.
        if (const auto is_variant{IsVariant(*tip.index, *active_block, /*read_blocks=*/true)}) {
            tip.compared_with = active_block;
            tip.is_variant = *is_variant;
        }
    }
}

const CBlockIndex* StaleTipTracker::GetEligibleForkPoint(const CChain& active_chain, const CBlockIndex& stale_tip) const
{
    const CBlockIndex* active_tip{active_chain.Tip()};
    if (active_tip == nullptr) return nullptr;
    if (active_chain.Contains(stale_tip)) return nullptr;
    if (IsExpired(active_chain, stale_tip)) return nullptr;
    if (stale_tip.nChainWork > active_tip->nChainWork) return nullptr;

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
    std::erase_if(m_tips, [&](const TrackedTip& tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return IsExpired(active_chain, *tip.index);
    });
}

bool StaleTipTracker::Add(const CChain& active_chain, const CBlockIndex& stale_tip, bool read_blocks)
{
    AssertLockHeld(::cs_main);

    // Nothing to do if the tip, or one of its descendants, is tracked, or
    // when deduplicating variants, if a tracked branch contains a variant of
    // the tip, or may contain one.
    for (const TrackedTip& tip : m_tips) {
        if (HasAncestor(*tip.index, stale_tip)) return false;
        if (m_signet && IsVariantOnBranch(stale_tip, *tip.index, read_blocks).value_or(true)) return false;
    }

    // The tip replaces any tracked ancestors and, when deduplicating variants,
    // tracked tips that are known to be variants of a block on its branch.
    std::erase_if(m_tips, [&](const TrackedTip& tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return HasAncestor(stale_tip, *tip.index) ||
               (m_signet && IsVariantOnBranch(*tip.index, stale_tip, read_blocks).value_or(false));
    });

    if (m_tips.size() == MAX_ADVERTISED_STALETIPS) {
        // Evict the tip with the least work, if it has less than the new
        // tip. min_element returns the first, so the oldest, of equals.
        const auto evict{std::ranges::min_element(m_tips, {}, [](const TrackedTip& tip) { return tip.index->nChainWork; })};
        if (evict->index->nChainWork >= stale_tip.nChainWork) return false;
        m_tips.erase(evict);
    }

    // AddStaleTip() found that the tip is not a variant of the active block.
    m_tips.push_back({.index = &stale_tip, .compared_with = active_chain[stale_tip.nHeight]});
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

bool StaleTipTracker::AddStaleTip(const CChain& active_chain, const CBlockIndex& stale_tip, bool read_blocks)
{
    AssertLockHeld(::cs_main);
    // Validation is never undone, so this is only checked when a tip is added.
    if (m_signet && !stale_tip.IsValid(BLOCK_VALID_TRANSACTIONS)) return false;
    if (GetEligibleForkPoint(active_chain, stale_tip) == nullptr) return false;
    // Only one variant of a block is tracked, and the active chain's block
    // counts as seen first, even if it became active later.
    if (m_signet && IsVariantOnBranch(stale_tip, *active_chain.Tip(), read_blocks).value_or(true)) return false;

    PruneExpired(active_chain);
    return Add(active_chain, stale_tip, read_blocks);
}

bool StaleTipTracker::CanRequestStaleTipBlock(const CChain& active_chain, const CBlockIndex& stale_tip) const
{
    AssertLockHeld(::cs_main);
    if (GetEligibleForkPoint(active_chain, stale_tip) == nullptr) return false;
    const CBlockIndex* active_block{active_chain[stale_tip.nHeight]};
    return !m_signet || active_block == nullptr || !IsHeaderVariant(stale_tip, *active_block).value_or(false);
}

bool StaleTipTracker::CanServeStaleBranchBlock(const CChain& active_chain, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    if (!(block.nStatus & BLOCK_HAVE_DATA)) return false;

    for (const TrackedTip& tip : m_tips) {
        if (!(tip.index->nStatus & BLOCK_HAVE_DATA)) continue;

        const CBlockIndex* fork_point{GetEligibleForkPoint(active_chain, *tip.index)};
        if (fork_point == nullptr) continue;
        if (m_signet && IsHiddenByActiveChain(active_chain, tip)) continue;
        if (block.nHeight > fork_point->nHeight && HasAncestor(*tip.index, block)) return true;
    }
    return false;
}

std::vector<StaleFork> StaleTipTracker::GetStaleTips(const CChain& active_chain) const
{
    AssertLockHeld(::cs_main);

    std::vector<StaleFork> tips;
    tips.reserve(m_tips.size());
    for (const TrackedTip& tip : m_tips) {
        const CBlockIndex* fork_point{GetEligibleForkPoint(active_chain, *tip.index)};
        if (fork_point == nullptr) continue;
        if (m_signet && IsHiddenByActiveChain(active_chain, tip)) continue;
        tips.push_back({.fork_point = fork_point, .tip = tip.index});
    }

    return tips;
}

bool StaleTipTracker::IsTracked(const CBlockIndex& tip) const
{
    AssertLockHeld(::cs_main);
    return std::ranges::find(m_tips, &tip, &TrackedTip::index) != m_tips.end();
}

} // namespace node
