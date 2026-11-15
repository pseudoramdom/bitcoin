// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/staletiptracker.h>

#include <arith_uint256.h>
#include <chain.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <signet.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace node {

namespace {

/** Maximum target of a stale tip tracked on testnet3 and testnet4: a
 *  difficulty of about 1,000,000 (2^20), the example threshold in BIP 332. */
constexpr uint256 TESTNET_MAX_TARGET{"0000000000000fffffffffffffffffffffffffffffffffffffffffffffffffff"};

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

struct StaleTipTracker::SignetState {
    const BlockManager* blockman{nullptr};

    struct CachedRoot {
        const CBlockIndex* block;
        std::optional<uint256> root;
        MockableSteadyClock::time_point retry_after;
    };
    //! Room for every tracked tip, its active sibling, and as many candidates.
    static constexpr size_t MAX_CACHED_ROOTS{4 * MAX_ADVERTISED_STALETIPS};
    std::vector<CachedRoot> roots; //!< Least recently used first.

    struct ActiveComparison {
        const CBlockIndex* active{nullptr};
        bool is_variant{false};
    };
    //! A known result stays valid for this pair even if its roots are evicted or pruned.
    std::map<const CBlockIndex*, ActiveComparison> active_comparisons;

    /** Whether the headers of two signet blocks settle if they are variants. A
     *  different previous block, version or time is signed data that differs.
     *  With the same header merkle root the transactions are the same, so the
     *  BIP 325 merkle root is too; only unsigned header fields such as nBits can
     *  differ. A block is a variant of itself.
     *
     * @return std::nullopt if the BIP 325 merkle roots must be compared.
     */
    static std::optional<bool> IsHeaderVariant(const CBlockIndex& block, const CBlockIndex& other)
    {
        if (block.pprev != other.pprev || block.nVersion != other.nVersion || block.nTime != other.nTime) return false;
        if (block.hashMerkleRoot == other.hashMerkleRoot) return true;
        return std::nullopt;
    }

    std::optional<uint256> GetRoot(const CBlockIndex& block, const BlockManager* storage) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const auto cached{std::ranges::find(roots, &block, &CachedRoot::block)};
        if (cached != roots.end()) {
            if (cached->root || MockableSteadyClock::now() < cached->retry_after) {
                std::rotate(cached, cached + 1, roots.end());
                return roots.back().root;
            }
            roots.erase(cached);
        }
        if (!storage) return std::nullopt;
        if (!(block.nStatus & BLOCK_HAVE_DATA) || !block.IsValid(BLOCK_VALID_TRANSACTIONS)) return std::nullopt;

        CBlock data;
        std::optional<uint256> root;
        if (storage->ReadBlock(data, block)) root = ComputeSignetMerkleRoot(data);
        if (roots.size() == MAX_CACHED_ROOTS) roots.erase(roots.begin());
        // A failed disk read should not be retried for every peer's send loop.
        roots.push_back({&block, root, root ? MockableSteadyClock::time_point{} : MockableSteadyClock::now() + 1min});
        return root;
    }

    /** Whether two blocks commit to the same signet merkle root, if both roots are available. */
    std::optional<bool> HaveSameRoot(const CBlockIndex& block, const CBlockIndex& other, const BlockManager* storage) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const auto root{GetRoot(block, storage)};
        if (!root) return std::nullopt;
        const auto other_root{GetRoot(other, storage)};
        if (!other_root) return std::nullopt;
        return *root == *other_root;
    }

    /** Compare `block` with the block at its height on the branch ending at `branch_tip`. */
    std::optional<bool> IsVariantOnBranch(const CBlockIndex& block, const CBlockIndex& branch_tip, const BlockManager* storage) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        if (block.nHeight > branch_tip.nHeight) return false;
        const CBlockIndex& other{*Assert(branch_tip.GetAncestor(block.nHeight))};
        if (const auto settled{IsHeaderVariant(block, other)}) return settled;
        return HaveSameRoot(block, other, storage);
    }

    void RememberAdmission(const CBlockIndex& tip, const CBlockIndex* active, const std::vector<const CBlockIndex*>& tips)
    {
        std::erase_if(active_comparisons, [&](const auto& entry) { return std::ranges::find(tips, entry.first) == tips.end(); });
        if (active && !IsHeaderVariant(tip, *active).has_value()) {
            active_comparisons[&tip] = {active, false};
        }
    }

    bool IsHiddenByActiveChain(const CChain& chain, const CBlockIndex& tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const CBlockIndex* active{chain[tip.nHeight]};
        if (!active) return false;
        if (const auto settled{IsHeaderVariant(tip, *active)}) return *settled;
        auto& comparison{active_comparisons[&tip]};
        if (comparison.active == active) return comparison.is_variant;
        // A reorg can introduce a new sibling. Withhold the tip until both roots are known.
        const auto is_variant{HaveSameRoot(tip, *active, blockman)};
        if (!is_variant) return true;
        comparison = {active, *is_variant};
        return *is_variant;
    }
};

StaleTipTracker::StaleTipTracker(ChainType chain_type, int recent_window, size_t max_headers)
    : m_signet{chain_type == ChainType::SIGNET ? std::make_unique<SignetState>() : nullptr},
      m_recent_window{recent_window},
      m_max_headers{max_headers}
{
    if (chain_type == ChainType::TESTNET || chain_type == ChainType::TESTNET4) {
        m_max_target = UintToArith256(TESTNET_MAX_TARGET);
    }
}

StaleTipTracker::~StaleTipTracker() = default;

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
    std::erase_if(m_tips, [&](const CBlockIndex* tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return IsExpired(active_chain, *tip);
    });
}

bool StaleTipTracker::Add(const CChain& active_chain, const CBlockIndex& stale_tip, const BlockManager* storage)
{
    AssertLockHeld(::cs_main);
    // Validation is never undone, so this is only checked when a tip is added.
    if (m_signet && !stale_tip.IsValid(BLOCK_VALID_TRANSACTIONS)) return false;
    if (GetEligibleForkPoint(active_chain, stale_tip) == nullptr) return false;
    // Only one variant of a block is tracked, and the active chain's block
    // counts as seen first, even if it became active later.
    if (m_signet && m_signet->IsVariantOnBranch(stale_tip, *active_chain.Tip(), storage).value_or(true)) return false;

    PruneExpired(active_chain);

    // Nothing to do if the tip, or one of its descendants, is tracked, or
    // when deduplicating variants, if a tracked branch contains a variant of
    // the tip, or may contain one.
    for (const CBlockIndex* tip : m_tips) {
        if (HasAncestor(*tip, stale_tip)) return false;
        if (m_signet && m_signet->IsVariantOnBranch(stale_tip, *tip, storage).value_or(true)) return false;
    }

    // The tip replaces any tracked ancestors and, when deduplicating variants,
    // tracked tips that are known to be variants of a block on its branch.
    std::erase_if(m_tips, [&](const CBlockIndex* tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return HasAncestor(stale_tip, *tip) ||
               (m_signet && m_signet->IsVariantOnBranch(*tip, stale_tip, storage).value_or(false));
    });

    if (m_tips.size() == MAX_ADVERTISED_STALETIPS) {
        // Evict the tip with the least work, if it has less than the new
        // tip. min_element returns the first, so the oldest, of equals.
        const auto evict{std::ranges::min_element(m_tips, {}, [](const CBlockIndex* tip) { return tip->nChainWork; })};
        if ((*evict)->nChainWork >= stale_tip.nChainWork) return false;
        m_tips.erase(evict);
    }

    m_tips.push_back(&stale_tip);
    if (m_signet) m_signet->RememberAdmission(stale_tip, active_chain[stale_tip.nHeight], m_tips);
    return true;
}

void StaleTipTracker::SeedFromBlockIndex(const node::BlockManager& blockman, const CChain& active_chain)
{
    AssertLockHeld(::cs_main);

    if (m_signet) m_signet->blockman = &blockman;

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
    return Add(active_chain, stale_tip, m_signet ? m_signet->blockman : nullptr);
}

bool StaleTipTracker::AddStaleTipFromPeer(const CChain& active_chain, const CBlockIndex& stale_tip)
{
    return Add(active_chain, stale_tip, nullptr);
}

bool StaleTipTracker::CanRequestStaleTipBlock(const CChain& active_chain, const CBlockIndex& stale_tip) const
{
    AssertLockHeld(::cs_main);
    if (GetEligibleForkPoint(active_chain, stale_tip) == nullptr) return false;
    const CBlockIndex* active_block{active_chain[stale_tip.nHeight]};
    return !m_signet || active_block == nullptr || !SignetState::IsHeaderVariant(stale_tip, *active_block).value_or(false);
}

bool StaleTipTracker::CanServeStaleBranchBlock(const CChain& active_chain, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    if (!(block.nStatus & BLOCK_HAVE_DATA)) return false;

    for (const CBlockIndex* tip : m_tips) {
        if (!(tip->nStatus & BLOCK_HAVE_DATA)) continue;

        const CBlockIndex* fork_point{GetEligibleForkPoint(active_chain, *tip)};
        if (fork_point == nullptr) continue;
        if (block.nHeight <= fork_point->nHeight || !HasAncestor(*tip, block)) continue;
        if (m_signet && m_signet->IsHiddenByActiveChain(active_chain, *tip)) continue;
        return true;
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
        if (m_signet && m_signet->IsHiddenByActiveChain(active_chain, *tip)) continue;
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
