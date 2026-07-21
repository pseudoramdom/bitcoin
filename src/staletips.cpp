// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>

#include <chain.h>

#include <algorithm>
#include <vector>

namespace {

/** Whether `ancestor` is an ancestor of `block`, or `block` itself. */
bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor)
{
    return block.nHeight >= ancestor.nHeight && block.GetAncestor(ancestor.nHeight) == &ancestor;
}

} // namespace

const CBlockIndex* StaleTipTracker::GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const
{
    const CBlockIndex* active_tip{chain.Tip()};
    if (active_tip == nullptr) return nullptr;
    if (chain.Contains(stale_tip)) return nullptr;
    if (IsExpired(chain, stale_tip)) return nullptr;
    if (stale_tip.nChainWork > active_tip->nChainWork) return nullptr;

    const CBlockIndex* fork_point{chain.FindFork(stale_tip)};
    if (fork_point == nullptr) return nullptr;

    const int fork_length{stale_tip.nHeight - fork_point->nHeight};
    if (fork_length <= 0 || static_cast<size_t>(fork_length) > m_max_headers) return nullptr;

    return fork_point;
}

bool StaleTipTracker::IsExpired(const CChain& chain, const CBlockIndex& stale_tip) const
{
    if (stale_tip.nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)) return true;
    const CBlockIndex* active_tip{chain.Tip()};
    return active_tip != nullptr && stale_tip.nHeight < active_tip->nHeight - m_recent_window;
}

void StaleTipTracker::PruneExpired(const CChain& chain)
{
    AssertLockHeld(::cs_main);
    for (auto& entry : m_tips) {
        if (entry.tip != nullptr && IsExpired(chain, *entry.tip)) entry = {};
    }
}

bool StaleTipTracker::Add(const CBlockIndex& stale_tip)
{
    AssertLockHeld(::cs_main);

    Entry* available{nullptr};
    Entry* evict{nullptr};
    std::vector<Entry*> replace;

    auto better_evict_candidate = [](const Entry* current, const Entry& candidate) {
        return current == nullptr || candidate.tip->nChainWork < current->tip->nChainWork ||
               (candidate.tip->nChainWork == current->tip->nChainWork && candidate.seqno < current->seqno);
    };

    for (auto& entry : m_tips) {
        if (entry.tip == nullptr) {
            if (available == nullptr) available = &entry;
            continue;
        }

        if (entry.tip == &stale_tip) return false;

        if (HasAncestor(stale_tip, *entry.tip)) {
            replace.push_back(&entry);
            continue;
        }
        if (HasAncestor(*entry.tip, stale_tip)) return false;

        if (entry.tip->nChainWork < stale_tip.nChainWork && better_evict_candidate(evict, entry)) {
            evict = &entry;
        }
    }

    Entry* target{!replace.empty() ? replace.front() : available != nullptr ? available : evict};
    if (target == nullptr) return false;

    for (Entry* entry : replace) {
        *entry = {};
    }
    target->tip = &stale_tip;
    target->seqno = m_next_seqno++;
    return true;
}

bool StaleTipTracker::AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip)
{
    AssertLockHeld(::cs_main);
    if (stale_tip == nullptr) return false;
    if (GetEligibleForkPoint(chain, *stale_tip) == nullptr) return false;

    PruneExpired(chain);
    return Add(*stale_tip);
}

std::vector<StaleFork> StaleTipTracker::GetStaleTips(const CChain& chain) const
{
    AssertLockHeld(::cs_main);

    // Slots are reused, so sort by sequence number to return tips in the
    // order they were added.
    std::vector<const Entry*> entries;
    entries.reserve(m_tips.size());
    for (const auto& entry : m_tips) {
        if (entry.tip != nullptr) entries.push_back(&entry);
    }
    std::ranges::sort(entries, {}, [](const Entry* entry) { return entry->seqno; });

    std::vector<StaleFork> tips;
    tips.reserve(entries.size());
    for (const Entry* entry : entries) {
        const CBlockIndex* fork_point{GetEligibleForkPoint(chain, *entry->tip)};
        if (fork_point == nullptr) continue;
        tips.push_back({.fork_point = *fork_point, .tip = *entry->tip});
    }

    return tips;
}
