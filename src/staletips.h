// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STALETIPS_H
#define BITCOIN_STALETIPS_H

#include <chain.h>
#include <kernel/cs_main.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

/** Maximum number of compressed headers permitted in a `staletip` message. */
static constexpr size_t MAX_STALETIP_HEADERS{20};
/** Default number of blocks below the active tip within which a stale tip is
 *  still considered recent enough to be tracked and relayed. */
static constexpr int STALETIP_RECENT_WINDOW{1000};
/** Maximum number of stale tips retained in StaleTipCache, and so the maximum
 *  number of previously known stale tips advertised to a peer. */
static constexpr size_t MAX_ADVERTISED_STALETIPS{10};

/** A stale branch of the block tree, described by its tip and the point where
 *  it forks off the active chain. */
struct StaleFork {
    //! Last common ancestor of the stale tip and the active chain.
    std::reference_wrapper<const CBlockIndex> fork_point;
    //! Tip of the stale branch.
    std::reference_wrapper<const CBlockIndex> tip;
};

/** Cache of recently seen stale tips: tips of valid (or potentially valid)
 *  branches of the block tree that are not part of the active chain.
 *
 * At most MAX_ADVERTISED_STALETIPS tips are tracked (retained in the cache)
 * for later relay to peers. A tracked tip is only relayed while it is
 * eligible: its branch forks off the active chain by no more than
 * `m_max_headers` blocks, its height is within `m_recent_window` blocks of
 * the active tip, it has no more work than the active tip, and it is not
 * known to be invalid. Stricter policies apply on test networks: on signet
 * the tip's block data must be available (the block signature cannot be
 * verified from headers alone) and header variants are deduplicated, while
 * on testnet the tip must meet a minimum difficulty so that min-difficulty
 * blocks are not relayed. A tip that is ineligible only for now, for
 * example because a reorg changed its fork point, stays tracked. A tip that
 * can never become eligible again is dropped the next time a tip is added.
 */
class StaleTipCache
{
private:
    struct Entry {
        //! Tracked stale tip, or nullptr for an unused slot.
        const CBlockIndex* tip{nullptr};
        //! Sequence number assigned when the tip was added, used as a
        //! deterministic tie-breaker for eviction.
        uint64_t seqno{0};
    };

    std::array<Entry, MAX_ADVERTISED_STALETIPS> m_tips{};
    //! Sequence number to assign to the next addition.
    uint64_t m_next_seqno{1};
    ChainType m_chain_type{ChainType::MAIN};
    //! Tips more than this many blocks below the active tip are not tracked.
    int m_recent_window{STALETIP_RECENT_WINDOW};
    //! Maximum stale branch length to track.
    size_t m_max_headers{MAX_STALETIP_HEADERS};

    /** Find the fork point of `stale_tip` with the active chain, checking that
     *  the tip is eligible for tracking.
     *
     * @return The fork point, or nullptr if the tip is not eligible.
     */
    const CBlockIndex* GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `stale_tip` can never become eligible again: it is known to be
     *  invalid, or too far below the active tip. */
    bool IsExpired(const CChain& chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Drop tracked tips that have expired (see IsExpired()). */
    void PruneExpired(const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Insert `stale_tip` into the cache, dropping any tracked tips that it
     *  descends from. Does nothing if one of its descendants is already
     *  tracked, or if the cache is full of tips with more work. When full,
     *  the tip with the least work is evicted, preferring to evict the least
     *  recently added among tips with equal work. On
     *  signet, tracked header variants of `stale_tip` are either kept in its
     *  place or replaced by it, whichever has the longer branch. */
    bool Add(const CBlockIndex& stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    /** Maximum target allowed for testnet stale-tip relay policy. */
    static const uint256 TESTNET_MAX_TARGET;

    StaleTipCache() = default;
    /** Construct a cache with a non-default chain type or policy parameters. */
    explicit StaleTipCache(ChainType chain_type, int recent_window = STALETIP_RECENT_WINDOW, size_t max_headers = MAX_STALETIP_HEADERS)
        : m_chain_type{chain_type}, m_recent_window{recent_window}, m_max_headers{max_headers}
    {
    }

    explicit StaleTipCache(int recent_window, size_t max_headers)
        : StaleTipCache{ChainType::MAIN, recent_window, max_headers}
    {
    }

    /** Track `stale_tip` if it is eligible (see GetEligibleForkPoint()) and can
     *  be retained under the cache's resource limits.
     *
     * @return Whether the cache was updated to track `stale_tip`.
     */
    bool AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Get the tracked tips that are eligible for relay, with their fork points. */
    std::vector<StaleFork> GetStaleTips(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

#endif // BITCOIN_STALETIPS_H
