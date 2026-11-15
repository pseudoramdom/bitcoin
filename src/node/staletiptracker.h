// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_STALETIPTRACKER_H
#define BITCOIN_NODE_STALETIPTRACKER_H

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/cs_main.h>
#include <staletipmessage.h>
#include <util/chaintype.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

namespace node {
class BlockManager;

/** Default number of blocks below the active tip within which a stale tip is
 *  still considered recent enough to be tracked. From BIP 332. */
inline constexpr int STALETIP_RECENT_WINDOW{1000};

/** Maximum number of stale tips StaleTipTracker retains. From BIP 332, which
 *  limits how many previously known stale tips are advertised to a peer. */
inline constexpr size_t MAX_ADVERTISED_STALETIPS{10};

/** Whether `ancestor` is an ancestor of `block`, or `block` itself. */
bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor);

/** A stale branch of the block tree, described by its tip and the point where
 *  it forks off the active chain. */
struct StaleFork {
    //! Last common ancestor of the stale tip and the active chain. Never null.
    const CBlockIndex* fork_point;
    //! Tip of the stale branch. Never null.
    const CBlockIndex* tip;
};

/** Build the `staletip` message announcing `fork`, compressing the headers
 *  between `fork.fork_point` (exclusive) and `fork.tip` (inclusive). */
StaleTipMessage MakeStaleTipMessage(const StaleFork& fork, bool have_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/** Tracker of recently seen stale tips: tips of valid (or potentially valid)
 *  branches of the block tree that are not part of the active chain.
 *
 * At most MAX_ADVERTISED_STALETIPS tips are tracked for later relay to
 * peers. A tracked tip is only relayed while it is eligible: its branch forks
 * off the active chain by no more than `m_max_headers` blocks, its height is
 * within `m_recent_window` blocks of the active tip, it has no more work than
 * the active tip, and it is not known to be invalid. A tip that is ineligible
 * only for now, for example because a reorg changed its fork point, stays
 * tracked. A tip that can never become eligible again is dropped the next
 * time an eligible tip is added.
 *
 * Stricter policies apply on test networks: on signet the tip's block must
 * have been validated (the block signature cannot be verified from headers
 * alone) and block variants are deduplicated, including against the active
 * chain, while on testnet the tip must meet a minimum difficulty so that
 * min-difficulty blocks are not relayed.
 *
 * Signet blocks are variants when the data their BIP 325 signature commits
 * to is the same: the previous block, version, time and signet merkle root.
 * Anyone can turn a signed block into a variant with a different header
 * merkle root by changing its unsigned solution. The signet merkle root is
 * not in the header, so comparing it can require reading both blocks. Blocks
 * are read on demand for local admission and for retained tips after a reorg.
 */
class StaleTipTracker
{
    struct SignetState;
    std::unique_ptr<SignetState> m_signet;

    //! Tracked stale tips in the order they were added, oldest first.
    //! Never holds more than MAX_ADVERTISED_STALETIPS entries.
    std::vector<const CBlockIndex*> m_tips;
    //! Highest proof-of-work target a tracked tip may have, if limited. Set
    //! on testnet3 and testnet4, where minimum-difficulty blocks are cheap.
    std::optional<arith_uint256> m_max_target;
    //! Tips more than this many blocks below the active tip are not tracked.
    int m_recent_window{STALETIP_RECENT_WINDOW};
    //! Maximum stale branch length to track.
    size_t m_max_headers{MAX_STALETIP_HEADERS};

    /** Find the fork point of `stale_tip` with the active chain, checking that
     *  the tip is eligible. On signet, AddStaleTip() also requires the tip's
     *  block to have been validated, and variants are checked separately.
     *
     * @return The fork point, or nullptr if the tip is not eligible.
     */
    const CBlockIndex* GetEligibleForkPoint(const CChain& active_chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `stale_tip` can never become eligible again: it is known to be
     *  invalid, or too far below the active tip. */
    bool IsExpired(const CChain& active_chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Drop tracked tips that have expired (see IsExpired()). */
    void PruneExpired(const CChain& active_chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Insert `stale_tip` into the tracker, dropping any tracked tips that it
     *  descends from. Does nothing if one of its descendants is already
     *  tracked, or if the tracker is full and no tracked tip has less work.
     *  When full, the tip with the least work is evicted, preferring to evict
     *  the least recently added among tips with equal work. A tip never
     *  evicts one with equal work, so announcing an evicted tip again cannot
     *  readmit it while the tracker stays full.
     *
     *  On signet, `stale_tip` is not added if it is a variant of a block on a
     *  tracked branch, and replaces tracked tips that are variants of a block
     *  on its own branch. A tip built on a variant of a tracked tip therefore
     *  replaces it, which BIP 332 does not require. Tips that only descend
     *  from variants of the same block, without being variants themselves,
     *  are all kept, as the BIP allows. A comparison that cannot be made
     *  keeps `stale_tip` out, but never drops a tracked tip. A null `storage`
     *  restricts these comparisons to headers and cached roots. */
    bool Add(const CChain& active_chain, const CBlockIndex& stale_tip, const BlockManager* storage) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    /** Construct a tracker applying `chain_type`'s policy, with optional
     *  non-default policy parameters for tests. */
    explicit StaleTipTracker(ChainType chain_type = ChainType::MAIN,
                             int recent_window = STALETIP_RECENT_WINDOW,
                             size_t max_headers = MAX_STALETIP_HEADERS);
    ~StaleTipTracker();

    /** Track the eligible stale tips already in the block index, as the
     *  tracker is not persisted. Scans every block index entry, so it is
     *  meant to be called once at startup. On signet, subsequent root
     *  comparisons use this block manager, which must outlive the tracker. */
    void SeedFromBlockIndex(const node::BlockManager& blockman, const CChain& active_chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Track `stale_tip` if it is eligible (see GetEligibleForkPoint()) and can
     *  be retained under the tracker's resource limits. On signet, the tip's
     *  block must also have been validated, and it must be known not to be a
     *  variant of an active or tracked block.
     *
     * @return Whether the tracker was updated to track `stale_tip`.
     */
    bool AddStaleTip(const CChain& active_chain, const CBlockIndex& stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Apply the same admission policy to a peer announcement, using only
     *  cached signet roots when a comparison needs block data. */
    bool AddStaleTipFromPeer(const CChain& active_chain, const CBlockIndex& stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether the block data for `stale_tip` may be requested from a peer.
     *  On signet, AddStaleTip() requires the block to have been validated;
     *  requesting it is allowed before then, since the signet signature can
     *  only be verified with the block data. The same goes for comparing
     *  variants, unless the headers alone show that it is one. */
    bool CanRequestStaleTipBlock(const CChain& active_chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `block` is stored on a tracked, still-eligible stale branch and
     *  may be served to a peer that negotiated stale-tip relay. */
    bool CanServeStaleBranchBlock(const CChain& active_chain, const CBlockIndex& block) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the tracked tips that are currently eligible, with their fork
     *  points, in the order they were added. */
    std::vector<StaleFork> GetStaleTips(const CChain& active_chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `tip` is tracked, even if it is currently ineligible. */
    bool IsTracked(const CBlockIndex& tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

} // namespace node

#endif // BITCOIN_NODE_STALETIPTRACKER_H
